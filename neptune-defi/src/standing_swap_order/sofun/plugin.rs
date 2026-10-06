//! The SOFuN plugin: it keeps the order book in step with the chain and has
//! the node fill the best order in every block it composes.

use std::fmt;

use neptune_consensus::block::block_header::BlockPow;
use neptune_consensus::block::Block;
use neptune_consensus::consensus_rule_set::ConsensusRuleSet;
use neptune_mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use neptune_primitives::block_selector::BlockSelector;
use neptune_primitives::network::Network;
use neptune_primitives::timestamp::Timestamp;
use neptune_rpc_api::api::rpc::RpcApi;
use neptune_rpc_api::api::rpc::RpcError;
use neptune_rpc_api::model::mining::RpcPrimitiveWitness;
use neptune_wallet::address::KeyType;
use neptune_wallet::address::ReceivingAddress;

use super::fill::fill_witness;
use super::fill::FillError;
use super::fill::FillTerms;
use super::Sofun;
use crate::chain::BlockId;
use crate::driver::Driver;
use crate::driver::DriverError;
use crate::driver::RpcChain;
use crate::plugin::Event;
use crate::plugin::Kind;
use crate::standing_swap_order::order_book::OrderBook;
use crate::standing_swap_order::order_book::OrderId;

/// Why the plugin could not follow an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginError {
    Driver(DriverError),
    Rpc(RpcError),
    Fill(FillError),

    /// The node gave something the plugin cannot use.
    Node(String),
}

impl fmt::Display for PluginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Driver(error) => write!(f, "{error}"),
            Self::Rpc(error) => write!(f, "{error}"),
            Self::Fill(error) => write!(f, "{error}"),
            Self::Node(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for PluginError {}

impl From<RpcError> for PluginError {
    fn from(error: RpcError) -> Self {
        Self::Rpc(error)
    }
}

/// What the plugin had the node do for the next block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The node fills this order in the next block it composes.
    Filling(OrderId),

    /// No open order can be filled in the next block, so the node composes its
    /// own coinbase transaction.
    NoOrder,

    /// The node's tip moved on while the fill was built, so nothing was set;
    /// the notification of the new tip sets the next one.
    TipMoved,

    /// The event was not about blocks, so nothing changed.
    Ignored,
}

/// The SOFuN plugin's state.
#[derive(Debug)]
pub struct SofunPlugin<C> {
    driver: Driver<OrderBook<Sofun>>,
    chain: RpcChain<C>,
    composer: ReceivingAddress,
    network: Network,
    depth: usize,
}

/// The notifications the plugin needs.
pub const SUBSCRIPTIONS: [Kind; 1] = [Kind::Block];

impl<C: RpcApi + Clone> SofunPlugin<C> {
    /// A plugin reading and instructing the node through `client`, whose book
    /// keeps closed orders, and whose driver follows reorganizations, for
    /// `depth` blocks.
    ///
    /// The composer's share of every fill goes to one new generation address
    /// of the node's wallet.
    pub async fn new(client: C, network: Network, depth: usize) -> Result<Self, PluginError> {
        let address = client.generate_address(KeyType::Generation).await?.address;
        let composer = ReceivingAddress::from_bech32m(&address, network)
            .map_err(|error| PluginError::Node(format!("not an address: {error}")))?;

        Ok(Self {
            driver: Self::driver(depth),
            chain: RpcChain { client },
            composer,
            network,
            depth,
        })
    }

    fn driver(depth: usize) -> Driver<OrderBook<Sofun>> {
        Driver::new(OrderBook::new(Sofun::asset_pair(), depth as u64), depth)
    }

    pub fn book(&self) -> &OrderBook<Sofun> {
        self.driver.state()
    }

    /// Follow `event`, and then set the fill for the block after the tip.
    ///
    /// A block notification and a lag notice move the book to the new tip;
    /// any other notification changes nothing. If the chain reorganized deeper
    /// than the driver follows, the book starts over at the tip, knowing only
    /// the orders placed after that.
    pub async fn on_event(&mut self, event: &Event) -> Result<Outcome, PluginError> {
        let followed = match event {
            Event::Notification(notification) if notification.kind == Kind::Block => {
                self.driver.on_block(notification.id, &self.chain).await
            }
            Event::Lagged(_) => self.driver.on_lagged(&self.chain).await,
            Event::Notification(_) => return Ok(Outcome::Ignored),
        };
        if let Err(DriverError::TooDeep { .. }) = followed {
            self.driver = Self::driver(self.depth);
            self.driver
                .on_lagged(&self.chain)
                .await
                .map_err(PluginError::Driver)?;
        } else {
            followed.map_err(PluginError::Driver)?;
        }

        self.set_fill().await
    }

    /// Set the fill of the best open order for the block after the book's tip,
    /// or unset the fill if there is none.
    async fn set_fill(&self) -> Result<Outcome, PluginError> {
        let tip = self.driver.tip().expect("the driver followed a block");
        let client = &self.chain.client;
        let header = client
            .get_block_header(BlockSelector::Digest(tip.hash))
            .await?
            .header
            .ok_or_else(|| PluginError::Node(format!("no header for {}", tip.hash.to_hex())))?;

        let height = tip.height.next();
        let timestamp = Timestamp::now().max(header.timestamp + self.network.minimum_block_time());
        let subsidy = Block::block_subsidy(height);
        let Some(order) = self.book().best_fill(subsidy, timestamp) else {
            client.set_coinbase_tx(None).await?;
            return Ok(Outcome::NoOrder);
        };

        let snapshot = client
            .restore_membership_proof(vec![order.order.absolute_index_set(order.id)])
            .await?
            .snapshot;
        if snapshot.synced_hash != tip.hash {
            return Ok(Outcome::TipMoved);
        }
        let membership_proof = snapshot
            .membership_proofs
            .into_iter()
            .next()
            .and_then(|proof| {
                proof.extract_ms_membership_proof(
                    order.id.0,
                    order.order.offered_sender_randomness(),
                    order.order.offered_receiver_preimage(),
                )
            })
            .ok_or_else(|| PluginError::Node("no membership proof for the order".to_owned()))?;

        let terms = FillTerms {
            height,
            timestamp,
            mutator_set: MutatorSetAccumulator::from(snapshot.synced_mutator_set),
            membership_proof,
            lustration_status: self.lustration_status(tip, header.pow.into())?,
            composer: self.composer.clone(),
            network: self.network,
        };
        let witness = fill_witness(order, &terms).map_err(PluginError::Fill)?;
        witness
            .validate()
            .await
            .map_err(|error| PluginError::Node(format!("the fill is invalid: {error:?}")))?;

        client
            .set_coinbase_tx(Some(RpcPrimitiveWitness::from(&witness)))
            .await?;
        Ok(Outcome::Filling(order.id))
    }

    /// The lustration status after `tip`, whose proof of work is `pow`, if
    /// lustration is in force there.
    fn lustration_status(
        &self,
        tip: BlockId,
        pow: BlockPow,
    ) -> Result<Option<neptune_consensus::block::pow::LustrationStatus>, PluginError> {
        if ConsensusRuleSet::first_lustration_block(self.network) > tip.height {
            return Ok(None);
        }
        pow.lustration_status()
            .map(Some)
            .map_err(|error| PluginError::Node(format!("no lustration status: {error:?}")))
    }
}
