//! The transaction pool (sometimes “mempool”) stores transactions prior to
//! their inclusion in the blockchain.

use std::collections::HashMap;
use std::sync::Arc;

use bytesize::ByteSize;
use get_size2::GetSize;
use thiserror::Error;
use tokio::time::Duration;
use tokio::time::Instant;

use crate::api::export::BlockHeight;
use crate::api::export::Timestamp;
use crate::api::export::Transaction;
use crate::api::export::TransactionKernelId;
use crate::models::blockchain::block::Block;

#[derive(Debug, GetSize)]
pub struct TransactionPool {
    // This type probably needs additional work.
    pool: HashMap<(BlockHeight, TransactionKernelId), PoolTransaction>,

    #[get_size(size = 8)] // Underlying type uses one u64.
    max_size: ByteSize,

    chain_tip: Block,

    /// The max time a transaction is kept in the transaction pool.
    tx_expiry: Duration,

    /// How often the transaction pool should prune stale and outdated
    /// transactions.
    prune_interval: Duration,

    /// The last time the transaction pool pruned stale and outdated
    /// transactions.
    #[get_size(size = 12)] // Underlying type uses one u64, one u32.
    last_prune_time: Instant,

    /// Transactions with a smaller fee density than this user-configured value
    /// will not be accepted into the transaction pool.
    ///
    /// In Bitcoin terms, this is `minrelaytxfee`.
    configured_min_fee_density: FeeDensity,

    /// Transactions with a smaller fee density than this dynamically computed
    /// value will not be accepted into the mempool.
    ///
    /// Inspired by Bitcoin's `mempoolminfee`.
    /// See also: https://bitcoin.stackexchange.com/questions/108126
    dynamic_min_fee_density: FeeDensity,

    /// as needed:
    more_fields: (),
}

/// A [`Transaction`] plus the metadata required for the [`TransactionPool`].
#[derive(Debug, Clone, GetSize)]
pub(self) struct PoolTransaction {
    tx: Arc<Transaction>,

    sequence_number: u64,

    #[get_size(size = 12)] // Underlying type uses one u64, one u32.
    entered: Instant,

    #[get_size(size = 12)] // Underlying type uses one u64, one u32.
    last_broadcast: Option<Instant>,

    fee_density: FeeDensity,

    priorities: HashMap<SubscriberToken, TransactionPriority>,

    /// as needed:
    more_fields: (),
}

/// In Neptune Atomic Units (NAU) per byte.
#[derive(Debug, Copy, Clone, GetSize)]
pub(self) struct FeeDensity(f64); // todo: figure out type

/// A unique identifier for a transaction pool subscriber.
#[derive(Debug, Copy, Clone, Eq, PartialEq, GetSize)]
pub struct SubscriberToken(u64); // todo: figure out type

/// Used by transaction pool subscribers to indicate how interested they are in
/// a specific transaction.
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, GetSize)]
pub enum TransactionPriority {
    #[default]
    Irrelevant,

    /// There's a certain amount of interest.
    ///
    /// For example, wallets can use the sum of the outputs the transaction
    /// sends to them. If the transaction relates to some smart contract, the
    /// wallet should judge the priority
    Interested(u64),

    /// The transaction in question is of the highest possible priority. Wallets
    /// should use this for transactions they have initiated.
    ///
    /// Transactions marked with this priority will not leave the pool (unless
    /// specifically instructed), will be re-broadcast occasionally, will always
    /// be updated first, and (if applicable) their proof quality will always be
    /// raised first.
    Critical,
}

#[derive(Debug, Clone, Eq, PartialEq, GetSize)]
#[non_exhaustive]
pub enum TransactionPoolEvent {
    Addition(Arc<Transaction>),
    Removal(TransactionKernelId),
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Error)]
pub(crate) enum TransactionPoolError {
    #[error("")]
    TransactionIsDuplicate,

    #[error("")]
    TransactionTooOld(Timestamp),

    #[error("")]
    TransactionTooFarInTheFuture(Timestamp),
}

impl TransactionPool {
    pub fn new(max_size: ByteSize, chain_tip: Block) -> Self {
        Self {
            pool: todo!(),
            max_size,
            chain_tip,
            tx_expiry: todo!(),
            prune_interval: todo!(),
            last_prune_time: todo!(),
            configured_min_fee_density: todo!(),
            dynamic_min_fee_density: todo!(),
            more_fields: (),
        }
    }

    /// It is not guaranteed that the passed-in transaction will get taken in by
    /// the transaction pool.
    pub fn insert(&mut self, tx: Arc<Transaction>) {
        // purposefully ignore the result
        let _ = self.try_insert(tx);
    }

    pub(crate) fn try_insert(&mut self, tx: Arc<Transaction>) -> Result<(), TransactionPoolError> {
        // See old PeerLoopHandler::handle_peer_message for how things used to
        // be done for the cases listed below.
        //
        // if tx already exists: error
        // if tx is too old: error
        // if tx is too far in the future: error
        // if tx cannot be confirmed relative to current tip:
        //   - match TransactionConfirmabilityError
        //   - think of strategy
        // if tx cannot be applied to current mutator set: think of strategy

        todo!()
    }

    pub fn get(&self, tx_id: TransactionKernelId) -> Option<Arc<Transaction>> {
        todo!()
    }

    pub fn get_mut(&mut self, tx_id: TransactionKernelId) -> Option<&mut Transaction> {
        todo!()
    }

    pub fn clear(&mut self) {
        todo!()
    }

    pub(crate) fn set_chain_tip(&mut self, block: &Block) {
        todo!()
    }

    pub fn subscribe(&mut self) -> SubscriberToken {
        todo!()
    }

    pub fn unsubscribe(&mut self, token: SubscriberToken) {
        todo!()
    }

    /// Should be regularly, ideally continuously polled by subscribers to get
    /// informed about changes to the transaction pool.
    ///
    /// Upon initial subscription, this method supplies the entire content of
    /// the transaction pool through a series of
    /// [events](TransactionPoolEvent::Addition).
    //
    // Only presents information relevant with respect to the current chain tip.
    pub async fn next_event(&mut self, token: SubscriberToken) -> Option<TransactionPoolEvent> {
        todo!()
    }

    pub fn set_tx_priority(
        &mut self,
        token: SubscriberToken,
        tx_id: TransactionKernelId,
        priority: TransactionPriority,
    ) {
        todo!()
    }

    /// For upgraders, which perform the first of the three mining steps.
    ///
    /// The proof quality of the returned transaction (if any) can still be
    /// raised, _i.e._, the transaction is not backed by a [`SingleProof`].
    /// Raising the proof quality is upgrading work for which a fee can be
    /// claimed.
    //
    // todo: should the return type be `impl Iterator<Transaction>`?
    pub(crate) async fn best_tx_for_raise(&self) -> Option<Transaction> {
        todo!()
    }

    /// For upgraders.
    ///
    /// The returned transaction (if any) is not confirmable with respect to the
    /// current tip of the blockchain. In other words, the transaction is
    /// confirmable with respect to an outdated [mutator set](MutatorSet).
    pub(crate) async fn best_tx_for_update(&self) -> Option<Transaction> {
        todo!()
    }

    /// For upgraders.
    ///
    /// The returned transactions (if any) can be merged without exceeding any
    /// of the limits imposed by the consensus rules.
    //
    // The four limits imposed by the consensus rules:
    // - max block size
    // - max number of inputs
    // - max number of outputs
    // - max number of public announcements
    pub(crate) async fn best_txs_for_merge(&self) -> Option<[Transaction; 2]> {
        todo!()
    }

    /// For composers, which perform the second of the three mining steps.
    ///
    /// The returned transaction (if any) can be combined with a coinbase
    /// transaction and turned into a block proposal.
    pub(crate) async fn best_tx_for_composition(&self) -> Option<Transaction> {
        todo!()
    }

    /// Prune stale and outdated transactions.
    ///
    /// Can be called often, as it only does something if the “prune interval”
    /// (see implementation of [`Self::new()`]) has expired.
    fn prune(&mut self) {
        if Instant::now() < self.last_prune_time + self.prune_interval {
            return;
        }

        todo!();

        self.last_prune_time = Instant::now();
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    impl TransactionPool {
        pub fn len(&self) -> usize {
            self.pool.len()
        }

        pub fn is_empty(&self) -> bool {
            self.pool.is_empty()
        }
    }
}
