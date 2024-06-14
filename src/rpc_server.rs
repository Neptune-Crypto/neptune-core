use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::models::state::wallet::coin_with_possible_timelock::CoinWithPossibleTimeLock;
use crate::prelude::twenty_first;

use anyhow::Result;
use get_size::GetSize;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::str::FromStr;
use systemstat::{Platform, System};
use tarpc::context;
use tokio::sync::mpsc::error::SendError;
use tracing::{error, info};
use twenty_first::math::digest::Digest;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;

use crate::config_models::network::Network;
use crate::models::blockchain::block::block_header::BlockHeader;
use crate::models::blockchain::block::block_height::BlockHeight;
use crate::models::blockchain::block::block_info::BlockInfo;
use crate::models::blockchain::block::block_selector::BlockSelector;
use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::channel::RPCServerToMain;
use crate::models::peer::InstanceId;
use crate::models::peer::PeerInfo;
use crate::models::peer::PeerStanding;
use crate::models::state::wallet::address::generation_address;
use crate::models::state::wallet::wallet_status::WalletStatus;
use crate::models::state::{GlobalStateLock, UtxoReceiverData};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DashBoardOverviewDataFromClient {
    pub tip_digest: Digest,
    pub tip_header: BlockHeader,
    pub syncing: bool,
    pub available_balance: NeptuneCoins,
    pub timelocked_balance: NeptuneCoins,
    pub mempool_size: usize,
    pub mempool_tx_count: usize,

    // `None` symbolizes failure in getting peer count
    pub peer_count: Option<usize>,

    // `None` symbolizes failure to get mining status
    pub is_mining: Option<bool>,

    // # of confirmations since last wallet balance change.
    // `None` indicates that wallet balance has never changed.
    pub confirmations: Option<BlockHeight>,

    /// CPU temperature in degrees Celcius
    pub cpu_temp: Option<f32>,
}

#[tarpc::service]
pub trait RPC {
    /******** READ DATA ********/
    // Place all methods that only read here
    // Return which network the client is running
    async fn network() -> Network;

    async fn own_listen_address_for_peers() -> Option<SocketAddr>;

    /// Return the node's instance-ID which is a globally unique random generated number
    /// set at startup used to ensure that the node does not connect to itself, or the
    /// same peer twice.
    async fn own_instance_id() -> InstanceId;

    /// Returns the current block height.
    async fn block_height() -> BlockHeight;

    /// Returns the number of blocks (confirmations) since wallet balance last changed.
    ///
    /// returns `Option<BlockHeight>`
    ///
    /// return value will be None if wallet has not received any incoming funds.
    async fn confirmations() -> Option<BlockHeight>;

    /// Returns info about the peers we are connected to
    async fn peer_info() -> Vec<PeerInfo>;

    /// Return info about all peers that have been sanctioned
    async fn all_sanctioned_peers() -> HashMap<IpAddr, PeerStanding>;

    /// Returns the digest of the latest n blocks
    async fn latest_tip_digests(n: usize) -> Vec<Digest>;

    /// Returns information about the specified block if found
    async fn block_info(block_selector: BlockSelector) -> Option<BlockInfo>;

    /// Return the digest for the specified block if found
    async fn block_digest(block_selector: BlockSelector) -> Option<Digest>;

    /// Return the digest for the specified UTXO leaf index if found
    async fn utxo_digest(leaf_index: u64) -> Option<Digest>;

    /// Return the block header for the specified block
    async fn header(block_selector: BlockSelector) -> Option<BlockHeader>;

    /// Get sum of unspent UTXOs.
    async fn synced_balance() -> NeptuneCoins;

    /// Get the client's wallet transaction history
    async fn history() -> Vec<(Digest, BlockHeight, Timestamp, NeptuneCoins)>;

    /// Return information about funds in the wallet
    async fn wallet_status() -> WalletStatus;

    /// Return an address that this client can receive funds on
    async fn own_receiving_address() -> generation_address::ReceivingAddress;

    /// Return the number of transactions in the mempool
    async fn mempool_tx_count() -> usize;

    // TODO: Change to return current size and max size
    async fn mempool_size() -> usize;

    /// Return the information used on the dashboard's overview tab
    async fn dashboard_overview_data() -> DashBoardOverviewDataFromClient;

    /// Determine whether the user-supplied string is a valid address
    async fn validate_address(
        address: String,
        network: Network,
    ) -> Option<generation_address::ReceivingAddress>;

    /// Determine whether the user-supplied string is a valid amount
    async fn validate_amount(amount: String) -> Option<NeptuneCoins>;

    /// Determine whether the given amount is less than (or equal to) the balance
    async fn amount_leq_synced_balance(amount: NeptuneCoins) -> bool;

    /// Generate a report of all owned and unspent coins, whether time-locked or not.
    async fn list_own_coins() -> Vec<CoinWithPossibleTimeLock>;

    /******** CHANGE THINGS ********/
    // Place all things that change state here

    /// Clears standing for all peers, connected or not
    async fn clear_all_standings();

    /// Clears standing for ip, whether connected or not
    async fn clear_standing_by_ip(ip: IpAddr);

    /// Send coins
    async fn send(
        amount: NeptuneCoins,
        address: generation_address::ReceivingAddress,
        fee: NeptuneCoins,
    ) -> Option<Digest>;

    /// Stop miner if running
    async fn pause_miner();

    /// Start miner if not running
    async fn restart_miner();

    /// mark MUTXOs as abandoned
    async fn prune_abandoned_monitored_utxos() -> usize;

    /// Gracious shutdown.
    async fn shutdown() -> bool;

    /// Get CPU temperature.
    async fn cpu_temp() -> Option<f32>;
}

#[derive(Clone)]
pub struct NeptuneRPCServer {
    pub socket_address: SocketAddr,
    pub state: GlobalStateLock,
    pub rpc_server_to_main_tx: tokio::sync::mpsc::Sender<RPCServerToMain>,
}

impl NeptuneRPCServer {
    async fn confirmations_internal(&self) -> Option<BlockHeight> {
        let state = self.state.lock_guard().await;

        match state.get_latest_balance_height().await {
            Some(latest_balance_height) => {
                let tip_block_header = state.chain.light_state().header();

                assert!(tip_block_header.height >= latest_balance_height);

                // subtract latest balance height from chain tip.
                // note: BlockHeight is u64 internally and BlockHeight::sub() returns i128.
                //       The subtraction and cast is safe given we passed the above assert.
                let confirmations: BlockHeight =
                    ((tip_block_header.height - latest_balance_height) as u64).into();
                Some(confirmations)
            }
            None => None,
        }
    }

    /// Return temperature of CPU, if available.
    fn cpu_temp_inner() -> Option<f32> {
        let current_system = System::new();
        match current_system.cpu_temp() {
            Ok(temp) => Some(temp),
            Err(_) => None,
        }
    }
}

impl RPC for NeptuneRPCServer {
    async fn network(self, _: context::Context) -> Network {
        self.state.cli().network
    }

    async fn own_listen_address_for_peers(self, _context: context::Context) -> Option<SocketAddr> {
        let listen_for_peers_ip = self.state.cli().listen_addr;
        let listen_for_peers_socket = self.state.cli().peer_port;
        let socket_address = SocketAddr::new(listen_for_peers_ip, listen_for_peers_socket);
        Some(socket_address)
    }

    async fn own_instance_id(self, _context: context::Context) -> InstanceId {
        self.state.lock_guard().await.net.instance_id
    }

    async fn block_height(self, _: context::Context) -> BlockHeight {
        self.state
            .lock_guard()
            .await
            .chain
            .light_state()
            .kernel
            .header
            .height
    }

    async fn confirmations(self, _: context::Context) -> Option<BlockHeight> {
        self.confirmations_internal().await
    }

    async fn utxo_digest(self, _: context::Context, leaf_index: u64) -> Option<Digest> {
        let state = self.state.lock_guard().await;
        let aocl = &state.chain.archival_state().archival_mutator_set.ams().aocl;

        match leaf_index > 0 && leaf_index < aocl.count_leaves().await {
            true => Some(aocl.get_leaf_async(leaf_index).await),
            false => None,
        }
    }

    async fn block_digest(
        self,
        _: context::Context,
        block_selector: BlockSelector,
    ) -> Option<Digest> {
        let state = self.state.lock_guard().await;
        let archival_state = state.chain.archival_state();
        let digest = block_selector.as_digest(&state).await?;
        // verify the block actually exists
        archival_state
            .get_block_header(digest)
            .await
            .map(|_| digest)
    }

    async fn block_info(
        self,
        _: context::Context,
        block_selector: BlockSelector,
    ) -> Option<BlockInfo> {
        let state = self.state.lock_guard().await;
        let digest = block_selector.as_digest(&state).await?;
        let archival_state = state.chain.archival_state();

        let block = archival_state.get_block(digest).await.unwrap()?;
        Some(BlockInfo::from_block_and_digests(
            &block,
            archival_state.genesis_block().hash(),
            state.chain.light_state().hash(),
        ))
    }

    async fn latest_tip_digests(self, _context: tarpc::context::Context, n: usize) -> Vec<Digest> {
        let state = self.state.lock_guard().await;

        let latest_block_digest = state.chain.light_state().hash();

        state
            .chain
            .archival_state()
            .get_ancestor_block_digests(latest_block_digest, n)
            .await
    }

    async fn peer_info(self, _: context::Context) -> Vec<PeerInfo> {
        self.state
            .lock_guard()
            .await
            .net
            .peer_map
            .values()
            .cloned()
            .collect()
    }

    #[doc = r" Return info about all peers that have been sanctioned"]
    async fn all_sanctioned_peers(
        self,
        _context: tarpc::context::Context,
    ) -> HashMap<IpAddr, PeerStanding> {
        let mut sanctions_in_memory = HashMap::default();

        let global_state = self.state.lock_guard().await;

        // Get all connected peers
        for (socket_address, peer_info) in global_state.net.peer_map.iter() {
            if peer_info.standing.is_negative() {
                sanctions_in_memory.insert(socket_address.ip(), peer_info.standing);
            }
        }

        let sanctions_in_db = global_state.net.all_peer_sanctions_in_database().await;

        // Combine result for currently connected peers and previously connected peers but
        // use result for currently connected peer if there is an overlap
        let mut all_sanctions = sanctions_in_memory;
        for (ip_addr, sanction) in sanctions_in_db {
            all_sanctions.entry(ip_addr).or_insert(sanction);
        }

        all_sanctions
    }

    async fn validate_address(
        self,
        _ctx: context::Context,
        address_string: String,
        network: Network,
    ) -> Option<generation_address::ReceivingAddress> {
        let ret = if let Ok(address) =
            generation_address::ReceivingAddress::from_bech32m(address_string.clone(), network)
        {
            Some(address)
        } else {
            None
        };
        tracing::debug!(
            "Responding to address validation request of {address_string}: {}",
            ret.is_some()
        );
        ret
    }

    async fn validate_amount(
        self,
        _ctx: context::Context,
        amount_string: String,
    ) -> Option<NeptuneCoins> {
        // parse string
        let amount = if let Ok(amt) = NeptuneCoins::from_str(&amount_string) {
            amt
        } else {
            return None;
        };

        // return amount
        Some(amount)
    }

    async fn amount_leq_synced_balance(self, _ctx: context::Context, amount: NeptuneCoins) -> bool {
        let now = Timestamp::now();
        // test inequality
        let wallet_status = self
            .state
            .lock_guard()
            .await
            .get_wallet_status_for_tip()
            .await;
        amount <= wallet_status.synced_unspent_available_amount(now)
    }

    async fn synced_balance(self, _context: tarpc::context::Context) -> NeptuneCoins {
        let now = Timestamp::now();
        let wallet_status = self
            .state
            .lock_guard()
            .await
            .get_wallet_status_for_tip()
            .await;
        wallet_status.synced_unspent_available_amount(now)
    }

    async fn wallet_status(self, _context: tarpc::context::Context) -> WalletStatus {
        self.state
            .lock_guard()
            .await
            .get_wallet_status_for_tip()
            .await
    }

    async fn header(
        self,
        _context: tarpc::context::Context,
        block_selector: BlockSelector,
    ) -> Option<BlockHeader> {
        let state = self.state.lock_guard().await;
        let block_digest = block_selector.as_digest(&state).await?;
        state
            .chain
            .archival_state()
            .get_block_header(block_digest)
            .await
    }

    async fn own_receiving_address(
        self,
        _context: tarpc::context::Context,
    ) -> generation_address::ReceivingAddress {
        self.state
            .lock_guard()
            .await
            .wallet_state
            .wallet_secret
            .nth_generation_spending_key(0)
            .to_address()
    }

    async fn mempool_tx_count(self, _context: tarpc::context::Context) -> usize {
        self.state.lock_guard().await.mempool.len()
    }

    async fn mempool_size(self, _context: tarpc::context::Context) -> usize {
        self.state.lock_guard().await.mempool.get_size()
    }

    async fn history(
        self,
        _context: tarpc::context::Context,
    ) -> Vec<(Digest, BlockHeight, Timestamp, NeptuneCoins)> {
        let history = self.state.lock_guard().await.get_balance_history().await;

        // sort
        let mut display_history: Vec<(Digest, BlockHeight, Timestamp, NeptuneCoins)> = history
            .iter()
            .map(|(h, t, bh, a)| (*h, *bh, *t, *a))
            .collect::<Vec<_>>();
        display_history.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());

        // return
        display_history
    }

    async fn dashboard_overview_data(
        self,
        _context: tarpc::context::Context,
    ) -> DashBoardOverviewDataFromClient {
        let now = Timestamp::now();
        let state = self.state.lock_guard().await;
        let tip_digest = state.chain.light_state().hash();
        let tip_header = state.chain.light_state().header().clone();
        let wallet_status = state.get_wallet_status_for_tip().await;
        let syncing = state.net.syncing;
        let mempool_size = state.mempool.get_size();
        let mempool_tx_count = state.mempool.len();
        let cpu_temp = Self::cpu_temp_inner();

        let peer_count = Some(state.net.peer_map.len());

        let is_mining = Some(state.mining);
        drop(state);

        let confirmations = self.confirmations_internal().await;

        DashBoardOverviewDataFromClient {
            tip_digest,
            tip_header,
            syncing,
            available_balance: wallet_status.synced_unspent_available_amount(now),
            timelocked_balance: wallet_status.synced_unspent_timelocked_amount(now),
            mempool_size,
            mempool_tx_count,
            peer_count,
            is_mining,
            confirmations,
            cpu_temp,
        }
    }

    /******** CHANGE THINGS ********/
    /// Locking:
    ///   * acquires `global_state_lock` for write
    async fn clear_all_standings(self, _: context::Context) {
        let mut global_state_mut = self.state.lock_guard_mut().await;
        global_state_mut
            .net
            .peer_map
            .iter_mut()
            .for_each(|(_, peerinfo)| {
                peerinfo.standing.clear_standing();
            });

        // iterates and modifies standing field for all connected peers
        global_state_mut.net.clear_all_standings_in_database().await;

        global_state_mut
            .flush_databases()
            .await
            .expect("flushed DBs");
    }

    /// Locking:
    ///   * acquires `global_state_lock` for write
    async fn clear_standing_by_ip(self, _: context::Context, ip: IpAddr) {
        let mut global_state_mut = self.state.lock_guard_mut().await;
        global_state_mut
            .net
            .peer_map
            .iter_mut()
            .for_each(|(socketaddr, peerinfo)| {
                if socketaddr.ip() == ip {
                    peerinfo.standing.clear_standing();
                }
            });

        //Also clears this IP's standing in database, whether it is connected or not.
        global_state_mut.net.clear_ip_standing_in_database(ip).await;

        global_state_mut
            .flush_databases()
            .await
            .expect("flushed DBs");
    }

    /// Locking:
    ///   * acquires `global_state_lock` for write
    async fn send(
        self,
        _ctx: context::Context,
        amount: NeptuneCoins,
        address: generation_address::ReceivingAddress,
        fee: NeptuneCoins,
    ) -> Option<Digest> {
        let span = tracing::debug_span!("Constructing transaction objects");
        let _enter = span.enter();

        let coins = amount.to_native_coins();
        let utxo = Utxo::new(address.lock_script(), coins);
        let now = Timestamp::now();

        // note: for future changes:
        // No consensus data should be read within this read-lock.
        // Else a write lock must be used instead and held until
        // create_transaction() completes, so entire op is atomic.
        // See: https://github.com/Neptune-Crypto/neptune-core/issues/134
        let state = self.state.lock_guard().await;
        let block_height = state.chain.light_state().header().height;
        let receiver_privacy_digest = address.privacy_digest;
        let sender_randomness = state
            .wallet_state
            .wallet_secret
            .generate_sender_randomness(block_height, receiver_privacy_digest);
        drop(state);

        // 1. Build transaction object
        // TODO: Allow user to set fee here. Don't set it automatically as we want the user
        // to be in control of this. But we could add an endpoint to get recommended fee
        // density.
        let public_announcement =
            match address.generate_public_announcement(&utxo, sender_randomness) {
                Ok(pa) => pa,
                Err(_) => {
                    tracing::error!(
                        "Failed to generate transaction because could not encrypt to address."
                    );
                    return None;
                }
            };
        let receiver_data = [(UtxoReceiverData {
            utxo,
            sender_randomness,
            receiver_privacy_digest,
            public_announcement,
        })]
        .to_vec();

        // Pause miner if we are mining
        let was_mining = self.state.mining().await;
        if was_mining {
            let _ = self
                .rpc_server_to_main_tx
                .send(RPCServerToMain::PauseMiner)
                .await;
        }

        // All cryptographic data must be in relation to a single block
        // and a write-lock must therefore be held over GlobalState to ensure this.
        let transaction_result = self
            .state
            .lock_guard_mut()
            .await
            .create_transaction(receiver_data, fee, now)
            .await;

        let transaction = match transaction_result {
            Ok(tx) => tx,
            Err(err) => {
                tracing::error!("Could not create transaction: {}", err);
                return None;
            }
        };

        // 2. Send transaction message to main
        let response: Result<(), SendError<RPCServerToMain>> = self
            .rpc_server_to_main_tx
            .send(RPCServerToMain::Send(Box::new(transaction.clone())))
            .await;

        // Restart mining if it was paused
        if was_mining {
            let _ = self
                .rpc_server_to_main_tx
                .send(RPCServerToMain::RestartMiner)
                .await;
        }

        self.state.flush_databases().await.expect("flushed DBs");

        if response.is_ok() {
            Some(Hash::hash(&transaction))
        } else {
            None
        }
    }

    async fn shutdown(self, _: context::Context) -> bool {
        // 1. Send shutdown message to main
        let response = self
            .rpc_server_to_main_tx
            .send(RPCServerToMain::Shutdown)
            .await;

        // 2. Send acknowledgement to client.
        response.is_ok()
    }

    async fn pause_miner(self, _context: tarpc::context::Context) {
        if self.state.cli().mine {
            let _ = self
                .rpc_server_to_main_tx
                .send(RPCServerToMain::PauseMiner)
                .await;
        } else {
            info!("Cannot pause miner since it was never started");
        }
    }

    async fn restart_miner(self, _context: tarpc::context::Context) {
        if self.state.cli().mine {
            let _ = self
                .rpc_server_to_main_tx
                .send(RPCServerToMain::RestartMiner)
                .await;
        } else {
            info!("Cannot restart miner since it was never started");
        }
    }

    async fn prune_abandoned_monitored_utxos(self, _context: tarpc::context::Context) -> usize {
        let mut global_state_mut = self.state.lock_guard_mut().await;
        const DEFAULT_MUTXO_PRUNE_DEPTH: usize = 200;

        let prune_count_res = global_state_mut
            .prune_abandoned_monitored_utxos(DEFAULT_MUTXO_PRUNE_DEPTH)
            .await;

        global_state_mut
            .flush_databases()
            .await
            .expect("flushed DBs");

        match prune_count_res {
            Ok(prune_count) => {
                info!("Marked {prune_count} monitored UTXOs as abandoned");
                prune_count
            }
            Err(err) => {
                error!("Pruning monitored UTXOs failed with error: {err}");
                0
            }
        }
    }

    #[doc = r" Generate a report of all owned and unspent coins, whether time-locked or not."]
    async fn list_own_coins(
        self,
        _context: ::tarpc::context::Context,
    ) -> Vec<CoinWithPossibleTimeLock> {
        self.state
            .lock_guard()
            .await
            .wallet_state
            .get_all_own_coins_with_possible_timelocks()
            .await
    }

    #[doc = r" Return the temperature of the CPU in degrees Celcius."]
    async fn cpu_temp(self, _context: tarpc::context::Context) -> Option<f32> {
        Self::cpu_temp_inner()
    }
}

#[cfg(test)]
mod rpc_server_tests {
    use super::*;
    use crate::Block;
    use crate::{
        config_models::network::Network,
        models::{peer::PeerSanctionReason, state::wallet::WalletSecret},
        rpc_server::NeptuneRPCServer,
        tests::shared::mock_genesis_global_state,
        RPC_CHANNEL_CAPACITY,
    };
    use anyhow::Result;
    use num_traits::{One, Zero};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use strum::IntoEnumIterator;
    use tracing_test::traced_test;

    async fn test_rpc_server(
        network: Network,
        wallet_secret: WalletSecret,
        peer_count: u8,
    ) -> (NeptuneRPCServer, GlobalStateLock) {
        let global_state_lock = mock_genesis_global_state(network, peer_count, wallet_secret).await;
        let (dummy_tx, _rx) = tokio::sync::mpsc::channel::<RPCServerToMain>(RPC_CHANNEL_CAPACITY);
        (
            NeptuneRPCServer {
                socket_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
                state: global_state_lock.clone(),
                rpc_server_to_main_tx: dummy_tx,
            },
            global_state_lock,
        )
    }

    #[tokio::test]
    async fn network_response_is_consistent() -> Result<()> {
        // Verify that a wallet not receiving a premine is empty at startup
        for network in Network::iter() {
            let (rpc_server, _) = test_rpc_server(network, WalletSecret::new_random(), 2).await;
            assert_eq!(network, rpc_server.network(context::current()).await);
        }

        Ok(())
    }

    #[tokio::test]
    async fn verify_that_all_requests_leave_server_running() -> Result<()> {
        // Got through *all* request types and verify that server does not crash.
        // We don't care about the actual response data in this test, just that the
        // requests do not crash the server.

        let network = Network::RegTest;
        let (rpc_server, _) = test_rpc_server(network, WalletSecret::new_random(), 2).await;
        let ctx = context::current();
        let _ = rpc_server.clone().network(ctx).await;
        let _ = rpc_server.clone().own_listen_address_for_peers(ctx).await;
        let _ = rpc_server.clone().own_instance_id(ctx).await;
        let _ = rpc_server.clone().block_height(ctx).await;
        let _ = rpc_server.clone().peer_info(ctx).await;
        let _ = rpc_server.clone().all_sanctioned_peers(ctx).await;
        let _ = rpc_server.clone().latest_tip_digests(ctx, 2).await;
        let _ = rpc_server
            .clone()
            .header(ctx, BlockSelector::Digest(Digest::default()))
            .await;
        let _ = rpc_server
            .clone()
            .block_info(ctx, BlockSelector::Digest(Digest::default()))
            .await;
        let _ = rpc_server
            .clone()
            .block_digest(ctx, BlockSelector::Digest(Digest::default()))
            .await;
        let _ = rpc_server.clone().utxo_digest(ctx, 0).await;
        let _ = rpc_server.clone().synced_balance(ctx).await;
        let _ = rpc_server.clone().history(ctx).await;
        let _ = rpc_server.clone().wallet_status(ctx).await;
        let own_receiving_address = rpc_server.clone().own_receiving_address(ctx).await;
        let _ = rpc_server.clone().mempool_tx_count(ctx).await;
        let _ = rpc_server.clone().mempool_size(ctx).await;
        let _ = rpc_server.clone().dashboard_overview_data(ctx).await;
        let _ = rpc_server
            .clone()
            .validate_address(ctx, "Not a valid address".to_owned(), Network::Testnet)
            .await;
        let _ = rpc_server.clone().clear_all_standings(ctx).await;
        let _ = rpc_server
            .clone()
            .clear_standing_by_ip(ctx, "127.0.0.1".parse().unwrap())
            .await;
        let _ = rpc_server
            .clone()
            .send(
                ctx,
                NeptuneCoins::one(),
                own_receiving_address,
                NeptuneCoins::one(),
            )
            .await;
        let _ = rpc_server.clone().pause_miner(ctx).await;
        let _ = rpc_server.clone().restart_miner(ctx).await;
        let _ = rpc_server
            .clone()
            .prune_abandoned_monitored_utxos(ctx)
            .await;
        let _ = rpc_server.shutdown(ctx).await;

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn balance_is_zero_at_init() -> Result<()> {
        // Verify that a wallet not receiving a premine is empty at startup
        let (rpc_server, _) = test_rpc_server(Network::Alpha, WalletSecret::new_random(), 2).await;
        let balance = rpc_server.synced_balance(context::current()).await;
        assert!(balance.is_zero());

        Ok(())
    }

    #[allow(clippy::shadow_unrelated)]
    #[traced_test]
    #[tokio::test]
    async fn clear_ip_standing_test() -> Result<()> {
        let (rpc_server, state_lock) =
            test_rpc_server(Network::Alpha, WalletSecret::new_random(), 2).await;
        let rpc_request_context = context::current();
        let global_state = state_lock.lock_guard().await;
        let peer_address_0 =
            global_state.net.peer_map.values().collect::<Vec<_>>()[0].connected_address;
        let peer_address_1 =
            global_state.net.peer_map.values().collect::<Vec<_>>()[1].connected_address;
        drop(global_state);

        // Verify that sanctions list is empty
        let sanctioned_peers_startup = rpc_server
            .clone()
            .all_sanctioned_peers(rpc_request_context)
            .await;
        assert!(
            sanctioned_peers_startup.is_empty(),
            "Sanctions list must be empty at startup"
        );

        // sanction both
        let (standing_0, standing_1) = {
            let mut global_state_mut = state_lock.lock_guard_mut().await;

            global_state_mut
                .net
                .peer_map
                .entry(peer_address_0)
                .and_modify(|p| {
                    p.standing.sanction(PeerSanctionReason::DifferentGenesis);
                });
            global_state_mut
                .net
                .peer_map
                .entry(peer_address_1)
                .and_modify(|p| {
                    p.standing.sanction(PeerSanctionReason::DifferentGenesis);
                });
            let standing_0 = global_state_mut.net.peer_map[&peer_address_0].standing;
            let standing_1 = global_state_mut.net.peer_map[&peer_address_1].standing;
            (standing_0, standing_1)
        };

        // Verify expected sanctions reading
        let sanction_peers_from_memory = rpc_server
            .clone()
            .all_sanctioned_peers(rpc_request_context)
            .await;
        assert_eq!(
            2,
            sanction_peers_from_memory.len(),
            "Sanctions list must have to elements after sanctionings"
        );

        {
            let mut global_state_mut = state_lock.lock_guard_mut().await;

            global_state_mut
                .net
                .write_peer_standing_on_decrease(peer_address_0.ip(), standing_0)
                .await;
            global_state_mut
                .net
                .write_peer_standing_on_decrease(peer_address_1.ip(), standing_1)
                .await;
        }

        // Verify expected sanctions reading, after DB-write
        let sanction_peers_from_memory_and_db = rpc_server
            .clone()
            .all_sanctioned_peers(rpc_request_context)
            .await;
        assert_eq!(
            2,
            sanction_peers_from_memory_and_db.len(),
            "Sanctions list must have to elements after sanctionings and after DB write"
        );

        // Verify expected initial conditions
        {
            let global_state = state_lock.lock_guard().await;
            let peer_standing_0 = global_state
                .net
                .get_peer_standing_from_database(peer_address_0.ip())
                .await;
            assert_ne!(0, peer_standing_0.unwrap().standing);
            assert_ne!(None, peer_standing_0.unwrap().latest_sanction);
            let peer_standing_1 = global_state
                .net
                .get_peer_standing_from_database(peer_address_1.ip())
                .await;
            assert_ne!(0, peer_standing_1.unwrap().standing);
            assert_ne!(None, peer_standing_1.unwrap().latest_sanction);
            drop(global_state);

            // Clear standing of #0
            rpc_server
                .clone()
                .clear_standing_by_ip(rpc_request_context, peer_address_0.ip())
                .await;
        }

        // Verify expected resulting conditions in database
        {
            let global_state = state_lock.lock_guard().await;
            let peer_standing_0 = global_state
                .net
                .get_peer_standing_from_database(peer_address_0.ip())
                .await;
            assert_eq!(0, peer_standing_0.unwrap().standing);
            assert_eq!(None, peer_standing_0.unwrap().latest_sanction);
            let peer_standing_1 = global_state
                .net
                .get_peer_standing_from_database(peer_address_1.ip())
                .await;
            assert_ne!(0, peer_standing_1.unwrap().standing);
            assert_ne!(None, peer_standing_1.unwrap().latest_sanction);

            // Verify expected resulting conditions in peer map
            let peer_standing_0_from_memory = global_state.net.peer_map[&peer_address_0].clone();
            assert_eq!(0, peer_standing_0_from_memory.standing.standing);
            let peer_standing_1_from_memory = global_state.net.peer_map[&peer_address_1].clone();
            assert_ne!(0, peer_standing_1_from_memory.standing.standing);
        }

        // Verify expected sanctions reading, after one forgiveness
        let sanctions_list_after_one_clear = rpc_server
            .clone()
            .all_sanctioned_peers(rpc_request_context)
            .await;
        assert!(
            sanctions_list_after_one_clear.len().is_one(),
            "Sanctions list must have to elements after sanctionings and after DB write"
        );

        Ok(())
    }

    #[allow(clippy::shadow_unrelated)]
    #[traced_test]
    #[tokio::test]
    async fn clear_all_standings_test() -> Result<()> {
        // Create initial conditions
        let (rpc_server, state_lock) =
            test_rpc_server(Network::Alpha, WalletSecret::new_random(), 2).await;
        let mut state = state_lock.lock_guard_mut().await;
        let peer_address_0 = state.net.peer_map.values().collect::<Vec<_>>()[0].connected_address;
        let peer_address_1 = state.net.peer_map.values().collect::<Vec<_>>()[1].connected_address;

        // sanction both peers
        let (standing_0, standing_1) = {
            state.net.peer_map.entry(peer_address_0).and_modify(|p| {
                p.standing.sanction(PeerSanctionReason::DifferentGenesis);
            });
            state.net.peer_map.entry(peer_address_1).and_modify(|p| {
                p.standing.sanction(PeerSanctionReason::DifferentGenesis);
            });
            let standing_0 = state.net.peer_map[&peer_address_0].standing;
            let standing_1 = state.net.peer_map[&peer_address_1].standing;
            (standing_0, standing_1)
        };

        state
            .net
            .write_peer_standing_on_decrease(peer_address_0.ip(), standing_0)
            .await;
        state
            .net
            .write_peer_standing_on_decrease(peer_address_1.ip(), standing_1)
            .await;

        drop(state);

        // Verify expected initial conditions
        {
            let peer_standing_0 = state_lock
                .lock_guard_mut()
                .await
                .net
                .get_peer_standing_from_database(peer_address_0.ip())
                .await;
            assert_ne!(0, peer_standing_0.unwrap().standing);
            assert_ne!(None, peer_standing_0.unwrap().latest_sanction);
        }

        {
            let peer_standing_1 = state_lock
                .lock_guard_mut()
                .await
                .net
                .get_peer_standing_from_database(peer_address_1.ip())
                .await;
            assert_ne!(0, peer_standing_1.unwrap().standing);
            assert_ne!(None, peer_standing_1.unwrap().latest_sanction);
        }

        // Verify expected reading through an RPC call
        let rpc_request_context = context::current();
        let after_two_sanctions = rpc_server
            .clone()
            .all_sanctioned_peers(rpc_request_context)
            .await;
        assert_eq!(2, after_two_sanctions.len());

        // Clear standing of both by clearing all standings
        rpc_server
            .clone()
            .clear_all_standings(rpc_request_context)
            .await;

        let state = state_lock.lock_guard().await;

        // Verify expected resulting conditions in database
        {
            let peer_standing_0 = state
                .net
                .get_peer_standing_from_database(peer_address_0.ip())
                .await;
            assert_eq!(0, peer_standing_0.unwrap().standing);
            assert_eq!(None, peer_standing_0.unwrap().latest_sanction);
        }

        {
            let peer_still_standing_1 = state
                .net
                .get_peer_standing_from_database(peer_address_1.ip())
                .await;
            assert_eq!(0, peer_still_standing_1.unwrap().standing);
            assert_eq!(None, peer_still_standing_1.unwrap().latest_sanction);
        }

        // Verify expected resulting conditions in peer map
        {
            let peer_standing_0_from_memory = state.net.peer_map[&peer_address_0].clone();
            assert_eq!(0, peer_standing_0_from_memory.standing.standing);
        }

        {
            let peer_still_standing_1_from_memory = state.net.peer_map[&peer_address_1].clone();
            assert_eq!(0, peer_still_standing_1_from_memory.standing.standing);
        }

        // Verify expected reading through an RPC call
        let after_global_forgiveness = rpc_server
            .clone()
            .all_sanctioned_peers(rpc_request_context)
            .await;
        assert!(after_global_forgiveness.is_empty());

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn utxo_digest_test() {
        let (rpc_server, state_lock) =
            test_rpc_server(Network::Alpha, WalletSecret::new_random(), 2).await;
        let global_state = state_lock.lock_guard().await;
        let aocl_leaves = global_state
            .chain
            .archival_state()
            .archival_mutator_set
            .ams()
            .aocl
            .count_leaves()
            .await;

        debug_assert!(aocl_leaves > 0);

        assert!(rpc_server
            .clone()
            .utxo_digest(context::current(), aocl_leaves - 1)
            .await
            .is_some());

        assert!(rpc_server
            .utxo_digest(context::current(), aocl_leaves)
            .await
            .is_none());
    }

    #[traced_test]
    #[tokio::test]
    async fn block_info_test() {
        let network = Network::RegTest;
        let (rpc_server, state_lock) =
            test_rpc_server(network, WalletSecret::new_random(), 2).await;
        let global_state = state_lock.lock_guard().await;
        let ctx = context::current();

        let genesis_hash = global_state.chain.archival_state().genesis_block().hash();
        let tip_hash = global_state.chain.light_state().hash();

        let genesis_block_info = BlockInfo::from_block_and_digests(
            global_state.chain.archival_state().genesis_block(),
            genesis_hash,
            tip_hash,
        );

        let tip_block_info = BlockInfo::from_block_and_digests(
            global_state.chain.light_state(),
            genesis_hash,
            tip_hash,
        );

        // should find genesis block by Genesis selector
        assert_eq!(
            genesis_block_info,
            rpc_server
                .clone()
                .block_info(ctx, BlockSelector::Genesis)
                .await
                .unwrap()
        );

        // should find latest/tip block by Tip selector
        assert_eq!(
            tip_block_info,
            rpc_server
                .clone()
                .block_info(ctx, BlockSelector::Tip)
                .await
                .unwrap()
        );

        // should find genesis block by Height selector
        assert_eq!(
            genesis_block_info,
            rpc_server
                .clone()
                .block_info(ctx, BlockSelector::Height(BlockHeight::from(0u64)))
                .await
                .unwrap()
        );

        // should find genesis block by Digest selector
        assert_eq!(
            genesis_block_info,
            rpc_server
                .clone()
                .block_info(ctx, BlockSelector::Digest(genesis_hash))
                .await
                .unwrap()
        );

        // should not find any block when Height selector is u64::Max
        assert!(rpc_server
            .clone()
            .block_info(ctx, BlockSelector::Height(BlockHeight::from(u64::MAX)))
            .await
            .is_none());

        // should not find any block when Digest selector is Digest::default()
        assert!(rpc_server
            .clone()
            .block_info(ctx, BlockSelector::Digest(Digest::default()))
            .await
            .is_none());
    }

    #[traced_test]
    #[tokio::test]
    async fn block_digest_test() {
        let network = Network::RegTest;
        let (rpc_server, state_lock) =
            test_rpc_server(network, WalletSecret::new_random(), 2).await;
        let global_state = state_lock.lock_guard().await;
        let ctx = context::current();

        let genesis_hash = Block::genesis_block(network).hash();

        // should find genesis block by Genesis selector
        assert_eq!(
            genesis_hash,
            rpc_server
                .clone()
                .block_digest(ctx, BlockSelector::Genesis)
                .await
                .unwrap()
        );

        // should find latest/tip block by Tip selector
        assert_eq!(
            global_state.chain.light_state().hash(),
            rpc_server
                .clone()
                .block_digest(ctx, BlockSelector::Tip)
                .await
                .unwrap()
        );

        // should find genesis block by Height selector
        assert_eq!(
            genesis_hash,
            rpc_server
                .clone()
                .block_digest(ctx, BlockSelector::Height(BlockHeight::from(0u64)))
                .await
                .unwrap()
        );

        // should find genesis block by Digest selector
        assert_eq!(
            genesis_hash,
            rpc_server
                .clone()
                .block_digest(ctx, BlockSelector::Digest(genesis_hash))
                .await
                .unwrap()
        );

        // should not find any block when Height selector is u64::Max
        assert!(rpc_server
            .clone()
            .block_digest(ctx, BlockSelector::Height(BlockHeight::from(u64::MAX)))
            .await
            .is_none());

        // should not find any block when Digest selector is Digest::default()
        assert!(rpc_server
            .clone()
            .block_digest(ctx, BlockSelector::Digest(Digest::default()))
            .await
            .is_none());
    }

    #[traced_test]
    #[tokio::test]
    async fn getting_temperature_doesnt_crash_test() {
        // On your local machine, this should return a temperature but in CI,
        // the RPC call returns `None`, so we only verify that the call doesn't
        // crash the host machine, we don't verify that any value is returned.
        let (rpc_server, _) = test_rpc_server(Network::Alpha, WalletSecret::new_random(), 2).await;
        let _current_server_temperature = rpc_server.cpu_temp(context::current()).await;
    }
}
