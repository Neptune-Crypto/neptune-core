use anyhow::Result;
use futures::executor;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;
use tarpc::context;
use tokio::sync::mpsc::error::SendError;
use tracing::{error, info};
use twenty_first::shared_math::digest::Digest;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;

use crate::config_models::network::Network;
use crate::models::blockchain::block::block_header::BlockHeader;
use crate::models::blockchain::block::block_height::BlockHeight;
use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::transaction::amount::Amount;
use crate::models::blockchain::transaction::amount::Sign;
use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::channel::RPCServerToMain;
use crate::models::peer::InstanceId;
use crate::models::peer::PeerInfo;
use crate::models::peer::PeerStanding;
use crate::models::state::wallet::address::generation_address;
use crate::models::state::wallet::wallet_status::WalletStatus;
use crate::models::state::{GlobalState, UtxoReceiverData};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DashBoardOverviewDataFromClient {
    pub tip_header: BlockHeader,
    pub syncing: bool,
    pub synced_balance: Amount,
    pub mempool_size: usize,
    pub mempool_tx_count: usize,

    // `None` symbolizes failure in getting peer count
    pub peer_count: Option<usize>,

    // `None` symbolizes failure to get mining status
    pub is_mining: Option<bool>,

    // # of confirmations since last wallet balance change.
    // `None` indicates that wallet balance has never changed.
    pub confirmations: Option<BlockHeight>,
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
    /// returns Option<BlockHeight>
    ///
    /// return value will be None if wallet has not received any incoming funds.
    async fn confirmations() -> Option<BlockHeight>;

    /// Returns info about the peers we are connected to
    async fn peer_info() -> Vec<PeerInfo>;

    /// Return info about all peers that have been sanctioned
    async fn all_sanctioned_peers() -> HashMap<IpAddr, PeerStanding>;

    /// Returns the digest of the latest block
    async fn tip_digest() -> Digest;

    /// Returns the digest of the latest n blocks
    async fn latest_tip_digests(n: usize) -> Vec<Digest>;

    /// Return the block header of the tip digest
    async fn tip_header() -> BlockHeader;

    /// Return the block header for the specified block
    async fn header(hash: Digest) -> Option<BlockHeader>;

    /// Get sum of unspent UTXOs.
    async fn synced_balance() -> Amount;

    /// Get the client's wallet transaction history
    async fn history() -> Vec<(Digest, BlockHeight, Duration, Amount, Sign)>;

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
    async fn validate_amount(amount: String) -> Option<Amount>;

    /// Determine whether the given amount is less than (or equal to) the balance
    async fn amount_leq_synced_balance(amount: Amount) -> bool;

    /******** CHANGE THINGS ********/
    // Place all things that change state here

    /// Clears standing for all peers, connected or not
    async fn clear_all_standings();

    /// Clears standing for ip, whether connected or not
    async fn clear_standing_by_ip(ip: IpAddr);

    /// Send coins
    async fn send(
        amount: Amount,
        address: generation_address::ReceivingAddress,
        fee: Amount,
    ) -> Option<Digest>;

    /// Stop miner if running
    async fn pause_miner();

    /// Start miner if not running
    async fn restart_miner();

    /// mark MUTXOs as abandoned
    async fn prune_abandoned_monitored_utxos() -> usize;

    /// Gracious shutdown.
    async fn shutdown() -> bool;
}

#[derive(Clone)]
pub struct NeptuneRPCServer {
    pub socket_address: SocketAddr,
    pub state: GlobalState,
    pub rpc_server_to_main_tx: tokio::sync::mpsc::Sender<RPCServerToMain>,
}

impl NeptuneRPCServer {
    fn confirmations_internal(&self) -> Option<BlockHeight> {
        match executor::block_on(self.state.get_latest_balance_height()) {
            Some(latest_balance_height) => {
                let tip_block_header =
                    executor::block_on(self.state.chain.light_state.get_latest_block_header());

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
}

impl RPC for NeptuneRPCServer {
    /******** READ DATA ********/
    async fn network(self, _: context::Context) -> Network {
        self.state.cli.network
    }

    async fn own_listen_address_for_peers(self, _context: context::Context) -> Option<SocketAddr> {
        let listen_for_peers_ip = self.state.cli.listen_addr;
        let listen_for_peers_socket = self.state.cli.peer_port;
        let socket_address = SocketAddr::new(listen_for_peers_ip, listen_for_peers_socket);
        Some(socket_address)
    }

    async fn own_instance_id(self, _context: context::Context) -> InstanceId {
        self.state.net.instance_id
    }

    async fn block_height(self, _: context::Context) -> BlockHeight {
        // let mut databases = executor::block_on(self.state.block_databases.lock());
        // let lookup_res = databases.latest_block_header.get(());
        let latest_block_header =
            executor::block_on(self.state.chain.light_state.get_latest_block_header());
        latest_block_header.height
    }

    async fn confirmations(self, _: context::Context) -> Option<BlockHeight> {
        self.confirmations_internal()
    }

    async fn tip_digest(self, _: context::Context) -> Digest {
        let latest_block = executor::block_on(self.state.chain.light_state.get_latest_block());
        latest_block.hash
    }

    async fn latest_tip_digests(self, _context: tarpc::context::Context, n: usize) -> Vec<Digest> {
        let latest_block_digest =
            executor::block_on(self.state.chain.light_state.get_latest_block()).hash;

        let head_hashes = executor::block_on(
            self.state
                .chain
                .archival_state
                .as_ref()
                .expect("Can not give multiple ancestor hashes unless there is an archival state.")
                .get_ancestor_block_digests(latest_block_digest, n),
        );

        head_hashes
    }

    async fn peer_info(self, _: context::Context) -> Vec<PeerInfo> {
        let peer_map = self
            .state
            .net
            .peer_map
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect();
        peer_map
    }

    #[doc = r" Return info about all peers that have been sanctioned"]
    async fn all_sanctioned_peers(
        self,
        _context: tarpc::context::Context,
    ) -> HashMap<IpAddr, PeerStanding> {
        let mut sanctions_in_memory = HashMap::default();

        // Get all connected peers
        let peers = self
            .state
            .net
            .peer_map
            .lock()
            .unwrap_or_else(|e| panic!("Failed to lock peer map: {}", e))
            .to_owned();

        for (socket_address, peer_info) in peers {
            if peer_info.standing.is_negative() {
                sanctions_in_memory.insert(socket_address.ip(), peer_info.standing);
            }
        }

        let sanctions_in_db = self.state.net.all_peer_sanctions_in_database().await;

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
    ) -> Option<Amount> {
        // parse string
        let amount = if let Ok(amt) = Amount::from_str(&amount_string) {
            amt
        } else {
            return None;
        };

        // return amount
        Some(amount)
    }

    async fn amount_leq_synced_balance(self, _ctx: context::Context, amount: Amount) -> bool {
        // test inequality
        let wallet_status = executor::block_on(self.state.get_wallet_status_for_tip());
        amount <= wallet_status.synced_unspent_amount
    }

    async fn synced_balance(self, _context: tarpc::context::Context) -> Amount {
        let wallet_status = executor::block_on(self.state.get_wallet_status_for_tip());
        wallet_status.synced_unspent_amount
    }

    async fn wallet_status(self, _context: tarpc::context::Context) -> WalletStatus {
        let wallet_status = executor::block_on(self.state.get_wallet_status_for_tip());
        wallet_status
    }

    async fn tip_header(self, _: context::Context) -> BlockHeader {
        let latest_block_block_header =
            executor::block_on(self.state.chain.light_state.get_latest_block_header());
        latest_block_block_header
    }

    async fn header(
        self,
        _context: tarpc::context::Context,
        block_digest: Digest,
    ) -> Option<BlockHeader> {
        let res = executor::block_on(
            self.state
                .chain
                .archival_state
                .as_ref()
                .expect("Can not give ancestor hash unless there is an archival state.")
                .get_block_header(block_digest),
        );
        res
    }

    async fn own_receiving_address(
        self,
        _context: tarpc::context::Context,
    ) -> generation_address::ReceivingAddress {
        self.state
            .wallet_state
            .wallet_secret
            .nth_generation_spending_key(0)
            .to_address()
    }

    async fn mempool_tx_count(self, _context: tarpc::context::Context) -> usize {
        self.state.mempool.len()
    }

    async fn mempool_size(self, _context: tarpc::context::Context) -> usize {
        self.state.mempool.get_size()
    }

    async fn history(
        self,
        _context: tarpc::context::Context,
    ) -> Vec<(Digest, BlockHeight, Duration, Amount, Sign)> {
        let history = executor::block_on(self.state.get_balance_history());

        // sort
        let mut display_history: Vec<(Digest, BlockHeight, Duration, Amount, Sign)> = history
            .iter()
            .map(|(h, t, bh, a, s)| (*h, *bh, *t, *a, *s))
            .collect::<Vec<_>>();
        display_history.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());

        // return
        display_history
    }

    async fn dashboard_overview_data(
        self,
        _context: tarpc::context::Context,
    ) -> DashBoardOverviewDataFromClient {
        let tip_header = executor::block_on(self.state.chain.light_state.get_latest_block_header());
        let wallet_status = executor::block_on(self.state.get_wallet_status_for_tip());
        let syncing = self.state.net.syncing.read().unwrap().to_owned();
        let mempool_size = self.state.mempool.get_size();
        let mempool_tx_count = self.state.mempool.len();

        // Return `None` if we fail to acquire the lock
        let peer_count = match self.state.net.peer_map.try_lock() {
            Ok(pm) => Some(pm.len()),
            Err(_) => None,
        };

        let is_mining = match self.state.mining.read() {
            Ok(is_mining) => Some(is_mining.to_owned()),
            Err(_) => None,
        };

        let confirmations = self.confirmations_internal();

        DashBoardOverviewDataFromClient {
            tip_header,
            syncing,
            synced_balance: wallet_status.synced_unspent_amount,
            mempool_size,
            mempool_tx_count,
            peer_count,
            is_mining,
            confirmations,
        }
    }

    /******** CHANGE THINGS ********/
    async fn clear_all_standings(self, _: context::Context) {
        {
            let mut peers = self
                .state
                .net
                .peer_map
                .lock()
                .unwrap_or_else(|e| panic!("Failed to lock peer map: {}", e));

            // iterates and modifies standing field for all connected peers
            peers.iter_mut().for_each(|(_, peerinfo)| {
                peerinfo.standing.clear_standing();
            });
        }

        // Clear standings from database
        executor::block_on(self.state.net.clear_all_standings_in_database());
    }

    async fn clear_standing_by_ip(self, _: context::Context, ip: IpAddr) {
        {
            let mut peers = self
                .state
                .net
                .peer_map
                .lock()
                .unwrap_or_else(|e| panic!("Failed to lock peer map: {}", e));
            peers.iter_mut().for_each(|(socketaddr, peerinfo)| {
                if socketaddr.ip() == ip {
                    peerinfo.standing.clear_standing();
                }
            });
        }

        // Clear standing from database
        executor::block_on(self.state.net.clear_ip_standing_in_database(ip));
    }

    async fn send(
        self,
        _ctx: context::Context,
        amount: Amount,
        address: generation_address::ReceivingAddress,
        fee: Amount,
    ) -> Option<Digest> {
        let span = tracing::debug_span!("Constructing transaction objects");
        let _enter = span.enter();

        let coins = amount.to_native_coins();
        let utxo = Utxo::new(address.lock_script(), coins);
        let block_height = executor::block_on(self.state.chain.light_state.latest_block.lock())
            .header
            .height;
        let receiver_privacy_digest = address.privacy_digest;
        let sender_randomness = self
            .state
            .wallet_state
            .wallet_secret
            .generate_sender_randomness(block_height, receiver_privacy_digest);

        // 1. Build transaction object
        // TODO: Allow user to set fee here. Don't set it automatically as we want the user
        // to be in control of this. But we could add an endpoint to get recommended fee
        // density.
        let (pubscript, pubscript_input) =
            match address.generate_pubscript_and_input(&utxo, sender_randomness) {
                Ok((ps, inp)) => (ps, inp),
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
            pubscript,
            pubscript_input,
        })]
        .to_vec();

        // Pause miner if we are mining
        let was_mining = self.state.mining.read().unwrap().to_owned();
        if was_mining {
            let _ =
                executor::block_on(self.rpc_server_to_main_tx.send(RPCServerToMain::PauseMiner));
        }

        let transaction_result =
            executor::block_on(self.state.create_transaction(receiver_data, fee));

        let transaction = match transaction_result {
            Ok(tx) => tx,
            Err(err) => {
                tracing::error!("Could not create transaction: {}", err);
                return None;
            }
        };

        // 2. Send transaction message to main
        let response: Result<(), SendError<RPCServerToMain>> = executor::block_on(
            self.rpc_server_to_main_tx
                .send(RPCServerToMain::Send(Box::new(transaction.clone()))),
        );

        // Restart mining if it was paused
        if was_mining {
            let _ = executor::block_on(
                self.rpc_server_to_main_tx
                    .send(RPCServerToMain::RestartMiner),
            );
        }

        if response.is_ok() {
            Some(Hash::hash(&transaction))
        } else {
            None
        }
    }

    async fn shutdown(self, _: context::Context) -> bool {
        // 1. Send shutdown message to main
        let response =
            executor::block_on(self.rpc_server_to_main_tx.send(RPCServerToMain::Shutdown));

        // 2. Send acknowledgement to client.
        response.is_ok()
    }

    async fn pause_miner(self, _context: tarpc::context::Context) {
        if self.state.cli.mine {
            let _ =
                executor::block_on(self.rpc_server_to_main_tx.send(RPCServerToMain::PauseMiner));
        } else {
            info!("Cannot pause miner since it was never started");
        }
    }

    async fn restart_miner(self, _context: tarpc::context::Context) {
        if self.state.cli.mine {
            let _ = executor::block_on(
                self.rpc_server_to_main_tx
                    .send(RPCServerToMain::RestartMiner),
            );
        } else {
            info!("Cannot restart miner since it was never started");
        }
    }

    async fn prune_abandoned_monitored_utxos(self, _context: tarpc::context::Context) -> usize {
        let prune_count_res = {
            // Hold lock on wallet_db
            let mut wallet_db_lock = executor::block_on(self.state.wallet_state.wallet_db.lock());
            let tip_block_header =
                executor::block_on(self.state.chain.light_state.get_latest_block_header());
            const DEFAULT_MUTXO_PRUNE_DEPTH: usize = 200;

            let prune_count_res = executor::block_on(
                self.state
                    .wallet_state
                    .prune_abandoned_monitored_utxos_with_lock(
                        DEFAULT_MUTXO_PRUNE_DEPTH,
                        &mut wallet_db_lock,
                        &tip_block_header,
                        &self.state.chain.archival_state.unwrap(),
                    ),
            );

            prune_count_res
        };

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
}

#[cfg(test)]
mod rpc_server_tests {
    use super::*;
    use crate::{
        config_models::network::Network,
        models::{peer::PeerSanctionReason, state::wallet::WalletSecret},
        rpc_server::NeptuneRPCServer,
        tests::shared::get_mock_global_state,
        RPC_CHANNEL_CAPACITY,
    };
    use anyhow::Result;
    use num_traits::{One, Zero};
    use std::{
        collections::HashMap,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::MutexGuard,
    };
    use strum::IntoEnumIterator;
    use tracing_test::traced_test;

    async fn test_rpc_server(
        network: Network,
        wallet_secret: WalletSecret,
        peer_count: u8,
    ) -> (NeptuneRPCServer, GlobalState) {
        let state = get_mock_global_state(network, peer_count, Some(wallet_secret)).await;
        let (dummy_tx, _rx) = tokio::sync::mpsc::channel::<RPCServerToMain>(RPC_CHANNEL_CAPACITY);
        (
            NeptuneRPCServer {
                socket_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
                state: state.clone(),
                rpc_server_to_main_tx: dummy_tx,
            },
            state,
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

        let (rpc_server, _) = test_rpc_server(Network::Alpha, WalletSecret::new_random(), 2).await;
        let ctx = context::current();
        let _ = rpc_server.clone().network(ctx).await;
        let _ = rpc_server.clone().own_listen_address_for_peers(ctx).await;
        let _ = rpc_server.clone().own_instance_id(ctx).await;
        let _ = rpc_server.clone().block_height(ctx).await;
        let _ = rpc_server.clone().peer_info(ctx).await;
        let _ = rpc_server.clone().all_sanctioned_peers(ctx).await;
        let _ = rpc_server.clone().tip_digest(ctx).await;
        let _ = rpc_server.clone().latest_tip_digests(ctx, 2).await;
        let _ = rpc_server.clone().header(ctx, Digest::default()).await;
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
            .send(ctx, Amount::one(), own_receiving_address, Amount::one())
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

    #[traced_test]
    #[tokio::test]
    async fn clear_ip_standing_test() -> Result<()> {
        let (rpc_server, state) =
            test_rpc_server(Network::Alpha, WalletSecret::new_random(), 2).await;
        let rpc_request_context = context::current();

        let peer_address_0 = state
            .net
            .peer_map
            .lock()
            .unwrap()
            .values()
            .collect::<Vec<_>>()[0]
            .connected_address;
        let peer_address_1 = state
            .net
            .peer_map
            .lock()
            .unwrap()
            .values()
            .collect::<Vec<_>>()[1]
            .connected_address;

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
            let mut peers = state
                .net
                .peer_map
                .lock()
                .unwrap_or_else(|e| panic!("Failed to lock peer map: {}", e));
            peers.entry(peer_address_0).and_modify(|p| {
                p.standing.sanction(PeerSanctionReason::DifferentGenesis);
            });
            peers.entry(peer_address_1).and_modify(|p| {
                p.standing.sanction(PeerSanctionReason::DifferentGenesis);
            });
            let standing_0 = peers[&peer_address_0].standing;
            let standing_1 = peers[&peer_address_1].standing;
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

        state
            .net
            .write_peer_standing_on_decrease(peer_address_0.ip(), standing_0)
            .await;
        state
            .net
            .write_peer_standing_on_decrease(peer_address_1.ip(), standing_1)
            .await;

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
            let peer_standing_0 = state
                .net
                .get_peer_standing_from_database(peer_address_0.ip())
                .await;
            assert_ne!(0, peer_standing_0.unwrap().standing);
            assert_ne!(None, peer_standing_0.unwrap().latest_sanction);
            let peer_standing_1 = state
                .net
                .get_peer_standing_from_database(peer_address_1.ip())
                .await;
            assert_ne!(0, peer_standing_1.unwrap().standing);
            assert_ne!(None, peer_standing_1.unwrap().latest_sanction);

            // Clear standing of #0
            rpc_server
                .clone()
                .clear_standing_by_ip(rpc_request_context, peer_address_0.ip())
                .await;
        }

        // Verify expected resulting conditions in database
        {
            let peer_standing_0 = state
                .net
                .get_peer_standing_from_database(peer_address_0.ip())
                .await;
            assert_eq!(0, peer_standing_0.unwrap().standing);
            assert_eq!(None, peer_standing_0.unwrap().latest_sanction);
            let peer_standing_1 = state
                .net
                .get_peer_standing_from_database(peer_address_1.ip())
                .await;
            assert_ne!(0, peer_standing_1.unwrap().standing);
            assert_ne!(None, peer_standing_1.unwrap().latest_sanction);

            // Verify expected resulting conditions in peer map
            let peer_standing_0_from_memory =
                state.net.peer_map.lock().unwrap()[&peer_address_0].clone();
            assert_eq!(0, peer_standing_0_from_memory.standing.standing);
            let peer_standing_1_from_memory =
                state.net.peer_map.lock().unwrap()[&peer_address_1].clone();
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
    #[traced_test]
    #[tokio::test]
    async fn clear_all_standings_test() -> Result<()> {
        // Create initial conditions
        let (rpc_server, state) =
            test_rpc_server(Network::Alpha, WalletSecret::new_random(), 2).await;
        let peer_address_0 = state
            .net
            .peer_map
            .lock()
            .unwrap()
            .values()
            .collect::<Vec<_>>()[0]
            .connected_address;
        let peer_address_1 = state
            .net
            .peer_map
            .lock()
            .unwrap()
            .values()
            .collect::<Vec<_>>()[1]
            .connected_address;

        // sanction both peers
        let (standing_0, standing_1) = {
            let mut peers: MutexGuard<HashMap<SocketAddr, PeerInfo>> = state
                .net
                .peer_map
                .lock()
                .unwrap_or_else(|e| panic!("Failed to lock peer map: {}", e));

            peers.entry(peer_address_0).and_modify(|p| {
                p.standing.sanction(PeerSanctionReason::DifferentGenesis);
            });
            peers.entry(peer_address_1).and_modify(|p| {
                p.standing.sanction(PeerSanctionReason::DifferentGenesis);
            });
            let standing_0 = peers[&peer_address_0].standing;
            let standing_1 = peers[&peer_address_1].standing;
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

        // Verify expected initial conditions
        {
            let peer_standing_0 = state
                .net
                .get_peer_standing_from_database(peer_address_0.ip())
                .await;
            assert_ne!(0, peer_standing_0.unwrap().standing);
            assert_ne!(None, peer_standing_0.unwrap().latest_sanction);
        }

        {
            let peer_standing_1 = state
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
            let peer_standing_0_from_memory =
                state.net.peer_map.lock().unwrap()[&peer_address_0].clone();
            assert_eq!(0, peer_standing_0_from_memory.standing.standing);
        }

        {
            let peer_still_standing_1_from_memory =
                state.net.peer_map.lock().unwrap()[&peer_address_1].clone();
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
}
