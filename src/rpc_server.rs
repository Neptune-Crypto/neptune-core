use anyhow::Result;
use futures::executor;
use futures::future::{self, Ready};
use serde::{Deserialize, Serialize};
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
use crate::models::peer::PeerInfo;
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
}

#[tarpc::service]
pub trait RPC {
    /******** READ DATA ********/
    // Place all methods that only read here
    // Return which network the client is running
    async fn get_network() -> Network;

    async fn get_listen_address_for_peers() -> Option<SocketAddr>;

    /// Returns the current block height.
    async fn block_height() -> BlockHeight;

    /// Returns info about the peers we are connected to
    async fn get_peer_info() -> Vec<PeerInfo>;

    /// Returns the digest of the latest block
    async fn head() -> Digest;

    /// Returns the digest of the latest n blocks
    async fn heads(n: usize) -> Vec<Digest>;

    async fn get_tip_header() -> BlockHeader;

    async fn get_header(hash: Digest) -> Option<BlockHeader>;

    // Get sum of unspent UTXOs.
    async fn get_synced_balance() -> Amount;

    async fn get_history() -> Vec<(Duration, Amount, Sign)>;

    async fn get_wallet_status() -> WalletStatus;

    async fn get_receiving_address() -> generation_address::ReceivingAddress;

    async fn get_mempool_tx_count() -> usize;

    // TODO: Change to return current size and max size
    async fn get_mempool_size() -> usize;

    async fn get_dashboard_overview_data() -> DashBoardOverviewDataFromClient;

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
    // Gracious shutdown.
    async fn shutdown() -> bool;

    /// Clears standing for all peers, connected or not
    async fn clear_all_standings();

    /// Clears standing for ip, whether connected or not
    async fn clear_ip_standing(ip: IpAddr);

    /// Send coins
    async fn send(
        amount: Amount,
        address: generation_address::ReceivingAddress,
        fee: Amount,
    ) -> Option<Digest>;

    // Stop miner if running
    async fn pause_miner();

    // Start miner if not running
    async fn restart_miner();

    // mark MUTXOs as abandoned
    async fn prune_abandoned_monitored_utxos() -> usize;
}

#[derive(Clone)]
pub struct NeptuneRPCServer {
    pub socket_address: SocketAddr,
    pub state: GlobalState,
    pub rpc_server_to_main_tx: tokio::sync::mpsc::Sender<RPCServerToMain>,
}

impl RPC for NeptuneRPCServer {
    type GetNetworkFut = Ready<Network>;
    type GetListenAddressForPeersFut = Ready<Option<SocketAddr>>;
    type BlockHeightFut = Ready<BlockHeight>;
    type GetPeerInfoFut = Ready<Vec<PeerInfo>>;
    type HeadFut = Ready<Digest>;
    type HeadsFut = Ready<Vec<Digest>>;
    type ClearAllStandingsFut = Ready<()>;
    type ClearIpStandingFut = Ready<()>;
    type SendFut = Ready<Option<Digest>>;
    type ValidateAddressFut = Ready<Option<generation_address::ReceivingAddress>>;
    type ValidateAmountFut = Ready<Option<Amount>>;
    type AmountLeqSyncedBalanceFut = Ready<bool>;
    type ShutdownFut = Ready<bool>;
    type GetSyncedBalanceFut = Ready<Amount>;
    type GetWalletStatusFut = Ready<WalletStatus>;
    type GetTipHeaderFut = Ready<BlockHeader>;
    type GetHeaderFut = Ready<Option<BlockHeader>>;
    type GetReceivingAddressFut = Ready<generation_address::ReceivingAddress>;
    type GetMempoolTxCountFut = Ready<usize>;
    type GetMempoolSizeFut = Ready<usize>;
    type GetHistoryFut = Ready<Vec<(Duration, Amount, Sign)>>;
    type GetDashboardOverviewDataFut = Ready<DashBoardOverviewDataFromClient>;
    type PauseMinerFut = Ready<()>;
    type RestartMinerFut = Ready<()>;
    type PruneAbandonedMonitoredUtxosFut = Ready<usize>;

    fn get_network(self, _: context::Context) -> Self::GetNetworkFut {
        let network = self.state.cli.network;
        future::ready(network)
    }

    fn get_listen_address_for_peers(
        self,
        _context: context::Context,
    ) -> Self::GetListenAddressForPeersFut {
        let listen_for_peers_ip = self.state.cli.listen_addr;
        let listen_for_peers_socket = self.state.cli.peer_port;
        let socket_address = SocketAddr::new(listen_for_peers_ip, listen_for_peers_socket);
        future::ready(Some(socket_address))
    }

    fn block_height(self, _: context::Context) -> Self::BlockHeightFut {
        // let mut databases = executor::block_on(self.state.block_databases.lock());
        // let lookup_res = databases.latest_block_header.get(());
        let latest_block_header =
            executor::block_on(self.state.chain.light_state.get_latest_block_header());
        future::ready(latest_block_header.height)
    }

    fn head(self, _: context::Context) -> Self::HeadFut {
        let latest_block = executor::block_on(self.state.chain.light_state.get_latest_block());
        future::ready(latest_block.hash)
    }

    fn heads(self, _context: tarpc::context::Context, n: usize) -> Self::HeadsFut {
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

        future::ready(head_hashes)
    }

    fn get_peer_info(self, _: context::Context) -> Self::GetPeerInfoFut {
        let peer_map = self
            .state
            .net
            .peer_map
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect();
        future::ready(peer_map)
    }

    fn validate_address(
        self,
        _ctx: context::Context,
        address_string: String,
        network: Network,
    ) -> Self::ValidateAddressFut {
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
        future::ready(ret)
    }

    fn validate_amount(
        self,
        _ctx: context::Context,
        amount_string: String,
    ) -> Self::ValidateAmountFut {
        // parse string
        let amount = if let Ok(amt) = Amount::from_str(&amount_string) {
            amt
        } else {
            return future::ready(None);
        };

        // return amount
        future::ready(Some(amount))
    }

    fn amount_leq_synced_balance(
        self,
        _ctx: context::Context,
        amount: Amount,
    ) -> Self::AmountLeqSyncedBalanceFut {
        // test inequality
        let wallet_status = executor::block_on(self.state.get_wallet_status_for_tip());
        future::ready(amount <= wallet_status.synced_unspent_amount)
    }

    fn get_synced_balance(self, _context: tarpc::context::Context) -> Self::GetSyncedBalanceFut {
        let wallet_status = executor::block_on(self.state.get_wallet_status_for_tip());
        future::ready(wallet_status.synced_unspent_amount)
    }

    fn get_wallet_status(self, _context: tarpc::context::Context) -> Self::GetWalletStatusFut {
        let wallet_status = executor::block_on(self.state.get_wallet_status_for_tip());
        future::ready(wallet_status)
    }

    fn get_tip_header(self, _: context::Context) -> Self::GetTipHeaderFut {
        let latest_block_block_header =
            executor::block_on(self.state.chain.light_state.get_latest_block_header());
        future::ready(latest_block_block_header)
    }

    fn get_header(
        self,
        _context: tarpc::context::Context,
        block_digest: Digest,
    ) -> Self::GetHeaderFut {
        let res = executor::block_on(
            self.state
                .chain
                .archival_state
                .as_ref()
                .expect("Can not give ancestor hash unless there is an archival state.")
                .get_block_header(block_digest),
        );
        future::ready(res)
    }

    fn get_receiving_address(
        self,
        _context: tarpc::context::Context,
    ) -> Self::GetReceivingAddressFut {
        let receiving_address = self
            .state
            .wallet_state
            .wallet_secret
            .nth_generation_spending_key(0)
            .to_address();
        future::ready(receiving_address)
    }

    fn get_mempool_tx_count(self, _context: tarpc::context::Context) -> Self::GetMempoolTxCountFut {
        future::ready(self.state.mempool.len())
    }

    fn get_mempool_size(self, _context: tarpc::context::Context) -> Self::GetMempoolSizeFut {
        future::ready(self.state.mempool.get_size())
    }

    fn get_history(self, _context: tarpc::context::Context) -> Self::GetHistoryFut {
        let history = executor::block_on(self.state.wallet_state.get_balance_history());

        // sort
        let mut display_history: Vec<(Duration, Amount, Sign)> = history
            .iter()
            .map(|(_h, t, a, s)| (*t, *a, *s))
            .collect::<Vec<_>>();
        display_history.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());

        // return
        future::ready(display_history)
    }

    fn get_dashboard_overview_data(
        self,
        _context: tarpc::context::Context,
    ) -> Self::GetDashboardOverviewDataFut {
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

        future::ready(DashBoardOverviewDataFromClient {
            tip_header,
            syncing,
            synced_balance: wallet_status.synced_unspent_amount,
            mempool_size,
            mempool_tx_count,
            peer_count,
            is_mining,
        })
    }

    // endpoints for changing stuff

    fn clear_all_standings(self, _: context::Context) -> Self::ClearAllStandingsFut {
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
        executor::block_on(self.state.clear_all_standings_in_database());
        future::ready(())
    }

    fn clear_ip_standing(self, _: context::Context, ip: IpAddr) -> Self::ClearIpStandingFut {
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
        //Also clears this IP's standing in database, whether it is connected or not.
        executor::block_on(self.state.clear_ip_standing_in_database(ip));
        future::ready(())
    }

    fn send(
        self,
        _ctx: context::Context,
        amount: Amount,
        address: generation_address::ReceivingAddress,
        fee: Amount,
    ) -> Self::SendFut {
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
                    return future::ready(None);
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
            Err(err) => panic!("Could not create transaction: {}", err),
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

        future::ready(if response.is_ok() {
            Some(Hash::hash(&transaction))
        } else {
            None
        })
    }

    fn shutdown(self, _: context::Context) -> Self::ShutdownFut {
        // 1. Send shutdown message to main
        let response =
            executor::block_on(self.rpc_server_to_main_tx.send(RPCServerToMain::Shutdown));

        // 2. Send acknowledgement to client.
        future::ready(response.is_ok())
    }

    fn pause_miner(self, _context: tarpc::context::Context) -> Self::PauseMinerFut {
        if self.state.cli.mine {
            let _ =
                executor::block_on(self.rpc_server_to_main_tx.send(RPCServerToMain::PauseMiner));
        } else {
            info!("Cannot pause miner since it was never started");
        }

        future::ready(())
    }

    fn restart_miner(self, _context: tarpc::context::Context) -> Self::RestartMinerFut {
        if self.state.cli.mine {
            let _ = executor::block_on(
                self.rpc_server_to_main_tx
                    .send(RPCServerToMain::RestartMiner),
            );
        } else {
            info!("Cannot restart miner since it was never started");
        }

        future::ready(())
    }

    fn prune_abandoned_monitored_utxos(
        self,
        _context: tarpc::context::Context,
    ) -> Self::PruneAbandonedMonitoredUtxosFut {
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
                future::ready(prune_count)
            }
            Err(err) => {
                error!("Pruning monitored UTXOs failed with error: {err}");
                future::ready(0)
            }
        }
    }
}

#[cfg(test)]
mod rpc_server_tests {
    use super::*;
    use crate::{
        config_models::network::Network,
        models::{
            peer::PeerSanctionReason,
            state::wallet::{generate_secret_key, WalletSecret},
        },
        rpc_server::NeptuneRPCServer,
        tests::shared::{get_mock_global_state, get_test_genesis_setup, unit_test_data_directory},
        RPC_CHANNEL_CAPACITY,
    };
    use anyhow::Result;
    use num_traits::Zero;
    use std::{
        collections::HashMap,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::MutexGuard,
    };
    use tracing_test::traced_test;

    #[traced_test]
    #[tokio::test]
    async fn balance_is_zero_at_init() -> Result<()> {
        // Verify that a wallet not receiving a premine is empty at startup
        let network = Network::Alpha;
        let state =
            get_mock_global_state(network, 2, Some(WalletSecret::new(generate_secret_key()))).await;
        let (dummy_tx, _rx) = tokio::sync::mpsc::channel::<RPCServerToMain>(RPC_CHANNEL_CAPACITY);
        let rpc_server = NeptuneRPCServer {
            socket_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
            state: state.clone(),
            rpc_server_to_main_tx: dummy_tx,
        };

        let balance = rpc_server.get_synced_balance(context::current()).await;
        assert!(balance.is_zero());

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn clear_ip_standing_test() -> Result<()> {
        // Create initial conditions
        let (_peer_broadcast_tx, _from_main_rx_clone, _to_main_tx, mut _to_main_rx, state, _hsd) =
            get_test_genesis_setup(Network::Alpha, 2).await?;
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

        state
            .write_peer_standing_on_decrease(peer_address_0.ip(), standing_0)
            .await;
        state
            .write_peer_standing_on_decrease(peer_address_1.ip(), standing_1)
            .await;

        // Verify expected initial conditions
        {
            let peer_standing_0 = state
                .get_peer_standing_from_database(peer_address_0.ip())
                .await;
            assert_ne!(0, peer_standing_0.unwrap().standing);
            assert_ne!(None, peer_standing_0.unwrap().latest_sanction);
            let peer_standing_1 = state
                .get_peer_standing_from_database(peer_address_1.ip())
                .await;
            assert_ne!(0, peer_standing_1.unwrap().standing);
            assert_ne!(None, peer_standing_1.unwrap().latest_sanction);

            // Clear standing of #0
            let (dummy_tx, _rx) =
                tokio::sync::mpsc::channel::<RPCServerToMain>(RPC_CHANNEL_CAPACITY);
            let rpc_server = NeptuneRPCServer {
                socket_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
                state: state.clone(),
                rpc_server_to_main_tx: dummy_tx,
            };
            rpc_server
                .clear_ip_standing(context::current(), peer_address_0.ip())
                .await;
        }
        // Verify expected resulting conditions in database
        {
            let peer_standing_0 = state
                .get_peer_standing_from_database(peer_address_0.ip())
                .await;
            assert_eq!(0, peer_standing_0.unwrap().standing);
            assert_eq!(None, peer_standing_0.unwrap().latest_sanction);
            let peer_standing_1 = state
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
        Ok(())
    }
    #[traced_test]
    #[tokio::test]
    async fn clear_all_standings_test() -> Result<()> {
        // Create initial conditions
        let (_peer_broadcast_tx, _from_main_rx_clone, _to_main_tx, mut _to_main_rx, state, _hsd) =
            get_test_genesis_setup(Network::Alpha, 2).await?;
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
            .write_peer_standing_on_decrease(peer_address_0.ip(), standing_0)
            .await;
        state
            .write_peer_standing_on_decrease(peer_address_1.ip(), standing_1)
            .await;

        // Verify expected initial conditions
        {
            let peer_standing_0 = state
                .get_peer_standing_from_database(peer_address_0.ip())
                .await;
            assert_ne!(0, peer_standing_0.unwrap().standing);
            assert_ne!(None, peer_standing_0.unwrap().latest_sanction);
        }

        {
            let peer_standing_1 = state
                .get_peer_standing_from_database(peer_address_1.ip())
                .await;
            assert_ne!(0, peer_standing_1.unwrap().standing);
            assert_ne!(None, peer_standing_1.unwrap().latest_sanction);
        }

        // Clear standing of both by clearing all standings
        let (dummy_tx, _rx) = tokio::sync::mpsc::channel::<RPCServerToMain>(RPC_CHANNEL_CAPACITY);
        let rpc_server = NeptuneRPCServer {
            socket_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
            state: state.clone(),
            rpc_server_to_main_tx: dummy_tx.clone(),
        };
        rpc_server.clear_all_standings(context::current()).await;

        // Verify expected resulting conditions in database
        {
            let peer_standing_0 = state
                .get_peer_standing_from_database(peer_address_0.ip())
                .await;
            assert_eq!(0, peer_standing_0.unwrap().standing);
            assert_eq!(None, peer_standing_0.unwrap().latest_sanction);
        }

        {
            let peer_still_standing_1 = state
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

        Ok(())
    }
}
