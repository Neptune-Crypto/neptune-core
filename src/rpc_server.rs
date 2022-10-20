use anyhow::Result;
use futures::executor;
use futures::future::{self, Ready};
use std::net::IpAddr;
use std::net::SocketAddr;
use tarpc::context;
use tokio::sync::mpsc::error::SendError;
use twenty_first::shared_math::rescue_prime_digest::Digest;

use crate::models::blockchain::block::block_header::BlockHeader;
use crate::models::blockchain::block::block_height::BlockHeight;
use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::blockchain::transaction::{Amount, Transaction};
use crate::models::channel::RPCServerToMain;
use crate::models::peer::PeerInfo;
use crate::models::state::wallet::wallet_status::WalletStatus;
use crate::models::state::GlobalState;

#[tarpc::service]
pub trait RPC {
    /// Returns the current block height.
    async fn block_height() -> BlockHeight;

    /// Returns info about the peers we are connected to
    async fn get_peer_info() -> Vec<PeerInfo>;

    /// Returns the digest of the latest block
    async fn head() -> Digest;

    /// Returns the digest of the latest n blocks
    async fn heads(n: usize) -> Vec<Digest>;

    async fn get_header(hash: Digest) -> Option<BlockHeader>;

    /// Clears standing for all peers, connected or not
    async fn clear_all_standings();

    /// Clears standing for ip, whether connected or not
    async fn clear_ip_standing(ip: IpAddr);

    /// Send coins
    async fn send(utxos: Vec<Utxo>) -> bool;

    // Gracious shutdown.
    async fn shutdown() -> bool;

    // Get sum of unspent UTXOs.
    async fn get_balance() -> Amount;

    async fn get_wallet_status() -> WalletStatus;

    async fn get_public_key() -> secp256k1::PublicKey;

    async fn get_mempool_tx_count() -> usize;

    // TODO: Change to return current size and max size
    async fn get_mempool_size() -> usize;
}

#[derive(Clone)]
pub struct NeptuneRPCServer {
    pub socket_address: SocketAddr,
    pub state: GlobalState,
    pub rpc_server_to_main_tx: tokio::sync::mpsc::Sender<RPCServerToMain>,
}

impl RPC for NeptuneRPCServer {
    type BlockHeightFut = Ready<BlockHeight>;
    type GetPeerInfoFut = Ready<Vec<PeerInfo>>;
    type HeadFut = Ready<Digest>;
    type HeadsFut = Ready<Vec<Digest>>;
    type ClearAllStandingsFut = Ready<()>;
    type ClearIpStandingFut = Ready<()>;
    type SendFut = Ready<bool>;
    type ShutdownFut = Ready<bool>;
    type GetBalanceFut = Ready<Amount>;
    type GetWalletStatusFut = Ready<WalletStatus>;
    type GetHeaderFut = Ready<Option<BlockHeader>>;
    type GetPublicKeyFut = Ready<secp256k1::PublicKey>;
    type GetMempoolTxCountFut = Ready<usize>;
    type GetMempoolSizeFut = Ready<usize>;

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

    fn send(self, _ctx: context::Context, recipient_utxos: Vec<Utxo>) -> Self::SendFut {
        let span = tracing::debug_span!("Constructing transaction objects");
        let _enter = span.enter();

        tracing::debug!(
            "Wallet public key: {}",
            self.state.wallet_state.wallet.get_public_key()
        );

        // 1. Build transaction object
        // TODO: Allow user to set fee here. Don't set it automatically as we want the user
        // to be in control of this. But we could add an endpoint to get recommended fee
        // density.
        let transaction_res: Result<Transaction> =
            executor::block_on(self.state.create_transaction(recipient_utxos, 1.into()));
        let transaction = match transaction_res {
            Ok(tx) => tx,
            Err(err) => panic!("Could not create transaction: {}", err),
        };

        // 2. Send transaction message to main
        let response: Result<(), SendError<RPCServerToMain>> = executor::block_on(
            self.rpc_server_to_main_tx
                .send(RPCServerToMain::Send(transaction)),
        );

        // 3. Send acknowledgement to client.
        future::ready(response.is_ok())
    }

    fn shutdown(self, _: context::Context) -> Self::ShutdownFut {
        // 1. Send shutdown message to main
        let response =
            executor::block_on(self.rpc_server_to_main_tx.send(RPCServerToMain::Shutdown()));

        // 2. Send acknowledgement to client.
        future::ready(response.is_ok())
    }

    fn get_balance(self, _context: tarpc::context::Context) -> Self::GetBalanceFut {
        let res = executor::block_on(self.state.wallet_state.get_balance());
        future::ready(res)
    }

    fn get_wallet_status(self, _context: tarpc::context::Context) -> Self::GetWalletStatusFut {
        let res = executor::block_on(self.state.wallet_state.get_wallet_status());
        future::ready(res)
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

    fn get_public_key(self, _context: tarpc::context::Context) -> Self::GetPublicKeyFut {
        future::ready(self.state.wallet_state.wallet.get_public_key())
    }

    fn get_mempool_tx_count(self, _context: tarpc::context::Context) -> Self::GetMempoolTxCountFut {
        future::ready(self.state.mempool.len())
    }

    fn get_mempool_size(self, _context: tarpc::context::Context) -> Self::GetMempoolSizeFut {
        future::ready(self.state.mempool.get_size())
    }
}

#[cfg(test)]
mod rpc_server_tests {
    use super::*;
    use crate::{
        config_models::network::Network,
        models::{
            peer::PeerSanctionReason,
            state::wallet::{generate_secret_key, Wallet},
        },
        rpc_server::NeptuneRPCServer,
        tests::shared::{get_mock_global_state, get_test_genesis_setup},
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
        let state =
            get_mock_global_state(Network::Main, 2, Some(Wallet::new(generate_secret_key()))).await;
        let (dummy_tx, _rx) = tokio::sync::mpsc::channel::<RPCServerToMain>(RPC_CHANNEL_CAPACITY);
        let rpc_server = NeptuneRPCServer {
            socket_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
            state: state.clone(),
            rpc_server_to_main_tx: dummy_tx,
        };

        let balance = rpc_server.get_balance(context::current()).await;
        assert!(balance.is_zero());

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn clear_ip_standing_test() -> Result<()> {
        // Create initial conditions
        let (_peer_broadcast_tx, _from_main_rx_clone, _to_main_tx, mut _to_main_rx, state, _hsd) =
            get_test_genesis_setup(Network::Main, 2).await?;
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
            .write_peer_standing_on_increase(peer_address_0.ip(), standing_0)
            .await;
        state
            .write_peer_standing_on_increase(peer_address_1.ip(), standing_1)
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
            get_test_genesis_setup(Network::Main, 2).await?;
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
            .write_peer_standing_on_increase(peer_address_0.ip(), standing_0)
            .await;
        state
            .write_peer_standing_on_increase(peer_address_1.ip(), standing_1)
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
