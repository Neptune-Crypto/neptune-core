//! A RegTest node for tests that play a plugin.

use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::time::Duration;

use neptune_cash::api::export::GlobalStateLock;
use neptune_cash::application::config::cli_args::Args;
use neptune_consensus::block::Block;
use neptune_primitives::network::Network;
use neptune_rpc_api::api::ops::Namespace;
use neptune_rpc_client::http::HttpClient;
use tokio::net::TcpListener;

pub const NETWORK: Network = Network::RegTest;

/// A RegTest node with a fresh wallet, serving the JSON-RPC namespaces
/// `neptune-defi` enables, with unrestricted access.
pub async fn start_node() -> (HttpClient, GlobalStateLock) {
    async fn free_port() -> u16 {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        listener.local_addr().unwrap().port()
    }

    let mut args = Args::default_with_network(NETWORK);
    args.peer_port = free_port().await;
    args.quic_port = free_port().await;
    args.tcp_port = free_port().await;
    args.rpc_port = free_port().await;
    let rpc_address = SocketAddr::from((Ipv4Addr::LOCALHOST, free_port().await));
    args.listen_rpc = Some(rpc_address);
    args.rpc_modules = vec![
        Namespace::Node,
        Namespace::Chain,
        Namespace::Archival,
        Namespace::Mempool,
        Namespace::Mining,
        Namespace::Wallet,
        Namespace::Personal,
    ];
    args.unsafe_rpc = true;
    args.data_dir = Some(
        std::env::temp_dir()
            .join("neptune-defi-tests")
            .join(format!("{:016x}", rand::random::<u64>())),
    );

    let mut main_loop = neptune_cash::initialize(args, None).await.unwrap();
    let state = main_loop.global_state_lock();
    tokio::spawn(async move { main_loop.run().await.unwrap() });

    // The RPC server needs a moment to start listening.
    tokio::time::sleep(Duration::from_secs(1)).await;

    (HttpClient::new(format!("http://{rpc_address}")), state)
}

/// Have the node mine one block on its tip, and return that block.
pub async fn mine_block(state: &mut GlobalStateLock) -> Block {
    state
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(1, false)
        .await
        .unwrap();
    state.lock_guard().await.chain.tip().clone()
}
