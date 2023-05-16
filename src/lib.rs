#![deny(clippy::shadow_unrelated)]
pub mod config_models;
mod connect_to_peers;
mod database;
mod main_loop;
mod mine_loop;
pub mod models;
mod peer_loop;
pub mod rpc_server;

#[cfg(test)]
mod tests;

use crate::config_models::data_directory::DataDirectory;
use crate::connect_to_peers::call_peer_wrapper;
use crate::main_loop::MainLoopHandler;
use crate::models::channel::RPCServerToMain;
use crate::models::database::BlockIndexKey;
use crate::models::database::BlockIndexValue;
use crate::models::state::archival_state::ArchivalState;
use crate::models::state::blockchain_state::BlockchainState;
use crate::models::state::light_state::LightState;
use crate::models::state::mempool::Mempool;
use crate::models::state::networking_state::NetworkingState;
use crate::models::state::wallet::wallet_state::WalletState;
use crate::models::state::wallet::WalletSecret;
use crate::models::state::GlobalState;
use crate::rpc_server::RPC;
use anyhow::{Context, Result};
use config_models::cli_args;
use config_models::network::Network;
use database::rusty::RustyLevelDB;
use futures::future;
use futures::StreamExt;
use models::blockchain::block::Block;
use models::blockchain::shared::Hash;
use models::database::PeerDatabases;
use models::peer::PeerInfo;
use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tarpc::server;
use tarpc::server::incoming::Incoming;
use tarpc::server::Channel;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc, watch};
use tokio_serde::formats::*;
use tracing::debug;

use crate::models::channel::{MainToMiner, MainToPeerThread, MinerToMain, PeerThreadToMain};
use crate::models::peer::HandshakeData;

/// Magic string to ensure other program is Neptune Core
pub const MAGIC_STRING_REQUEST: &[u8] = b"EDE8991A9C599BE908A759B6BF3279CD";
pub const MAGIC_STRING_RESPONSE: &[u8] = b"Hello Neptune!\n";
const PEER_CHANNEL_CAPACITY: usize = 1000;
const MINER_CHANNEL_CAPACITY: usize = 3;
const RPC_CHANNEL_CAPACITY: usize = 1000;
const VERSION: &str = env!("CARGO_PKG_VERSION");

pub async fn initialize(cli_args: cli_args::Args) -> Result<()> {
    // Get data directory (wallet, block database), create one if none exists
    let data_dir = DataDirectory::get(cli_args.data_dir.clone(), cli_args.network)?;
    DataDirectory::create_dir_if_not_exists(&data_dir.root_dir_path())?;
    debug!("Data directory is {}", data_dir);

    // Get wallet object, create various wallet secret files
    let wallet_dir = data_dir.wallet_director_path();
    DataDirectory::create_dir_if_not_exists(&wallet_dir)?;
    let wallet_secret: WalletSecret =
        WalletSecret::read_from_file_or_create(&data_dir.wallet_director_path())?;
    let wallet_state =
        WalletState::new_from_wallet_secret(Some(&data_dir), wallet_secret, &cli_args).await;

    // Connect to or create databases for block index, peers, mutator set, block sync
    let block_index_db = ArchivalState::initialize_block_index_database(&data_dir)?;
    let block_index_db: Arc<tokio::sync::Mutex<RustyLevelDB<BlockIndexKey, BlockIndexValue>>> =
        Arc::new(tokio::sync::Mutex::new(block_index_db));

    let peer_databases = NetworkingState::initialize_peer_databases(&data_dir)?;
    let peer_databases: Arc<tokio::sync::Mutex<PeerDatabases>> =
        Arc::new(tokio::sync::Mutex::new(peer_databases));

    let archival_mutator_set = ArchivalState::initialize_mutator_set(&data_dir)?;
    let archival_mutator_set = Arc::new(tokio::sync::Mutex::new(archival_mutator_set));

    let archival_state = ArchivalState::new(data_dir, block_index_db, archival_mutator_set).await;

    // Get latest block. Use hardcoded genesis block if nothing is in database.
    let latest_block: Block = archival_state.get_latest_block().await;

    // Bind socket to port on this machine, to handle incoming connections from peers
    let listener = TcpListener::bind((cli_args.listen_addr, cli_args.peer_port))
        .await
        .with_context(|| format!("Failed to bind to local TCP port {}:{}. Is an instance of this program already running?", cli_args.listen_addr, cli_args.peer_port))?;

    let peer_map: Arc<Mutex<HashMap<SocketAddr, PeerInfo>>> =
        Arc::new(std::sync::Mutex::new(HashMap::new()));

    // Construct the broadcast channel to communicate from the main thread to peer threads
    let (main_to_peer_broadcast_tx, _main_to_peer_broadcast_rx) =
        broadcast::channel::<MainToPeerThread>(PEER_CHANNEL_CAPACITY);

    // Add the MPSC (multi-producer, single consumer) channel for peer-thread-to-main communication
    let (peer_thread_to_main_tx, peer_thread_to_main_rx) =
        mpsc::channel::<PeerThreadToMain>(PEER_CHANNEL_CAPACITY);

    // Create handshake data which is used when connecting to outgoing peers specified in the
    // CLI arguments
    let syncing = Arc::new(std::sync::RwLock::new(false));
    let networking_state = NetworkingState::new(peer_map, peer_databases, syncing);

    let light_state: LightState = LightState::new(latest_block.clone());
    let blockchain_state = BlockchainState {
        light_state,
        archival_state: Some(archival_state),
    };
    let mempool = Mempool::new(cli_args.max_mempool_size);
    let state = GlobalState {
        chain: blockchain_state,
        cli: cli_args,
        net: networking_state,
        wallet_state,
        mempool,
    };
    let own_handshake_data: HandshakeData = state.get_handshakedata().await;

    // Connect to peers, and provide each peer thread with a thread-safe copy of the state
    for peer in state.cli.peers.clone() {
        let peer_state_var = state.clone();
        let main_to_peer_broadcast_rx_clone: broadcast::Receiver<MainToPeerThread> =
            main_to_peer_broadcast_tx.subscribe();
        let peer_thread_to_main_tx_clone: mpsc::Sender<PeerThreadToMain> =
            peer_thread_to_main_tx.clone();
        let own_handshake_data_clone = own_handshake_data.clone();
        tokio::spawn(async move {
            call_peer_wrapper(
                peer,
                peer_state_var.clone(),
                main_to_peer_broadcast_rx_clone,
                peer_thread_to_main_tx_clone,
                own_handshake_data_clone,
                1, // All outgoing connections have distance 1
            )
            .await;
        });
    }

    // Start handling of mining. So far we can only mine on the `RegTest` network.
    let (miner_to_main_tx, miner_to_main_rx) = mpsc::channel::<MinerToMain>(MINER_CHANNEL_CAPACITY);
    let (main_to_miner_tx, main_to_miner_rx) = watch::channel::<MainToMiner>(MainToMiner::Empty);
    let (rpc_server_to_main_tx, rpc_server_to_main_rx) =
        mpsc::channel::<RPCServerToMain>(RPC_CHANNEL_CAPACITY);
    let state_clone_for_miner = state.clone();
    if state.cli.mine && state.cli.network == Network::RegTest {
        tokio::spawn(async move {
            mine_loop::mock_regtest_mine(
                main_to_miner_rx,
                miner_to_main_tx,
                latest_block,
                state_clone_for_miner,
            )
            .await
            .expect("Error in mining thread");
        });
    }

    // Start RPC server for CLI request and more
    let mut rpc_listener = tarpc::serde_transport::tcp::listen(
        format!("127.0.0.1:{}", state.cli.rpc_port),
        Json::default,
    )
    .await?;
    rpc_listener.config_mut().max_frame_length(usize::MAX);
    let rpc_listener_state: GlobalState = state.clone();
    tokio::spawn(async move {
        rpc_listener
            // Ignore accept errors.
            .filter_map(|r| future::ready(r.ok()))
            .map(server::BaseChannel::with_defaults)
            // Limit channels to 5 per IP. 1 for dashboard and a few more for CLI interactions
            .max_channels_per_key(5, |t| t.transport().peer_addr().unwrap().ip())
            // serve is generated by the service attribute. It takes as input any type implementing
            // the generated RPC trait.
            .map(|channel| {
                let server = rpc_server::NeptuneRPCServer {
                    socket_address: channel.transport().peer_addr().unwrap(),
                    state: rpc_listener_state.clone(),
                    rpc_server_to_main_tx: rpc_server_to_main_tx.clone(),
                };
                channel.execute(server.serve())
            })
            // Max 10 channels.
            .buffer_unordered(10)
            .for_each(|_| async {})
            .await;
    });

    // Handle incoming connections, messages from peer threads, and messages from the mining thread
    let main_loop_handler = MainLoopHandler::new(
        listener,
        state,
        main_to_peer_broadcast_tx,
        peer_thread_to_main_tx,
        main_to_miner_tx,
    );
    main_loop_handler
        .run(
            peer_thread_to_main_rx,
            miner_to_main_rx,
            rpc_server_to_main_rx,
        )
        .await
}
