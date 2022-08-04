#![deny(clippy::shadow_unrelated)]
pub mod config_models;
mod connect_to_peers;
mod database;
mod main_loop;
mod mine_loop;
mod models;
mod peer_loop;
pub mod rpc_server;

#[cfg(test)]
mod tests;

use crate::connect_to_peers::call_peer_wrapper;
use crate::database::leveldb::LevelDB;
use crate::main_loop::MainLoopHandler;
use crate::models::state::ArchivalState;
use crate::models::state::BlockchainState;
use crate::models::state::LightState;
use crate::models::state::NetworkingState;
use crate::models::state::State;
use crate::rpc_server::RPC;
use anyhow::{bail, Context, Result};
use config_models::cli_args;
use config_models::network::Network;
use database::rusty::RustyLevelDB;
use directories::ProjectDirs;
use futures::future;
use futures::StreamExt;
use models::blockchain::block::block_header::BlockHeader;
use models::blockchain::block::block_height::BlockHeight;
use models::blockchain::block::Block;
use models::blockchain::digest::Digest;
use models::blockchain::wallet::Wallet;
use models::database::{BlockDatabases, PeerDatabases};
use models::peer::PeerInfo;
use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tarpc::server;
use tarpc::server::incoming::Incoming;
use tarpc::server::Channel;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc, watch};
use tokio_serde::formats::*;
use tracing::{debug, info, instrument};

use crate::models::channel::{MainToMiner, MainToPeerThread, MinerToMain, PeerThreadToMain};
use crate::models::peer::{HandshakeData, PeerStanding};

/// Magic string to ensure other program is Neptune Core
pub const MAGIC_STRING_REQUEST: &[u8] = b"EDE8991A9C599BE908A759B6BF3279CD";
pub const MAGIC_STRING_RESPONSE: &[u8] = b"Hello Neptune!\n";
const PEER_CHANNEL_CAPACITY: usize = 1000;
const MINER_CHANNEL_CAPACITY: usize = 3;
const VERSION: &str = env!("CARGO_PKG_VERSION");
const BLOCK_HASH_TO_BLOCK_DB_NAME: &str = "blocks";
const BLOCK_HEIGHT_TO_HASH_DB_NAME: &str = "block_hashes";
const LATEST_BLOCK_DB_NAME: &str = "latest";
const BANNED_IPS_DB_NAME: &str = "banned_ips";
const DATABASE_DIRECTORY_ROOT_NAME: &str = "databases";
const WALLET_FILE_NAME: &str = "wallet.dat";
const STANDARD_WALLET_NAME: &str = "standard";
const STANDARD_WALLET_VERSION: u8 = 0;

fn get_data_directory(network: Network) -> Result<PathBuf> {
    if let Some(proj_dirs) = ProjectDirs::from("org", "neptune", "neptune") {
        let mut path = proj_dirs.data_dir().to_path_buf();
        path.push(network.to_string());
        Ok(path)
    } else {
        bail!("Could not determine data directory")
    }
}

/// Create a wallet file, and set restrictive permissions
#[cfg(target_family = "unix")]
fn create_wallet_file_unix(path: &PathBuf, wallet_as_json: String) {
    // On Unix/Linux we set the file permissions to 600, to disallow
    // other users on the same machine to access the secrets.
    use std::os::unix::prelude::OpenOptionsExt;
    fs::OpenOptions::new()
        .create(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    fs::write(path.clone(), wallet_as_json).expect("Failed to write wallet file to disk");
}

/// Create a wallet file, without setting restrictive UNIX permissions
// #[cfg(not(target_family = "unix"))]
fn create_wallet_file_windows(path: &PathBuf, wallet_as_json: String) {
    fs::OpenOptions::new()
        .create(true)
        .write(true)
        .open(path)
        .unwrap();
    fs::write(path.clone(), wallet_as_json).expect("Failed to write wallet file to disk");
}

/// Read the wallet from disk. Create one if none exists.
fn initialize_wallet(root_path: &Path, name: &str, version: u8) -> Wallet {
    let mut path = root_path.to_owned();
    path.push(WALLET_FILE_NAME);

    // Check if file exists
    let wallet: Wallet = if path.exists() {
        info!("Found wallet file: {}", path.to_string_lossy());

        // Read wallet from disk
        let file_content: String = match fs::read_to_string(path.clone()) {
            Ok(fc) => fc,
            Err(err) => panic!(
                "Failed to read file {}. Got error: {}",
                path.to_string_lossy(),
                err
            ),
        };

        // Parse wallet as JSON and return result
        match serde_json::from_str(&file_content) {
            Ok(stored_wallet) => stored_wallet,
            Err(err) => {
                panic!(
                    "Failed to parse {} as Wallet in JSON format. Is the wallet file corrupted? Error: {}",
                    path.to_string_lossy(),
                    err
                )
            }
        }
    } else {
        info!("Creating new wallet file: {}", path.to_string_lossy());

        // New wallet must be made and stored to disk
        let new_wallet: Wallet = Wallet::new_random_wallet(name, version);
        let wallet_as_json: String =
            serde_json::to_string(&new_wallet).expect("wallet serialization must succeed");

        // Store to disk, with the right permissions
        if cfg!(target_family = "unix") {
            create_wallet_file_unix(&path, wallet_as_json);
        } else {
            create_wallet_file_windows(&path, wallet_as_json);
        }

        new_wallet
    };

    // Sanity check that wallet file was stored on disk.
    assert!(
        path.exists(),
        "wallet file must exist on disk after creation."
    );

    wallet
}

/// Create databases if they don't already exists. Also return the databases used by the client.
fn initialize_databases(root_path: &Path) -> Result<(BlockDatabases, PeerDatabases)> {
    let mut path = root_path.to_owned();
    path.push(DATABASE_DIRECTORY_ROOT_NAME);

    // Create root directory for all databases if it does not exist
    std::fs::create_dir_all(path.clone()).unwrap_or_else(|_| {
        panic!(
            "Failed to create database directory in {}",
            path.to_string_lossy()
        )
    });

    let block_hash_to_block =
        RustyLevelDB::<Digest, Block>::new(&path, BLOCK_HASH_TO_BLOCK_DB_NAME)?;
    let block_height_to_hash =
        RustyLevelDB::<BlockHeight, Digest>::new(&path, BLOCK_HEIGHT_TO_HASH_DB_NAME)?;
    let latest_block = RustyLevelDB::<(), BlockHeader>::new(&path, LATEST_BLOCK_DB_NAME)?;
    let banned_peers = RustyLevelDB::<IpAddr, PeerStanding>::new(&path, BANNED_IPS_DB_NAME)?;

    Ok((
        BlockDatabases {
            block_hash_to_block,
            block_height_to_hash,
            latest_block_header: latest_block,
        },
        PeerDatabases {
            peer_standings: banned_peers,
        },
    ))
}

/// Return the tip of the blockchain, the most canonical block. If no block is stored in the database,
/// the use the genesis block.
async fn get_latest_block(databases: Arc<tokio::sync::Mutex<BlockDatabases>>) -> Result<Block> {
    let mut dbs = databases.lock().await;
    let lookup_res_info: Option<Block> = BlockDatabases::get_latest_block(&mut dbs)?;

    match lookup_res_info {
        None => {
            info!("No previous state saved. Using genesis block.");
            Ok(Block::genesis_block())
        }
        Some(block) => {
            info!(
                "Latest block was block height {}, hash = {:?}",
                block.header.height, block.hash
            );
            Ok(block)
        }
    }
}

#[instrument]
pub async fn initialize(cli_args: cli_args::Args) -> Result<()> {
    let path_buf = get_data_directory(cli_args.network)?;

    // The root path is where both the wallet and all databases are stored
    let root_path = path_buf.as_path();

    // Create root directory for databases and wallet if it does not already exist
    std::fs::create_dir_all(root_path).unwrap_or_else(|_| {
        panic!(
            "Failed to create data directory in {}",
            root_path.to_string_lossy()
        )
    });

    // Get wallet object, create one if none exists
    debug!("Data root path is {:?}", root_path);
    let wallet: Wallet =
        initialize_wallet(root_path, STANDARD_WALLET_NAME, STANDARD_WALLET_VERSION);

    // Connect to or create databases for block state, and for peer state
    let (block_databases, peer_databases) = initialize_databases(root_path)?;
    let block_databases: Arc<tokio::sync::Mutex<BlockDatabases>> =
        Arc::new(tokio::sync::Mutex::new(block_databases));
    let peer_databases: Arc<tokio::sync::Mutex<PeerDatabases>> =
        Arc::new(tokio::sync::Mutex::new(peer_databases));

    // Get latest block. Use hardcoded genesis block if nothing is in database.
    let latest_block = get_latest_block(Arc::clone(&block_databases)).await?;

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
    let listen_addr_socket = SocketAddr::new(cli_args.listen_addr, cli_args.peer_port);
    let own_handshake_data = HandshakeData {
        tip_header: latest_block.header.clone(),
        listen_address: Some(listen_addr_socket),
        network: cli_args.network,
        instance_id: rand::random(),
        version: VERSION.to_string(),
    };

    // Connect to peers, and provide each peer thread with a thread-safe copy of the state
    let syncing = Arc::new(std::sync::RwLock::new(false));
    let networking_state = NetworkingState::new(peer_map, peer_databases, syncing);
    let light_state: LightState = LightState::new(latest_block.header.clone());
    let blockchain_state = BlockchainState {
        light_state,
        archival_state: Some(ArchivalState::new(block_databases)),
    };
    let state = State {
        chain: blockchain_state,
        cli: cli_args,
        net: networking_state,
    };

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
    let state_clone_for_miner = state.clone();
    if state.cli.mine && state.cli.network == Network::RegTest {
        tokio::spawn(async move {
            mine_loop::mock_regtest_mine(
                main_to_miner_rx,
                miner_to_main_tx,
                latest_block,
                wallet.get_public_key(),
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
    let rpc_listener_state: State = state.clone();
    tokio::spawn(async move {
        rpc_listener
            // Ignore accept errors.
            .filter_map(|r| future::ready(r.ok()))
            .map(server::BaseChannel::with_defaults)
            // Limit channels to 1 per IP.
            .max_channels_per_key(1, |t| t.transport().peer_addr().unwrap().ip())
            // serve is generated by the service attribute. It takes as input any type implementing
            // the generated World trait.
            .map(|channel| {
                let server = rpc_server::NeptuneRPCServer {
                    socket_address: channel.transport().peer_addr().unwrap(),
                    state: rpc_listener_state.clone(),
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
        .run(peer_thread_to_main_rx, miner_to_main_rx)
        .await
}
