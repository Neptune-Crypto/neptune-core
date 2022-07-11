#![deny(clippy::shadow_unrelated)]
pub mod config_models;
mod main_loop;
mod mine_loop;
mod models;
mod peer_loop;
pub mod rpc;

#[cfg(test)]
mod tests;

use crate::models::state::State;
use crate::rpc::RPC;
use anyhow::{bail, Context, Result};
use config_models::cli_args;
use config_models::network::Network;
use directories::ProjectDirs;
use futures::future;
use futures::sink::SinkExt;
use futures::stream::TryStreamExt;
use futures::StreamExt;
use leveldb::database::Database;
use leveldb::kv::KV;
use leveldb::options::ReadOptions;
use models::blockchain::block::block_height::BlockHeight;
use models::blockchain::block::Block;
use models::blockchain::digest::keyable_digest::KeyableDigest;
use models::blockchain::wallet::Wallet;
use models::database::{BlockDatabases, DatabaseUnit, KeyableIpAddress, PeerDatabases};
use models::peer::PeerInfo;
use std::collections::HashMap;
use std::fmt::Debug;
use std::fs;
use std::marker::Unpin;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;
use tarpc::server;
use tarpc::server::incoming::Incoming;
use tarpc::server::Channel;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc, watch};
use tokio_serde::formats::*;
use tokio_serde::SymmetricallyFramed;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::{debug, error, info, instrument, warn};

use crate::models::channel::{MainToMiner, MainToPeerThread, MinerToMain, PeerThreadToMain};
use crate::models::peer::{ConnectionStatus, HandshakeData, PeerMessage, PeerStanding, PeerState};

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

/// Create a database with key type `T`, name `db_name` in directory `path/db_name/`
/// Returns this database.
fn initialize_database<T: db_key::Key>(path: &PathBuf, db_name: &str) -> Database<T> {
    let mut path = path.to_owned();
    path.push(db_name);
    let mut options = leveldb::options::Options::new();
    options.create_if_missing = true;
    match Database::open(path.as_path(), options) {
        Ok(db) => db,
        Err(e) => {
            panic!("failed to open {} database: {:?}", db_name, e)
        }
    }
}

/// Create databases if they don't already exists. Also return the databases used by the client.
fn initialize_databases(root_path: &Path) -> (BlockDatabases, PeerDatabases) {
    let mut path = root_path.to_owned();
    path.push(DATABASE_DIRECTORY_ROOT_NAME);

    // Create root directory for all databases if it does not exist
    std::fs::create_dir_all(path.clone()).unwrap_or_else(|_| {
        panic!(
            "Failed to create database directory in {}",
            path.to_string_lossy()
        )
    });

    let block_hash_to_block: Database<KeyableDigest> =
        initialize_database::<KeyableDigest>(&path, BLOCK_HASH_TO_BLOCK_DB_NAME);
    let block_height_to_hash: Database<BlockHeight> =
        initialize_database::<BlockHeight>(&path, BLOCK_HEIGHT_TO_HASH_DB_NAME);
    let latest_block: Database<DatabaseUnit> =
        initialize_database::<DatabaseUnit>(&path, LATEST_BLOCK_DB_NAME);
    let banned_peers: Database<KeyableIpAddress> =
        initialize_database::<KeyableIpAddress>(&path, BANNED_IPS_DB_NAME);

    (
        BlockDatabases {
            block_hash_to_block,
            block_height_to_hash,
            latest_block_header: latest_block,
        },
        PeerDatabases {
            peer_standings: banned_peers,
        },
    )
}

/// Return the tip of the blockchain, the most canonical block. If no block is stored in the database,
/// the use the genesis block.
async fn get_latest_block(databases: Arc<tokio::sync::Mutex<BlockDatabases>>) -> Result<Block> {
    let dbs = databases.lock().await;
    let lookup_res_info: Option<Block> = BlockDatabases::get_latest_block(dbs)?;

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
    let (block_databases, peer_databases) = initialize_databases(root_path);
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

    let peer_map = Arc::new(std::sync::Mutex::new(HashMap::new()));

    // Construct the broadcast channel to communicate from the main thread to peer threads
    let (main_to_peer_broadcast_tx, _main_to_peer_broadcast_rx) =
        broadcast::channel::<MainToPeerThread>(PEER_CHANNEL_CAPACITY);

    // Add the MPSC (multi-producer, single consumer) channel for peer-thread-to-main communication
    let (peer_thread_to_main_tx, peer_thread_to_main_rx) =
        mpsc::channel::<PeerThreadToMain>(PEER_CHANNEL_CAPACITY);

    // Create handshake data which is used when connecting to peers
    let listen_addr_socket = SocketAddr::new(cli_args.listen_addr, cli_args.peer_port);
    let own_handshake_data = HandshakeData {
        latest_block_info: (&latest_block).into(),
        listen_address: Some(listen_addr_socket),
        network: cli_args.network,
        instance_id: rand::random(),
        version: VERSION.to_string(),
    };

    // Connect to peers, and provide each peer thread with a thread-safe copy of the state
    let latest_block_header = Arc::new(std::sync::Mutex::new(latest_block.header.clone()));
    let syncing = Arc::new(std::sync::RwLock::new(false));
    let state = State {
        peer_map: Arc::clone(&peer_map),
        block_databases: Arc::clone(&block_databases),
        latest_block_header: Arc::clone(&latest_block_header),
        syncing: Arc::clone(&syncing),
        peer_databases: Arc::clone(&peer_databases),
    };
    for peer in cli_args.peers.clone() {
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
                &own_handshake_data_clone,
            )
            .await;
        });
    }

    // Start handling of mining. So far we can only mine on the `RegTest` network.
    let (miner_to_main_tx, miner_to_main_rx) = mpsc::channel::<MinerToMain>(MINER_CHANNEL_CAPACITY);
    let (main_to_miner_tx, main_to_miner_rx) = watch::channel::<MainToMiner>(MainToMiner::Empty);
    if cli_args.mine && cli_args.network == Network::RegTest {
        tokio::spawn(async move {
            mine_loop::mock_regtest_mine(
                main_to_miner_rx,
                miner_to_main_tx,
                latest_block,
                wallet.get_public_key(),
            )
            .await
            .expect("Error in mining thread");
        });
    }

    // Start RPC server for CLI request and more
    let mut rpc_listener = tarpc::serde_transport::tcp::listen(
        format!("127.0.0.1:{}", cli_args.rpc_port),
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
                let server = rpc::NeptuneRPCServer {
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
    main_loop::main_loop(
        listener,
        state,
        main_to_peer_broadcast_tx,
        peer_thread_to_main_tx,
        peer_thread_to_main_rx,
        own_handshake_data,
        miner_to_main_rx,
        cli_args,
        main_to_miner_tx,
    )
    .await
}

#[instrument]
pub async fn call_peer_wrapper(
    peer_address: std::net::SocketAddr,
    state: State,
    main_to_peer_thread_rx: broadcast::Receiver<MainToPeerThread>,
    peer_thread_to_main_tx: mpsc::Sender<PeerThreadToMain>,
    own_handshake_data: &HandshakeData,
) {
    debug!("Attempting to initiate connection");
    match tokio::net::TcpStream::connect(peer_address).await {
        Err(e) => {
            warn!("Failed to establish connection: {}", e);
        }
        Ok(stream) => {
            match call_peer(
                stream,
                state,
                peer_address,
                main_to_peer_thread_rx,
                peer_thread_to_main_tx,
                own_handshake_data,
            )
            .await
            {
                Ok(()) => (),
                Err(e) => error!("An error occurred: {}. Connection closing", e),
            }
        }
    };

    info!("Connection closing");
}

#[instrument]
pub async fn call_peer<S>(
    stream: S,
    state: State,
    peer_address: std::net::SocketAddr,
    main_to_peer_thread_rx: broadcast::Receiver<MainToPeerThread>,
    peer_thread_to_main_tx: mpsc::Sender<PeerThreadToMain>,
    own_handshake_data: &HandshakeData,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Debug + Unpin,
{
    info!("Established connection");

    // Delimit frames using a length header
    let length_delimited = Framed::new(stream, LengthDelimitedCodec::new());

    // Serialize frames with bincode
    let mut peer: SymmetricallyFramed<
        Framed<S, LengthDelimitedCodec>,
        PeerMessage,
        Bincode<PeerMessage, PeerMessage>,
    > = SymmetricallyFramed::new(length_delimited, SymmetricalBincode::default());

    // Make Neptune handshake
    peer.send(PeerMessage::Handshake((
        Vec::from(MAGIC_STRING_REQUEST),
        own_handshake_data.to_owned(),
    )))
    .await?;
    let peer_handshake_data: HandshakeData = match peer.try_next().await? {
        Some(PeerMessage::Handshake((v, hsd))) if &v[..] == MAGIC_STRING_RESPONSE => {
            if hsd.network != own_handshake_data.network {
                bail!(
                    "Cannot connect with {}: Peer runs {}, this client runs {}.",
                    peer_address,
                    hsd.network,
                    own_handshake_data.network,
                );
            }
            debug!("Got correct magic value response!");
            hsd
        }
        v => {
            bail!("Expected magic value, got {:?}", v);
        }
    };

    match peer.try_next().await? {
        Some(PeerMessage::ConnectionStatus(ConnectionStatus::Accepted)) => (),
        Some(PeerMessage::ConnectionStatus(ConnectionStatus::Refused(reason))) => {
            bail!("Connection attempt refused. Reason: {:?}", reason);
        }
        _ => {
            bail!("Got invalid connection status response");
        }
    }

    // Check if peer standing exists in database, return default if it does not.
    let standing: PeerStanding =
        match state
            .peer_databases
            .lock()
            .await
            .peer_standings
            .get::<KeyableIpAddress>(ReadOptions::new(), peer_address.ip().into())
        {
            Ok(res) => match res {
                None => PeerStanding::default(),
                Some(standing_bytes) => bincode::deserialize(&standing_bytes)
                    .expect("Failed to deserialize peer standing"),
            },
            Err(_) => panic!("Failed to read from peer standing database"),
        };

    // Add peer to peer map
    let new_peer = PeerInfo {
        address: peer_address,
        inbound: false,
        instance_id: peer_handshake_data.instance_id,
        last_seen: SystemTime::now(),
        standing,
        version: peer_handshake_data.version,
    };
    state
        .peer_map
        .lock()
        .unwrap_or_else(|e| panic!("Failed to lock peer map: {}", e))
        .entry(peer_address)
        .or_insert(new_peer);

    // Do we want to set the "syncing" status here, and do something different if we are
    // syncing?

    // Enter `peer_loop` to handle incoming peer messages/messages from main thread
    peer_loop::peer_loop(
        peer,
        main_to_peer_thread_rx,
        peer_thread_to_main_tx,
        state,
        &peer_address,
        &mut PeerState::default(),
    )
    .await?;

    Ok(())
}
