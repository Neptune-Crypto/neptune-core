pub mod config_models;
mod main_loop;
mod mine_loop;
mod models;
mod peer_loop;

#[cfg(test)]
mod tests;

use anyhow::{bail, Context, Result};
use config_models::network::Network;
use directories::ProjectDirs;
use futures::sink::SinkExt;
use futures::stream::TryStreamExt;
use leveldb::database::Database;
use leveldb::kv::KV;
use leveldb::options::{Options, ReadOptions};
use models::blockchain::{BlockHash, BlockHeight};
use models::database::{DatabaseUnit, Databases};
use models::peer::Peer;
use models::State;
use std::collections::HashMap;
use std::fmt::Debug;
use std::marker::Unpin;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc, watch};
use tokio_serde::formats::*;
use tokio_serde::SymmetricallyFramed;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::{debug, error, info, instrument, warn};

use crate::models::channel::{MainToMiner, MainToPeerThread, MinerToMain, PeerThreadToMain};
use crate::models::peer::{HandshakeData, PeerMessage};
use crate::models::shared::LatestBlockInfo;

/// Magic string to ensure other program is Neptune Core
pub const MAGIC_STRING_REQUEST: &[u8] = b"EDE8991A9C599BE908A759B6BF3279CD";
pub const MAGIC_STRING_RESPONSE: &[u8] = b"Hello Neptune!\n";
const PEER_CHANNEL_CAPACITY: usize = 1000;
const MINER_CHANNEL_CAPACITY: usize = 3;
const VERSION: &str = env!("CARGO_PKG_VERSION");
const BLOCK_HASH_TO_BLOCK_DB_NAME: &str = "blocks";
const BLOCK_HEIGHT_TO_HASH_DB_NAME: &str = "block_hashes";
const LATEST_BLOCK_DB_NAME: &str = "latest";

fn get_database_root_path() -> Result<PathBuf> {
    let data_home = if let Some(proj_dirs) = ProjectDirs::from("org", "neptune", "neptune") {
        Ok(proj_dirs.data_dir().to_path_buf())
    } else {
        bail!("Could not determine data directory");
    };

    data_home
}

fn initialize_databases(root_path: &Path, network: Network) -> Databases {
    let mut path = root_path.to_owned();
    path.push(network.to_string());

    // Create directory for database if it does not exist
    std::fs::create_dir_all(path.clone()).unwrap_or_else(|_| {
        panic!(
            "Failed to create database directory in {}",
            path.to_string_lossy()
        )
    });

    let mut block_height_to_hash_path = path.to_owned();
    block_height_to_hash_path.push(BLOCK_HEIGHT_TO_HASH_DB_NAME);
    let mut block_hash_to_block_path = path.to_owned();
    block_hash_to_block_path.push(BLOCK_HASH_TO_BLOCK_DB_NAME);
    let mut latest_path = path;
    latest_path.push(LATEST_BLOCK_DB_NAME);

    let mut hash_options = Options::new();
    hash_options.create_if_missing = true;
    let block_hash_to_block: Database<BlockHash> =
        match Database::open(block_hash_to_block_path.as_path(), hash_options) {
            Ok(db) => db,
            Err(e) => {
                panic!(
                    "failed to open {} database: {:?}",
                    BLOCK_HASH_TO_BLOCK_DB_NAME, e
                )
            }
        };

    let mut height_options = Options::new();
    height_options.create_if_missing = true;
    let block_height_to_hash: Database<BlockHeight> =
        match Database::open(block_height_to_hash_path.as_path(), height_options) {
            Ok(db) => db,
            Err(e) => {
                panic!(
                    "failed to open {} database: {:?}",
                    BLOCK_HASH_TO_BLOCK_DB_NAME, e
                )
            }
        };

    let mut latest_options = Options::new();
    latest_options.create_if_missing = true;
    let latest_block: Database<DatabaseUnit> =
        match Database::open(latest_path.as_path(), latest_options) {
            Ok(db) => db,
            Err(e) => {
                panic!("failed to open {} database: {:?}", LATEST_BLOCK_DB_NAME, e)
            }
        };

    Databases {
        block_hash_to_block,
        block_height_to_hash,
        latest_block,
    }
}

#[instrument]
pub async fn initialize(
    listen_addr: IpAddr,
    port: u16,
    peers: Vec<SocketAddr>,
    network: Network,
    mine: bool,
) -> Result<()> {
    // Connect to database
    let path_buf = get_database_root_path()?;
    let root_path = path_buf.as_path();
    debug!("Database root path is {:?}", root_path);

    let databases: Arc<tokio::sync::Mutex<Databases>> = Arc::new(tokio::sync::Mutex::new(
        initialize_databases(root_path, network),
    ));

    // Get latest block height
    let latest_block_info: Option<LatestBlockInfo> = {
        let dbs = databases.lock().await;
        let lookup_res = dbs
            .latest_block
            .get(ReadOptions::new(), DatabaseUnit())
            .expect("Failed to get latest block info on init");
        lookup_res.map(|bytes| {
            bincode::deserialize(&bytes).expect("Failed to deserialize latest block info")
        })
    };
    match latest_block_info {
        None => info!("No previous state saved"),
        Some(block) => info!(
            "Latest block was block height {}, hash = {:?}",
            block.height, block.hash
        ),
    }

    // Bind socket to port on this machine
    let listener = TcpListener::bind((listen_addr, port))
        .await
        .with_context(|| format!("Failed to bind to local TCP port {}:{}. Is an instance of this program already running?", listen_addr, port))?;

    let peer_map = Arc::new(std::sync::Mutex::new(HashMap::new()));

    // Construct the broadcast channel to communicate from the main thread to peer threads
    let (main_to_peer_broadcast_tx, _main_to_peer_broadcast_rx) =
        broadcast::channel::<MainToPeerThread>(PEER_CHANNEL_CAPACITY);

    // Add the MPSC (multi-producer, single consumer) channel for peer-thread-to-main communication
    let (peer_thread_to_main_tx, peer_thread_to_main_rx) =
        mpsc::channel::<PeerThreadToMain>(PEER_CHANNEL_CAPACITY);

    // Create handshake data
    let listen_addr_socket = SocketAddr::new(listen_addr, port);
    let own_handshake_data = HandshakeData {
        latest_block_info,
        listen_address: Some(listen_addr_socket),
        network,
        version: VERSION.to_string(),
    };

    // Connect to peers
    for peer in peers {
        let peer_map_thread = Arc::clone(&peer_map);
        let databases_thread = Arc::clone(&databases);
        let state = State {
            peer_map: peer_map_thread,
            databases: databases_thread,
        };
        let main_to_peer_broadcast_rx_clone: broadcast::Receiver<MainToPeerThread> =
            main_to_peer_broadcast_tx.subscribe();
        let peer_thread_to_main_tx_clone: mpsc::Sender<PeerThreadToMain> =
            peer_thread_to_main_tx.clone();
        let own_handshake_data_clone = own_handshake_data.clone();
        tokio::spawn(async move {
            call_peer_wrapper(
                peer,
                state,
                main_to_peer_broadcast_rx_clone,
                peer_thread_to_main_tx_clone,
                &own_handshake_data_clone,
            )
            .await;
        });
    }

    // Start handling of mining
    let (miner_to_main_tx, miner_to_main_rx) = mpsc::channel::<MinerToMain>(MINER_CHANNEL_CAPACITY);
    let (main_to_miner_tx, main_to_miner_rx) = watch::channel::<MainToMiner>(MainToMiner::Empty);
    if mine && network == Network::RegTest {
        tokio::spawn(async move {
            mine_loop::mock_regtest_mine(main_to_miner_rx, miner_to_main_tx, latest_block_info)
                .await
                .expect("Error in mining thread");
        });
    }

    // Handle incoming connections, messages from peer threads, and messages from the mining thread
    main_loop::main_loop(
        listener,
        peer_map,
        databases,
        main_to_peer_broadcast_tx,
        peer_thread_to_main_tx,
        peer_thread_to_main_rx,
        own_handshake_data,
        miner_to_main_rx,
        mine,
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

    // Add peer to peer map if not already there
    let new_peer = Peer {
        address: peer_address,
        banscore: 0,
        inbound: false,
        last_seen: SystemTime::now(),
        version: peer_handshake_data.version,
    };
    state
        .peer_map
        .lock()
        .unwrap_or_else(|e| panic!("Failed to lock peer map: {}", e))
        .entry(peer_address)
        .or_insert(new_peer);

    // Enter `peer_loop` to handle incoming peer messages/messages from main thread
    peer_loop::peer_loop(
        peer,
        main_to_peer_thread_rx,
        peer_thread_to_main_tx,
        state,
        &peer_address,
    )
    .await?;

    Ok(())
}
