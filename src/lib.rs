pub mod big_array;
pub mod config_models;
mod mine;
mod model;
mod peer;
mod peer_loop;

#[cfg(test)]
mod tests;

use anyhow::{anyhow, bail, Context, Result};
use config_models::network::Network;
use directories::ProjectDirs;
use futures::sink::SinkExt;
use futures::stream::TryStreamExt;
use model::{
    FromMinerToMain, HandshakeData, MainToPeerThread, PeerMessage, PeerThreadToMain, ToMiner,
};
use peer::Peer;
use peer_loop::peer_loop;
use std::collections::HashMap;
use std::fmt::Debug;
use std::marker::Unpin;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::select;
use tokio::sync::{broadcast, mpsc, watch};
use tokio_serde::formats::*;
use tokio_serde::SymmetricallyFramed;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::{debug, error, info, instrument, warn};

/// Magic string to ensure other program is Neptune Core
pub const MAGIC_STRING_REQUEST: &[u8] = b"EDE8991A9C599BE908A759B6BF3279CD";
pub const MAGIC_STRING_RESPONSE: &[u8] = b"Hello Neptune!\n";
const PEER_CHANNEL_CAPACITY: usize = 1000;
const MINER_CHANNEL_CAPACITY: usize = 3;
const VERSION: &str = env!("CARGO_PKG_VERSION");

fn get_database_root_path() -> Result<PathBuf> {
    let data_home = if let Some(proj_dirs) = ProjectDirs::from("org", "neptune", "neptune") {
        Ok(proj_dirs.data_dir().to_path_buf())
    } else {
        bail!("Could not determine data directory");
    };

    data_home
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
    let path = get_database_root_path().expect("Failed to get database path");
    debug!("Database root path is {:?}", path);

    // Bind socket to port on this machine
    let listener = TcpListener::bind((listen_addr, port))
        .await
        .with_context(|| format!("Failed to bind to local TCP port {}:{}. Is an instance of this program already running?", listen_addr, port))?;

    let peer_map = Arc::new(Mutex::new(HashMap::new()));

    // Construct the broadcast channel to communicate from the main thread to peer threads
    let (peer_broadcast_tx, _peer_broadcast_rx) =
        broadcast::channel::<MainToPeerThread>(PEER_CHANNEL_CAPACITY);

    // Add the MPSC (multi-producer, single consumer) channel for peer-thread-to-main communication
    let (to_main_tx, mut to_main_rx) = mpsc::channel::<PeerThreadToMain>(PEER_CHANNEL_CAPACITY);

    // Create handshake data
    let listen_addr_socket = SocketAddr::new(listen_addr, port);
    let own_handshake_data = HandshakeData {
        listen_address: Some(listen_addr_socket),
        network,
        version: VERSION.to_string(),
    };

    // Connect to peers
    for peer in peers {
        let thread_arc = Arc::clone(&peer_map);
        let peer_broadcast_rx_clone: broadcast::Receiver<MainToPeerThread> =
            peer_broadcast_tx.subscribe();
        let to_main_tx_clone: mpsc::Sender<PeerThreadToMain> = to_main_tx.clone();
        let own_handshake_data_clone = own_handshake_data.clone();
        tokio::spawn(async move {
            call_peer_wrapper(
                peer,
                thread_arc,
                peer_broadcast_rx_clone,
                to_main_tx_clone,
                &own_handshake_data_clone,
            )
            .await;
        });
    }

    // Start handling of mining
    let (from_miner_tx, mut from_miner_rx) =
        mpsc::channel::<FromMinerToMain>(MINER_CHANNEL_CAPACITY);
    let (to_miner_tx, to_miner_rx) = watch::channel::<ToMiner>(ToMiner::Empty);
    if mine && network == Network::RegTest {
        tokio::spawn(async move {
            mine::mock_regtest_mine(to_miner_rx, from_miner_tx)
                .await
                .expect("Error in mining thread");
        });
    }

    // Handle incoming connections, messages from peer threads, and messages from the mining thread
    loop {
        select! {
            // The second item contains the IP and port of the new connection.
            Ok((stream, _)) = listener.accept() => {
                let thread_arc = Arc::clone(&peer_map);
                let from_main_rx_clone: broadcast::Receiver<MainToPeerThread> = peer_broadcast_tx.subscribe();
                let to_main_tx_clone: mpsc::Sender<PeerThreadToMain> = to_main_tx.clone();
                let peer_address = stream.peer_addr().unwrap();
                let own_handshake_data_clone = own_handshake_data.clone();
                tokio::spawn(async move {
                    match answer_peer(stream, thread_arc, peer_address, from_main_rx_clone, to_main_tx_clone, own_handshake_data_clone).await {
                        Ok(()) => (),
                        Err(err) => error!("Got error: {:?}", err),
                    }
                });
            }
            Some(msg) = to_main_rx.recv() => {
                info!("Received message sent to main thread.");
                match msg {
                    PeerThreadToMain::NewBlock(block) => {
                        if mine {
                            to_miner_tx.send(ToMiner::NewBlock(block.clone()))?;
                        }

                        peer_broadcast_tx.send(MainToPeerThread::Block(block))
                            .expect("Peer handler broadcast was closed. This should never happen");
                    }
                    PeerThreadToMain::NewTransaction(_txs) => {
                        error!("Unimplemented txs msg received");
                    }
                }
            }
            Some(main_message) = from_miner_rx.recv() => {
                match main_message {
                    FromMinerToMain::NewBlock(block) => {
                        info!("Miner found new block: {}", block.height);
                        peer_broadcast_tx.send(MainToPeerThread::BlockFromMiner(block))
                            .expect("Peer handler broadcast channel prematurely closed. This should never happen.");
                        // TODO: Store block into own database
                    }
                }
            }
            // TODO: Add signal::ctrl_c/shutdown handling here
        }
    }
}

#[instrument]
pub async fn call_peer_wrapper(
    peer_address: std::net::SocketAddr,
    peer_map: Arc<Mutex<HashMap<SocketAddr, Peer>>>,
    from_main_rx: broadcast::Receiver<MainToPeerThread>,
    to_main_tx: mpsc::Sender<PeerThreadToMain>,
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
                peer_map,
                peer_address,
                from_main_rx,
                to_main_tx,
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
    peer_map: Arc<Mutex<HashMap<SocketAddr, Peer>>>,
    peer_address: std::net::SocketAddr,
    from_main_rx: broadcast::Receiver<MainToPeerThread>,
    to_main_tx: mpsc::Sender<PeerThreadToMain>,
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
    peer_map
        .lock()
        .unwrap_or_else(|e| panic!("Failed to lock peer map: {}", e))
        .entry(peer_address)
        .or_insert(new_peer);

    // Enter `peer_loop` to handle incoming peer messages/messages from main thread
    peer_loop(peer, from_main_rx, to_main_tx, peer_map, &peer_address).await?;

    Ok(())
}

#[instrument]
pub async fn answer_peer<S>(
    stream: S,
    peer_map: Arc<Mutex<HashMap<SocketAddr, Peer>>>,
    peer_address: std::net::SocketAddr,
    from_main_rx: broadcast::Receiver<MainToPeerThread>,
    to_main_tx: mpsc::Sender<PeerThreadToMain>,
    own_handshake_data: HandshakeData,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + std::fmt::Debug + std::marker::Unpin,
{
    info!("Established connection");

    // Build the communication/serialization/frame handler
    let length_delimited = Framed::new(stream, LengthDelimitedCodec::new());
    let mut peer = tokio_serde::SymmetricallyFramed::new(
        length_delimited,
        SymmetricalBincode::<PeerMessage>::default(),
    );

    // Complete Neptune handshake
    let peer_handshake_data: HandshakeData = match peer.try_next().await? {
        Some(PeerMessage::Handshake((v, hsd))) if &v[..] == MAGIC_STRING_REQUEST => {
            // Send handshake answer to peer
            peer.send(PeerMessage::Handshake((
                MAGIC_STRING_RESPONSE.to_vec(),
                own_handshake_data.clone(),
            )))
            .await?;

            // Verify peer network before moving on
            if hsd.network != own_handshake_data.network {
                bail!(
                    "Cannot connect with {}: Peer runs {}, this client runs {}.",
                    peer_address,
                    hsd.network,
                    own_handshake_data.network,
                );
            }
            debug!("Got correct magic value request!");
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
        inbound: true,
        last_seen: SystemTime::now(),
        version: peer_handshake_data.version,
    };
    peer_map
        .lock()
        .map_err(|e| anyhow!("Failed to lock peer map: {}", e))?
        .entry(peer_address)
        .or_insert(new_peer);

    // Enter `peer_loop` to handle incoming peer messages/messages from main thread
    peer_loop(peer, from_main_rx, to_main_tx, peer_map, &peer_address).await?;

    Ok(())
}
