use crate::models::database::{DatabaseUnit, Databases};
use crate::models::peer::Peer;
use crate::models::State;
use anyhow::{bail, Result};
use futures::sink::SinkExt;
use futures::stream::TryStreamExt;
use leveldb::kv::KV;
use leveldb::options::WriteOptions;
use std::collections::hash_map::RandomState;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::select;
use tokio::sync::{broadcast, mpsc, watch};
use tokio_serde::formats::*;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::{debug, error, info, instrument};

use crate::models::channel::{MainToMiner, MainToPeerThread, MinerToMain, PeerThreadToMain};
use crate::models::peer::{HandshakeData, PeerMessage};
use crate::models::shared::LatestBlockInfo;

#[instrument]
pub async fn answer_peer<S>(
    stream: S,
    state: State,
    peer_address: std::net::SocketAddr,
    main_to_peer_thread_rx: broadcast::Receiver<MainToPeerThread>,
    peer_thread_to_main_tx: mpsc::Sender<PeerThreadToMain>,
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
        Some(PeerMessage::Handshake((v, hsd))) if &v[..] == crate::MAGIC_STRING_REQUEST => {
            // Send handshake answer to peer
            peer.send(PeerMessage::Handshake((
                crate::MAGIC_STRING_RESPONSE.to_vec(),
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
    state
        .peer_map
        .lock()
        .unwrap_or_else(|e| panic!("Failed to lock peer map: {}", e))
        .entry(peer_address)
        .or_insert(new_peer);

    // Enter `peer_loop` to handle incoming peer messages/messages from main thread
    crate::peer_loop::peer_loop(
        peer,
        main_to_peer_thread_rx,
        peer_thread_to_main_tx,
        state,
        &peer_address,
    )
    .await?;

    Ok(())
}

async fn handle_miner_thread_message(
    msg: MinerToMain,
    main_to_peer_broadcast_tx: &broadcast::Sender<MainToPeerThread>,
    databases: &Arc<tokio::sync::Mutex<Databases>>,
) -> Result<()> {
    match msg {
        MinerToMain::NewBlock(block) => {
            // When receiving a block from the miner thread, we assume it is valid
            info!("Miner found new block: {}", block.height);
            main_to_peer_broadcast_tx
                .send(MainToPeerThread::BlockFromMiner(block.clone()))
                .expect(
                    "Peer handler broadcast channel prematurely closed. This should never happen.",
                );

            // Store block in database
            let block_hash_raw: [u8; 32] = block.hash.into();
            let latest_block_info = LatestBlockInfo::new(block.hash, block.height);
            {
                let db = databases.lock().await;
                db.block_hash_to_block.put(
                    WriteOptions::new(),
                    block.hash,
                    &bincode::serialize(&block).expect("Failed to serialize block"),
                )?;
                db.block_height_to_hash
                    .put(WriteOptions::new(), block.height, &block_hash_raw)?;
                db.latest_block.put(
                    WriteOptions::new(),
                    DatabaseUnit(),
                    &bincode::serialize(&latest_block_info).expect("Failed to serialize block"),
                )?;
            }
        }
    }

    Ok(())
}

async fn handle_peer_thread_message(
    msg: PeerThreadToMain,
    mine: bool,
    main_to_miner_tx: &watch::Sender<MainToMiner>,
    databases: &Arc<tokio::sync::Mutex<Databases>>,
    main_to_peer_broadcast_tx: &broadcast::Sender<MainToPeerThread>,
) -> Result<()> {
    info!("Received message sent to main thread.");
    match msg {
        PeerThreadToMain::NewBlock(block) => {
            // When receiving a block from a peer thread, we assume it is verified.
            // It is the peer thread's responsibility to verify the block.
            if mine {
                main_to_miner_tx.send(MainToMiner::NewBlock(block.clone()))?;
            }

            // Store block in database
            let block_hash_raw: [u8; 32] = block.hash.into();
            let latest_block_info = LatestBlockInfo::new(block.hash, block.height);
            {
                let db = databases.lock().await;
                db.block_hash_to_block.put(
                    WriteOptions::new(),
                    block.hash,
                    &bincode::serialize(&block).expect("Failed to serialize block"),
                )?;
                db.block_height_to_hash
                    .put(WriteOptions::new(), block.height, &block_hash_raw)?;
                db.latest_block.put(
                    WriteOptions::new(),
                    DatabaseUnit(),
                    &bincode::serialize(&latest_block_info).expect("Failed to serialize block"),
                )?;
                debug!("Storing block {:?} in database", block_hash_raw);
            }

            main_to_peer_broadcast_tx
                .send(MainToPeerThread::Block(block))
                .expect("Peer handler broadcast was closed. This should never happen");
        }
        PeerThreadToMain::NewTransaction(_txs) => {
            error!("Unimplemented txs msg received");
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn main_loop(
    listener: TcpListener,
    peer_map: Arc<std::sync::Mutex<HashMap<SocketAddr, Peer, RandomState>>>,
    databases: Arc<tokio::sync::Mutex<Databases>>,
    main_to_peer_broadcast_tx: broadcast::Sender<MainToPeerThread>,
    peer_thread_to_main_tx: mpsc::Sender<PeerThreadToMain>,
    mut peer_thread_to_main_rx: mpsc::Receiver<PeerThreadToMain>,
    own_handshake_data: HandshakeData,
    mut miner_to_main_rx: mpsc::Receiver<MinerToMain>,
    mine: bool,
    main_to_miner_tx: watch::Sender<MainToMiner>,
) -> Result<()> {
    // Handle incoming connections, messages from peer threads, and messages from the mining thread
    loop {
        select! {
            // The second item contains the IP and port of the new connection.
            Ok((stream, _)) = listener.accept() => {
                let peer_map_thread = Arc::clone(&peer_map);
                let databases_thread = Arc::clone(&databases);
                let state = State {
                    peer_map: peer_map_thread,
                    databases: databases_thread,
                };
                let main_to_peer_broadcast_rx_clone: broadcast::Receiver<MainToPeerThread> = main_to_peer_broadcast_tx.subscribe();
                let peer_thread_to_main_tx_clone: mpsc::Sender<PeerThreadToMain> = peer_thread_to_main_tx.clone();
                let peer_address = stream.peer_addr().unwrap();
                let own_handshake_data_clone = own_handshake_data.clone();
                tokio::spawn(async move {
                    match answer_peer(stream, state, peer_address, main_to_peer_broadcast_rx_clone, peer_thread_to_main_tx_clone, own_handshake_data_clone).await {
                        Ok(()) => (),
                        Err(err) => error!("Got error: {:?}", err),
                    }
                });
            }
            Some(msg) = peer_thread_to_main_rx.recv() => {
                info!("Received message sent to main thread.");
                handle_peer_thread_message(msg, mine, &main_to_miner_tx, &databases, &main_to_peer_broadcast_tx).await?
            }
            Some(main_message) = miner_to_main_rx.recv() => {
                handle_miner_thread_message(main_message, &main_to_peer_broadcast_tx, &databases).await?
            }
            // TODO: Add signal::ctrl_c/shutdown handling here
        }
    }
}
