use crate::models::peer::{
    ConnectionRefusedReason, ConnectionStatus, PeerInfo, PeerStanding, PeerState,
};
use crate::models::state::State;
use anyhow::{bail, Result};
use futures::sink::SinkExt;
use futures::stream::TryStreamExt;
use std::net::SocketAddr;
use std::time::SystemTime;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::select;
use tokio::sync::{broadcast, mpsc, watch};
use tokio_serde::formats::*;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::{debug, error, info, instrument, warn};

use crate::models::channel::{MainToMiner, MainToPeerThread, MinerToMain, PeerThreadToMain};
use crate::models::peer::{HandshakeData, PeerMessage};

pub async fn get_connection_status(
    max_peers: u16,
    state: &State,
    own_handshake: &HandshakeData,
    other_handshake: &HandshakeData,
    peer_address: &SocketAddr,
) -> ConnectionStatus {
    // Disallow connection if peer is banned via CLI arguments
    if state.cli_args.ban.contains(&peer_address.ip()) {
        warn!(
            "Banned peer {} attempted to connect. Disallowing.",
            peer_address.ip()
        );
        return ConnectionStatus::Refused(ConnectionRefusedReason::BadStanding);
    }

    // Disallow connection if peer is in bad standing
    let standing = state
        .get_peer_standing_from_database(peer_address.ip())
        .await;
    if standing.is_some() && standing.unwrap().standing > state.cli_args.peer_tolerance {
        return ConnectionStatus::Refused(ConnectionRefusedReason::BadStanding);
    }

    let pm = state.peer_map.lock().unwrap();

    // Disallow connection if max number of peers has been attained
    if (max_peers as usize) <= pm.len() {
        return ConnectionStatus::Refused(ConnectionRefusedReason::MaxPeerNumberExceeded);
    }

    // Disallow connection to already connected peer
    if pm
        .values()
        .any(|peer| peer.instance_id == other_handshake.instance_id)
    {
        return ConnectionStatus::Refused(ConnectionRefusedReason::AlreadyConnected);
    }

    // Disallow connection to self
    if own_handshake.instance_id == other_handshake.instance_id {
        return ConnectionStatus::Refused(ConnectionRefusedReason::SelfConnect);
    }

    info!("ConnectionStatus::Accepted");
    ConnectionStatus::Accepted
}

#[instrument]
pub async fn answer_peer<S>(
    stream: S,
    state: State,
    peer_address: std::net::SocketAddr,
    main_to_peer_thread_rx: broadcast::Receiver<MainToPeerThread>,
    peer_thread_to_main_tx: mpsc::Sender<PeerThreadToMain>,
    own_handshake_data: HandshakeData,
    max_peers: u16,
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

            // Check if connection is allowed
            let connection_status =
                get_connection_status(max_peers, &state, &own_handshake_data, &hsd, &peer_address)
                    .await;

            peer.send(PeerMessage::ConnectionStatus(connection_status))
                .await?;
            if let ConnectionStatus::Refused(refused_reason) = connection_status {
                warn!("Connection refused: {:?}", refused_reason);
                bail!("Refusing incoming connection. Reason: {:?}", refused_reason);
            }

            debug!("Got correct magic value request!");
            hsd
        }
        v => {
            bail!("Expected magic value, got {:?}", v);
        }
    };

    // Whether the incoming connection comes from a peer in bad standing is checked in `get_connection_status`
    info!("Connection accepted from {}", peer_address);
    let standing: PeerStanding = match state
        .get_peer_standing_from_database(peer_address.ip())
        .await
    {
        Some(stnd) => stnd,
        None => PeerStanding::default(),
    };
    let new_peer = PeerInfo {
        address: peer_address,
        standing,
        inbound: true,
        instance_id: peer_handshake_data.instance_id,
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
        &mut PeerState::default(),
    )
    .await?;

    Ok(())
}

async fn handle_miner_thread_message(
    msg: MinerToMain,
    main_to_peer_broadcast_tx: &broadcast::Sender<MainToPeerThread>,
    state: State,
) -> Result<()> {
    match msg {
        MinerToMain::NewBlock(block) => {
            // When receiving a block from the miner thread, we assume it is valid
            // and we assume it is the longest chain even though we could have received
            // a block from a peer thread before this event is triggered.
            // info!("Miner found new block: {}", block.height);
            info!("Miner found new block: {}", block.header.height);
            main_to_peer_broadcast_tx
                .send(MainToPeerThread::BlockFromMiner(block.clone()))
                .expect(
                    "Peer handler broadcast channel prematurely closed. This should never happen.",
                );

            // Store block in database
            state.update_latest_block(block).await?;
        }
    }

    Ok(())
}

async fn handle_peer_thread_message(
    msg: PeerThreadToMain,
    mine: bool,
    main_to_miner_tx: &watch::Sender<MainToMiner>,
    state: State,
    main_to_peer_broadcast_tx: &broadcast::Sender<MainToPeerThread>,
) -> Result<()> {
    debug!("Received message sent to main thread.");
    match msg {
        PeerThreadToMain::NewBlocks(blocks) => {
            let last_block = blocks.last().unwrap().to_owned();
            {
                let mut databases = state.block_databases.lock().await;
                let mut block_header = state
                    .latest_block_header
                    .lock()
                    .expect("Lock on block header must succeed");

                // The peer threads also check this condition, if block is more canonical than current
                // tip, but we have to check it again since the block update might have already been applied
                // through a message from another peer.
                let block_is_new =
                    block_header.proof_of_work_family < last_block.header.proof_of_work_family;
                if !block_is_new {
                    return Ok(());
                }

                // When receiving a block from a peer thread, we assume it is verified.
                // It is the peer thread's responsibility to verify the block.
                if mine {
                    main_to_miner_tx.send(MainToMiner::NewBlock(Box::new(last_block.clone())))?;
                }

                // Store block in database
                for block in blocks {
                    debug!("Storing block {:?} in database", block.hash);
                    state.update_latest_block_with_block_header_mutexguard(
                        Box::new(block),
                        &mut databases,
                        &mut block_header,
                    )?;
                }
            }

            main_to_peer_broadcast_tx
                .send(MainToPeerThread::Block(Box::new(last_block)))
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
    state: State,
    main_to_peer_broadcast_tx: broadcast::Sender<MainToPeerThread>,
    peer_thread_to_main_tx: mpsc::Sender<PeerThreadToMain>,
    mut peer_thread_to_main_rx: mpsc::Receiver<PeerThreadToMain>,
    own_handshake_data: HandshakeData,
    mut miner_to_main_rx: mpsc::Receiver<MinerToMain>,
    main_to_miner_tx: watch::Sender<MainToMiner>,
) -> Result<()> {
    // Handle incoming connections, messages from peer threads, and messages from the mining thread
    loop {
        select! {
            // The second item contains the IP and port of the new connection.
            Ok((stream, _)) = listener.accept() => {

                // Handle incoming connections from peer
                let state = state.clone();
                let main_to_peer_broadcast_rx_clone: broadcast::Receiver<MainToPeerThread> = main_to_peer_broadcast_tx.subscribe();
                let peer_thread_to_main_tx_clone: mpsc::Sender<PeerThreadToMain> = peer_thread_to_main_tx.clone();
                let peer_address = stream.peer_addr().unwrap();
                let own_handshake_data_clone = own_handshake_data.clone();
                let max_peers = state.cli_args.max_peers;
                tokio::spawn(async move {
                    match answer_peer(
                        stream,
                        state,
                        peer_address,
                        main_to_peer_broadcast_rx_clone,
                        peer_thread_to_main_tx_clone,
                        own_handshake_data_clone,
                        max_peers
                    ).await {
                        Ok(()) => (),
                        Err(err) => error!("Got error: {:?}", err),
                    }
                });

            }

            // Handle messages from main thread
            Some(msg) = peer_thread_to_main_rx.recv() => {
                info!("Received message sent to main thread.");
                handle_peer_thread_message(msg, state.cli_args.mine, &main_to_miner_tx, state.clone(), &main_to_peer_broadcast_tx).await?
            }

            // Handle messages from miner thread
            Some(main_message) = miner_to_main_rx.recv() => {
                handle_miner_thread_message(main_message, &main_to_peer_broadcast_tx, state.clone()).await?
            }
            // TODO: Add signal::ctrl_c/shutdown handling here
        }
    }
}
