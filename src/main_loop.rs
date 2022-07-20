use crate::models::peer::{
    ConnectionRefusedReason, ConnectionStatus, PeerInfo, PeerStanding, PeerState,
};
use crate::models::state::State;
use crate::peer_loop::peer_loop_wrapper;
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
    peer_loop_wrapper(
        peer,
        main_to_peer_thread_rx,
        peer_thread_to_main_tx,
        state,
        peer_address,
        peer_handshake_data,
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

            // Handle messages from peer threads
            Some(msg) = peer_thread_to_main_rx.recv() => {
                info!("Received message sent to main thread.");
                handle_peer_thread_message(msg, state.cli_args.mine, &main_to_miner_tx, state.clone(), &main_to_peer_broadcast_tx).await?
            }

            // Handle messages from miner thread
            Some(main_message) = miner_to_main_rx.recv() => {
                handle_miner_thread_message(main_message, &main_to_peer_broadcast_tx, state.clone()).await?
            }

            // TODO: Add timer to request peer information from connected peers iff
            // we are currently connected to less than `max_peers`. This should be mesage-based to/from
            // peer thread and main thread.
            // TODO: Add signal::ctrl_c/shutdown handling here
        }
    }
}

#[cfg(test)]
mod main_loop_tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use anyhow::{bail, Result};
    use tokio_test::io::Builder;
    use tracing_test::traced_test;

    use crate::{
        config_models::network::Network,
        main_loop,
        models::{
            blockchain::digest::Digest,
            peer::{
                ConnectionRefusedReason, ConnectionStatus, PeerMessage, PeerSanctionReason,
                PeerStanding,
            },
        },
        tests::shared::{
            get_dummy_address, get_dummy_handshake_data, get_dummy_latest_block, get_genesis_setup,
            to_bytes,
        },
        MAGIC_STRING_REQUEST, MAGIC_STRING_RESPONSE,
    };

    #[traced_test]
    #[tokio::test]
    async fn test_incoming_connection_succeed() -> Result<()> {
        // This builds a mock object which expects to have a certain
        // sequence of methods called on it: First it expects to have
        // the `MAGIC_STRING_REQUEST` and then the `MAGIC_STRING_RESPONSE`
        // value written. This is followed by a read of the bye message,
        // as this is a way to close the connection by the peer initiating
        // the connection. If this sequence is not followed, the `mock`
        // object will panic, and the `await` operator will evaluate
        // to Error.
        let network = Network::Main;
        let other_handshake = get_dummy_handshake_data(network);
        let own_handshake = get_dummy_handshake_data(network);
        let mock = Builder::new()
            .read(&to_bytes(&PeerMessage::Handshake((
                MAGIC_STRING_REQUEST.to_vec(),
                other_handshake,
            )))?)
            .write(&to_bytes(&PeerMessage::Handshake((
                MAGIC_STRING_RESPONSE.to_vec(),
                own_handshake.clone(),
            )))?)
            .write(&to_bytes(&PeerMessage::ConnectionStatus(
                ConnectionStatus::Accepted,
            ))?)
            .read(&to_bytes(&PeerMessage::Bye)?)
            .build();
        let (
            _peer_broadcast_tx,
            from_main_rx_clone,
            to_main_tx,
            _to_main_rx1,
            state,
            peer_map,
            hsd,
        ) = get_genesis_setup(network, 0)?;
        main_loop::answer_peer(
            mock,
            state,
            get_dummy_address(),
            from_main_rx_clone,
            to_main_tx,
            own_handshake,
            8,
        )
        .await?;

        // Verify that peer map is empty after connection has been closed
        match peer_map.lock().unwrap().keys().len() {
            0 => (),
            _ => bail!("Incorrect number of maps in peer map"),
        };

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn test_incoming_connection_fail_bad_magic_value() -> Result<()> {
        let network = Network::Main;
        let other_handshake = get_dummy_handshake_data(network);
        let own_handshake = get_dummy_handshake_data(network);
        let mock = Builder::new()
            .read(&to_bytes(&PeerMessage::Handshake((
                MAGIC_STRING_RESPONSE.to_vec(),
                other_handshake,
            )))?)
            .build();

        let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, _to_main_rx1, state, _, _hsd) =
            get_genesis_setup(network, 0)?;
        if let Err(_) = main_loop::answer_peer(
            mock,
            state,
            get_dummy_address(),
            from_main_rx_clone,
            to_main_tx,
            own_handshake,
            8,
        )
        .await
        {
            Ok(())
        } else {
            bail!("Expected error from run")
        }
    }

    #[traced_test]
    #[tokio::test]
    async fn test_incoming_connection_fail_bad_network() -> Result<()> {
        let other_handshake = get_dummy_handshake_data(Network::Testnet);
        let own_handshake = get_dummy_handshake_data(Network::Main);
        let mock = Builder::new()
            .read(&to_bytes(&PeerMessage::Handshake((
                MAGIC_STRING_REQUEST.to_vec(),
                other_handshake,
            )))?)
            .write(&to_bytes(&PeerMessage::Handshake((
                MAGIC_STRING_RESPONSE.to_vec(),
                own_handshake.clone(),
            )))?)
            .build();

        let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, _to_main_rx1, state, _, _hsd) =
            get_genesis_setup(Network::Main, 0)?;
        if let Err(_) = main_loop::answer_peer(
            mock,
            state,
            get_dummy_address(),
            from_main_rx_clone,
            to_main_tx,
            own_handshake,
            8,
        )
        .await
        {
            Ok(())
        } else {
            bail!("Expected error from run")
        }
    }

    #[traced_test]
    #[tokio::test]
    async fn test_incoming_connection_fail_max_peers_exceeded() -> Result<()> {
        let network = Network::Main;
        let other_handshake = get_dummy_handshake_data(network);
        let own_handshake = get_dummy_handshake_data(network);
        let mock = Builder::new()
            .read(&to_bytes(&PeerMessage::Handshake((
                MAGIC_STRING_REQUEST.to_vec(),
                other_handshake,
            )))?)
            .write(&to_bytes(&PeerMessage::Handshake((
                MAGIC_STRING_RESPONSE.to_vec(),
                own_handshake.clone(),
            )))?)
            .build();

        let (
            _peer_broadcast_tx,
            from_main_rx_clone,
            to_main_tx,
            _to_main_rx1,
            state,
            _peer_map,
            _hsd,
        ) = get_genesis_setup(Network::Main, 2)?;
        let (_, _, _latest_block_header) = get_dummy_latest_block(None);

        if let Err(_) = main_loop::answer_peer(
            mock,
            state,
            get_dummy_address(),
            from_main_rx_clone,
            to_main_tx,
            own_handshake,
            2,
        )
        .await
        {
            Ok(())
        } else {
            bail!("Expected error from run")
        }
    }

    #[traced_test]
    #[tokio::test]
    async fn disallow_ingoing_connections_from_banned_peers_test() -> Result<()> {
        // In this scenario a peer has been banned, and is attempting to make an ingoing
        // connection. This should not be possible.
        let network = Network::Main;
        let other_handshake = get_dummy_handshake_data(network);
        let own_handshake = get_dummy_handshake_data(network);
        let mock = Builder::new()
            .read(&to_bytes(&PeerMessage::Handshake((
                MAGIC_STRING_REQUEST.to_vec(),
                other_handshake,
            )))?)
            .write(&to_bytes(&PeerMessage::Handshake((
                MAGIC_STRING_RESPONSE.to_vec(),
                own_handshake.clone(),
            )))?)
            .write(&to_bytes(&PeerMessage::ConnectionStatus(
                ConnectionStatus::Refused(ConnectionRefusedReason::BadStanding),
            ))?)
            .build();

        let (
            _peer_broadcast_tx,
            from_main_rx_clone,
            to_main_tx,
            _to_main_rx1,
            state,
            peer_map,
            _hsd,
        ) = get_genesis_setup(Network::Main, 0)?;
        let bad_standing: PeerStanding = PeerStanding {
            standing: u16::MAX,
            latest_sanction: Some(PeerSanctionReason::InvalidBlock((
                7u64.into(),
                Digest::default(),
            ))),
            timestamp_of_latest_sanction: Some(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Failed to generate timestamp for peer standing")
                    .as_secs(),
            ),
        };
        let peer_address = get_dummy_address();
        state
            .write_peer_standing_on_increase(peer_address.ip(), bad_standing)
            .await;

        if let Err(_) = main_loop::answer_peer(
            mock,
            state,
            peer_address,
            from_main_rx_clone,
            to_main_tx,
            own_handshake,
            42,
        )
        .await
        {
        } else {
            bail!("Expected error from run")
        }

        // Verify that peer map is empty after connection has been refused
        match peer_map.lock().unwrap().keys().len() {
            0 => (),
            _ => bail!("Incorrect number of maps in peer map"),
        };

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn test_get_connection_status() -> Result<()> {
        let network = Network::Main;
        let (
            _peer_broadcast_tx,
            _from_main_rx_clone,
            _to_main_tx,
            _to_main_rx1,
            state,
            peer_map,
            _hsd,
        ) = get_genesis_setup(network, 1)?;
        let peer = peer_map.lock().unwrap().values().collect::<Vec<_>>()[0].clone();
        let peer_id = peer.instance_id;

        let own_handshake = get_dummy_handshake_data(network);
        let mut other_handshake = get_dummy_handshake_data(network);

        let mut status = main_loop::get_connection_status(
            4,
            &state,
            &own_handshake,
            &other_handshake,
            &peer.address,
        )
        .await;
        if status != ConnectionStatus::Accepted {
            bail!("Must return ConnectionStatus::Accepted");
        }

        status = main_loop::get_connection_status(
            4,
            &state,
            &own_handshake,
            &own_handshake,
            &peer.address,
        )
        .await;
        if status != ConnectionStatus::Refused(ConnectionRefusedReason::SelfConnect) {
            bail!("Must return ConnectionStatus::Refused(ConnectionRefusedReason::SelfConnect))");
        }

        status = main_loop::get_connection_status(
            1,
            &state,
            &own_handshake,
            &other_handshake,
            &peer.address,
        )
        .await;
        if status != ConnectionStatus::Refused(ConnectionRefusedReason::MaxPeerNumberExceeded) {
            bail!(
            "Must return ConnectionStatus::Refused(ConnectionRefusedReason::MaxPeerNumberExceeded))"
        );
        }

        // Attempt to connect to already connected peer
        other_handshake.instance_id = peer_id;
        status = main_loop::get_connection_status(
            100,
            &state,
            &own_handshake,
            &other_handshake,
            &peer.address,
        )
        .await;
        if status != ConnectionStatus::Refused(ConnectionRefusedReason::AlreadyConnected) {
            bail!(
                "Must return ConnectionStatus::Refused(ConnectionRefusedReason::AlreadyConnected))"
            );
        }

        Ok(())
    }
}
