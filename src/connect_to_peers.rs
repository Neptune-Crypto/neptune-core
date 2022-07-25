use anyhow::{bail, Result};
use futures::{SinkExt, TryStreamExt};
use std::{fmt::Debug, net::SocketAddr};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{broadcast, mpsc},
};
use tokio_serde::{
    formats::{Bincode, SymmetricalBincode},
    SymmetricallyFramed,
};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::{debug, error, info, instrument, warn};

use crate::{
    models::{
        channel::{MainToPeerThread, PeerThreadToMain},
        peer::{ConnectionRefusedReason, ConnectionStatus, HandshakeData, PeerMessage},
        state::State,
    },
    peer_loop::peer_loop_wrapper,
    MAGIC_STRING_REQUEST, MAGIC_STRING_RESPONSE,
};

async fn get_connection_status(
    max_peers: u16,
    state: &State,
    own_handshake: &HandshakeData,
    other_handshake: &HandshakeData,
    peer_address: &SocketAddr,
) -> ConnectionStatus {
    // Disallow connection if peer is banned via CLI arguments
    if state.cli.ban.contains(&peer_address.ip()) {
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
    if standing.is_some() && standing.unwrap().standing > state.cli.peer_tolerance {
        return ConnectionStatus::Refused(ConnectionRefusedReason::BadStanding);
    }

    let pm = state.net.peer_map.lock().unwrap();

    // Disallow connection if max number of &peers has been attained
    if (max_peers as usize) <= pm.len() {
        return ConnectionStatus::Refused(ConnectionRefusedReason::MaxPeerNumberExceeded);
    }

    // Disallow connection to already connected peer
    if pm.values().any(|peer| {
        peer.instance_id == other_handshake.instance_id
            || other_handshake.listen_address == peer.address_for_incoming_connections
    }) {
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
        true,
        1, // All incoming connections have distance 1
    )
    .await?;

    Ok(())
}

#[instrument]
pub async fn call_peer_wrapper(
    peer_address: std::net::SocketAddr,
    state: State,
    main_to_peer_thread_rx: broadcast::Receiver<MainToPeerThread>,
    peer_thread_to_main_tx: mpsc::Sender<PeerThreadToMain>,
    own_handshake_data: &HandshakeData,
    distance: u8,
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
                distance,
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
async fn call_peer<S>(
    stream: S,
    state: State,
    peer_address: std::net::SocketAddr,
    main_to_peer_thread_rx: broadcast::Receiver<MainToPeerThread>,
    peer_thread_to_main_tx: mpsc::Sender<PeerThreadToMain>,
    own_handshake_data: &HandshakeData,
    distance: u8,
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

    peer_loop_wrapper(
        peer,
        main_to_peer_thread_rx,
        peer_thread_to_main_tx,
        state,
        peer_address,
        peer_handshake_data,
        false,
        distance,
    )
    .await?;

    Ok(())
}

#[cfg(test)]
mod connect_tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    use anyhow::{bail, Result};
    use tokio_test::io::Builder;
    use tracing_test::traced_test;

    use crate::{
        config_models::network::Network,
        models::{
            blockchain::digest::Digest,
            peer::{ConnectionStatus, PeerMessage, PeerSanctionReason, PeerStanding},
        },
        tests::shared::{
            get_dummy_address, get_dummy_handshake_data, get_dummy_latest_block, get_genesis_setup,
            to_bytes,
        },
        MAGIC_STRING_REQUEST, MAGIC_STRING_RESPONSE,
    };

    #[traced_test]
    #[tokio::test]
    async fn test_outgoing_connection_succeed() -> Result<()> {
        let network = Network::Main;
        let other_handshake = get_dummy_handshake_data(network);
        let own_handshake = get_dummy_handshake_data(network);
        let mock = Builder::new()
            .write(&to_bytes(&PeerMessage::Handshake((
                MAGIC_STRING_REQUEST.to_vec(),
                own_handshake.clone(),
            )))?)
            .read(&to_bytes(&PeerMessage::Handshake((
                MAGIC_STRING_RESPONSE.to_vec(),
                other_handshake,
            )))?)
            .read(&to_bytes(&PeerMessage::ConnectionStatus(
                ConnectionStatus::Accepted,
            ))?)
            .read(&to_bytes(&PeerMessage::Bye)?)
            .build();

        let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, _to_main_rx1, state, _hsd) =
            get_genesis_setup(Network::Main, 0)?;
        call_peer(
            mock,
            state.clone(),
            get_dummy_address(),
            from_main_rx_clone,
            to_main_tx,
            &own_handshake,
            1,
        )
        .await?;

        // Verify that peer map is empty after connection has been closed
        match state.net.peer_map.lock().unwrap().keys().len() {
            0 => (),
            _ => bail!("Incorrect number of maps in peer map"),
        };

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn test_get_connection_status() -> Result<()> {
        let network = Network::Main;
        let (_peer_broadcast_tx, _from_main_rx_clone, _to_main_tx, _to_main_rx1, state, _hsd) =
            get_genesis_setup(network, 1)?;
        let peer = state
            .net
            .peer_map
            .lock()
            .unwrap()
            .values()
            .collect::<Vec<_>>()[0]
            .clone();
        let peer_id = peer.instance_id;

        let own_handshake = get_dummy_handshake_data(network);
        let mut other_handshake = get_dummy_handshake_data(network);

        let mut status = get_connection_status(
            4,
            &state,
            &own_handshake,
            &other_handshake,
            &peer.connected_address,
        )
        .await;
        if status != ConnectionStatus::Accepted {
            bail!("Must return ConnectionStatus::Accepted");
        }

        status = get_connection_status(
            4,
            &state,
            &own_handshake,
            &own_handshake,
            &peer.connected_address,
        )
        .await;
        if status != ConnectionStatus::Refused(ConnectionRefusedReason::SelfConnect) {
            bail!("Must return ConnectionStatus::Refused(ConnectionRefusedReason::SelfConnect))");
        }

        status = get_connection_status(
            1,
            &state,
            &own_handshake,
            &other_handshake,
            &peer.connected_address,
        )
        .await;
        if status != ConnectionStatus::Refused(ConnectionRefusedReason::MaxPeerNumberExceeded) {
            bail!(
            "Must return ConnectionStatus::Refused(ConnectionRefusedReason::MaxPeerNumberExceeded))"
        );
        }

        // Attempt to connect to already connected peer
        other_handshake.instance_id = peer_id;
        status = get_connection_status(
            100,
            &state,
            &own_handshake,
            &other_handshake,
            &peer.connected_address,
        )
        .await;
        if status != ConnectionStatus::Refused(ConnectionRefusedReason::AlreadyConnected) {
            bail!(
                "Must return ConnectionStatus::Refused(ConnectionRefusedReason::AlreadyConnected))"
            );
        }

        Ok(())
    }

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
        let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, _to_main_rx1, state, _hsd) =
            get_genesis_setup(network, 0)?;
        answer_peer(
            mock,
            state.clone(),
            get_dummy_address(),
            from_main_rx_clone,
            to_main_tx,
            own_handshake,
            8,
        )
        .await?;

        // Verify that peer map is empty after connection has been closed
        match state.net.peer_map.lock().unwrap().keys().len() {
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

        let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, _to_main_rx1, state, _hsd) =
            get_genesis_setup(network, 0)?;
        if let Err(_) = answer_peer(
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

        let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, _to_main_rx1, state, _hsd) =
            get_genesis_setup(Network::Main, 0)?;
        if let Err(_) = answer_peer(
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

        let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, _to_main_rx1, state, _hsd) =
            get_genesis_setup(Network::Main, 2)?;
        let (_, _, _latest_block_header) = get_dummy_latest_block(None);

        if let Err(_) = answer_peer(
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

        let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, _to_main_rx1, state, _hsd) =
            get_genesis_setup(Network::Main, 0)?;
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

        if let Err(_) = answer_peer(
            mock,
            state.clone(),
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
        match state.net.peer_map.lock().unwrap().keys().len() {
            0 => (),
            _ => bail!("Incorrect number of maps in peer map"),
        };

        Ok(())
    }
}
