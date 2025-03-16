use std::fmt::Debug;
use std::net::SocketAddr;
use std::time::SystemTime;

use anyhow::bail;
use anyhow::Result;
use futures::FutureExt;
use futures::SinkExt;
use futures::TryStreamExt;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio_serde::formats::Bincode;
use tokio_serde::formats::SymmetricalBincode;
use tokio_serde::SymmetricallyFramed;
use tokio_util::codec::Framed;
use tokio_util::codec::LengthDelimitedCodec;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::models::channel::MainToPeerTask;
use crate::models::channel::PeerTaskToMain;
use crate::models::peer::ConnectionRefusedReason;
use crate::models::peer::InternalConnectionStatus;
use crate::models::peer::NegativePeerSanction;
use crate::models::peer::PeerMessage;
use crate::models::peer::PeerSanction;
use crate::models::peer::PeerStanding;
use crate::models::peer::TransferConnectionStatus;
use crate::models::state::GlobalStateLock;
use crate::peer_loop::PeerLoopHandler;
use crate::HandshakeData;
use crate::MAGIC_STRING_REQUEST;
use crate::MAGIC_STRING_RESPONSE;

// Max peer message size is 500MB. Should be enough to send 250 blocks in a
// block batch-response.
pub const MAX_PEER_FRAME_LENGTH_IN_BYTES: usize = 500 * 1024 * 1024;

/// Use this function to ensure that the same rules apply for both
/// ingoing and outgoing connections. This limits the size of messages
/// peers can send.
fn get_codec_rules() -> LengthDelimitedCodec {
    let mut codec_rules = LengthDelimitedCodec::new();
    codec_rules.set_max_frame_length(MAX_PEER_FRAME_LENGTH_IN_BYTES);
    codec_rules
}

/// Returns true iff version numbers are compatible. Returns false otherwise.
///
/// # Panics
///
/// panics if own version could not be parsed.
fn versions_are_compatible(own_version: &str, other_version: &str) -> bool {
    let own_version = semver::Version::parse(own_version)
        .unwrap_or_else(|_| panic!("Must be able to parse own version string. Got: {own_version}"));
    let other_version = match semver::Version::parse(other_version) {
        Ok(version) => version,
        Err(err) => {
            warn!("Peer version is not a valid semver version. Got error: {err}",);
            return false;
        }
    };

    // All alphanet and betanet versions are incompatible with each other.
    // Alpha and betanet have versions "0.0.n". Alpha and betanet are
    // incompatible with all other versions.
    if own_version.major == 0 && own_version.minor == 0
        || other_version.major == 0 && other_version.minor == 0
    {
        return own_version == other_version;
    }

    true
}

/// Check if connection is allowed. Used for both ingoing and outgoing connections.
///
/// Locking:
///   * acquires `global_state_lock` for read
async fn check_if_connection_is_allowed(
    global_state_lock: GlobalStateLock,
    own_handshake: &HandshakeData,
    other_handshake: &HandshakeData,
    peer_address: &SocketAddr,
) -> InternalConnectionStatus {
    let cli_arguments = global_state_lock.cli();
    let global_state = global_state_lock.lock_guard().await;

    // Disallow connection if peer is banned via CLI arguments
    if cli_arguments.ban.contains(&peer_address.ip()) {
        let ip = peer_address.ip();
        warn!("Peer {ip}, banned via CLI argument, attempted to connect. Disallowing.");
        return InternalConnectionStatus::Refused(ConnectionRefusedReason::BadStanding);
    }

    // Disallow connection if peer is in bad standing
    let standing = global_state
        .net
        .get_peer_standing_from_database(peer_address.ip())
        .await;

    if standing.is_some_and(|standing| standing.is_bad()) {
        let ip = peer_address.ip();
        warn!("Peer {ip}, banned because of bad standing, attempted to connect. Disallowing.");
        return InternalConnectionStatus::Refused(ConnectionRefusedReason::BadStanding);
    }

    if let Some(time) = global_state
        .net
        .last_disconnection_time_of_peer(other_handshake.instance_id)
    {
        if SystemTime::now()
            .duration_since(time)
            .is_ok_and(|d| d < cli_arguments.reconnect_cooldown)
        {
            info!(
                "Refusing connection with {peer_address} \
                 due to reconnect cooldown ({cooldown} seconds).",
                cooldown = cli_arguments.reconnect_cooldown.as_secs(),
            );

            // A “wrong” reason is given because of backwards compatibility.
            // todo: Use next breaking release to give a more accurate reason here.
            let reason = ConnectionRefusedReason::MaxPeerNumberExceeded;
            return InternalConnectionStatus::Refused(reason);
        }
    }

    // Disallow connection if max number of peers has been reached or
    // exceeded. There is another test in `answer_peer_inner` that precedes
    // this one; however this test is still necessary to resolve potential
    // race conditions.
    // Note that if we are bootstrapping, then we *do* want to accept the
    // connection and temporarily exceed the maximum. In this case a
    // `DisconnectFromLongestLivedPeer` message should have been sent to
    // the main loop already but that message need not have been processed by
    // the time we get here.
    if cli_arguments.max_num_peers <= global_state.net.peer_map.len() && !cli_arguments.bootstrap {
        return InternalConnectionStatus::Refused(ConnectionRefusedReason::MaxPeerNumberExceeded);
    }

    // Disallow connection to already connected peer.
    if global_state.net.peer_map.values().any(|peer| {
        peer.instance_id() == other_handshake.instance_id
            || *peer_address == peer.connected_address()
    }) {
        return InternalConnectionStatus::Refused(ConnectionRefusedReason::AlreadyConnected);
    }

    // Cap connections per IP, if specified.
    if let Some(max_connections_per_ip) = cli_arguments.max_connections_per_ip {
        let peer_ip = peer_address.ip();
        let num_connections_to_this_ip = global_state
            .net
            .peer_map
            .keys()
            .map(|x| x.ip())
            .filter(|ip| *ip == peer_ip)
            .count();
        if num_connections_to_this_ip >= max_connections_per_ip {
            return InternalConnectionStatus::Refused(
                ConnectionRefusedReason::MaxPeerNumberExceeded,
            );
        }
    }

    // Disallow connection to self
    if own_handshake.instance_id == other_handshake.instance_id {
        return InternalConnectionStatus::Refused(ConnectionRefusedReason::SelfConnect);
    }

    // Disallow connection if versions are incompatible
    if !versions_are_compatible(&own_handshake.version, &other_handshake.version) {
        warn!(
            "Attempting to connect to incompatible version. You might have to upgrade, or the other node does. Own version: {}, other version: {}",
            own_handshake.version,
            other_handshake.version);
        return InternalConnectionStatus::Refused(ConnectionRefusedReason::IncompatibleVersion);
    }

    // If this connection touches the maximum number of peer connections, say
    // so with special OK code.
    if cli_arguments.max_num_peers == global_state.net.peer_map.len() + 1 {
        info!("ConnectionStatus::Accepted, but max # connections is now reached");
        return InternalConnectionStatus::AcceptedMaxReached;
    }

    info!("ConnectionStatus::Accepted");
    InternalConnectionStatus::Accepted
}

/// Respond to an incoming connection initiation.
///
/// Catch and process errors (if any) gracefully.
///
/// All incoming connections from peers must go through this function.
pub(crate) async fn answer_peer<S>(
    stream: S,
    state_lock: GlobalStateLock,
    peer_address: std::net::SocketAddr,
    main_to_peer_task_rx: broadcast::Receiver<MainToPeerTask>,
    peer_task_to_main_tx: mpsc::Sender<PeerTaskToMain>,
    own_handshake_data: HandshakeData,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + std::fmt::Debug + std::marker::Unpin,
{
    let state_lock_clone = state_lock.clone();
    let peer_task_to_main_tx_clone = peer_task_to_main_tx.clone();
    let mut inner_ret: anyhow::Result<()> = Ok(());

    let panic_result = std::panic::AssertUnwindSafe(async {
        inner_ret = answer_peer_inner(
            stream,
            state_lock_clone,
            peer_address,
            main_to_peer_task_rx,
            peer_task_to_main_tx,
            own_handshake_data,
        )
        .await;
    })
    .catch_unwind()
    .await;

    match panic_result {
        Ok(_) => (),
        Err(_err) => {
            error!("Peer task (incoming) for {peer_address} panicked. Invoking close connection callback");
            close_peer_connected_callback(
                state_lock.clone(),
                peer_address,
                &peer_task_to_main_tx_clone,
            )
            .await;
        }
    }

    inner_ret
}

async fn answer_peer_inner<S>(
    stream: S,
    state: GlobalStateLock,
    peer_address: SocketAddr,
    main_to_peer_task_rx: broadcast::Receiver<MainToPeerTask>,
    peer_task_to_main_tx: mpsc::Sender<PeerTaskToMain>,
    own_handshake_data: HandshakeData,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Debug + Unpin,
{
    info!("Established incoming TCP connection with {peer_address}");

    // Build the communication/serialization/frame handler
    let length_delimited = Framed::new(stream, get_codec_rules());
    let mut peer = SymmetricallyFramed::<
        Framed<S, LengthDelimitedCodec>,
        PeerMessage,
        Bincode<PeerMessage, PeerMessage>,
    >::new(length_delimited, SymmetricalBincode::default());

    // Complete Neptune handshake
    let Some(PeerMessage::Handshake(payload)) = peer.try_next().await? else {
        bail!("Didn't get handshake on connection attempt");
    };
    let (magic_string_request, peer_handshake_data) = *payload;
    if magic_string_request != MAGIC_STRING_REQUEST {
        bail!("Expected magic value, got {magic_string_request:?}");
    }

    let handshake_response = Box::new((MAGIC_STRING_RESPONSE.to_vec(), own_handshake_data.clone()));
    peer.send(PeerMessage::Handshake(handshake_response))
        .await?;

    // Verify peer network before moving on
    let peer_network = peer_handshake_data.network;
    let own_network = own_handshake_data.network;
    if peer_network != own_network {
        bail!(
            "Cannot connect with {peer_address}: \
            Peer runs {peer_network}, this client runs {own_network}."
        );
    }

    // Check if incoming connection is allowed
    let connection_status = check_if_connection_is_allowed(
        state.clone(),
        &own_handshake_data,
        &peer_handshake_data,
        &peer_address,
    )
    .await;
    peer.send(PeerMessage::ConnectionStatus(connection_status.into()))
        .await?;
    if let InternalConnectionStatus::Refused(reason) = connection_status {
        let reason = format!("Refusing incoming connection. Reason: {reason:?}");
        warn!("{reason}");
        bail!("{reason}");
    }

    // Whether the incoming connection comes from a peer in bad standing is
    // checked in `check_if_connection_is_allowed`. So if we get here, we are
    // good to go.
    info!("Connection accepted from {peer_address}");

    // If necessary, disconnect from another, existing peer.
    if connection_status == InternalConnectionStatus::AcceptedMaxReached && state.cli().bootstrap {
        info!("Maximum # peers reached, so disconnecting from an existing peer.");
        peer_task_to_main_tx
            .send(PeerTaskToMain::DisconnectFromLongestLivedPeer)
            .await?;
    }

    let peer_distance = 1; // All incoming connections have distance 1
    let mut peer_loop_handler = PeerLoopHandler::new(
        peer_task_to_main_tx,
        state,
        peer_address,
        peer_handshake_data,
        true,
        peer_distance,
    );

    peer_loop_handler
        .run_wrapper(peer, main_to_peer_task_rx)
        .await?;

    Ok(())
}

/// Perform handshake and establish connection to a new peer while handling any
/// panics in the peer task gracefully.
///
/// All outgoing connections to peers must go through this function.
pub(crate) async fn call_peer(
    peer_address: std::net::SocketAddr,
    state: GlobalStateLock,
    main_to_peer_task_rx: broadcast::Receiver<MainToPeerTask>,
    peer_task_to_main_tx: mpsc::Sender<PeerTaskToMain>,
    own_handshake_data: HandshakeData,
    peer_distance: u8,
) {
    let state_clone = state.clone();
    let peer_task_to_main_tx_clone = peer_task_to_main_tx.clone();
    let panic_result = std::panic::AssertUnwindSafe(async {
        debug!("Attempting to initiate connection to {peer_address}");
        match tokio::net::TcpStream::connect(peer_address).await {
            Err(e) => {
                let msg = format!("Failed to establish TCP connection to {peer_address}: {e}");
                if peer_distance == 1 {
                    // outgoing connection to peer of distance 1 means user has
                    // requested a connection to this peer through CLI
                    // arguments, and should be warned if this fails.
                    warn!("{msg}");
                } else {
                    info!("{msg}");
                }
            }
            Ok(stream) => {
                match call_peer_inner(
                    stream,
                    state,
                    peer_address,
                    main_to_peer_task_rx,
                    peer_task_to_main_tx,
                    &own_handshake_data,
                    peer_distance,
                )
                .await
                {
                    Ok(()) => (),
                    Err(e) => {
                        let msg = format!("{e}. Failed to establish connection.");
                        // outgoing connection to peer of distance 1 means user has
                        // requested a connection to this peer through CLI
                        // arguments, and should be warned if this fails.
                        if peer_distance == 1 {
                            warn!("{msg}");
                        } else {
                            info!("{msg}");
                        }
                    }
                }
            }
        };

        info!("Connection to {peer_address} closing");
    })
    .catch_unwind()
    .await;

    match panic_result {
        Ok(_) => (),
        Err(_) => {
            error!("Peer task (outgoing) for {peer_address} panicked. Invoking close connection callback");
            close_peer_connected_callback(state_clone, peer_address, &peer_task_to_main_tx_clone)
                .await;
        }
    }
}

async fn call_peer_inner<S>(
    stream: S,
    state: GlobalStateLock,
    peer_address: std::net::SocketAddr,
    main_to_peer_task_rx: broadcast::Receiver<MainToPeerTask>,
    peer_task_to_main_tx: mpsc::Sender<PeerTaskToMain>,
    own_handshake: &HandshakeData,
    peer_distance: u8,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Debug + Unpin,
{
    info!("Established outgoing TCP connection with {peer_address}");

    // Build the communication/serialization/frame handler
    let length_delimited = Framed::new(stream, get_codec_rules());
    let mut peer: tokio_serde::Framed<
        Framed<S, LengthDelimitedCodec>,
        PeerMessage,
        PeerMessage,
        Bincode<PeerMessage, PeerMessage>,
    > = SymmetricallyFramed::new(length_delimited, SymmetricalBincode::default());

    // Make Neptune handshake
    peer.send(PeerMessage::Handshake(Box::new((
        Vec::from(MAGIC_STRING_REQUEST),
        own_handshake.to_owned(),
    ))))
    .await?;
    debug!("Awaiting connection status response from {peer_address}");

    let Some(PeerMessage::Handshake(handshake_payload)) = peer.try_next().await? else {
        bail!("Didn't get handshake response from {peer_address}");
    };
    let (magic_string_response, other_handshake) = *handshake_payload;
    if magic_string_response != MAGIC_STRING_RESPONSE {
        bail!("Didn't get expected magic value for handshake from {peer_address}");
    }
    debug!("Got correct magic value response from {peer_address}!");
    if other_handshake.network != own_handshake.network {
        let other = other_handshake.network;
        let own = own_handshake.network;
        bail!("Cannot connect with {peer_address}: Peer runs {other}, this client runs {own}.");
    }

    match peer.try_next().await? {
        Some(PeerMessage::ConnectionStatus(TransferConnectionStatus::Accepted)) => {
            info!("Outgoing connection accepted by {peer_address}");
        }
        Some(PeerMessage::ConnectionStatus(TransferConnectionStatus::Refused(reason))) => {
            bail!("Outgoing connection attempt to {peer_address} refused. Reason: {reason:?}");
        }
        _ => {
            bail!(
                "Got invalid connection status response from {peer_address} on outgoing connection"
            );
        }
    }

    // Peer accepted us. Check if we accept the peer. Note that the protocol does not stipulate
    // that we answer with a connection status here, so if the connection is *not* accepted, we
    // simply hang up but log the reason for the refusal.
    let connection_status = check_if_connection_is_allowed(
        state.clone(),
        own_handshake,
        &other_handshake,
        &peer_address,
    )
    .await;
    if let InternalConnectionStatus::Refused(refused_reason) = connection_status {
        warn!(
            "Outgoing connection to {peer_address} refused. Reason: {:?}\nNow hanging up.",
            refused_reason
        );
        peer.send(PeerMessage::Bye).await?;
        bail!("Attempted to connect to peer ({peer_address}) that was not allowed. This connection attempt should not have been made.");
    }

    // By default, start by asking the peer for its peers. In an adversarial
    // context, we want the network topology to be as robust as possible.
    // Blockchain data can be obtained from other peers, if this connection
    // fails.
    peer.send(PeerMessage::PeerListRequest).await?;

    let mut peer_loop_handler = PeerLoopHandler::new(
        peer_task_to_main_tx,
        state,
        peer_address,
        other_handshake,
        false,
        peer_distance,
    );
    peer_loop_handler
        .run_wrapper(peer, main_to_peer_task_rx)
        .await?;

    Ok(())
}

/// Remove peer from state. This function must be called every time
/// a peer is disconnected. Whether this happens through a panic
/// in the peer task or through a regular disconnect.
///
/// Locking:
///   * acquires `global_state_lock` for write
pub(crate) async fn close_peer_connected_callback(
    mut global_state_lock: GlobalStateLock,
    peer_address: SocketAddr,
    to_main_tx: &mpsc::Sender<PeerTaskToMain>,
) {
    let cli_arguments = global_state_lock.cli().clone();
    let mut global_state_mut = global_state_lock.lock_guard_mut().await;

    // Store any new peer-standing to database
    let peer_info_writeback = global_state_mut.net.peer_map.remove(&peer_address);
    let new_standing = if let Some(new) = peer_info_writeback {
        new.standing()
    } else {
        error!("Could not find peer standing for {peer_address}");
        let mut standing = PeerStanding::new(cli_arguments.peer_tolerance);
        let sanction = NegativePeerSanction::NoStandingFoundMaybeCrash;

        // Don't return early: _must_ send message to main loop at the end of this
        // function.
        // If the peer has now reached bad standing, the connection to it should be
        // dropped, which is currently happening anyway.
        let _ = standing.sanction(PeerSanction::Negative(sanction));
        standing
    };
    debug!("Fetched peer info standing {new_standing} for peer {peer_address}");

    global_state_mut
        .net
        .write_peer_standing_on_decrease(peer_address.ip(), new_standing)
        .await;
    drop(global_state_mut); // avoid holding across mpsc::Sender::send()
    debug!("Stored peer info standing {new_standing} for peer {peer_address}");

    // This message is used to determine if we are to exit synchronization mode
    to_main_tx
        .send(PeerTaskToMain::RemovePeerMaxBlockHeight(peer_address))
        .await
        .expect("channel to main task should exist");
}

#[cfg(test)]
mod connect_tests {
    use std::str::FromStr;
    use std::time::Duration;
    use std::time::SystemTime;

    use anyhow::bail;
    use anyhow::Result;
    use tokio_test::io::Builder;
    use tracing_test::traced_test;
    use twenty_first::math::digest::Digest;

    use super::*;
    use crate::config_models::cli_args;
    use crate::config_models::network::Network;
    use crate::models::peer::handshake_data::VersionString;
    use crate::models::peer::peer_info::PeerInfo;
    use crate::models::peer::InternalConnectionStatus;
    use crate::models::peer::NegativePeerSanction;
    use crate::models::peer::PeerMessage;
    use crate::models::peer::PeerStanding;
    use crate::prelude::twenty_first;
    use crate::tests::shared::get_dummy_handshake_data_for_genesis;
    use crate::tests::shared::get_dummy_peer_connection_data_genesis;
    use crate::tests::shared::get_dummy_peer_incoming;
    use crate::tests::shared::get_dummy_socket_address;
    use crate::tests::shared::get_test_genesis_setup;
    use crate::tests::shared::to_bytes;
    use crate::MAGIC_STRING_REQUEST;
    use crate::MAGIC_STRING_RESPONSE;

    #[traced_test]
    #[tokio::test]
    async fn test_outgoing_connection_succeed() -> Result<()> {
        let network = Network::Alpha;
        let other_handshake = get_dummy_handshake_data_for_genesis(network);
        let own_handshake = get_dummy_handshake_data_for_genesis(network);
        let mock = Builder::new()
            .write(&to_bytes(&PeerMessage::Handshake(Box::new((
                MAGIC_STRING_REQUEST.to_vec(),
                own_handshake.clone(),
            ))))?)
            .read(&to_bytes(&PeerMessage::Handshake(Box::new((
                MAGIC_STRING_RESPONSE.to_vec(),
                other_handshake,
            ))))?)
            .read(&to_bytes(&PeerMessage::ConnectionStatus(
                TransferConnectionStatus::Accepted,
            ))?)
            .write(&to_bytes(&PeerMessage::PeerListRequest)?)
            .read(&to_bytes(&PeerMessage::Bye)?)
            .build();

        let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, _to_main_rx1, state, _hsd) =
            get_test_genesis_setup(Network::Alpha, 0, cli_args::Args::default()).await?;
        call_peer_inner(
            mock,
            state.clone(),
            get_dummy_socket_address(0),
            from_main_rx_clone,
            to_main_tx,
            &own_handshake,
            1,
        )
        .await?;

        // Verify that peer map is empty after connection has been closed
        match state.lock(|s| s.net.peer_map.keys().len()).await {
            0 => (),
            _ => bail!("Incorrect number of maps in peer map"),
        };

        Ok(())
    }

    #[test]
    fn malformed_version_from_peer_doesnt_crash() {
        let version_numbers = ["potato", "&&&&"];
        for b in version_numbers {
            assert!(!versions_are_compatible("0.1.0", b));
        }
    }

    #[test]
    fn versions_are_compatible_for_all_versions_above_0_1_0() {
        let version_numbers = [
            "0.1.0",
            "0.1.1",
            "0.1.99",
            "0.2.0",
            "1.2.0",
            "2.2.0",
            "3.2.0",
            "9999.99999.9999",
        ];
        for a in version_numbers {
            for b in version_numbers {
                assert!(versions_are_compatible(a, b));
            }
        }
    }

    #[traced_test]
    #[tokio::test]
    async fn test_get_connection_status() -> Result<()> {
        let network = Network::Alpha;
        let (
            _peer_broadcast_tx,
            _from_main_rx_clone,
            _to_main_tx,
            _to_main_rx1,
            mut state_lock,
            _hsd,
        ) = get_test_genesis_setup(network, 1, cli_args::Args::default()).await?;

        // Get an address for a peer that's not already connected
        let (other_handshake, peer_sa) = get_dummy_peer_connection_data_genesis(network, 1);
        let own_handshake = get_dummy_handshake_data_for_genesis(network);

        let mut status = check_if_connection_is_allowed(
            state_lock.clone(),
            &own_handshake,
            &other_handshake,
            &peer_sa,
        )
        .await;
        if status != InternalConnectionStatus::Accepted {
            bail!("Must return ConnectionStatus::Accepted");
        }

        status = check_if_connection_is_allowed(
            state_lock.clone(),
            &own_handshake,
            &own_handshake,
            &peer_sa,
        )
        .await;
        if status != InternalConnectionStatus::Refused(ConnectionRefusedReason::SelfConnect) {
            bail!("Must return ConnectionStatus::Refused(ConnectionRefusedReason::SelfConnect))");
        }

        // pretend --max_peers is 1.
        let mut cli = state_lock.cli().clone();
        cli.max_num_peers = 1;
        state_lock.set_cli(cli.clone()).await;

        status = check_if_connection_is_allowed(
            state_lock.clone(),
            &own_handshake,
            &other_handshake,
            &peer_sa,
        )
        .await;
        if status
            != InternalConnectionStatus::Refused(ConnectionRefusedReason::MaxPeerNumberExceeded)
        {
            bail!(
                "Must return ConnectionStatus::Refused(ConnectionRefusedReason::MaxPeerNumberExceeded))"
            );
        }

        // pretend --max-peers is 100
        cli.max_num_peers = 100;
        state_lock.set_cli(cli.clone()).await;

        // Attempt to connect to already connected peer
        let connected_peer: PeerInfo = state_lock
            .lock(|s| s.net.peer_map.values().collect::<Vec<_>>()[0].clone())
            .await;
        let mut mutated_other_handshake = other_handshake.clone();
        mutated_other_handshake.instance_id = connected_peer.instance_id();
        status = check_if_connection_is_allowed(
            state_lock.clone(),
            &own_handshake,
            &mutated_other_handshake,
            &peer_sa,
        )
        .await;
        if status != InternalConnectionStatus::Refused(ConnectionRefusedReason::AlreadyConnected) {
            bail!(
                "Must return ConnectionStatus::Refused(ConnectionRefusedReason::AlreadyConnected))"
            );
        }

        // pretend --ban <peer_sa>
        cli.ban.push(peer_sa.ip());
        state_lock.set_cli(cli.clone()).await;

        // Verify that banned peers are rejected by this check
        // First check that peers can be banned by command-line arguments
        status = check_if_connection_is_allowed(
            state_lock.clone(),
            &own_handshake,
            &other_handshake,
            &peer_sa,
        )
        .await;
        if status != InternalConnectionStatus::Refused(ConnectionRefusedReason::BadStanding) {
            bail!("Must return ConnectionStatus::Refused(ConnectionRefusedReason::BadStanding)) on CLI-ban");
        }

        // pretend --ban ""
        cli.ban.pop();
        state_lock.set_cli(cli.clone()).await;

        status = check_if_connection_is_allowed(
            state_lock.clone(),
            &own_handshake,
            &other_handshake,
            &peer_sa,
        )
        .await;
        if status != InternalConnectionStatus::Accepted {
            bail!("Must return ConnectionStatus::Accepted after unban");
        }

        // Then check that peers can be banned by bad behavior
        let bad_standing: PeerStanding = PeerStanding::init(
            i32::MIN,
            Some((
                NegativePeerSanction::InvalidBlock((7u64.into(), Digest::default())),
                SystemTime::now(),
            )),
            None,
            i32::from(cli.peer_tolerance),
        );

        state_lock
            .lock_guard_mut()
            .await
            .net
            .write_peer_standing_on_decrease(peer_sa.ip(), bad_standing)
            .await;

        status = check_if_connection_is_allowed(
            state_lock.clone(),
            &own_handshake,
            &other_handshake,
            &peer_sa,
        )
        .await;
        if status != InternalConnectionStatus::Refused(ConnectionRefusedReason::BadStanding) {
            bail!("Must return ConnectionStatus::Refused(ConnectionRefusedReason::BadStanding)) on db-ban");
        }

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn node_refuses_reconnects_within_disconnect_cooldown_period() -> Result<()> {
        let network = Network::Main;
        let reconnect_cooldown = Duration::from_secs(8);
        let args = cli_args::Args {
            network,
            reconnect_cooldown,
            ..Default::default()
        };

        let (broadcast_tx, _broadcast_rx, to_main_tx, _to_main_rx, mut state_lock, handshake) =
            get_test_genesis_setup(network, 0, args).await?;

        // fake a graceful disconnect
        let node_0_address = get_dummy_socket_address(0);
        let node_0_handshake_data = get_dummy_handshake_data_for_genesis(network);
        state_lock
            .lock_guard_mut()
            .await
            .net
            .register_peer_disconnection(node_0_handshake_data.instance_id, SystemTime::now());

        // check that an immediate reconnection attempt is rejected
        let handshake_request = PeerMessage::Handshake(Box::new((
            MAGIC_STRING_REQUEST.to_vec(),
            node_0_handshake_data,
        )));
        let handshake_response = PeerMessage::Handshake(Box::new((
            MAGIC_STRING_RESPONSE.to_vec(),
            handshake.clone(),
        )));
        let rejected_connection = Builder::new()
            .read(&to_bytes(&handshake_request)?)
            .write(&to_bytes(&handshake_response)?)
            .write(&to_bytes(&PeerMessage::ConnectionStatus(
                TransferConnectionStatus::Refused(ConnectionRefusedReason::MaxPeerNumberExceeded),
            ))?)
            .build();
        let err = answer_peer_inner(
            rejected_connection,
            state_lock.clone(),
            node_0_address,
            broadcast_tx.subscribe(),
            to_main_tx.clone(),
            handshake.clone(),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("Refusing incoming connection."));

        // check that a reconnection attempt after some time goes through
        let accepted_connection = Builder::new()
            .wait(reconnect_cooldown)
            .read(&to_bytes(&handshake_request)?)
            .write(&to_bytes(&handshake_response)?)
            .write(&to_bytes(&PeerMessage::ConnectionStatus(
                TransferConnectionStatus::Accepted,
            ))?)
            .read(&to_bytes(&PeerMessage::Bye)?)
            .build();
        answer_peer_inner(
            accepted_connection,
            state_lock,
            node_0_address,
            broadcast_tx.subscribe(),
            to_main_tx,
            handshake,
        )
        .await?;

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
        let network = Network::Alpha;
        let other_handshake = get_dummy_handshake_data_for_genesis(network);
        let own_handshake = get_dummy_handshake_data_for_genesis(network);
        let mock = Builder::new()
            .read(&to_bytes(&PeerMessage::Handshake(Box::new((
                MAGIC_STRING_REQUEST.to_vec(),
                other_handshake,
            ))))?)
            .write(&to_bytes(&PeerMessage::Handshake(Box::new((
                MAGIC_STRING_RESPONSE.to_vec(),
                own_handshake.clone(),
            ))))?)
            .write(&to_bytes(&PeerMessage::ConnectionStatus(
                TransferConnectionStatus::Accepted,
            ))?)
            .read(&to_bytes(&PeerMessage::Bye)?)
            .build();
        let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, _to_main_rx1, state_lock, _hsd) =
            get_test_genesis_setup(network, 0, cli_args::Args::default()).await?;
        answer_peer_inner(
            mock,
            state_lock.clone(),
            get_dummy_socket_address(0),
            from_main_rx_clone,
            to_main_tx,
            own_handshake,
        )
        .await?;

        // Verify that peer map is empty after connection has been closed
        match state_lock.lock(|s| s.net.peer_map.keys().len()).await {
            0 => (),
            _ => bail!("Incorrect number of maps in peer map"),
        };

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn test_incoming_connection_fail_bad_magic_value() -> Result<()> {
        let network = Network::Alpha;
        let other_handshake = get_dummy_handshake_data_for_genesis(network);
        let own_handshake = get_dummy_handshake_data_for_genesis(network);
        let mock = Builder::new()
            .read(&to_bytes(&PeerMessage::Handshake(Box::new((
                MAGIC_STRING_RESPONSE.to_vec(),
                other_handshake,
            ))))?)
            .build();

        let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, _to_main_rx1, state, _hsd) =
            get_test_genesis_setup(network, 0, cli_args::Args::default()).await?;

        let answer = answer_peer_inner(
            mock,
            state,
            get_dummy_socket_address(0),
            from_main_rx_clone,
            to_main_tx,
            own_handshake,
        )
        .await;
        assert!(answer.is_err(), "expected bad magic value failure");

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn test_incoming_connection_fail_bad_network() -> Result<()> {
        let other_handshake = get_dummy_handshake_data_for_genesis(Network::Testnet);
        let own_handshake = get_dummy_handshake_data_for_genesis(Network::Alpha);
        let mock = Builder::new()
            .read(&to_bytes(&PeerMessage::Handshake(Box::new((
                MAGIC_STRING_REQUEST.to_vec(),
                other_handshake,
            ))))?)
            .write(&to_bytes(&PeerMessage::Handshake(Box::new((
                MAGIC_STRING_RESPONSE.to_vec(),
                own_handshake.clone(),
            ))))?)
            .build();

        let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, _to_main_rx1, state, _hsd) =
            get_test_genesis_setup(Network::Alpha, 0, cli_args::Args::default()).await?;

        let answer = answer_peer_inner(
            mock,
            state,
            get_dummy_socket_address(0),
            from_main_rx_clone,
            to_main_tx,
            own_handshake,
        )
        .await;
        assert!(answer.is_err(), "bad network must result in error");

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn test_incoming_connection_fail_bad_version() {
        let mut other_handshake = get_dummy_handshake_data_for_genesis(Network::Testnet);
        let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, _to_main_rx1, state_lock, _hsd) =
            get_test_genesis_setup(Network::Alpha, 0, cli_args::Args::default())
                .await
                .unwrap();
        let state = state_lock.lock_guard().await;
        let mut own_handshake = state.get_own_handshakedata();

        // Set reported versions to something incompatible
        VersionString::try_from_str("0.0.3")
            .unwrap()
            .clone_into(&mut own_handshake.version);
        VersionString::try_from_str("0.0.0")
            .unwrap()
            .clone_into(&mut other_handshake.version);

        let peer_address = get_dummy_socket_address(55);
        let connection_status = check_if_connection_is_allowed(
            state_lock.clone(),
            &own_handshake,
            &other_handshake,
            &peer_address,
        )
        .await;
        assert_eq!(
            InternalConnectionStatus::Refused(ConnectionRefusedReason::IncompatibleVersion),
            connection_status,
            "Connection status must be refused for incompatible version"
        );

        // Test that the same logic is applied when going through the full connection process
        let mock = Builder::new()
            .read(
                &to_bytes(&PeerMessage::Handshake(Box::new((
                    MAGIC_STRING_REQUEST.to_vec(),
                    other_handshake,
                ))))
                .unwrap(),
            )
            .write(
                &to_bytes(&PeerMessage::Handshake(Box::new((
                    MAGIC_STRING_RESPONSE.to_vec(),
                    own_handshake.clone(),
                ))))
                .unwrap(),
            )
            .build();

        let answer = answer_peer_inner(
            mock,
            state_lock.clone(),
            get_dummy_socket_address(0),
            from_main_rx_clone,
            to_main_tx,
            own_handshake,
        )
        .await;
        assert!(
            answer.is_err(),
            "incompatible version numbers must result in error in call to answer_peer"
        );
    }

    #[traced_test]
    #[tokio::test]
    async fn test_incoming_connection_fail_max_peers_exceeded() -> Result<()> {
        // In this scenario a node attempts to make an ingoing connection but the max
        // peer count should prevent a new incoming connection from being accepted.
        let network = Network::Alpha;
        let other_handshake = get_dummy_handshake_data_for_genesis(network);
        let own_handshake = get_dummy_handshake_data_for_genesis(network);
        let mock = Builder::new()
            .read(&to_bytes(&PeerMessage::Handshake(Box::new((
                MAGIC_STRING_REQUEST.to_vec(),
                other_handshake,
            ))))?)
            .write(&to_bytes(&PeerMessage::Handshake(Box::new((
                MAGIC_STRING_RESPONSE.to_vec(),
                own_handshake.clone(),
            ))))?)
            .write(&to_bytes(&PeerMessage::ConnectionStatus(
                TransferConnectionStatus::Refused(ConnectionRefusedReason::MaxPeerNumberExceeded),
            ))?)
            .build();

        let (
            _peer_broadcast_tx,
            from_main_rx_clone,
            to_main_tx,
            _to_main_rx1,
            mut state_lock,
            _hsd,
        ) = get_test_genesis_setup(Network::Alpha, 2, cli_args::Args::default()).await?;

        // set max_peers to 2 to ensure failure on next connection attempt
        let mut cli = state_lock.cli().clone();
        cli.max_num_peers = 2;
        state_lock.set_cli(cli).await;

        let answer = answer_peer_inner(
            mock,
            state_lock.clone(),
            get_dummy_socket_address(2),
            from_main_rx_clone,
            to_main_tx,
            own_handshake,
        )
        .await;
        assert!(answer.is_err(), "max peers exceeded must result in error");

        Ok(())
    }

    #[tokio::test]
    async fn allow_capping_number_of_peers_per_ip() {
        let allow_5_connections_from_same_ip = cli_args::Args {
            max_connections_per_ip: Some(5),
            ..Default::default()
        };
        let (
            _peer_broadcast_tx,
            _from_main_rx_clone,
            _to_main_tx,
            _to_main_rx1,
            mut state_lock,
            _hsd,
        ) = get_test_genesis_setup(Network::Main, 0, allow_5_connections_from_same_ip)
            .await
            .unwrap();

        let dummy_address =
            |i: usize| std::net::SocketAddr::from_str(&format!("253.4.5.1:2801{i}")).unwrap();
        let five_dummy_addresses = (1..=5).map(dummy_address);

        let own_handshake = state_lock.lock_guard().await.get_own_handshakedata();

        // First five connections are allowed, from the same IP.
        for peer_address in five_dummy_addresses {
            let peer_info = get_dummy_peer_incoming(peer_address);
            let peer_handshake = get_dummy_handshake_data_for_genesis(Network::Main);
            let accepted = check_if_connection_is_allowed(
                state_lock.clone(),
                &own_handshake,
                &peer_handshake,
                &peer_address,
            )
            .await;
            assert_eq!(InternalConnectionStatus::Accepted, accepted);

            state_lock
                .lock_guard_mut()
                .await
                .net
                .peer_map
                .insert(peer_address, peer_info.clone());
        }

        // The next connection from the same IP is rejected, as the limit per
        // IP is reached.
        let sixth_peer = dummy_address(6);
        let peer_handshake = get_dummy_handshake_data_for_genesis(Network::Main);
        let refused = check_if_connection_is_allowed(
            state_lock.clone(),
            &own_handshake,
            &peer_handshake,
            &sixth_peer,
        )
        .await;
        assert_eq!(
            InternalConnectionStatus::Refused(ConnectionRefusedReason::MaxPeerNumberExceeded),
            refused
        );

        // But if connections per IP is not capped, allow this sixth connection.
        let allow_all_ips = cli_args::Args::default();
        state_lock.set_cli(allow_all_ips).await;

        assert_eq!(
            InternalConnectionStatus::Accepted,
            check_if_connection_is_allowed(
                state_lock.clone(),
                &own_handshake,
                &peer_handshake,
                &sixth_peer,
            )
            .await
        );
    }

    #[traced_test]
    #[tokio::test]
    async fn disallow_ingoing_connections_from_banned_peers_test() -> Result<()> {
        // In this scenario a peer has been banned, and is attempting to make an ingoing
        // connection. This should not be possible.
        let network = Network::Alpha;
        let other_handshake = get_dummy_handshake_data_for_genesis(network);
        let own_handshake = get_dummy_handshake_data_for_genesis(network);
        let mock = Builder::new()
            .read(&to_bytes(&PeerMessage::Handshake(Box::new((
                MAGIC_STRING_REQUEST.to_vec(),
                other_handshake,
            ))))?)
            .write(&to_bytes(&PeerMessage::Handshake(Box::new((
                MAGIC_STRING_RESPONSE.to_vec(),
                own_handshake.clone(),
            ))))?)
            .write(&to_bytes(&PeerMessage::ConnectionStatus(
                TransferConnectionStatus::Refused(ConnectionRefusedReason::BadStanding),
            ))?)
            .build();

        let peer_count_before_incoming_connection_request = 3;
        let (
            _peer_broadcast_tx,
            from_main_rx_clone,
            to_main_tx,
            _to_main_rx1,
            mut state_lock,
            _hsd,
        ) = get_test_genesis_setup(
            Network::Alpha,
            peer_count_before_incoming_connection_request,
            cli_args::Args::default(),
        )
        .await?;
        let bad_standing: PeerStanding = PeerStanding::init(
            i32::MIN,
            Some((
                NegativePeerSanction::InvalidBlock((7u64.into(), Digest::default())),
                SystemTime::now(),
            )),
            None,
            i32::from(cli_args::Args::default().peer_tolerance),
        );
        let peer_address = get_dummy_socket_address(3);

        state_lock
            .lock_guard_mut()
            .await
            .net
            .write_peer_standing_on_decrease(peer_address.ip(), bad_standing)
            .await;

        let answer = answer_peer_inner(
            mock,
            state_lock.clone(),
            peer_address,
            from_main_rx_clone,
            to_main_tx,
            own_handshake,
        )
        .await;
        assert!(
            answer.is_err(),
            "ingoing connection from banned peers must be disallowed"
        );

        // Verify that peer map is empty after connection has been refused
        match state_lock.lock(|s| s.net.peer_map.keys().len()).await {
            3 => (),
            _ => bail!("Incorrect number of maps in peer map"),
        };

        Ok(())
    }
}
