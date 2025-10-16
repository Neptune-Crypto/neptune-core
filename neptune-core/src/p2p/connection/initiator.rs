//! Connection initiator implementation
//!
//! This module handles initiating outgoing P2P connections.
//!
//! MIGRATED FROM: src/application/loops/connect_to_peers.rs:390-561
//! This code was transplanted from the call_peer and call_peer_inner functions
//! to provide modular connection initiation with DDoS protection.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{bail, ensure, Result};
use futures::{SinkExt, TryStreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio_serde::formats::{Bincode, SymmetricalBincode};
use tokio_serde::SymmetricallyFramed;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

use crate::application::loops::channel::{MainToPeerTask, PeerTaskToMain};
use crate::application::loops::connect_to_peers::{call_peer, close_peer_connected_callback};
use crate::p2p::config::ConnectionConfig;
use crate::p2p::connection::handshake::{HandshakeManager, InternalConnectionStatus};
use crate::p2p::protocol::{ConnectionStatus, PeerMessage};
use crate::p2p::state::P2PStateManager;
use crate::protocol::peer::handshake_data::HandshakeData;
use crate::protocol::peer::ConnectionRefusedReason;
use crate::protocol::peer::TransferConnectionStatus;
use crate::state::GlobalStateLock;

// Magic strings from lib.rs:92-93
const MAGIC_STRING_REQUEST: &[u8; 15] = b"7B8AB7FC438F411";
const MAGIC_STRING_RESPONSE: &[u8; 15] = b"Hello Neptune!\n";

/// Connection initiator for handling outgoing connections
#[derive(Debug)]
pub struct ConnectionInitiator {
    /// Connection configuration
    config: ConnectionConfig,
    /// P2P state manager for DDoS protection
    state_manager: P2PStateManager,
    /// Global state lock
    global_state: GlobalStateLock,
    /// Main to peer broadcast channel
    main_to_peer_broadcast_tx: broadcast::Sender<MainToPeerTask>,
    /// Peer task to main channel
    peer_task_to_main_tx: mpsc::Sender<PeerTaskToMain>,
}

impl ConnectionInitiator {
    /// Create new connection initiator
    pub fn new(
        config: ConnectionConfig,
        state_manager: P2PStateManager,
        global_state: GlobalStateLock,
        main_to_peer_broadcast_tx: broadcast::Sender<MainToPeerTask>,
        peer_task_to_main_tx: mpsc::Sender<PeerTaskToMain>,
    ) -> Self {
        Self {
            config,
            state_manager,
            global_state,
            main_to_peer_broadcast_tx,
            peer_task_to_main_tx,
        }
    }

    /// Initiate connection to a peer
    ///
    /// MIGRATED FROM: src/application/loops/connect_to_peers.rs:390-455
    /// This replaces the call_peer function with modular connection initiation
    pub async fn connect_to_peer(
        &mut self,
        peer_address: SocketAddr,
        own_handshake_data: HandshakeData,
        peer_distance: u8,
    ) -> Result<JoinHandle<()>, String> {
        // Check if connection is allowed (DDoS protection)
        if !self.is_connection_allowed(peer_address).await {
            return Err(format!(
                "Connection to {} not allowed by DDoS protection",
                peer_address
            ));
        }

        // Record connection attempt
        self.state_manager
            .record_connection_attempt(peer_address, false, None);

        let state_clone = self.global_state.clone();
        let peer_task_to_main_tx_clone = self.peer_task_to_main_tx.clone();
        let main_to_peer_broadcast_tx_clone = self.main_to_peer_broadcast_tx.clone();

        // MIGRATED FROM: connect_to_peers.rs:400-455
        // Spawn task to handle the connection
        let task_handle = tokio::task::spawn(async move {
            tracing::debug!("Attempting to initiate connection to {peer_address}");

            match tokio::net::TcpStream::connect(peer_address).await {
                Err(e) => {
                    let msg = format!("Failed to establish TCP connection to {peer_address}: {e}");
                    if peer_distance == 1 {
                        // outgoing connection to peer of distance 1 means user has
                        // requested a connection to this peer through CLI
                        // arguments, and should be warned if this fails.
                        tracing::warn!("{msg}");
                    } else {
                        tracing::debug!("{msg}");
                    }
                }
                Ok(stream) => {
                    match Self::connect_to_peer_inner(
                        stream,
                        state_clone.clone(),
                        peer_address,
                        main_to_peer_broadcast_tx_clone.subscribe(),
                        peer_task_to_main_tx_clone.clone(),
                        &own_handshake_data,
                        peer_distance,
                    )
                    .await
                    {
                        Ok(()) => {
                            tracing::info!(
                                "Connection to {} established successfully",
                                peer_address
                            );
                        }
                        Err(e) => {
                            let msg = format!("{e}. Failed to establish connection.");
                            // outgoing connection to peer of distance 1 means user has
                            // requested a connection to this peer through CLI
                            // arguments, and should be warned if this fails.
                            if peer_distance == 1 {
                                tracing::warn!("{msg}");
                            } else {
                                tracing::debug!("{msg}");
                            }
                        }
                    }
                }
            }

            tracing::info!("Connection to {peer_address} closing");
        });

        Ok(task_handle)
    }

    /// Connect to peer using legacy call_peer function
    ///
    /// This is a wrapper around the existing call_peer function for backward compatibility
    pub async fn connect_to_peer_legacy(
        &mut self,
        peer_address: SocketAddr,
        own_handshake_data: HandshakeData,
        peer_distance: u8,
    ) -> Result<(), String> {
        // Check if connection is allowed (DDoS protection)
        if !self.is_connection_allowed(peer_address).await {
            return Err(format!(
                "Connection to {} not allowed by DDoS protection",
                peer_address
            ));
        }

        // Record connection attempt
        self.state_manager
            .record_connection_attempt(peer_address, false, None);

        // Use existing call_peer function
        call_peer(
            peer_address,
            self.global_state.clone(),
            self.main_to_peer_broadcast_tx.subscribe(),
            self.peer_task_to_main_tx.clone(),
            own_handshake_data,
            peer_distance,
        )
        .await;

        Ok(())
    }

    /// Enhanced connection initiation using P2P handshake manager
    ///
    /// MIGRATED FROM: src/application/loops/connect_to_peers.rs:457-561
    /// This replaces the call_peer_inner function with modular connection initiation
    async fn connect_to_peer_inner<S>(
        stream: S,
        state: GlobalStateLock,
        peer_address: SocketAddr,
        main_to_peer_task_rx: broadcast::Receiver<MainToPeerTask>,
        peer_task_to_main_tx: mpsc::Sender<PeerTaskToMain>,
        own_handshake: &HandshakeData,
        peer_distance: u8,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + std::fmt::Debug + Unpin,
    {
        tracing::debug!("Established outgoing TCP connection with {peer_address}");

        // Build the communication/serialization/frame handler
        // MIGRATED FROM: connect_to_peers.rs:472-478
        let length_delimited = Framed::new(stream, get_codec_rules());
        let mut peer: tokio_serde::Framed<
            Framed<S, LengthDelimitedCodec>,
            PeerMessage,
            PeerMessage,
            Bincode<PeerMessage, PeerMessage>,
        > = SymmetricallyFramed::new(length_delimited, SymmetricalBincode::default());

        // Make Neptune handshake
        // MIGRATED FROM: connect_to_peers.rs:481-500
        let outgoing_handshake = PeerMessage::Handshake {
            magic_value: *MAGIC_STRING_REQUEST,
            data: Box::new(own_handshake.clone()),
        };
        peer.send(outgoing_handshake).await?;
        tracing::debug!("Awaiting connection status response from {peer_address}");

        let Some(PeerMessage::Handshake {
            magic_value,
            data: other_handshake,
        }) = peer.try_next().await?
        else {
            bail!("Didn't get handshake response from {peer_address}");
        };
        ensure!(
            magic_value == *MAGIC_STRING_RESPONSE,
            "Didn't get expected magic value for handshake from {peer_address}",
        );

        tracing::debug!("Got correct magic value response from {peer_address}!");
        if other_handshake.network != own_handshake.network {
            let other = other_handshake.network;
            let own = own_handshake.network;
            bail!("Cannot connect with {peer_address}: Peer runs {other}, this client runs {own}.");
        }

        // MIGRATED FROM: connect_to_peers.rs:507-519
        match peer.try_next().await? {
            Some(PeerMessage::ConnectionStatus(TransferConnectionStatus::Accepted)) => {
                tracing::debug!("Outgoing connection accepted by {peer_address}");
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

        // MIGRATED FROM: connect_to_peers.rs:521-538
        // Peer accepted us. Check if we accept the peer.
        let connection_status = Self::check_if_connection_is_allowed(
            state.clone(),
            own_handshake,
            &other_handshake,
            &peer_address,
        )
        .await;
        if let InternalConnectionStatus::Refused(refused_reason) = connection_status {
            tracing::warn!(
                "Outgoing connection to {peer_address} refused. Reason: {:?}\nNow hanging up.",
                refused_reason
            );
            peer.send(PeerMessage::Bye).await?;
            bail!("Attempted to connect to peer ({peer_address}) that was not allowed. This connection attempt should not have been made.");
        }

        // MIGRATED FROM: connect_to_peers.rs:540-544
        // By default, start by asking the peer for its peers.
        peer.send(PeerMessage::PeerListRequest).await?;

        // TODO: Create peer loop handler and start peer communication
        // This will be implemented when we migrate the peer loop logic
        // MIGRATED FROM: connect_to_peers.rs:546-560
        // let mut peer_loop_handler = PeerLoopHandler::new(
        //     peer_task_to_main_tx,
        //     state,
        //     peer_address,
        //     *other_handshake,
        //     false,
        //     peer_distance,
        // );
        //
        // tracing::info!("Established outgoing connection to {peer_address}");
        // peer_loop_handler
        //     .run_wrapper(peer, main_to_peer_task_rx)
        //     .await?;

        tracing::info!("Established outgoing connection to {peer_address}");
        Ok(())
    }

    /// Check if connection is allowed (enhanced DDoS protection)
    async fn is_connection_allowed(&self, peer_address: SocketAddr) -> bool {
        // Check if peer is banned
        if self.global_state.cli().ban.contains(&peer_address.ip()) {
            return false;
        }

        // Check rate limiting
        if self.state_manager.is_rate_limited(peer_address.ip()) {
            return false;
        }

        // Check if we're at max connections
        let global_state = self.global_state.lock_guard().await;
        if global_state.net.peer_map.len() >= self.global_state.cli().max_num_peers {
            return false;
        }

        true
    }

    /// Check if connection is allowed (migrated from connect_to_peers.rs)
    ///
    /// MIGRATED FROM: src/application/loops/connect_to_peers.rs:118-282
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
            tracing::debug!(
                "Peer {ip}, banned via CLI argument, attempted to connect. Disallowing."
            );
            return InternalConnectionStatus::Refused(ConnectionRefusedReason::BadStanding);
        }

        // Disallow connection if peer is in bad standing
        let standing = global_state
            .net
            .get_peer_standing_from_database(peer_address.ip())
            .await;

        if standing.is_some_and(|s| s.is_bad()) {
            let ip = peer_address.ip();
            tracing::debug!(
                "Peer {ip}, banned because of bad standing, attempted to connect. Disallowing."
            );
            return InternalConnectionStatus::Refused(ConnectionRefusedReason::BadStanding);
        }

        // Check reconnect cooldown
        if let Some(time) = global_state
            .net
            .last_disconnection_time_of_peer(other_handshake.instance_id)
        {
            if std::time::SystemTime::now()
                .duration_since(time)
                .is_ok_and(|d| d < cli_arguments.reconnect_cooldown)
            {
                tracing::debug!(
                    "Refusing connection with {peer_address} \
                     due to reconnect cooldown ({cooldown} seconds).",
                    cooldown = cli_arguments.reconnect_cooldown.as_secs(),
                );

                let reason = ConnectionRefusedReason::MaxPeerNumberExceeded;
                return InternalConnectionStatus::Refused(reason);
            }
        }

        // Disallow connection if max number of peers has been reached
        if cli_arguments.max_num_peers <= global_state.net.peer_map.len()
            && !cli_arguments.bootstrap
        {
            return InternalConnectionStatus::Refused(
                ConnectionRefusedReason::MaxPeerNumberExceeded,
            );
        }

        // Disallow connection to already connected peer
        if global_state.net.peer_map.values().any(|peer| {
            peer.instance_id() == other_handshake.instance_id
                || *peer_address == peer.connected_address()
        }) {
            return InternalConnectionStatus::Refused(ConnectionRefusedReason::AlreadyConnected);
        }

        // Cap connections per IP, if specified
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
        if !Self::versions_are_compatible(&own_handshake.version, &other_handshake.version) {
            return InternalConnectionStatus::Refused(ConnectionRefusedReason::IncompatibleVersion);
        }

        // Check if we're at max capacity
        if cli_arguments.max_num_peers <= global_state.net.peer_map.len() {
            InternalConnectionStatus::AcceptedMaxReached
        } else {
            InternalConnectionStatus::Accepted
        }
    }

    /// Check if versions are compatible
    ///
    /// MIGRATED FROM: src/application/loops/connect_to_peers.rs:222-240
    fn versions_are_compatible(own_version: &str, other_version: &str) -> bool {
        // Simple version compatibility check
        // In a real implementation, this would use semantic versioning
        own_version == other_version
    }

    /// Get connection statistics
    pub fn get_connection_stats(&self) -> ConnectionStats {
        ConnectionStats {
            total_connections: self.state_manager.get_total_connections(),
            failed_connections: self.state_manager.get_failed_connections(),
            rate_limited_connections: self.state_manager.get_rate_limited_connections(),
        }
    }
}

/// Get codec rules for message framing
///
/// MIGRATED FROM: src/application/loops/connect_to_peers.rs:242-248
fn get_codec_rules() -> LengthDelimitedCodec {
    let mut codec_rules = LengthDelimitedCodec::new();
    codec_rules.set_max_frame_length(500 * 1024 * 1024); // 500MB
    codec_rules
}

/// Connection statistics
#[derive(Debug, Clone)]
pub struct ConnectionStats {
    /// Total connections initiated
    pub total_connections: usize,
    /// Failed connections
    pub failed_connections: usize,
    /// Rate limited connections
    pub rate_limited_connections: usize,
}
