//! Handshake manager implementation
//!
//! This module handles the P2P handshake protocol.
//!
//! MIGRATED FROM: src/application/loops/connect_to_peers.rs:284-377
//! This code was transplanted from the original answer_peer_inner function
//! and check_if_connection_is_allowed function to provide modular handshake handling.

use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

use anyhow::{bail, ensure, Result};
use futures::{SinkExt, TryStreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_serde::formats::{Bincode, SymmetricalBincode};
use tokio_serde::SymmetricallyFramed;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

use crate::application::config::cli_args;
use crate::p2p::config::ProtocolConfig;
use crate::p2p::protocol::{
    ConnectionStatus, HandshakeData, PeerMessage, TransferConnectionStatus,
};
use crate::p2p::state::P2PStateManager;
use crate::protocol::peer::ConnectionRefusedReason as OriginalConnectionRefusedReason;
use crate::protocol::peer::ConnectionRefusedReason;
use crate::state::GlobalStateLock;

// Implement From trait for ConnectionRefusedReason conversion
impl From<OriginalConnectionRefusedReason> for crate::p2p::protocol::ConnectionRefusedReason {
    fn from(reason: OriginalConnectionRefusedReason) -> Self {
        match reason {
            OriginalConnectionRefusedReason::BadStanding => {
                crate::p2p::protocol::ConnectionRefusedReason::BadStanding
            }
            OriginalConnectionRefusedReason::MaxPeerNumberExceeded => {
                crate::p2p::protocol::ConnectionRefusedReason::MaxPeerNumberExceeded
            }
            OriginalConnectionRefusedReason::AlreadyConnected => {
                crate::p2p::protocol::ConnectionRefusedReason::AlreadyConnected
            }
            OriginalConnectionRefusedReason::SelfConnect => {
                crate::p2p::protocol::ConnectionRefusedReason::SelfConnect
            }
            OriginalConnectionRefusedReason::IncompatibleVersion => {
                crate::p2p::protocol::ConnectionRefusedReason::IncompatibleVersion
            }
            OriginalConnectionRefusedReason::Other(_) => {
                // Map Other to InvalidHandshake for now
                crate::p2p::protocol::ConnectionRefusedReason::InvalidHandshake
            }
        }
    }
}

// Magic strings from lib.rs:92-93
const MAGIC_STRING_REQUEST: &[u8; 15] = b"7B8AB7FC438F411";
const MAGIC_STRING_RESPONSE: &[u8; 15] = b"Hello Neptune!\n";

/// Handshake manager for handling P2P handshake protocol
#[derive(Debug)]
pub struct HandshakeManager {
    /// Protocol configuration
    config: ProtocolConfig,
    /// P2P state manager
    state_manager: P2PStateManager,
    /// Global state lock
    global_state: GlobalStateLock,
}

impl HandshakeManager {
    /// Create new handshake manager
    pub fn new(
        config: ProtocolConfig,
        state_manager: P2PStateManager,
        global_state: GlobalStateLock,
    ) -> Self {
        Self {
            config,
            state_manager,
            global_state,
        }
    }

    /// Perform handshake with a peer
    ///
    /// MIGRATED FROM: src/application/loops/connect_to_peers.rs:284-377
    /// This replaces the answer_peer_inner function with modular handshake handling
    pub async fn perform_handshake<S>(
        &self,
        stream: S,
        peer_address: SocketAddr,
        own_handshake_data: HandshakeData,
    ) -> Result<HandshakeResult>
    where
        S: AsyncRead + AsyncWrite + std::fmt::Debug + Unpin,
    {
        tracing::debug!("Established incoming TCP connection with {peer_address}");

        // Build the communication/serialization/frame handler
        // MIGRATED FROM: connect_to_peers.rs:298-303
        let length_delimited = Framed::new(stream, get_codec_rules());
        let mut peer = SymmetricallyFramed::<
            Framed<S, LengthDelimitedCodec>,
            PeerMessage,
            Bincode<PeerMessage, PeerMessage>,
        >::new(length_delimited, SymmetricalBincode::default());

        // Complete Neptune handshake
        // MIGRATED FROM: connect_to_peers.rs:305-322
        let Some(PeerMessage::Handshake {
            magic_value,
            data: peer_handshake_data,
        }) = peer.try_next().await?
        else {
            bail!("Didn't get handshake on connection attempt");
        };
        ensure!(
            magic_value == *MAGIC_STRING_REQUEST,
            "Expected magic value, got {magic_value:?}",
        );

        let handshake_response = PeerMessage::Handshake {
            magic_value: *MAGIC_STRING_RESPONSE,
            data: Box::new(own_handshake_data.clone()),
        };
        peer.send(handshake_response).await?;

        // Verify peer network before moving on
        // MIGRATED FROM: connect_to_peers.rs:324-331
        let peer_network = peer_handshake_data.network;
        let own_network = own_handshake_data.network;
        ensure!(
            peer_network == own_network,
            "Cannot connect with {peer_address}: \
            Peer runs {peer_network}, this client runs {own_network}."
        );

        // Check if incoming connection is allowed
        // MIGRATED FROM: connect_to_peers.rs:333-347
        let connection_status = self
            .check_if_connection_is_allowed(
                &own_handshake_data,
                &peer_handshake_data,
                &peer_address,
            )
            .await;

        // Convert InternalConnectionStatus to TransferConnectionStatus
        let transfer_status = match connection_status {
            InternalConnectionStatus::Accepted => TransferConnectionStatus::Accepted,
            InternalConnectionStatus::AcceptedMaxReached => TransferConnectionStatus::Accepted,
            InternalConnectionStatus::Refused(reason) => TransferConnectionStatus::Refused(reason),
        };
        peer.send(PeerMessage::ConnectionStatus(transfer_status))
            .await?;

        if let InternalConnectionStatus::Refused(reason) = connection_status {
            let reason = format!("Refusing incoming connection. Reason: {reason:?}");
            tracing::debug!("{reason}");
            bail!("{reason}");
        }

        // Whether the incoming connection comes from a peer in bad standing is
        // checked in `check_if_connection_is_allowed`. So if we get here, we are
        // good to go.
        tracing::info!("Connection accepted from {peer_address}");

        Ok(HandshakeResult {
            peer_handshake_data: *peer_handshake_data,
            connection_status: connection_status.into(),
        })
    }

    /// Check if connection is allowed
    ///
    /// MIGRATED FROM: src/application/loops/connect_to_peers.rs:118-282
    /// This replaces the check_if_connection_is_allowed function with modular validation
    async fn check_if_connection_is_allowed(
        &self,
        own_handshake: &HandshakeData,
        other_handshake: &HandshakeData,
        peer_address: &SocketAddr,
    ) -> InternalConnectionStatus {
        let cli_arguments = self.global_state.cli();
        let global_state = self.global_state.lock_guard().await;

        // Disallow connection if peer is banned via CLI arguments
        // MIGRATED FROM: connect_to_peers.rs:131-136
        if cli_arguments.ban.contains(&peer_address.ip()) {
            let ip = peer_address.ip();
            tracing::debug!(
                "Peer {ip}, banned via CLI argument, attempted to connect. Disallowing."
            );
            return InternalConnectionStatus::Refused(ConnectionRefusedReason::BadStanding);
        }

        // Disallow connection if peer is in bad standing
        // MIGRATED FROM: connect_to_peers.rs:138-148
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
        // MIGRATED FROM: connect_to_peers.rs:150-169
        if let Some(time) = global_state
            .net
            .last_disconnection_time_of_peer(other_handshake.instance_id)
        {
            if SystemTime::now()
                .duration_since(time)
                .is_ok_and(|d| d < cli_arguments.reconnect_cooldown)
            {
                tracing::debug!(
                    "Refusing connection with {peer_address} \
                     due to reconnect cooldown ({cooldown} seconds).",
                    cooldown = cli_arguments.reconnect_cooldown.as_secs(),
                );

                // A "wrong" reason is given because of backwards compatibility.
                let reason = ConnectionRefusedReason::MaxPeerNumberExceeded;
                return InternalConnectionStatus::Refused(reason);
            }
        }

        // Disallow connection if max number of peers has been reached
        // MIGRATED FROM: connect_to_peers.rs:175-182
        if cli_arguments.max_num_peers <= global_state.net.peer_map.len()
            && !cli_arguments.bootstrap
        {
            return InternalConnectionStatus::Refused(
                ConnectionRefusedReason::MaxPeerNumberExceeded,
            );
        }

        // Disallow connection to already connected peer
        // MIGRATED FROM: connect_to_peers.rs:184-190
        if global_state.net.peer_map.values().any(|peer| {
            peer.instance_id() == other_handshake.instance_id
                || *peer_address == peer.connected_address()
        }) {
            return InternalConnectionStatus::Refused(ConnectionRefusedReason::AlreadyConnected);
        }

        // Cap connections per IP, if specified
        // MIGRATED FROM: connect_to_peers.rs:192-207
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
        // MIGRATED FROM: connect_to_peers.rs:209-212
        if own_handshake.instance_id == other_handshake.instance_id {
            return InternalConnectionStatus::Refused(ConnectionRefusedReason::SelfConnect);
        }

        // Disallow connection if versions are incompatible
        // MIGRATED FROM: connect_to_peers.rs:214-220
        if !versions_are_compatible(&own_handshake.version, &other_handshake.version) {
            return InternalConnectionStatus::Refused(ConnectionRefusedReason::IncompatibleVersion);
        }

        // Check if we're at max capacity
        if cli_arguments.max_num_peers <= global_state.net.peer_map.len() {
            InternalConnectionStatus::AcceptedMaxReached
        } else {
            InternalConnectionStatus::Accepted
        }
    }

    /// Validate handshake data
    pub fn validate_handshake_data(
        &self,
        handshake_data: &HandshakeData,
        own_handshake_data: &HandshakeData,
    ) -> Result<(), String> {
        // Check version compatibility
        if !versions_are_compatible(&handshake_data.version, &own_handshake_data.version) {
            return Err("Version mismatch".to_string());
        }

        // Check network compatibility
        if handshake_data.network != own_handshake_data.network {
            return Err("Network mismatch".to_string());
        }

        // Check instance ID (prevent self-connection)
        if handshake_data.instance_id == own_handshake_data.instance_id {
            return Err("Self-connection attempt".to_string());
        }

        Ok(())
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

/// Get codec rules for message framing
///
/// MIGRATED FROM: src/application/loops/connect_to_peers.rs:242-248
fn get_codec_rules() -> LengthDelimitedCodec {
    let mut codec_rules = LengthDelimitedCodec::new();
    codec_rules.set_max_frame_length(500 * 1024 * 1024); // 500MB
    codec_rules
}

/// Internal connection status (used for processing)
///
/// MIGRATED FROM: src/application/loops/connect_to_peers.rs:250-260
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InternalConnectionStatus {
    /// Connection accepted
    Accepted,
    /// Connection accepted but max peers reached
    AcceptedMaxReached,
    /// Connection refused
    Refused(ConnectionRefusedReason),
}

impl From<InternalConnectionStatus> for ConnectionStatus {
    fn from(status: InternalConnectionStatus) -> Self {
        match status {
            InternalConnectionStatus::Accepted => ConnectionStatus::Accepted,
            InternalConnectionStatus::AcceptedMaxReached => ConnectionStatus::AcceptedMaxReached,
            InternalConnectionStatus::Refused(reason) => ConnectionStatus::Refused(reason.into()),
        }
    }
}

/// Handshake result
#[derive(Debug, Clone)]
pub struct HandshakeResult {
    /// Peer's handshake data
    pub peer_handshake_data: HandshakeData,
    /// Connection status
    pub connection_status: ConnectionStatus,
}
