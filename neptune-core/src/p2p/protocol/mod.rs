//! P2P protocol module
//!
//! This module contains the P2P protocol definitions, message handling,
//! and protocol-specific logic.

pub mod codec;
pub mod handler;
pub mod messages;
pub mod validation;

// Re-export main types
pub use codec::PeerCodec;
pub use handler::MessageHandler;
pub use messages::PeerMessage;
pub use validation::MessageValidator;

use std::net::SocketAddr;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

// Type aliases for original Neptune Core types for compatibility
pub type HandshakeData = crate::protocol::peer::handshake_data::HandshakeData;
pub use crate::protocol::peer::TransferConnectionStatus;

/// Connection status enumeration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionStatus {
    /// Connection accepted
    Accepted,
    /// Connection accepted but max peers reached
    AcceptedMaxReached,
    /// Connection refused
    Refused(ConnectionRefusedReason),
}

/// Connection refused reason
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionRefusedReason {
    /// Bad peer standing
    BadStanding,
    /// Maximum peer number exceeded
    MaxPeerNumberExceeded,
    /// Already connected to this peer
    AlreadyConnected,
    /// Self-connection attempt
    SelfConnect,
    /// Incompatible version
    IncompatibleVersion,
    /// Network mismatch
    NetworkMismatch,
    /// Invalid handshake
    InvalidHandshake,
}

/// Internal connection status (used for processing)
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
            InternalConnectionStatus::Refused(reason) => ConnectionStatus::Refused(reason),
        }
    }
}

/// Protocol event
#[derive(Debug, Clone)]
pub enum ProtocolEvent {
    /// Message received
    MessageReceived(SocketAddr, PeerMessage),
    /// Message sent
    MessageSent(SocketAddr, PeerMessage),
    /// Handshake completed
    HandshakeCompleted(SocketAddr, HandshakeData),
    /// Handshake failed
    HandshakeFailed(SocketAddr, String),
    /// Protocol error
    ProtocolError(SocketAddr, String),
}
