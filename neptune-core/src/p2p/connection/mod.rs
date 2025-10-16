//! Connection management module for P2P networking
//!
//! This module handles the lifecycle of P2P connections including
//! establishment, handshake, validation, and teardown.

pub mod acceptor;
pub mod handshake;
pub mod initiator;
pub mod manager;
pub mod validator;

// Re-export main types
pub use acceptor::ConnectionAcceptor;
pub use handshake::HandshakeManager;
pub use initiator::ConnectionInitiator;
pub use manager::ConnectionManager;
pub use validator::ConnectionValidator;

use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

/// Connection state enumeration
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    /// Connection is being established
    Connecting,
    /// Handshake is in progress
    Handshaking,
    /// Connection is established and ready
    Connected,
    /// Connection is being closed
    Disconnecting,
    /// Connection is closed
    Disconnected,
    /// Connection failed
    Failed,
}

/// Connection information
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    /// Remote peer address
    pub peer_address: SocketAddr,
    /// Connection state
    pub state: ConnectionState,
    /// Connection start time
    pub start_time: std::time::Instant,
    /// Last activity time
    pub last_activity: std::time::Instant,
    /// Whether this is an incoming connection
    pub is_incoming: bool,
    /// Connection timeout
    pub timeout: Duration,
}

impl ConnectionInfo {
    /// Create new connection info
    pub fn new(peer_address: SocketAddr, is_incoming: bool, timeout: Duration) -> Self {
        let now = std::time::Instant::now();
        Self {
            peer_address,
            state: ConnectionState::Connecting,
            start_time: now,
            last_activity: now,
            is_incoming,
            timeout,
        }
    }

    /// Update last activity time
    pub fn update_activity(&mut self) {
        self.last_activity = std::time::Instant::now();
    }

    /// Check if connection has timed out
    pub fn is_timed_out(&self) -> bool {
        self.last_activity.elapsed() > self.timeout
    }

    /// Get connection duration
    pub fn duration(&self) -> Duration {
        self.start_time.elapsed()
    }
}

/// Connection result
#[derive(Debug)]
pub enum ConnectionResult {
    /// Connection established successfully
    Success(ConnectionInfo),
    /// Connection failed with reason
    Failed(String),
    /// Connection was rejected
    Rejected(String),
    /// Connection timed out
    Timeout,
}

/// Connection event
#[derive(Debug, Clone)]
pub enum ConnectionEvent {
    /// New connection established
    Connected(ConnectionInfo),
    /// Connection lost
    Disconnected(SocketAddr),
    /// Connection failed
    Failed(SocketAddr, String),
    /// Connection timeout
    Timeout(SocketAddr),
}
