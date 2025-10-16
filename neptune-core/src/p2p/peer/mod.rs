//! Peer management module for P2P networking
//!
//! This module handles peer lifecycle, information, reputation,
//! and discovery.

pub mod discovery;
pub mod info;
pub mod manager;
pub mod standing;

// Re-export main types
pub use discovery::PeerDiscovery;
pub use info::PeerInfo;
pub use manager::PeerManager;
pub use standing::PeerStanding;

use std::net::SocketAddr;
use std::time::SystemTime;

/// Peer state enumeration
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerState {
    /// Peer is being discovered
    Discovering,
    /// Connection is being established
    Connecting,
    /// Handshake is in progress
    Handshaking,
    /// Peer is connected and active
    Connected,
    /// Peer is being disconnected
    Disconnecting,
    /// Peer is disconnected
    Disconnected,
    /// Peer is banned
    Banned,
}

/// Peer connection information
#[derive(Debug, Clone)]
pub struct PeerConnectionInfo {
    /// Port for incoming connections (if any)
    pub port_for_incoming_connections: Option<u16>,
    /// Connected address
    pub connected_address: SocketAddr,
    /// Whether this is an inbound connection
    pub inbound: bool,
}

impl PeerConnectionInfo {
    /// Create new peer connection info
    pub fn new(
        port_for_incoming_connections: Option<u16>,
        connected_address: SocketAddr,
        inbound: bool,
    ) -> Self {
        Self {
            port_for_incoming_connections,
            connected_address,
            inbound,
        }
    }

    /// Get the listen address if peer accepts incoming connections
    pub fn listen_address(&self) -> Option<SocketAddr> {
        self.port_for_incoming_connections
            .map(|port| SocketAddr::new(self.connected_address.ip(), port))
    }
}

/// Peer event
#[derive(Debug, Clone)]
pub enum PeerEvent {
    /// New peer discovered
    Discovered(SocketAddr),
    /// Peer connected
    Connected(PeerInfo),
    /// Peer disconnected
    Disconnected(SocketAddr),
    /// Peer banned
    Banned(SocketAddr, String),
    /// Peer reputation changed
    ReputationChanged(SocketAddr, PeerStanding),
}
