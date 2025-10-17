//! P2P service module
//!
//! This module provides the main P2P service that coordinates all
//! P2P networking components and provides a clean interface to the
//! rest of the system.

pub mod event_loop;
pub mod metrics;
pub mod p2p_service;

// Re-export main types
pub use event_loop::EventLoop;
pub use metrics::P2PMetrics;
pub use p2p_service::P2PService;

use std::net::SocketAddr;

use crate::p2p::peer::PeerInfo;
use crate::p2p::protocol::PeerMessage;

/// P2P service event
#[derive(Debug, Clone)]
pub enum P2PServiceEvent {
    /// Peer connected
    PeerConnected(PeerInfo),
    /// Peer disconnected
    PeerDisconnected(SocketAddr),
    /// Message received from peer
    MessageReceived(SocketAddr, PeerMessage),
    /// Service started
    ServiceStarted,
    /// Service stopped
    ServiceStopped,
    /// Service error
    ServiceError(String),
}

/// P2P service command
#[derive(Debug, Clone)]
pub enum P2PServiceCommand {
    /// Start the P2P service
    Start,
    /// Stop the P2P service
    Stop,
    /// Connect to a peer
    ConnectToPeer(SocketAddr),
    /// Disconnect from a peer
    DisconnectFromPeer(SocketAddr),
    /// Send message to peer
    SendMessage(SocketAddr, PeerMessage),
    /// Broadcast message to all peers
    BroadcastMessage(PeerMessage),
    /// Ban a peer
    BanPeer(SocketAddr),
    /// Unban a peer
    UnbanPeer(SocketAddr),
    /// Get peer information
    GetPeerInfo(SocketAddr),
    /// Get all peers
    GetAllPeers,
    /// Get service status
    GetStatus,
}

/// P2P service response
#[derive(Debug, Clone)]
pub enum P2PServiceResponse {
    /// Service started
    Started,
    /// Service stopped
    Stopped,
    /// Peer connected
    PeerConnected(PeerInfo),
    /// Peer disconnected
    PeerDisconnected(SocketAddr),
    /// Message sent
    MessageSent(SocketAddr),
    /// Message broadcasted
    MessageBroadcasted,
    /// Peer banned
    PeerBanned(SocketAddr),
    /// Peer unbanned
    PeerUnbanned(SocketAddr),
    /// Peer information
    PeerInfo(Option<PeerInfo>),
    /// All peers
    AllPeers(Vec<PeerInfo>),
    /// Service status
    Status(P2PServiceStatus),
    /// Error
    Error(String),
}

/// P2P service status
#[derive(Debug, Clone)]
pub struct P2PServiceStatus {
    /// Whether the service is running
    pub is_running: bool,
    /// Number of connected peers
    pub connected_peers: usize,
    /// Number of active connections
    pub active_connections: usize,
    /// Service uptime
    pub uptime: std::time::Duration,
    /// Last activity time
    pub last_activity: std::time::SystemTime,
}

/// P2P service interface
pub trait P2PServiceInterface {
    /// Start the P2P service
    async fn start(&mut self) -> Result<(), String>;

    /// Stop the P2P service
    async fn stop(&mut self) -> Result<(), String>;

    /// Connect to a peer
    async fn connect_to_peer(&mut self, address: SocketAddr) -> Result<(), String>;

    /// Disconnect from a peer
    async fn disconnect_from_peer(&mut self, address: SocketAddr) -> Result<(), String>;

    /// Send message to peer
    async fn send_message(
        &mut self,
        address: SocketAddr,
        message: PeerMessage,
    ) -> Result<(), String>;

    /// Broadcast message to all peers
    async fn broadcast_message(&mut self, message: PeerMessage) -> Result<(), String>;

    /// Get peer information
    async fn get_peer_info(&self, address: SocketAddr) -> Option<PeerInfo>;

    /// Get all connected peers
    async fn get_all_peers(&self) -> Vec<PeerInfo>;

    /// Get service status
    async fn get_status(&self) -> P2PServiceStatus;
}
