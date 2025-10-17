//! P2P state management module
//!
//! This module handles P2P-specific state management including
//! peer maps, connection tracking, and reputation systems.

pub mod connection_tracker;
pub mod manager;
pub mod peer_map;
pub mod reputation;

// Re-export main types
pub use connection_tracker::ConnectionTracker;
pub use manager::{P2PStateManager, SharedP2PStateManager};
pub use peer_map::PeerMap;
pub use reputation::ReputationManager;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::SystemTime;

use crate::p2p::peer::PeerInfo;

/// P2P state structure
#[derive(Debug, Clone)]
pub struct P2PState {
    /// Map of connected peers
    pub peer_map: PeerMap,

    /// Connection tracker for monitoring connection attempts
    pub connection_tracker: ConnectionTracker,

    /// Reputation manager for peer reputation
    pub reputation_manager: ReputationManager,

    /// Disconnection times of past peers
    pub disconnection_times: HashMap<u128, SystemTime>,

    /// Instance ID for this node
    pub instance_id: u128,

    /// Whether the node is frozen (no P2P operations)
    pub freeze: bool,
}

impl P2PState {
    /// Create new P2P state
    pub fn new(instance_id: u128) -> Self {
        Self {
            peer_map: PeerMap::new(),
            connection_tracker: ConnectionTracker::new(),
            reputation_manager: ReputationManager::new(),
            disconnection_times: HashMap::new(),
            instance_id,
            freeze: false,
        }
    }

    /// Add a peer to the state
    pub fn add_peer(&mut self, peer_info: PeerInfo) {
        let address = peer_info.connected_address();
        self.peer_map.insert(address, peer_info);
    }

    /// Remove a peer from the state
    pub fn remove_peer(&mut self, address: SocketAddr) -> Option<PeerInfo> {
        self.peer_map.remove(&address)
    }

    /// Get peer by address
    pub fn get_peer(&self, address: SocketAddr) -> Option<&PeerInfo> {
        self.peer_map.get(&address)
    }

    /// Get all connected peers
    pub fn get_all_peers(&self) -> &PeerMap {
        &self.peer_map
    }

    /// Check if peer is connected
    pub fn is_peer_connected(&self, address: SocketAddr) -> bool {
        self.peer_map.contains_key(&address)
    }

    /// Get number of connected peers
    pub fn peer_count(&self) -> usize {
        self.peer_map.len()
    }

    /// Set freeze state
    pub fn set_freeze(&mut self, freeze: bool) {
        self.freeze = freeze;
    }

    /// Check if frozen
    pub fn is_frozen(&self) -> bool {
        self.freeze
    }

    /// Record disconnection time for a peer
    pub fn record_disconnection(&mut self, instance_id: u128, time: SystemTime) {
        self.disconnection_times.insert(instance_id, time);
    }

    /// Get last disconnection time for a peer
    pub fn get_last_disconnection_time(&self, instance_id: u128) -> Option<SystemTime> {
        self.disconnection_times.get(&instance_id).copied()
    }
}

/// P2P state event
#[derive(Debug, Clone)]
pub enum P2PStateEvent {
    /// Peer added
    PeerAdded(PeerInfo),
    /// Peer removed
    PeerRemoved(SocketAddr),
    /// State frozen
    StateFrozen,
    /// State unfrozen
    StateUnfrozen,
    /// Reputation updated
    ReputationUpdated(SocketAddr, f64),
}
