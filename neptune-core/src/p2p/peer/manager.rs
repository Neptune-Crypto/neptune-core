//! Peer manager implementation
//!
//! This module provides peer lifecycle management functionality.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::SystemTime;

use super::{PeerInfo, PeerState};
use crate::p2p::config::PeerConfig;

/// Peer manager for handling peer lifecycle
#[derive(Debug)]
pub struct PeerManager {
    /// Peer configuration
    config: PeerConfig,
    /// Map of peer states
    peer_states: HashMap<SocketAddr, PeerState>,
    /// Map of peer information
    peer_info: HashMap<SocketAddr, PeerInfo>,
}

impl PeerManager {
    /// Create new peer manager
    pub fn new(config: PeerConfig) -> Self {
        Self {
            config,
            peer_states: HashMap::new(),
            peer_info: HashMap::new(),
        }
    }

    /// Add a peer
    pub fn add_peer(&mut self, peer_info: PeerInfo) {
        let address = peer_info.connected_address();
        self.peer_info.insert(address, peer_info);
        self.peer_states.insert(address, PeerState::Connected);
    }

    /// Remove a peer
    pub fn remove_peer(&mut self, address: SocketAddr) -> Option<PeerInfo> {
        self.peer_states.remove(&address);
        self.peer_info.remove(&address)
    }

    /// Get peer info
    pub fn get_peer_info(&self, address: SocketAddr) -> Option<&PeerInfo> {
        self.peer_info.get(&address)
    }

    /// Get peer state
    pub fn get_peer_state(&self, address: SocketAddr) -> Option<&PeerState> {
        self.peer_states.get(&address)
    }

    /// Update peer state
    pub fn update_peer_state(&mut self, address: SocketAddr, state: PeerState) {
        self.peer_states.insert(address, state);
    }

    /// Get all peers
    pub fn get_all_peers(&self) -> &HashMap<SocketAddr, PeerInfo> {
        &self.peer_info
    }

    /// Get peer count
    pub fn peer_count(&self) -> usize {
        self.peer_info.len()
    }

    /// Check if peer exists
    pub fn has_peer(&self, address: SocketAddr) -> bool {
        self.peer_info.contains_key(&address)
    }
}
