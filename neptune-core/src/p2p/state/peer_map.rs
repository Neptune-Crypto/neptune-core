//! Peer map implementation
//!
//! This module provides a map for managing connected peers.

use std::collections::HashMap;
use std::net::SocketAddr;

use crate::p2p::peer::PeerInfo;

/// Map of connected peers
#[derive(Debug, Clone)]
pub struct PeerMap {
    /// Map of peer address to peer info
    peers: HashMap<SocketAddr, PeerInfo>,
}

impl PeerMap {
    /// Create new peer map
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
        }
    }

    /// Insert a peer
    pub fn insert(&mut self, address: SocketAddr, peer_info: PeerInfo) -> Option<PeerInfo> {
        self.peers.insert(address, peer_info)
    }

    /// Remove a peer
    pub fn remove(&mut self, address: &SocketAddr) -> Option<PeerInfo> {
        self.peers.remove(address)
    }

    /// Get a peer
    pub fn get(&self, address: &SocketAddr) -> Option<&PeerInfo> {
        self.peers.get(address)
    }

    /// Get a mutable peer
    pub fn get_mut(&mut self, address: &SocketAddr) -> Option<&mut PeerInfo> {
        self.peers.get_mut(address)
    }

    /// Check if peer exists
    pub fn contains_key(&self, address: &SocketAddr) -> bool {
        self.peers.contains_key(address)
    }

    /// Get number of peers
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Get all peer addresses
    pub fn keys(&self) -> impl Iterator<Item = &SocketAddr> {
        self.peers.keys()
    }

    /// Get all peer info
    pub fn values(&self) -> impl Iterator<Item = &PeerInfo> {
        self.peers.values()
    }

    /// Get all peer info mutably
    pub fn values_mut(&mut self) -> impl Iterator<Item = &mut PeerInfo> {
        self.peers.values_mut()
    }

    /// Get all peers as iterator
    pub fn iter(&self) -> impl Iterator<Item = (&SocketAddr, &PeerInfo)> {
        self.peers.iter()
    }

    /// Get all peers as mutable iterator
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&SocketAddr, &mut PeerInfo)> {
        self.peers.iter_mut()
    }

    /// Clear all peers
    pub fn clear(&mut self) {
        self.peers.clear();
    }

    /// Convert to HashMap
    pub fn to_hashmap(&self) -> HashMap<SocketAddr, PeerInfo> {
        self.peers.clone()
    }
}

impl Default for PeerMap {
    fn default() -> Self {
        Self::new()
    }
}
