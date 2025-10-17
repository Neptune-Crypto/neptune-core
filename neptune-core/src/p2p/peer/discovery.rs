//! Peer discovery implementation
//!
//! This module handles peer discovery functionality.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Duration;

use crate::p2p::config::PeerConfig;

/// Peer discovery manager
#[derive(Debug)]
pub struct PeerDiscovery {
    /// Peer configuration
    config: PeerConfig,
    /// Known peer addresses
    known_peers: HashSet<SocketAddr>,
    /// Discovered peer addresses
    discovered_peers: HashSet<SocketAddr>,
}

impl PeerDiscovery {
    /// Create new peer discovery manager
    pub fn new(config: PeerConfig) -> Self {
        let mut known_peers = HashSet::new();
        for peer in &config.known_peers {
            known_peers.insert(*peer);
        }

        Self {
            config,
            known_peers,
            discovered_peers: HashSet::new(),
        }
    }

    /// Add a discovered peer
    pub fn add_discovered_peer(&mut self, address: SocketAddr) {
        self.discovered_peers.insert(address);
    }

    /// Get discovered peers
    pub fn get_discovered_peers(&self) -> &HashSet<SocketAddr> {
        &self.discovered_peers
    }

    /// Get known peers
    pub fn get_known_peers(&self) -> &HashSet<SocketAddr> {
        &self.known_peers
    }

    /// Check if peer discovery is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enable_peer_discovery
    }

    /// Get discovery interval
    pub fn discovery_interval(&self) -> Duration {
        self.config.discovery_interval
    }

    /// Get maximum peers per discovery
    pub fn max_peers_per_discovery(&self) -> usize {
        self.config.max_peers_per_discovery
    }
}
