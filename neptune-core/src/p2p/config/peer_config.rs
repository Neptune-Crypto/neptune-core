//! Peer configuration for P2P networking
//!
//! This module contains configuration related to peer management,
//! discovery, and reputation.

use std::net::SocketAddr;
use std::time::Duration;

use crate::application::config::cli_args;
use crate::p2p::DEFAULT_PEER_DISCOVERY_INTERVAL_SECS;

/// Configuration for peer management
#[derive(Debug, Clone)]
pub struct PeerConfig {
    /// List of known peer addresses to connect to
    pub known_peers: Vec<SocketAddr>,

    /// Peer discovery interval
    pub discovery_interval: Duration,

    /// Whether to enable peer discovery
    pub enable_peer_discovery: bool,

    /// Maximum number of peers to discover per discovery round
    pub max_peers_per_discovery: usize,

    /// Peer tolerance threshold for bad behavior
    pub peer_tolerance: u16,

    /// Whether this node acts as a bootstrapper
    pub is_bootstrapper: bool,

    /// Maximum peer message size in bytes
    pub max_message_size: usize,

    /// Whether to enable peer reputation system
    pub enable_reputation_system: bool,

    /// Reputation decay rate (per hour)
    pub reputation_decay_rate: f64,

    /// Minimum reputation score to accept connections
    pub min_reputation_score: f64,
}

impl PeerConfig {
    /// Create peer configuration from CLI arguments
    pub fn from_cli_args(cli_args: &cli_args::Args) -> Self {
        Self {
            known_peers: cli_args.peers.clone(),
            discovery_interval: Duration::from_secs(DEFAULT_PEER_DISCOVERY_INTERVAL_SECS),
            enable_peer_discovery: true,
            max_peers_per_discovery: 10,
            peer_tolerance: cli_args.peer_tolerance,
            is_bootstrapper: cli_args.bootstrap,
            max_message_size: 500 * 1024 * 1024, // 500MB
            enable_reputation_system: true,
            reputation_decay_rate: 0.1, // 10% decay per hour
            min_reputation_score: 0.5,  // 50% minimum reputation
        }
    }

    /// Create default peer configuration
    pub fn default() -> Self {
        Self {
            known_peers: Vec::new(),
            discovery_interval: Duration::from_secs(DEFAULT_PEER_DISCOVERY_INTERVAL_SECS),
            enable_peer_discovery: true,
            max_peers_per_discovery: 10,
            peer_tolerance: 1000,
            is_bootstrapper: false,
            max_message_size: 500 * 1024 * 1024, // 500MB
            enable_reputation_system: true,
            reputation_decay_rate: 0.1,
            min_reputation_score: 0.5,
        }
    }

    /// Validate the peer configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.discovery_interval.as_secs() == 0 {
            return Err("discovery_interval must be greater than 0".to_string());
        }

        if self.max_peers_per_discovery == 0 {
            return Err("max_peers_per_discovery must be greater than 0".to_string());
        }

        if self.peer_tolerance == 0 {
            return Err("peer_tolerance must be greater than 0".to_string());
        }

        if self.max_message_size == 0 {
            return Err("max_message_size must be greater than 0".to_string());
        }

        if self.reputation_decay_rate < 0.0 || self.reputation_decay_rate > 1.0 {
            return Err("reputation_decay_rate must be between 0.0 and 1.0".to_string());
        }

        if self.min_reputation_score < 0.0 || self.min_reputation_score > 1.0 {
            return Err("min_reputation_score must be between 0.0 and 1.0".to_string());
        }

        Ok(())
    }

    /// Check if peer discovery is enabled
    pub fn is_peer_discovery_enabled(&self) -> bool {
        self.enable_peer_discovery
    }

    /// Check if reputation system is enabled
    pub fn is_reputation_system_enabled(&self) -> bool {
        self.enable_reputation_system
    }

    /// Get the maximum message size in bytes
    pub fn max_message_size_bytes(&self) -> usize {
        self.max_message_size
    }
}

impl Default for PeerConfig {
    fn default() -> Self {
        Self::default()
    }
}
