//! Connection configuration for P2P networking
//!
//! This module contains configuration related to connection management,
//! timeouts, and connection limits.

use std::net::IpAddr;
use std::time::Duration;

use crate::application::config::cli_args;
use crate::p2p::{
    DEFAULT_CONNECTION_RATE_LIMIT_PER_MINUTE, DEFAULT_CONNECTION_TIMEOUT_SECS,
    DEFAULT_HANDSHAKE_TIMEOUT_SECS, DEFAULT_MAX_CONNECTIONS_PER_IP,
};

/// Configuration for connection management
#[derive(Debug, Clone)]
pub struct ConnectionConfig {
    /// Maximum number of peers to accept connections from
    pub max_num_peers: usize,

    /// Maximum number of connections per IP address
    pub max_connections_per_ip: Option<usize>,

    /// Connection timeout duration
    pub connection_timeout: Duration,

    /// Handshake timeout duration
    pub handshake_timeout: Duration,

    /// Rate limit for connection attempts per IP per minute
    pub connection_rate_limit_per_minute: usize,

    /// Whether to restrict peers to the provided list
    pub restrict_peers_to_list: bool,

    /// List of banned IP addresses
    pub banned_ips: Vec<IpAddr>,

    /// Reconnect cooldown duration
    pub reconnect_cooldown: Duration,

    /// Whether to allow incoming connections
    pub allow_incoming_connections: bool,

    /// Peer listen address
    pub peer_listen_addr: IpAddr,

    /// Own listen port (if accepting incoming connections)
    pub own_listen_port: Option<u16>,
}

impl ConnectionConfig {
    /// Create connection configuration from CLI arguments
    pub fn from_cli_args(cli_args: &cli_args::Args) -> Self {
        Self {
            max_num_peers: cli_args.max_num_peers,
            max_connections_per_ip: cli_args.max_connections_per_ip,
            connection_timeout: Duration::from_secs(DEFAULT_CONNECTION_TIMEOUT_SECS),
            handshake_timeout: Duration::from_secs(DEFAULT_HANDSHAKE_TIMEOUT_SECS),
            connection_rate_limit_per_minute: DEFAULT_CONNECTION_RATE_LIMIT_PER_MINUTE,
            restrict_peers_to_list: cli_args.restrict_peers_to_list,
            banned_ips: cli_args.ban.clone(),
            reconnect_cooldown: cli_args.reconnect_cooldown,
            allow_incoming_connections: cli_args.own_listen_port().is_some(),
            peer_listen_addr: cli_args.peer_listen_addr,
            own_listen_port: cli_args.own_listen_port(),
        }
    }

    /// Create default connection configuration
    pub fn default() -> Self {
        Self {
            max_num_peers: 10,
            max_connections_per_ip: Some(DEFAULT_MAX_CONNECTIONS_PER_IP),
            connection_timeout: Duration::from_secs(DEFAULT_CONNECTION_TIMEOUT_SECS),
            handshake_timeout: Duration::from_secs(DEFAULT_HANDSHAKE_TIMEOUT_SECS),
            connection_rate_limit_per_minute: DEFAULT_CONNECTION_RATE_LIMIT_PER_MINUTE,
            restrict_peers_to_list: false,
            banned_ips: Vec::new(),
            reconnect_cooldown: Duration::from_secs(60),
            allow_incoming_connections: true,
            peer_listen_addr: "0.0.0.0".parse().unwrap(),
            own_listen_port: Some(9798),
        }
    }

    /// Validate the connection configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.max_num_peers == 0 {
            return Err("max_num_peers must be greater than 0".to_string());
        }

        if let Some(max_per_ip) = self.max_connections_per_ip {
            if max_per_ip == 0 {
                return Err("max_connections_per_ip must be greater than 0".to_string());
            }
            if max_per_ip > self.max_num_peers {
                return Err(
                    "max_connections_per_ip cannot be greater than max_num_peers".to_string(),
                );
            }
        }

        if self.connection_timeout.as_secs() == 0 {
            return Err("connection_timeout must be greater than 0".to_string());
        }

        if self.handshake_timeout.as_secs() == 0 {
            return Err("handshake_timeout must be greater than 0".to_string());
        }

        if self.connection_rate_limit_per_minute == 0 {
            return Err("connection_rate_limit_per_minute must be greater than 0".to_string());
        }

        Ok(())
    }

    /// Check if an IP address is banned
    pub fn is_ip_banned(&self, ip: IpAddr) -> bool {
        self.banned_ips.contains(&ip)
    }

    /// Check if incoming connections are allowed
    pub fn allows_incoming_connections(&self) -> bool {
        self.allow_incoming_connections && self.own_listen_port.is_some()
    }
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self::default()
    }
}
