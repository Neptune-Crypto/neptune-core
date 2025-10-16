//! Connection manager implementation
//!
//! This module provides connection lifecycle management.

use std::net::SocketAddr;

use super::{ConnectionInfo, ConnectionState};
use crate::p2p::config::ConnectionConfig;

/// Connection manager for handling connection lifecycle
#[derive(Debug)]
pub struct ConnectionManager {
    /// Connection configuration
    config: ConnectionConfig,
    /// Active connections
    active_connections: std::collections::HashMap<SocketAddr, ConnectionInfo>,
}

impl ConnectionManager {
    /// Create new connection manager
    pub fn new(config: ConnectionConfig) -> Self {
        Self {
            config,
            active_connections: std::collections::HashMap::new(),
        }
    }

    /// Add a new connection
    pub fn add_connection(&mut self, connection_info: ConnectionInfo) {
        let address = connection_info.peer_address;
        self.active_connections.insert(address, connection_info);
    }

    /// Remove a connection
    pub fn remove_connection(&mut self, address: SocketAddr) -> Option<ConnectionInfo> {
        self.active_connections.remove(&address)
    }

    /// Get connection info
    pub fn get_connection(&self, address: SocketAddr) -> Option<&ConnectionInfo> {
        self.active_connections.get(&address)
    }

    /// Update connection state
    pub fn update_connection_state(&mut self, address: SocketAddr, state: ConnectionState) {
        if let Some(connection) = self.active_connections.get_mut(&address) {
            connection.state = state;
        }
    }

    /// Get active connection count
    pub fn active_connection_count(&self) -> usize {
        self.active_connections.len()
    }

    /// Check if connection exists
    pub fn has_connection(&self, address: SocketAddr) -> bool {
        self.active_connections.contains_key(&address)
    }

    /// Get all active connections
    pub fn get_all_connections(&self) -> &std::collections::HashMap<SocketAddr, ConnectionInfo> {
        &self.active_connections
    }

    /// Cleanup timed out connections
    pub fn cleanup_timed_out_connections(&mut self) -> Vec<SocketAddr> {
        let mut timed_out = Vec::new();
        let mut to_remove = Vec::new();

        for (address, connection) in &self.active_connections {
            if connection.is_timed_out() {
                to_remove.push(*address);
                timed_out.push(*address);
            }
        }

        for address in to_remove {
            self.active_connections.remove(&address);
        }

        timed_out
    }
}
