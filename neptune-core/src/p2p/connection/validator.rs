//! Connection validator implementation
//!
//! This module handles connection validation logic.

use std::net::SocketAddr;

use crate::p2p::config::ConnectionConfig;
use crate::p2p::protocol::{ConnectionRefusedReason, HandshakeData, InternalConnectionStatus};

/// Connection validator for validating incoming connections
#[derive(Debug)]
pub struct ConnectionValidator {
    /// Connection configuration
    config: ConnectionConfig,
}

impl ConnectionValidator {
    /// Create new connection validator
    pub fn new(config: ConnectionConfig) -> Self {
        Self { config }
    }

    /// Validate if connection is allowed
    pub fn validate_connection(
        &self,
        peer_address: SocketAddr,
        own_handshake: &HandshakeData,
        peer_handshake: &HandshakeData,
    ) -> InternalConnectionStatus {
        // Check if IP is banned
        if self.config.is_ip_banned(peer_address.ip()) {
            return InternalConnectionStatus::Refused(ConnectionRefusedReason::BadStanding);
        }

        // Check if peer is already connected (by instance ID)
        // This would need access to the peer map in a real implementation
        // For now, we'll skip this check

        // Check if max peers limit is reached
        // This would need access to the current peer count in a real implementation
        // For now, we'll skip this check

        // Check if max connections per IP is reached
        if let Some(max_per_ip) = self.config.max_connections_per_ip {
            // This would need access to the peer map in a real implementation
            // For now, we'll skip this check
        }

        // Check for self-connection
        if own_handshake.instance_id == peer_handshake.instance_id {
            return InternalConnectionStatus::Refused(ConnectionRefusedReason::SelfConnect);
        }

        // Check version compatibility
        if !self.versions_are_compatible(&own_handshake.version, &peer_handshake.version) {
            return InternalConnectionStatus::Refused(ConnectionRefusedReason::IncompatibleVersion);
        }

        // Check network compatibility
        if own_handshake.network != peer_handshake.network {
            return InternalConnectionStatus::Refused(ConnectionRefusedReason::NetworkMismatch);
        }

        InternalConnectionStatus::Accepted
    }

    /// Check if versions are compatible
    fn versions_are_compatible(&self, own_version: &str, other_version: &str) -> bool {
        // Simple version compatibility check
        // In a real implementation, this would use semantic versioning
        own_version == other_version
    }
}
