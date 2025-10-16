//! Connection validator implementation
//!
//! This module handles comprehensive connection validation with DDoS protection.

use std::net::SocketAddr;

use crate::p2p::config::ConnectionConfig;
use crate::p2p::protocol::{ConnectionRefusedReason, HandshakeData, InternalConnectionStatus};
use crate::p2p::state::connection_tracker::ConnectionTracker;
use crate::p2p::state::reputation::{BehaviorEvent, ReputationManager};

/// Connection validator for validating incoming connections with DDoS protection
#[derive(Debug)]
pub struct ConnectionValidator {
    /// Connection configuration
    config: ConnectionConfig,
}

/// Validation result with detailed reason
#[derive(Debug, Clone)]
pub enum ValidationResult {
    /// Connection allowed
    Allowed,
    /// Connection refused with reason
    Refused(ConnectionRefusedReason, String),
}

impl ConnectionValidator {
    /// Create new connection validator
    pub fn new(config: ConnectionConfig) -> Self {
        Self { config }
    }

    /// Comprehensive connection validation with DDoS protection
    pub fn validate_connection_comprehensive(
        &self,
        peer_address: SocketAddr,
        own_handshake: &HandshakeData,
        peer_handshake: &HandshakeData,
        rate_limiter: &mut ConnectionTracker,
        reputation_manager: &mut ReputationManager,
        current_peer_count: usize,
        connections_from_ip: usize,
    ) -> ValidationResult {
        let ip = peer_address.ip();

        // Phase 1: Rate Limiting Check
        if let Err(reason) = rate_limiter.should_allow_connection(ip) {
            tracing::warn!("Connection from {} rejected: {}", peer_address, reason);
            reputation_manager.record_behavior(ip, BehaviorEvent::RateLimitViolation);
            return ValidationResult::Refused(
                ConnectionRefusedReason::BadStanding,
                format!("Rate limit: {}", reason),
            );
        }

        // Phase 2: Reputation Check
        if let Err(reason) = reputation_manager.should_allow_connection(ip) {
            tracing::warn!("Connection from {} rejected: {}", peer_address, reason);
            return ValidationResult::Refused(
                ConnectionRefusedReason::BadStanding,
                format!("Reputation: {}", reason),
            );
        }

        // Phase 3: Static Ban Check
        if self.config.is_ip_banned(ip) {
            tracing::warn!(
                "Connection from {} rejected: IP banned in config",
                peer_address
            );
            reputation_manager.record_behavior(ip, BehaviorEvent::FailedConnection);
            return ValidationResult::Refused(
                ConnectionRefusedReason::BadStanding,
                "IP banned in configuration".to_string(),
            );
        }

        // Phase 4: Max Peers Limit
        if let Some(max_peers) = self.config.max_peers {
            if current_peer_count >= max_peers {
                tracing::debug!(
                    "Connection from {} rejected: Max peers reached ({}/{})",
                    peer_address,
                    current_peer_count,
                    max_peers
                );
                reputation_manager.record_behavior(ip, BehaviorEvent::FailedConnection);
                return ValidationResult::Refused(
                    ConnectionRefusedReason::MaxPeerNumberExceeded,
                    format!("Max peers reached: {}/{}", current_peer_count, max_peers),
                );
            }
        }

        // Phase 5: Max Connections Per IP
        if let Some(max_per_ip) = self.config.max_connections_per_ip {
            if connections_from_ip >= max_per_ip {
                tracing::warn!(
                    "Connection from {} rejected: Too many connections from this IP ({}/{})",
                    peer_address,
                    connections_from_ip,
                    max_per_ip
                );
                reputation_manager.record_behavior(ip, BehaviorEvent::RateLimitViolation);
                return ValidationResult::Refused(
                    ConnectionRefusedReason::MaxPeerNumberExceeded,
                    format!(
                        "Too many connections from IP: {}/{}",
                        connections_from_ip, max_per_ip
                    ),
                );
            }
        }

        // Phase 6: Self-Connection Check
        if own_handshake.instance_id == peer_handshake.instance_id {
            tracing::debug!("Connection from {} rejected: Self-connection", peer_address);
            return ValidationResult::Refused(
                ConnectionRefusedReason::SelfConnect,
                "Self-connection not allowed".to_string(),
            );
        }

        // Phase 7: Network Compatibility
        if own_handshake.network != peer_handshake.network {
            tracing::warn!(
                "Connection from {} rejected: Network mismatch ({} vs {})",
                peer_address,
                own_handshake.network,
                peer_handshake.network
            );
            reputation_manager.record_behavior(ip, BehaviorEvent::ProtocolViolation);
            return ValidationResult::Refused(
                ConnectionRefusedReason::NetworkMismatch,
                format!(
                    "Network mismatch: {} vs {}",
                    own_handshake.network, peer_handshake.network
                ),
            );
        }

        // Phase 8: Version Compatibility
        if !self.versions_are_compatible(&own_handshake.version, &peer_handshake.version) {
            tracing::info!(
                "Connection from {} rejected: Incompatible version ({} vs {})",
                peer_address,
                own_handshake.version,
                peer_handshake.version
            );
            reputation_manager.record_behavior(ip, BehaviorEvent::FailedConnection);
            return ValidationResult::Refused(
                ConnectionRefusedReason::IncompatibleVersion,
                format!(
                    "Incompatible version: {} vs {}",
                    own_handshake.version, peer_handshake.version
                ),
            );
        }

        // All checks passed - record successful validation
        tracing::debug!("Connection from {} validated successfully", peer_address);
        reputation_manager.record_behavior(ip, BehaviorEvent::SuccessfulConnection);

        ValidationResult::Allowed
    }

    /// Legacy validation method (for backward compatibility)
    pub fn validate_connection(
        &self,
        peer_address: SocketAddr,
        own_handshake: &HandshakeData,
        peer_handshake: &HandshakeData,
    ) -> InternalConnectionStatus {
        let ip = peer_address.ip();

        // Basic checks without DDoS protection
        if self.config.is_ip_banned(ip) {
            return InternalConnectionStatus::Refused(ConnectionRefusedReason::BadStanding);
        }

        if own_handshake.instance_id == peer_handshake.instance_id {
            return InternalConnectionStatus::Refused(ConnectionRefusedReason::SelfConnect);
        }

        if !self.versions_are_compatible(&own_handshake.version, &peer_handshake.version) {
            return InternalConnectionStatus::Refused(ConnectionRefusedReason::IncompatibleVersion);
        }

        if own_handshake.network != peer_handshake.network {
            return InternalConnectionStatus::Refused(ConnectionRefusedReason::NetworkMismatch);
        }

        InternalConnectionStatus::Accepted
    }

    /// Check if versions are compatible
    fn versions_are_compatible(&self, own_version: &str, other_version: &str) -> bool {
        // Neptune uses semantic versioning compatibility
        // For now, we'll accept same major version
        let own_major = own_version.split('.').next().unwrap_or("0");
        let other_major = other_version.split('.').next().unwrap_or("0");
        own_major == other_major
    }

    /// Get connection configuration
    pub fn get_config(&self) -> &ConnectionConfig {
        &self.config
    }
}

impl ValidationResult {
    /// Check if validation passed
    pub fn is_allowed(&self) -> bool {
        matches!(self, ValidationResult::Allowed)
    }

    /// Get refusal reason if refused
    pub fn refusal_reason(&self) -> Option<(ConnectionRefusedReason, &str)> {
        match self {
            ValidationResult::Refused(reason, msg) => Some((*reason, msg.as_str())),
            ValidationResult::Allowed => None,
        }
    }

    /// Convert to InternalConnectionStatus
    pub fn to_connection_status(self) -> InternalConnectionStatus {
        match self {
            ValidationResult::Allowed => InternalConnectionStatus::Accepted,
            ValidationResult::Refused(reason, _) => InternalConnectionStatus::Refused(reason),
        }
    }
}
