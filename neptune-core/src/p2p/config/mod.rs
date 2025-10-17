//! P2P configuration module
//!
//! This module contains all P2P-specific configuration structures and
//! extraction logic from CLI arguments.

pub mod connection_config;
pub mod peer_config;
pub mod protocol_config;

pub use connection_config::ConnectionConfig;
pub use peer_config::PeerConfig;
pub use protocol_config::ProtocolConfig;

use crate::application::config::cli_args;

/// Main P2P configuration structure
#[derive(Debug, Clone)]
pub struct P2PConfig {
    /// Connection-related configuration
    pub connection: ConnectionConfig,
    /// Peer management configuration
    pub peer: PeerConfig,
    /// Protocol-specific configuration
    pub protocol: ProtocolConfig,
}

impl P2PConfig {
    /// Create P2P configuration from CLI arguments
    pub fn from_cli_args(cli_args: &cli_args::Args) -> Self {
        Self {
            connection: ConnectionConfig::from_cli_args(cli_args),
            peer: PeerConfig::from_cli_args(cli_args),
            protocol: ProtocolConfig::default(),
        }
    }

    /// Create default P2P configuration
    pub fn default() -> Self {
        Self {
            connection: ConnectionConfig::default(),
            peer: PeerConfig::default(),
            protocol: ProtocolConfig::default(),
        }
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), String> {
        self.connection.validate()?;
        self.peer.validate()?;
        self.protocol.validate()?;
        Ok(())
    }
}

impl Default for P2PConfig {
    fn default() -> Self {
        Self::default()
    }
}
