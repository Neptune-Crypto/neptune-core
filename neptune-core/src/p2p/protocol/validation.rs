//! P2P protocol message validation
//!
//! This module handles validation of P2P protocol messages.

use std::net::SocketAddr;

use super::PeerMessage;

/// P2P protocol message validator
#[derive(Debug)]
pub struct MessageValidator {
    /// Validation configuration
    config: ValidationConfig,
}

/// Validation configuration
#[derive(Debug, Clone)]
pub struct ValidationConfig {
    /// Maximum message size
    pub max_message_size: usize,
    /// Whether to validate message format
    pub validate_format: bool,
    /// Whether to validate message content
    pub validate_content: bool,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            max_message_size: 500 * 1024 * 1024, // 500MB
            validate_format: true,
            validate_content: true,
        }
    }
}

impl MessageValidator {
    /// Create new message validator
    pub fn new(config: ValidationConfig) -> Self {
        Self { config }
    }

    /// Validate incoming message
    pub fn validate_message(
        &self,
        peer_address: SocketAddr,
        message: &PeerMessage,
    ) -> Result<(), String> {
        if self.config.validate_format {
            self.validate_message_format(message)?;
        }

        if self.config.validate_content {
            self.validate_message_content(peer_address, message)?;
        }

        Ok(())
    }

    /// Validate message format
    fn validate_message_format(&self, message: &PeerMessage) -> Result<(), String> {
        match message {
            PeerMessage::Handshake { magic_value, data } => {
                if magic_value.len() != 15 {
                    return Err("Invalid magic value length".to_string());
                }
                if data.version.is_empty() {
                    return Err("Empty version string".to_string());
                }
            }
            _ => {
                // Basic validation for other message types
            }
        }
        Ok(())
    }

    /// Validate message content
    fn validate_message_content(
        &self,
        peer_address: SocketAddr,
        message: &PeerMessage,
    ) -> Result<(), String> {
        match message {
            PeerMessage::Handshake { data, .. } => {
                if data.instance_id == 0 {
                    return Err("Invalid instance ID".to_string());
                }
            }
            _ => {
                // Content validation for other message types
            }
        }
        Ok(())
    }
}

impl Default for MessageValidator {
    fn default() -> Self {
        Self::new(ValidationConfig::default())
    }
}
