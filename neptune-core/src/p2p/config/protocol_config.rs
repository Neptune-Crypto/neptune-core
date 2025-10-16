//! Protocol configuration for P2P networking
//!
//! This module contains configuration related to the P2P protocol,
//! message handling, and protocol-specific settings.

use std::time::Duration;

/// Configuration for P2P protocol
#[derive(Debug, Clone)]
pub struct ProtocolConfig {
    /// Protocol version
    pub version: String,

    /// Magic string for protocol identification
    pub magic_string_request: [u8; 15],

    /// Magic string for protocol response
    pub magic_string_response: [u8; 15],

    /// Maximum number of blocks in a batch request
    pub max_blocks_per_batch: usize,

    /// Maximum number of transactions in a batch
    pub max_transactions_per_batch: usize,

    /// Message processing timeout
    pub message_processing_timeout: Duration,

    /// Whether to enable message compression
    pub enable_compression: bool,

    /// Whether to enable message encryption
    pub enable_encryption: bool,

    /// Maximum number of pending requests per peer
    pub max_pending_requests_per_peer: usize,

    /// Request timeout duration
    pub request_timeout: Duration,

    /// Whether to enable protocol metrics
    pub enable_metrics: bool,
}

impl ProtocolConfig {
    /// Create default protocol configuration
    pub fn default() -> Self {
        Self {
            version: "1.0.0".to_string(),
            magic_string_request: *b"neptune-request",
            magic_string_response: *b"neptune-respons",
            max_blocks_per_batch: 200,
            max_transactions_per_batch: 1000,
            message_processing_timeout: Duration::from_secs(30),
            enable_compression: false,
            enable_encryption: false,
            max_pending_requests_per_peer: 10,
            request_timeout: Duration::from_secs(60),
            enable_metrics: true,
        }
    }

    /// Validate the protocol configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.version.is_empty() {
            return Err("protocol version cannot be empty".to_string());
        }

        if self.max_blocks_per_batch == 0 {
            return Err("max_blocks_per_batch must be greater than 0".to_string());
        }

        if self.max_transactions_per_batch == 0 {
            return Err("max_transactions_per_batch must be greater than 0".to_string());
        }

        if self.message_processing_timeout.as_secs() == 0 {
            return Err("message_processing_timeout must be greater than 0".to_string());
        }

        if self.max_pending_requests_per_peer == 0 {
            return Err("max_pending_requests_per_peer must be greater than 0".to_string());
        }

        if self.request_timeout.as_secs() == 0 {
            return Err("request_timeout must be greater than 0".to_string());
        }

        Ok(())
    }

    /// Check if compression is enabled
    pub fn is_compression_enabled(&self) -> bool {
        self.enable_compression
    }

    /// Check if encryption is enabled
    pub fn is_encryption_enabled(&self) -> bool {
        self.enable_encryption
    }

    /// Check if metrics are enabled
    pub fn is_metrics_enabled(&self) -> bool {
        self.enable_metrics
    }

    /// Get the protocol version
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Get the magic string for requests
    pub fn magic_string_request(&self) -> &[u8; 15] {
        &self.magic_string_request
    }

    /// Get the magic string for responses
    pub fn magic_string_response(&self) -> &[u8; 15] {
        &self.magic_string_response
    }
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        Self::default()
    }
}
