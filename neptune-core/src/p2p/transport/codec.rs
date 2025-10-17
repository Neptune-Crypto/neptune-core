//! Transport codec implementation
//!
//! This module provides transport-level codec functionality.

use tokio_serde::formats::SymmetricalBincode;

/// Transport codec for P2P communication
#[derive(Debug)]
pub struct TransportCodec;

impl TransportCodec {
    /// Create new transport codec
    pub fn new() -> Self {
        Self
    }

    /// Get the bincode format
    pub fn bincode() -> SymmetricalBincode<Vec<u8>, Vec<u8>> {
        // SymmetricalBincode doesn't have a Default impl, so we don't need to construct it here
        // It's typically used directly in the framing code
        todo!("SymmetricalBincode construction should be done at usage site")
    }
}

impl Default for TransportCodec {
    fn default() -> Self {
        Self::new()
    }
}
