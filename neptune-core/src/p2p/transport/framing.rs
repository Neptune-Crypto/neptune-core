//! Message framing implementation
//!
//! This module handles message framing for P2P communication.

use tokio_util::codec::LengthDelimitedCodec;

/// Message framing for P2P communication
#[derive(Debug)]
pub struct MessageFraming {
    /// Length delimited codec
    codec: LengthDelimitedCodec,
}

impl MessageFraming {
    /// Create new message framing
    pub fn new() -> Self {
        let mut codec = LengthDelimitedCodec::new();
        codec.set_max_frame_length(500 * 1024 * 1024); // 500MB
        Self { codec }
    }

    /// Get the codec
    pub fn codec(self) -> LengthDelimitedCodec {
        self.codec
    }
}

impl Default for MessageFraming {
    fn default() -> Self {
        Self::new()
    }
}
