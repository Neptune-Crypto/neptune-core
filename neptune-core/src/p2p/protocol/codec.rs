//! P2P protocol codec
//!
//! This module handles message serialization and deserialization.

use tokio_serde::formats::Bincode;
use tokio_serde::formats::SymmetricalBincode;
use tokio_serde::SymmetricallyFramed;
use tokio_util::codec::Framed;
use tokio_util::codec::LengthDelimitedCodec;

use super::PeerMessage;

/// P2P protocol codec
pub struct PeerCodec;

impl PeerCodec {
    /// Create new codec with default settings
    pub fn new() -> Self {
        Self
    }

    /// Get codec rules for message framing
    pub fn get_codec_rules() -> LengthDelimitedCodec {
        let mut codec_rules = LengthDelimitedCodec::new();
        codec_rules.set_max_frame_length(500 * 1024 * 1024); // 500MB
        codec_rules
    }

    /// Create framed codec for peer communication
    pub fn create_framed_codec<S>(
        stream: S,
    ) -> SymmetricallyFramed<
        Framed<S, LengthDelimitedCodec>,
        PeerMessage,
        Bincode<PeerMessage, PeerMessage>,
    >
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + std::fmt::Debug + Unpin,
    {
        let length_delimited = Framed::new(stream, Self::get_codec_rules());
        SymmetricallyFramed::new(length_delimited, SymmetricalBincode::default())
    }
}

impl Default for PeerCodec {
    fn default() -> Self {
        Self::new()
    }
}
