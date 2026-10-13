//! Length-delimited framing of peer messages with a size limit per kind of
//! message.
//!
//! A frame is a big-endian `u32` length followed by that many bytes of one
//! encoded PeerMessage. The codec reads the kind of message from the first
//! bytes of the payload and refuses the frame as soon as its announced length
//! exceeds what a message of that kind can legitimately need, long before the
//! whole frame has been received and buffered.

use std::io;

use bincode::Options;
use bytes::Bytes;
use bytes::BytesMut;
use neptune_p2p::peer::PeerMessageKind;
use tokio_util::codec::Decoder;
use tokio_util::codec::Encoder;
use tokio_util::codec::LengthDelimitedCodec;

use crate::application::loops::connect_to_peers::bincode_options;
use crate::application::loops::connect_to_peers::MAX_PEER_FRAME_LENGTH_IN_BYTES;
use crate::application::network::handshake::WireEncoding;

/// Size of the length prefix of a frame, as [`LengthDelimitedCodec`] writes
/// it by default.
const LENGTH_FIELD_LEN: usize = 4;

/// Payload bytes that suffice to read the kind of message. A bincode variant
/// index takes at most five bytes; a JSON frame starts with the variant name
/// in quotes, inside an object unless the variant is a unit.
const KIND_PEEK_LEN: usize = 64;

/// Factor by which a JSON encoding of a message may exceed its bincode
/// encoding. Field elements are up to twenty decimal digits and a comma in
/// JSON, against nine bytes as bincode.
const JSON_SIZE_FACTOR: usize = 3;

pub(crate) struct PeerFrameCodec {
    inner: LengthDelimitedCodec,
    encoding: WireEncoding,

    /// Whether the frame being received has passed the check against the
    /// limit for its kind.
    checked: bool,
}

impl PeerFrameCodec {
    pub(crate) fn new(encoding: WireEncoding) -> Self {
        let mut inner = LengthDelimitedCodec::new();
        inner.set_max_frame_length(MAX_PEER_FRAME_LENGTH_IN_BYTES);
        Self {
            inner,
            encoding,
            checked: false,
        }
    }

    /// The most bytes a frame carrying a message of the given kind may have.
    fn frame_limit(&self, kind: PeerMessageKind) -> usize {
        let Some(limit) = kind.max_frame_length() else {
            return MAX_PEER_FRAME_LENGTH_IN_BYTES;
        };
        let limit = match self.encoding {
            WireEncoding::Bincode => limit,
            WireEncoding::Json => limit.saturating_mul(JSON_SIZE_FACTOR),
        };
        limit.min(MAX_PEER_FRAME_LENGTH_IN_BYTES)
    }

    /// The kind of message that a frame starting with the given payload bytes
    /// carries.
    fn peek_kind(&self, payload: &[u8]) -> io::Result<PeerMessageKind> {
        let kind = match self.encoding {
            // Only the tag is read; the payload continues after it.
            WireEncoding::Bincode => bincode_options()
                .deserialize_from::<_, u32>(payload)
                .ok()
                .and_then(PeerMessageKind::from_bincode_tag),
            WireEncoding::Json => json_variant_name(payload).and_then(|name| name.parse().ok()),
        };
        kind.ok_or_else(|| invalid_data("frame does not start with a known kind of message"))
    }

    /// Check the frame whose length prefix and first payload bytes are in
    /// `src`. Returns `Ok(false)` if more bytes are needed to decide.
    fn check(&mut self, src: &[u8]) -> io::Result<bool> {
        let Some(length_field) = src.get(..LENGTH_FIELD_LEN) else {
            return Ok(false);
        };
        let frame_len = u32::from_be_bytes(length_field.try_into().unwrap()) as usize;
        let payload = &src[LENGTH_FIELD_LEN..];
        let peek_len = frame_len.min(KIND_PEEK_LEN);
        let available = &payload[..payload.len().min(peek_len)];

        // The kind is usually clear from the first byte or few. Only wait for
        // more bytes while they could still complete the tag.
        let kind = match self.peek_kind(available) {
            Ok(kind) => kind,
            Err(_) if available.len() < peek_len => return Ok(false),
            Err(error) => return Err(error),
        };
        let limit = self.frame_limit(kind);
        if frame_len > limit {
            return Err(invalid_data(format!(
                "{kind} message of {frame_len} bytes exceeds the limit of {limit} bytes"
            )));
        }

        Ok(true)
    }
}

/// The variant name that starts a JSON encoding of an externally tagged enum:
/// `"Name"` for a unit variant, `{"Name":` otherwise. The bytes may end
/// anywhere after the name.
fn json_variant_name(bytes: &[u8]) -> Option<&str> {
    let text = match std::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(error) => std::str::from_utf8(&bytes[..error.valid_up_to()]).ok()?,
    };
    let text = text.trim_start();
    let text = text.strip_prefix('{').map_or(text, str::trim_start);
    let name = text.strip_prefix('"')?;
    let end = name.find('"')?;
    Some(&name[..end])
}

fn invalid_data(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

impl Decoder for PeerFrameCodec {
    type Item = BytesMut;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> io::Result<Option<BytesMut>> {
        if !self.checked {
            if !self.check(src)? {
                return Ok(None);
            }
            self.checked = true;
        }

        let frame = self.inner.decode(src)?;
        if frame.is_some() {
            self.checked = false;
        }

        Ok(frame)
    }
}

impl Encoder<Bytes> for PeerFrameCodec {
    type Error = io::Error;

    fn encode(&mut self, item: Bytes, dst: &mut BytesMut) -> io::Result<()> {
        self.inner.encode(item, dst)
    }
}

#[cfg(test)]
mod tests {
    use neptune_p2p::peer::PeerMessage;

    use super::*;

    /// A frame announcing `frame_len` payload bytes, of which only the
    /// encoding of `message` is present.
    fn frame_start(encoding: WireEncoding, message: &PeerMessage, frame_len: u32) -> BytesMut {
        let payload = match encoding {
            WireEncoding::Bincode => bincode_options().serialize(message).unwrap(),
            WireEncoding::Json => serde_json::to_vec(message).unwrap(),
        };
        let mut frame = BytesMut::new();
        frame.extend_from_slice(&frame_len.to_be_bytes());
        frame.extend_from_slice(&payload);
        frame
    }

    fn whole_frame(encoding: WireEncoding, message: &PeerMessage) -> BytesMut {
        let payload_len = frame_start(encoding, message, 0).len() - LENGTH_FIELD_LEN;
        frame_start(encoding, message, payload_len as u32)
    }

    #[test]
    fn whole_frames_decode_in_every_encoding() {
        for encoding in WireEncoding::SUPPORTED {
            let mut codec = PeerFrameCodec::new(encoding);
            for message in [
                PeerMessage::Bye,
                PeerMessage::BlockRequestByHeight(7u64.into()),
            ] {
                let mut src = whole_frame(encoding, &message);
                let expected = src[LENGTH_FIELD_LEN..].to_vec();
                let frame = codec.decode(&mut src).unwrap().unwrap();
                assert_eq!(expected, frame.to_vec());
                assert!(src.is_empty());
            }
        }
    }

    #[test]
    fn a_frame_is_decoded_once_all_its_bytes_arrived() {
        for encoding in WireEncoding::SUPPORTED {
            let mut codec = PeerFrameCodec::new(encoding);
            let whole = whole_frame(encoding, &PeerMessage::BlockRequestByHeight(7u64.into()));
            for cut in 0..whole.len() {
                let mut src = BytesMut::from(&whole[..cut]);
                assert!(codec.decode(&mut src).unwrap().is_none(), "{cut} bytes");
                src.extend_from_slice(&whole[cut..]);
                assert!(codec.decode(&mut src).unwrap().is_some(), "{cut} bytes");
            }
        }
    }

    #[test]
    fn an_oversized_frame_is_refused_before_it_arrived() {
        for encoding in WireEncoding::SUPPORTED {
            let mut codec = PeerFrameCodec::new(encoding);
            let claimed = 100 * 1024 * 1024;
            let mut src = frame_start(encoding, &PeerMessage::Bye, claimed);
            let error = codec.decode(&mut src).unwrap_err();
            assert_eq!(io::ErrorKind::InvalidData, error.kind());
            assert!(error.to_string().contains("Bye message"), "{error}");
        }
    }

    #[test]
    fn the_limit_depends_on_the_kind_of_message() {
        let claimed = 100 * 1024 * 1024;
        let small_kinds = [
            PeerMessage::TransactionRequest(Default::default()),
            PeerMessage::BlockNotificationRequest,
        ];
        for message in small_kinds {
            let mut src = frame_start(WireEncoding::Bincode, &message, claimed);
            assert!(PeerFrameCodec::new(WireEncoding::Bincode)
                .decode(&mut src)
                .is_err());
        }

        // The same announced length passes for a kind that may be this big;
        // the codec then waits for the rest of the frame.
        let mut src = BytesMut::new();
        src.extend_from_slice(&claimed.to_be_bytes());
        src.extend_from_slice(&[PeerMessageKind::Transaction as u8; KIND_PEEK_LEN]);
        assert!(PeerFrameCodec::new(WireEncoding::Bincode)
            .decode(&mut src)
            .unwrap()
            .is_none());
    }

    #[test]
    fn json_frames_may_be_larger_than_bincode_frames() {
        let bincode_limit = PeerMessageKind::Block.max_frame_length().unwrap() as u32;

        // A block frame just above the bincode limit passes the check on a
        // JSON stream; the codec then waits for the rest of the frame.
        let mut src = BytesMut::new();
        src.extend_from_slice(&(bincode_limit + 1).to_be_bytes());
        src.extend_from_slice(b"{\"Block\":");
        src.extend_from_slice(&[b' '; KIND_PEEK_LEN]);
        assert!(PeerFrameCodec::new(WireEncoding::Json)
            .decode(&mut src)
            .unwrap()
            .is_none());

        // On a bincode stream the same length is refused.
        let mut bincode_src = BytesMut::new();
        bincode_src.extend_from_slice(&(bincode_limit + 1).to_be_bytes());
        bincode_src.extend_from_slice(&[PeerMessageKind::Block as u8; KIND_PEEK_LEN]);
        assert!(PeerFrameCodec::new(WireEncoding::Bincode)
            .decode(&mut bincode_src)
            .is_err());
    }

    #[test]
    fn frames_of_unknown_kind_are_refused() {
        let mut src = BytesMut::new();
        src.extend_from_slice(&64u32.to_be_bytes());
        src.extend_from_slice(&[250u8; KIND_PEEK_LEN]);
        assert!(PeerFrameCodec::new(WireEncoding::Bincode)
            .decode(&mut src)
            .is_err());

        let mut json_src = BytesMut::new();
        json_src.extend_from_slice(&64u32.to_be_bytes());
        json_src.extend_from_slice(b"{\"NoSuchMessage\":");
        json_src.extend_from_slice(&[b' '; KIND_PEEK_LEN]);
        assert!(PeerFrameCodec::new(WireEncoding::Json)
            .decode(&mut json_src)
            .is_err());
    }

    #[test]
    fn json_variant_names_are_read_from_a_prefix() {
        assert_eq!(Some("Bye"), json_variant_name(b"\"Bye\""));
        assert_eq!(Some("Block"), json_variant_name(b"{\"Block\":{\"kernel"));
        assert_eq!(Some("Block"), json_variant_name(b" { \"Block\" : 1"));
        assert_eq!(None, json_variant_name(b"{\"Block"));
        assert_eq!(None, json_variant_name(b"[1,2]"));
        assert_eq!(None, json_variant_name(b""));
    }
}
