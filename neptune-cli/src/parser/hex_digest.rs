use std::error::Error;
use std::fmt::Display;
use std::str::FromStr;

use neptune_cash::api::export::Digest;

/// Newtype for [`Digest`] so that clap can parse.
#[derive(Debug, Clone, Copy)]
pub(crate) struct HexDigest(pub(crate) Digest);

#[derive(Debug, Clone)]
pub(crate) enum DigestParseError {
    InvalidHexString(String),
    InputLengthMismatch,
    NonCanonicalRepresentation,
}

impl Error for DigestParseError {}

impl Display for DigestParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DigestParseError::InvalidHexString(s) => write!(f, "invalid hex string: '{s}'"),
            DigestParseError::InputLengthMismatch => write!(f, "wrong input length"),
            DigestParseError::NonCanonicalRepresentation => {
                write!(f, "non-canonical representation")
            }
        }
    }
}

impl FromStr for HexDigest {
    type Err = DigestParseError;
    fn from_str(unparsed: &str) -> Result<HexDigest, DigestParseError> {
        if unparsed.len() != 80 {
            return Err(DigestParseError::InputLengthMismatch);
        }
        let mut arr = [0u8; 40];
        for i in 0..40 {
            let byte_str = &unparsed[2 * i..2 * i + 2];
            arr[i] = u8::from_str_radix(byte_str, 16)
                .map_err(|_| DigestParseError::InvalidHexString(byte_str.to_owned()))?;
        }

        let digest = HexDigest(
            Digest::try_from(arr).map_err(|_| DigestParseError::NonCanonicalRepresentation)?,
        );

        Ok(digest)
    }
}
