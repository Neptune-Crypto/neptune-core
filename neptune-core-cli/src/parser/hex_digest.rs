use std::error::Error;
use std::fmt::Display;
use std::str::FromStr;

use neptune_cash::api::export::Digest;

/// Newtype for [`Digest`] so that clap can parse.
#[derive(Debug, Clone, Copy)]
pub(crate) struct HexDigest(pub(crate) Digest);

#[derive(Debug, Clone, PartialEq, Eq)]
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

            // `u8::from_str_radix` accepts the "+" prefix, but we do not
            if byte_str.chars().nth(0) == Some('+') {
                return Err(DigestParseError::InvalidHexString(byte_str.to_owned()));
            }

            arr[i] = u8::from_str_radix(byte_str, 16)
                .map_err(|_| DigestParseError::InvalidHexString(byte_str.to_owned()))?;
        }

        let digest = HexDigest(
            Digest::try_from(arr).map_err(|_| DigestParseError::NonCanonicalRepresentation)?,
        );

        Ok(digest)
    }
}

#[cfg(test)]
mod tests {
    use std::primitive::char;

    use itertools::Itertools;
    use neptune_cash::prelude::triton_vm::prelude::BFieldElement;
    use proptest::collection::vec;
    use proptest::prelude::prop;
    use proptest::prop_assert;
    use proptest::prop_assert_eq;
    use proptest::strategy::Strategy;
    use proptest_arbitrary_interop::arb;
    use test_strategy::proptest;

    use super::*;

    #[proptest]
    fn round_trip(#[strategy(arb::<Digest>())] digest: Digest) {
        let parsed = HexDigest::from_str(&format!("{digest:x}")).unwrap();
        prop_assert_eq!(parsed.0, digest);
    }

    #[proptest]
    fn too_short(#[strategy(arb::<Digest>())] digest: Digest, #[strategy(0_usize..80)] len: usize) {
        let as_string = format!("{digest:x}");
        let parse_result = HexDigest::from_str(&as_string[..len]);
        prop_assert_eq!(
            parse_result.unwrap_err(),
            DigestParseError::InputLengthMismatch
        );
    }

    #[proptest]
    fn too_long(
        #[strategy(arb::<Digest>())] digest1: Digest,
        #[strategy(arb::<Digest>())] digest2: Digest,
        #[strategy(81_usize..160)] len: usize,
    ) {
        let as_string = format!("{digest1:x}{digest2:x}");
        let parse_result = HexDigest::from_str(&as_string[..len]);
        prop_assert_eq!(
            parse_result.unwrap_err(),
            DigestParseError::InputLengthMismatch
        );
    }

    #[proptest]
    fn non_canonical(
        #[strategy(BFieldElement::P..=u64::MAX)] non_bfe: u64,
        #[strategy(vec(0_u64..=BFieldElement::MAX,Digest::LEN))] mut bfes: Vec<u64>,
        #[strategy(0usize..Digest::LEN)] index: usize,
    ) {
        bfes[index] = non_bfe;
        let s = bfes
            .into_iter()
            .flat_map(|i| i.to_le_bytes())
            .map(|b| format!("{b:02x}"))
            .join("");
        let parse_result = HexDigest::from_str(&s);
        prop_assert_eq!(
            parse_result.unwrap_err(),
            DigestParseError::NonCanonicalRepresentation
        );
    }

    #[proptest]
    fn invalid_hex(
        #[strategy(arb::<Digest>())] digest: Digest,
        #[strategy(0usize..80)] index: usize,
        #[strategy(prop::char::range(' ', '~').prop_filter("Exclude hex digits", |c| !c.is_ascii_hexdigit()))]
        ch: char,
    ) {
        let mut s = format!("{digest:x}");
        s.replace_range(index..=index, &ch.to_string());
        let parse_result = HexDigest::from_str(&s).unwrap_err();
        prop_assert!(
            matches!(parse_result, DigestParseError::InvalidHexString(_),),
            "{parse_result:?}"
        );
    }

    #[test]
    fn invalid_hex_unit() {
        for s in [
            "00000000000000000000000000000000000000000000000000000000000000+00000000000000000",
            "00000000000000000000000000000000000000000000000000000000000000-00000000000000000",
            "+0000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "-0000000000000000000000000000000000000000000000000000000000000000000000000000000",
        ] {
            let parse_result = HexDigest::from_str(s).unwrap_err();
            assert!(
                matches!(parse_result, DigestParseError::InvalidHexString(_),),
                "{parse_result:?}"
            );
        }
    }
}
