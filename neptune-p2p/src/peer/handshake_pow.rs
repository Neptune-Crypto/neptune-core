//! Proof of work demanded of the dialer during the libp2p handshake.
//!
//! The listener puts a random challenge, and the difficulty it requires, into
//! the `extra_data` of its own [`HandshakeData`]. The dialer must answer with
//! a nonce whose Tip5 hash together with the challenge clears that many leading
//! zero bits. The challenge is generated per connection and is never reused, so
//! a solution is usable exactly once. Verification is one hash.
//!
//! The encoding is `pow:<bits>:<hex>` with exactly 32 hex characters of
//! challenge; anything after them is ignored, so the field can be expanded in
//! a backwards-compatible manner later.
//!
//! Only the dialer solves: the listener is the party being protected, and
//! making it work per inbound attempt be an attack vector. The dialer refuses
//! to solve anything harder than [`MAX_HANDSHAKE_POW_BITS`], so a listener
//! cannot burn a dialer's CPU either.
//!
//! [`HandshakeData`]: super::handshake_data::HandshakeData

use arraystring::ArrayString;
use arraystring::typenum::U255;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;

use super::handshake_data::ExtraDataString;

/// Leading zero bits a listener requires. Expect about
/// `2^HANDSHAKE_POW_BITS` hashes to solve: around 130,000, which is a tenth of
/// a second at a million Tip5 hashes per second and still only a second or two
/// on a device ten to twenty times slower.
pub const HANDSHAKE_POW_BITS: u32 = 17;

/// The hardest challenge a dialer is willing to solve.
pub const MAX_HANDSHAKE_POW_BITS: u32 = 18;

const EXTRA_DATA_PREFIX: &str = "pow:";

/// Hex characters in the encoded challenge: a `u128`, zero-padded.
///
/// Each hex encodes four bits.
const CHALLENGE_HEX_LEN: usize = u128::BITS as usize / 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ChallengeError {
    #[error("malformed proof-of-work challenge")]
    Malformed,

    #[error("proof-of-work difficulty {0} exceeds the maximum of {MAX_HANDSHAKE_POW_BITS}")]
    TooHard(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Challenge {
    pub bits: u32,
    pub challenge: u128,
}

impl Challenge {
    /// A fresh challenge at the difficulty this node requires.
    pub fn random() -> Self {
        Self {
            bits: HANDSHAKE_POW_BITS,
            challenge: rand::random(),
        }
    }

    /// The form carried in a handshake's `extra_data`.
    pub fn to_extra_data(self) -> ExtraDataString {
        let text = format!(
            "{EXTRA_DATA_PREFIX}{}:{:0width$x}",
            self.bits,
            self.challenge,
            width = CHALLENGE_HEX_LEN
        );
        ArrayString::<U255>::from_chars(text.chars())
    }

    /// Inverse of [`Self::to_extra_data`].
    ///
    /// `Ok(None)` when no challenge is carried, as with peers predating it.
    pub fn parse(extra_data: &str) -> Result<Option<Self>, ChallengeError> {
        let Some(body) = extra_data.strip_prefix(EXTRA_DATA_PREFIX) else {
            return Ok(None);
        };
        let (bits, challenge) = body.split_once(':').ok_or(ChallengeError::Malformed)?;
        let bits = bits.parse().map_err(|_| ChallengeError::Malformed)?;

        // Zero bits would make `verify` shift by the full word width, and
        // `solve` run for ~2^64 hashes on a blocking thread that a timeout
        // cannot cancel.
        if bits == 0 {
            return Err(ChallengeError::Malformed);
        }
        if bits > MAX_HANDSHAKE_POW_BITS {
            return Err(ChallengeError::TooHard(bits));
        }
        let challenge = challenge
            .get(..CHALLENGE_HEX_LEN)
            .and_then(|hex| u128::from_str_radix(hex, 16).ok())
            .ok_or(ChallengeError::Malformed)?;

        Ok(Some(Self { bits, challenge }))
    }

    fn hash(self, nonce: u64) -> Digest {
        let preimage = [
            BFieldElement::new(self.challenge as u64),
            BFieldElement::new((self.challenge >> 64) as u64),
            BFieldElement::new(nonce),
        ];
        Tip5::hash_varlen(&preimage)
    }

    /// Whether `nonce` answers this challenge.
    pub fn verify(self, nonce: u64) -> bool {
        self.hash(nonce).values()[0].value() >> (u64::BITS - self.bits) == 0
    }

    /// Find a nonce solving this challenge.
    ///
    /// Blocking, and expected to take `2^bits` hashes; run it off the async
    /// executor.
    pub fn solve(self) -> u64 {
        (0..)
            .find(|&nonce| self.verify(nonce))
            .expect("some nonce in 0..2^64 answers the challenge")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solution_verifies() {
        let challenge = Challenge::random();
        assert!(challenge.verify(challenge.solve()));
    }

    #[test]
    fn a_wrong_nonce_does_not_verify() {
        let challenge = Challenge::random();
        let wrong = (0..).find(|&nonce| !challenge.verify(nonce)).unwrap();
        assert!(!challenge.verify(wrong));
    }

    #[test]
    fn extra_data_round_trip() {
        let challenge = Challenge::random();
        let extra_data = challenge.to_extra_data();
        assert_eq!(Ok(Some(challenge)), Challenge::parse(&extra_data));
        assert!(extra_data.len() <= 39, "{extra_data}");
    }

    #[test]
    fn data_after_the_challenge_is_ignored() {
        let challenge = Challenge::random();
        let extended = format!("{}:later=field", challenge.to_extra_data());
        assert_eq!(Ok(Some(challenge)), Challenge::parse(&extended));
    }

    #[test]
    fn a_short_challenge_is_malformed() {
        let challenge = Challenge::random();
        let mut short = challenge.to_extra_data().to_string();
        short.pop();
        assert_eq!(Err(ChallengeError::Malformed), Challenge::parse(&short));
    }

    #[test]
    fn absent_and_malformed_and_too_hard() {
        assert_eq!(Ok(None), Challenge::parse(""));
        assert_eq!(Ok(None), Challenge::parse("something else"));
        assert_eq!(
            Err(ChallengeError::Malformed),
            Challenge::parse(&format!("pow:{HANDSHAKE_POW_BITS}"))
        );
        assert_eq!(
            Err(ChallengeError::Malformed),
            Challenge::parse(&format!("pow:{HANDSHAKE_POW_BITS}:zz"))
        );
        assert_eq!(Err(ChallengeError::Malformed), Challenge::parse("pow:x:00"));
        let zero_bits = format!("pow:0:{:032x}", Challenge::random().challenge);
        assert_eq!(Err(ChallengeError::Malformed), Challenge::parse(&zero_bits));

        let too_hard = Challenge {
            bits: MAX_HANDSHAKE_POW_BITS + 1,
            ..Challenge::random()
        };
        assert_eq!(
            Err(ChallengeError::TooHard(MAX_HANDSHAKE_POW_BITS + 1)),
            Challenge::parse(&too_hard.to_extra_data())
        );
    }
}
