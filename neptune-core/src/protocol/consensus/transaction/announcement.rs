use std::fmt::Display;
use std::fmt::LowerHex;
use std::num::ParseIntError;

use get_size2::GetSize;
use itertools::Itertools;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::TasmObject;
use tasm_lib::triton_vm::prelude::BFieldCodec;
use tasm_lib::triton_vm::prelude::BFieldElement;
use tracing::debug;

use crate::api::export::UnlockedUtxo;
use crate::protocol::consensus::block::pow::LustrationStatus;
use crate::protocol::consensus::transaction::transaction_kernel::LUSTRATION_FLAG;

/// Represents arbitrary data that can be stored in a transaction on the public
/// blockchain.
///
/// These are typically used for transmitting encrypted UTXO notifications, so
/// that a recipient can identify and claim the UTXO.
///
/// See [Transaction](super::Transaction).
#[derive(
    Clone,
    Debug,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Hash,
    GetSize,
    BFieldCodec,
    Default,
    TasmObject,
)]
#[cfg_attr(any(test, feature = "arbitrary-impls"), derive(arbitrary::Arbitrary))]
pub struct Announcement {
    pub message: Vec<BFieldElement>,
}

impl Announcement {
    pub fn new(message: Vec<BFieldElement>) -> Self {
        Self { message }
    }

    /// Returns true iff the announcement carries the lustration flag.
    ///
    /// Does not attempt to check if the lustration can be decoded. Just checks
    /// for the flag, so if the announcement is not generated locally, this
    /// method cannot be trusted to correctly identify lustration announcements
    /// which would be meaningless anyway without the context of the whole
    /// transaction kernel.
    pub(crate) fn looks_like_lustration(&self) -> bool {
        self.message
            .first()
            .is_some_and(|elem0| *elem0 == LUSTRATION_FLAG)
    }

    pub fn lustration_announcements(
        lustration_status: LustrationStatus,
        tx_inputs: &[UnlockedUtxo],
    ) -> Vec<Self> {
        let mut lustrations = vec![];

        for input in tx_inputs {
            // Match consensus rule that defines when inputs need to be
            // lustrated.
            let (input_index_lower_end, _) = input
                .absolute_indices()
                .aocl_range()
                .expect("Must be able to calculate AOCL range of own input");

            if input_index_lower_end <= lustration_status.max_lustrating_aocl_leaf_index {
                debug!(
                    "Found input in need of lustration. Lustrating now. Input index min
                     range was: {input_index_lower_end}"
                );
                // Input must be lustrated
                lustrations.push(input.lustration());
            }
        }

        lustrations
    }
}

impl LowerHex for Announcement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for m in &self.message {
            // big-endian (Arabic)
            write!(f, "{:016x}", m.value())?;
        }
        Ok(())
    }
}

impl Display for Announcement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // add hex delimiter, then use hex formatter
        write!(f, "0x{:x}", self)
    }
}

#[derive(Debug, Clone)]
pub enum ParsePublicAnnouncementError {
    TooShort,
    BadHexDelimiter,
    BadLengthAlignment,
    ParseIntError(ParseIntError),
    NonCanonicalRepresentation,
}

impl TryFrom<String> for Announcement {
    type Error = ParsePublicAnnouncementError;

    fn try_from(unparsed: String) -> Result<Self, Self::Error> {
        const BFE_HEX_LEN: usize = 16;
        let (delimiter, payload) = unparsed
            .split_at_checked(2)
            .ok_or(ParsePublicAnnouncementError::TooShort)?;

        let _hex_delimiter_is_valid = (delimiter == "0x")
            .then_some(true)
            .ok_or(ParsePublicAnnouncementError::BadHexDelimiter)?;

        let _payload_length_aligns_with_bfes = payload
            .len()
            .is_multiple_of(BFE_HEX_LEN)
            .then_some(true)
            .ok_or(ParsePublicAnnouncementError::BadLengthAlignment)?;

        let mut bfes = vec![];
        for chunk in &payload.chars().chunks(BFE_HEX_LEN) {
            let substring: String = chunk.collect();
            let representant = u64::from_str_radix(&substring, 16)
                .map_err(ParsePublicAnnouncementError::ParseIntError)?;

            let _representation_is_canonical = (representant <= BFieldElement::MAX)
                .then_some(true)
                .ok_or(ParsePublicAnnouncementError::NonCanonicalRepresentation)?;
            bfes.push(BFieldElement::new(representant));
        }

        Ok(Self { message: bfes })
    }
}

#[cfg(test)]
impl rand::distr::Distribution<Announcement> for rand::distr::StandardUniform {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> Announcement {
        Announcement {
            message: (0..10).map(|_| rng.random()).collect_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prop_assert_eq;
    use proptest_arbitrary_interop::arb;
    use test_strategy::proptest;

    use super::*;

    #[proptest]
    fn try_from_string_inverts_display_format(#[strategy(arb())] announcement: Announcement) {
        let as_hex = format!("{}", announcement);
        let as_announcement_again = Announcement::try_from(as_hex).unwrap();
        prop_assert_eq!(announcement, as_announcement_again);
    }

    #[proptest]
    fn try_from_string_cannot_crash(s: String) {
        let _announcement = Announcement::try_from(s); // no crash
    }
}
