use std::fmt::Display;

use arbitrary::Arbitrary;
use get_size2::GetSize;
use serde::Deserialize;
use serde::Serialize;
use strum::EnumCount;
use twenty_first::math::b_field_element::BFieldElement;
use twenty_first::math::bfield_codec::BFieldCodec;
use twenty_first::math::digest::Digest;

use super::block_height::BlockHeight;
use super::difficulty_control::Difficulty;
use super::difficulty_control::ProofOfWork;
use crate::models::proof_abstractions::mast_hash::HasDiscriminant;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::prelude::twenty_first;

/// Desired/average time between blocks.
///
/// 558000 milliseconds equals 9.8 minutes.
pub(crate) const TARGET_BLOCK_INTERVAL: Timestamp = Timestamp::millis(588000);

/// Minimum time between blocks.
///
/// Blocks spaced apart by less than this amount of time are not valid.
pub(crate) const MINIMUM_BLOCK_TIME: Timestamp = Timestamp::seconds(60);

/// Controls how long to wait before the difficulty for the *next* block is
/// reduced.
///
/// Typically, the difficulty of the block's predecessor is used to determine
/// whether the new block has enough proof-of-work. But if the time difference
/// (relative to the target block interval) exceeds this parameter, the
/// difficulty is effectively reduced by a factor
/// [`ADVANCE_DIFFICULTY_CORRECTION_FACTOR`]. Consequently, if for whatever
/// reason the difficulty is set too high for the available mining power to find
/// blocks, then the network has to wait some time (without needing to find
/// blocks) before the difficulty is automatically lowered.
///
/// This parameter must be a power of two.
pub(crate) const ADVANCE_DIFFICULTY_CORRECTION_WAIT: usize = 128;

/// Controls by how much the advance difficulty correction reduces the effective
/// difficulty by.
///
/// Typically, the difficulty of the block's predecessor is used to determine
/// whether the new block has enough proof-of-work. But if the time difference
/// (relative to the target block interval) exceeds parameter
/// [`ADVANCE_DIFFICULTY_CORRECTION_WAIT`], the
/// difficulty is effectively reduced by this amount. Consequently, if for
/// whatever reason the difficulty is set too high for the available mining
/// power to find blocks, then the network has to wait some time (without
/// needing to find blocks) before the difficulty is automatically lowered.
///
/// This parameter must be a power of two.
pub(crate) const ADVANCE_DIFFICULTY_CORRECTION_FACTOR: usize = 4;

pub(crate) const BLOCK_HEADER_VERSION: BFieldElement = BFieldElement::new(0);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, BFieldCodec, GetSize, Arbitrary)]
pub struct BlockHeader {
    pub version: BFieldElement,
    pub height: BlockHeight,
    pub prev_block_digest: Digest,

    /// Time since unix epoch, in milliseconds
    pub timestamp: Timestamp,

    pub nonce: Digest,

    /// Total proof-of-work accumulated by this chain
    pub cumulative_proof_of_work: ProofOfWork,

    /// The difficulty for the *next* block. Unit: expected # hashes
    pub difficulty: Difficulty,
}

impl Display for BlockHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let string = format!(
            "Height: {}\n\
            Timestamp: {}\n\
            Prev. Digest: {}\n\
            Cumulative Proof-of-Work: {}\n",
            self.height,
            self.timestamp.standard_format(),
            self.prev_block_digest.to_hex(),
            self.cumulative_proof_of_work,
        );

        write!(f, "{}", string)
    }
}

#[derive(Debug, Clone, EnumCount)]
pub enum BlockHeaderField {
    Version,
    Height,
    PrevBlockDigest,
    Timestamp,
    Nonce,
    CumulativeProofOfWork,
    Difficulty,
}

impl HasDiscriminant for BlockHeaderField {
    fn discriminant(&self) -> usize {
        self.clone() as usize
    }
}

impl MastHash for BlockHeader {
    type FieldEnum = BlockHeaderField;

    fn mast_sequences(&self) -> Vec<Vec<BFieldElement>> {
        vec![
            self.version.encode(),
            self.height.encode(),
            self.prev_block_digest.encode(),
            self.timestamp.encode(),
            self.nonce.encode(),
            self.cumulative_proof_of_work.encode(),
            self.difficulty.encode(),
        ]
    }
}

#[cfg(test)]
pub(crate) mod block_header_tests {
    use rand::thread_rng;
    use rand::Rng;

    use super::*;

    pub fn random_block_header() -> BlockHeader {
        let mut rng = thread_rng();
        BlockHeader {
            version: rng.gen(),
            height: BlockHeight::from(rng.gen::<u64>()),
            prev_block_digest: rng.gen(),
            timestamp: rng.gen(),
            nonce: rng.gen(),
            cumulative_proof_of_work: rng.gen(),
            difficulty: rng.gen(),
        }
    }
    #[test]
    pub fn test_block_header_decode() {
        let block_header = random_block_header();
        let encoded = block_header.encode();
        let decoded = *BlockHeader::decode(&encoded).unwrap();
        assert_eq!(block_header, decoded);
    }

    #[test]
    fn advance_difficulty_correction_parameters_are_powers_of_two() {
        assert_eq!(
            ADVANCE_DIFFICULTY_CORRECTION_WAIT,
            1 << ADVANCE_DIFFICULTY_CORRECTION_WAIT.ilog2()
        );
        assert_eq!(
            ADVANCE_DIFFICULTY_CORRECTION_FACTOR,
            1 << ADVANCE_DIFFICULTY_CORRECTION_FACTOR.ilog2()
        );
    }
}
