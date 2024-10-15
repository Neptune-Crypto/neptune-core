use std::fmt::Display;

use get_size::GetSize;
use serde::Deserialize;
use serde::Serialize;
use strum::EnumCount;
use twenty_first::amount::u32s::U32s;
use twenty_first::math::b_field_element::BFieldElement;
use twenty_first::math::bfield_codec::BFieldCodec;
use twenty_first::math::digest::Digest;

use super::block_height::BlockHeight;
use crate::models::proof_abstractions::mast_hash::HasDiscriminant;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::prelude::twenty_first;

pub(crate) const TARGET_DIFFICULTY_U32_SIZE: usize = 5;
pub(crate) const PROOF_OF_WORK_COUNT_U32_SIZE: usize = 5;
/// 9.8 minutes in milliseconds
pub(crate) const TARGET_BLOCK_INTERVAL: u64 = 588000;
pub(crate) const MINIMUM_BLOCK_TIME: Timestamp = Timestamp::seconds(60);
pub(crate) const MINIMUM_DIFFICULTY: u32 = 2;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, BFieldCodec, GetSize)]
pub struct BlockHeader {
    pub version: BFieldElement,
    pub height: BlockHeight,
    pub prev_block_digest: Digest,

    // TODO: Reject blocks that are more than 10 seconds into the future
    /// Time since unix epoch, in milliseconds
    pub timestamp: Timestamp,

    // TODO: Consider making a type for `nonce`
    pub nonce: [BFieldElement; 3],
    pub max_block_size: u32,

    /// Total proof-of-work accumulated by this chain
    pub cumulative_proof_of_work: U32s<PROOF_OF_WORK_COUNT_U32_SIZE>,

    /// The difficulty for the *next* block. Unit: expected # hashes
    pub difficulty: U32s<TARGET_DIFFICULTY_U32_SIZE>,
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
    MaxBlockSize,
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
            self.max_block_size.encode(),
            self.cumulative_proof_of_work.encode(),
            self.difficulty.encode(),
        ]
    }
}

#[cfg(test)]
mod block_header_tests {
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
            max_block_size: rng.gen(),
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
}
