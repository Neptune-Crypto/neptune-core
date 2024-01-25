use crate::prelude::twenty_first;

use serde::{Deserialize, Serialize};
use std::fmt::Display;
use twenty_first::shared_math::bfield_codec::BFieldCodec;
use twenty_first::shared_math::digest::Digest;

use twenty_first::amount::u32s::U32s;
use twenty_first::shared_math::b_field_element::BFieldElement;

use super::block_height::BlockHeight;

pub const TARGET_DIFFICULTY_U32_SIZE: usize = 5;
pub const PROOF_OF_WORK_COUNT_U32_SIZE: usize = 5;
pub const TARGET_BLOCK_INTERVAL: u64 = 588000; // 9.8 minutes in milliseconds
pub const MINIMUM_DIFFICULTY: u32 = 2;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, BFieldCodec)]
pub struct BlockHeader {
    pub version: BFieldElement,
    pub height: BlockHeight,
    pub mutator_set_hash: Digest,
    pub prev_block_digest: Digest,

    // TODO: Reject blocks that are more than 10 seconds into the future
    // number of milliseconds since unix epoch
    pub timestamp: BFieldElement,

    // TODO: Consider making a type for `nonce`
    pub nonce: [BFieldElement; 3],
    pub max_block_size: u32,

    // use to compare two forks of different height
    pub proof_of_work_line: U32s<PROOF_OF_WORK_COUNT_U32_SIZE>,

    // use to compare two forks of the same height
    pub proof_of_work_family: U32s<PROOF_OF_WORK_COUNT_U32_SIZE>,

    // This is the difficulty for the *next* block. Unit: expected # hashes
    pub difficulty: U32s<TARGET_DIFFICULTY_U32_SIZE>,
    pub block_body_merkle_root: Digest,
    pub uncles: Vec<Digest>,
}

impl Display for BlockHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let string = format!(
            "Height: {}\n\
            Timestamp: {}\n\
            Prev. Digest: {}\n\
            Proof-of-work-line: {}\n\
            Proof-of-work-family: {}",
            self.height,
            self.timestamp,
            self.prev_block_digest,
            self.proof_of_work_line,
            self.proof_of_work_family
        );

        write!(f, "{}", string)
    }
}

#[cfg(test)]
mod block_header_tests {
    use rand::{thread_rng, Rng, RngCore};
    use twenty_first::shared_math::other::random_elements;

    use super::*;

    pub fn random_block_header() -> BlockHeader {
        let mut rng = thread_rng();
        BlockHeader {
            version: rng.gen(),
            height: BlockHeight::from(rng.gen::<u64>()),
            mutator_set_hash: rng.gen(),
            prev_block_digest: rng.gen(),
            timestamp: rng.gen(),
            nonce: rng.gen(),
            max_block_size: rng.gen(),
            proof_of_work_line: rng.gen(),
            proof_of_work_family: rng.gen(),
            difficulty: rng.gen(),
            block_body_merkle_root: rng.gen(),
            uncles: random_elements((rng.next_u32() % 3) as usize),
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
