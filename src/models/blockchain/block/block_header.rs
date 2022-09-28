use std::fmt::Display;

use serde::{Deserialize, Serialize};
use twenty_first::{
    amount::u32s::U32s, shared_math::b_field_element::BFieldElement,
    util_types::simple_hasher::Hasher,
};

use crate::models::blockchain::{
    digest::{Digest, Hashable, RESCUE_PRIME_OUTPUT_SIZE_IN_BFES},
    shared::Hash,
};

use super::block_height::BlockHeight;

pub const TARGET_DIFFICULTY_U32_SIZE: usize = 5;
pub const PROOF_OF_WORK_COUNT_U32_SIZE: usize = 5;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockHeader {
    pub version: BFieldElement,
    pub height: BlockHeight,
    pub mutator_set_commitment: Digest,
    pub prev_block_digest: Digest,

    // TODO: Reject blocks that are more than 10 seconds into the future
    pub timestamp: BFieldElement,

    // TODO: Consider making a type for `nonce`
    pub nonce: [BFieldElement; 3],
    pub max_block_size: u32,

    // use to compare two forks of different height
    pub proof_of_work_line: U32s<PROOF_OF_WORK_COUNT_U32_SIZE>,

    // use to compare two forks of the same height
    pub proof_of_work_family: U32s<PROOF_OF_WORK_COUNT_U32_SIZE>,

    // This is the target difficulty for the current (*this*) block.
    pub target_difficulty: U32s<TARGET_DIFFICULTY_U32_SIZE>,
    pub block_body_merkle_root: Digest,
    pub uncles: Vec<Digest>,
}

impl Display for BlockHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let string = format!(
            "Height: {}\n\
            Timestamp: {}\n\
            Prev. Digest: {}\n\
            Proof-of-work-line: IMPLEMENT\n\
            Proof-of-work-family: IMPLEMENT",
            self.height,
            self.timestamp,
            self.prev_block_digest,
            //self.proof_of_work_line,
            //self.proof_of_work_family
        );

        write!(f, "{}", string)
    }
}

impl Hashable for BlockHeader {
    fn neptune_hash(&self) -> Digest {
        let hasher = Hash::new();
        Digest::new(
            hasher
                .hash(&self.accumulate(), RESCUE_PRIME_OUTPUT_SIZE_IN_BFES)
                .try_into()
                .unwrap(),
        )
    }
}

impl BlockHeader {
    fn accumulate(&self) -> Vec<BFieldElement> {
        let mut ret: Vec<BFieldElement> = vec![self.version, self.height.into()];
        ret.append(&mut self.mutator_set_commitment.values().to_vec());
        ret.append(&mut self.prev_block_digest.values().to_vec());
        ret.push(self.timestamp);
        ret.append(&mut self.nonce.to_vec());
        let max_block_value: BFieldElement = self.max_block_size.into();
        ret.push(max_block_value);
        let pow_line_values: [BFieldElement; 5] = self.proof_of_work_line.into();
        ret.append(&mut pow_line_values.to_vec());
        let pow_family_values: [BFieldElement; 5] = self.proof_of_work_family.into();
        ret.append(&mut pow_family_values.to_vec());
        let target_difficulty: [BFieldElement; 5] = self.target_difficulty.into();
        ret.append(&mut target_difficulty.to_vec());
        ret.append(&mut self.block_body_merkle_root.values().to_vec());

        ret.append(
            &mut self
                .uncles
                .iter()
                .map(|uncle| uncle.values().to_vec())
                .collect::<Vec<_>>()
                .concat(),
        );

        ret
    }
}
