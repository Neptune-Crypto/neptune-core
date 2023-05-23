use anyhow::bail;
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use twenty_first::shared_math::bfield_codec::{decode_field_length_prepended, BFieldCodec};
use twenty_first::shared_math::digest::Digest;

use twenty_first::amount::u32s::U32s;
use twenty_first::shared_math::b_field_element::BFieldElement;

use super::block_height::BlockHeight;

pub const TARGET_DIFFICULTY_U32_SIZE: usize = 5;
pub const PROOF_OF_WORK_COUNT_U32_SIZE: usize = 5;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
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

impl BFieldCodec for BlockHeader {
    fn encode(&self) -> Vec<BFieldElement> {
        let version_encoded = self.version.encode();
        let height_encoded = self.height.encode();
        let mutator_set_hash_encoded = self.mutator_set_hash.encode();
        let prev_block_digest_encoded = self.prev_block_digest.encode();
        let timestamp_encoded = self.timestamp.encode();
        let nonce_encoded = self.nonce.encode();
        let max_block_size_encoded = self.max_block_size.encode();
        let proof_of_work_line_encoded = self.proof_of_work_line.encode();
        let proof_of_work_family_encoded = self.proof_of_work_family.encode();
        let target_difficulty_encoded = self.target_difficulty.encode();
        let block_body_merkle_root_encoded = self.block_body_merkle_root.encode();
        let uncles_encoded = self.uncles.encode();
        let version_length = BFieldElement::new(version_encoded.len() as u64);
        let height_length = BFieldElement::new(height_encoded.len() as u64);
        let mutator_set_hash_length = BFieldElement::new(mutator_set_hash_encoded.len() as u64);
        let prev_block_digest_length = BFieldElement::new(prev_block_digest_encoded.len() as u64);
        let timestamp_length = BFieldElement::new(timestamp_encoded.len() as u64);
        let nonce_length = BFieldElement::new(nonce_encoded.len() as u64);
        let max_block_size_length = BFieldElement::new(max_block_size_encoded.len() as u64);
        let proof_of_work_line_length = BFieldElement::new(proof_of_work_line_encoded.len() as u64);
        let proof_of_work_family_length =
            BFieldElement::new(proof_of_work_family_encoded.len() as u64);
        let target_difficulty_length = BFieldElement::new(target_difficulty_encoded.len() as u64);
        let block_body_merkle_root_length =
            BFieldElement::new(block_body_merkle_root_encoded.len() as u64);
        let uncles_length = BFieldElement::new(uncles_encoded.len() as u64);

        [
            vec![version_length],
            version_encoded,
            vec![height_length],
            height_encoded,
            vec![mutator_set_hash_length],
            mutator_set_hash_encoded,
            vec![prev_block_digest_length],
            prev_block_digest_encoded,
            vec![timestamp_length],
            timestamp_encoded,
            vec![nonce_length],
            nonce_encoded,
            vec![max_block_size_length],
            max_block_size_encoded,
            vec![proof_of_work_line_length],
            proof_of_work_line_encoded,
            vec![proof_of_work_family_length],
            proof_of_work_family_encoded,
            vec![target_difficulty_length],
            target_difficulty_encoded,
            vec![block_body_merkle_root_length],
            block_body_merkle_root_encoded,
            vec![uncles_length],
            uncles_encoded,
        ]
        .concat()
    }

    fn decode(sequence: &[BFieldElement]) -> anyhow::Result<Box<Self>> {
        let (version, sequence) = decode_field_length_prepended(sequence)?;
        let (height, sequence) = decode_field_length_prepended(sequence)?;
        let (mutator_set_hash, sequence) = decode_field_length_prepended(sequence)?;
        let (prev_block_digest, sequence) = decode_field_length_prepended(sequence)?;
        let (timestamp, sequence) = decode_field_length_prepended(sequence)?;
        let (nonce, sequence) = decode_field_length_prepended(sequence)?;
        let (max_block_size, sequence) = decode_field_length_prepended(sequence)?;
        let (proof_of_work_line, sequence) = decode_field_length_prepended(sequence)?;
        let (proof_of_work_family, sequence) = decode_field_length_prepended(sequence)?;
        let (target_difficulty, sequence) = decode_field_length_prepended(sequence)?;
        let (block_body_merkle_root, sequence) = decode_field_length_prepended(sequence)?;
        let (uncles, sequence) = decode_field_length_prepended(sequence)?;
        if !sequence.is_empty() {
            bail!("After decoding sequence of BFieldElements as BlockHeader, sequence should be empty!");
        }
        Ok(Box::new(BlockHeader {
            version,
            height,
            mutator_set_hash,
            prev_block_digest,
            timestamp,
            nonce,
            max_block_size,
            proof_of_work_line,
            proof_of_work_family,
            target_difficulty,
            block_body_merkle_root,
            uncles,
        }))
    }
}
