use std::collections::HashMap;

use super::{
    chunk_dictionary::ChunkDictionary,
    set_commitment::{SetCommitment, CHUNK_SIZE, NUM_TRIALS},
};
use crate::{
    shared_math::b_field_element::BFieldElement,
    util_types::{
        mmr::mmr_trait::Mmr,
        simple_hasher::{self, ToDigest},
    },
};

#[derive(Clone, Debug)]
pub struct RemovalRecord<H: simple_hasher::Hasher> {
    pub bit_indices: [u128; NUM_TRIALS],
    pub target_chunks: ChunkDictionary<H>,
}

impl<H> RemovalRecord<H>
where
    u128: ToDigest<<H as simple_hasher::Hasher>::Digest>,
    Vec<BFieldElement>: ToDigest<<H as simple_hasher::Hasher>::Digest>,
    H: simple_hasher::Hasher,
{
    pub fn validate<M>(&self, mutator_set: &SetCommitment<H, M>) -> bool
    where
        M: Mmr<H>,
    {
        let peaks = mutator_set.swbf_inactive.get_peaks();
        self.target_chunks.dictionary.iter().all(|(_i, (p, c))| {
            p.verify(
                &peaks,
                &c.hash::<H>(&mutator_set.hasher),
                mutator_set.swbf_inactive.count_leaves(),
            )
            .0
        })
    }

    pub fn get_chunk_index_to_bit_indices(&self) -> HashMap<u128, Vec<u128>> {
        let mut rem_record_chunk_idx_to_bit_indices: HashMap<u128, Vec<u128>> = HashMap::new();
        self.bit_indices
            .iter()
            .map(|bi| (bi / CHUNK_SIZE as u128, bi))
            .for_each(|(k, v)| {
                rem_record_chunk_idx_to_bit_indices
                    .entry(k)
                    .or_insert_with(Vec::new)
                    .push(*v);
            });

        rem_record_chunk_idx_to_bit_indices
    }
}
