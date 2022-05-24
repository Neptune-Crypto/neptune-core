use super::{
    chunk_dictionary::ChunkDictionary,
    set_commitment::{SetCommitment, NUM_TRIALS},
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

impl<H: simple_hasher::Hasher> RemovalRecord<H>
where
    u128: ToDigest<<H as simple_hasher::Hasher>::Digest>,
    Vec<BFieldElement>: ToDigest<<H as simple_hasher::Hasher>::Digest>,
{
    pub fn validate(&self, mutator_set: &SetCommitment<H>) -> bool {
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
}
