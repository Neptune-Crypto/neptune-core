use crate::util_types::{
    mmr::{mmr_accumulator::MmrAccumulator, mmr_trait::Mmr},
    simple_hasher::{self, ToDigest},
};

#[derive(Clone, Debug)]
pub struct AdditionRecord<H: simple_hasher::Hasher> {
    pub commitment: H::Digest,
    aocl_snapshot: MmrAccumulator<H>,
}

impl<H: simple_hasher::Hasher> AdditionRecord<H>
where
    u128: ToDigest<<H as simple_hasher::Hasher>::Digest>,
{
    pub fn new(commitment: H::Digest, aocl_snapshot: MmrAccumulator<H>) -> Self {
        Self {
            commitment,
            aocl_snapshot,
        }
    }
    pub fn has_matching_aocl(&self, aocl_accumulator: &MmrAccumulator<H>) -> bool {
        self.aocl_snapshot.count_leaves() == aocl_accumulator.count_leaves()
            && self.aocl_snapshot.get_peaks() == aocl_accumulator.get_peaks()
    }
}
