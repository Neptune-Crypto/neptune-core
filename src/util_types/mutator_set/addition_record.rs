use crate::util_types::{
    mmr::{mmr_accumulator::MmrAccumulator, mmr_trait::Mmr},
    simple_hasher::{self, ToDigest},
};

#[derive(Clone, Debug)]
pub struct AdditionRecord<H: simple_hasher::Hasher> {
    pub commitment: H::Digest,

    // Although the mutator set is defined in both an accumulator and an archival version,
    // this function only accepts an accumulator MMR here, since we don't want to copy the
    // archival MMRs around.
    aocl_snapshot: MmrAccumulator<H>,
}

impl<H> AdditionRecord<H>
where
    u128: ToDigest<<H as simple_hasher::Hasher>::Digest>,
    H: simple_hasher::Hasher,
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

#[cfg(test)]
mod addition_record_tests {
    use crate::util_types::mutator_set::{
        mutator_set_accumulator::MutatorSetAccumulator, mutator_set_trait::MutatorSet,
    };

    use super::*;

    #[test]
    fn has_matching_aocl_test() {
        type Hasher = blake3::Hasher;

        let mut msa0: MutatorSetAccumulator<Hasher> = MutatorSetAccumulator::default();
        let mut msa1: MutatorSetAccumulator<Hasher> = MutatorSetAccumulator::default();
        let addition_record_0: AdditionRecord<Hasher> =
            msa0.commit(&1492u128.into(), &1522u128.into());
        let addition_record_1: AdditionRecord<Hasher> =
            msa1.commit(&1451u128.into(), &1480u128.into());

        // Verify behavior with empty mutator sets. All empty MS' are the same.
        assert!(
            addition_record_0.has_matching_aocl(&msa0.aocl),
            "Addition record made from MS accumulator must match"
        );
        assert!(
            addition_record_0.has_matching_aocl(&msa1.aocl),
            "Addition record made from equivalent MS accumulator must match (1)"
        );

        // Verify behavior with two different mutator sets, with different leaf count.
        msa0.add(&addition_record_0);
        assert!(
            !addition_record_1.has_matching_aocl(&msa0.aocl),
            "Addition record made from MS accumulator must match"
        );
        assert!(
            addition_record_1.has_matching_aocl(&msa1.aocl),
            "Addition record made from equivalent MS accumulator must match (2)"
        );

        // Verify behavior with two different mutator sets, with same leaf count.
        msa1.add(&addition_record_1);
        let new_addition_record_1: AdditionRecord<Hasher> =
            msa1.commit(&1957u128.into(), &1969u128.into());
        let new_addition_record_0: AdditionRecord<blake3::Hasher> =
            msa0.commit(&1957u128.into(), &1969u128.into());
        assert!(new_addition_record_1.has_matching_aocl(&new_addition_record_1.aocl_snapshot));
        assert!(!new_addition_record_1.has_matching_aocl(&new_addition_record_0.aocl_snapshot));
        assert!(!new_addition_record_1.has_matching_aocl(&msa0.aocl));
        assert!(new_addition_record_1.has_matching_aocl(&msa1.aocl));

        assert!(new_addition_record_0.has_matching_aocl(&new_addition_record_0.aocl_snapshot));
        assert!(!new_addition_record_0.has_matching_aocl(&new_addition_record_1.aocl_snapshot));
    }
}
