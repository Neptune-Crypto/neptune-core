use serde::{Deserialize, Serialize};

use twenty_first::util_types::{
    mmr::{mmr_accumulator::MmrAccumulator, mmr_trait::Mmr},
    simple_hasher::{self, ToDigest},
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
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

    pub fn has_matching_aocl(&mut self, aocl_accumulator: &mut MmrAccumulator<H>) -> bool {
        self.aocl_snapshot.count_leaves() == aocl_accumulator.count_leaves()
            && self.aocl_snapshot.get_peaks() == aocl_accumulator.get_peaks()
    }

    pub fn hash(&mut self) -> H::Digest {
        let mmr_digest = self.aocl_snapshot.bag_peaks();
        H::new().hash_pair(&self.commitment, &mmr_digest)
    }
}

#[cfg(test)]
mod addition_record_tests {
    use crate::util_types::mutator_set::{
        mutator_set_accumulator::MutatorSetAccumulator, mutator_set_trait::MutatorSet,
    };
    use twenty_first::shared_math::rescue_prime_xlix::{RescuePrimeXlix, RP_DEFAULT_WIDTH};

    use super::*;

    #[test]
    fn hash_test() {
        type Hasher = blake3::Hasher;

        let mut msa0: MutatorSetAccumulator<Hasher> = MutatorSetAccumulator::default();
        let mut msa1: MutatorSetAccumulator<Hasher> = MutatorSetAccumulator::default();
        let mut addition_record_0: AdditionRecord<Hasher> =
            msa0.commit(&1492u128.into(), &1522u128.into());
        let mut addition_record_1: AdditionRecord<Hasher> =
            msa1.commit(&1492u128.into(), &1522u128.into());
        assert_eq!(
            addition_record_0.hash(),
            addition_record_1.hash(),
            "Two addition records with same commitments and same MMR AOCLs must agree."
        );
    }

    #[test]
    fn has_matching_aocl_test() {
        type Hasher = blake3::Hasher;

        // let mut msa0: MutatorSetAccumulator<Hasher> = MutatorSetAccumulator::default();
        let mut msa0: MutatorSetAccumulator<Hasher> = MutatorSetAccumulator::default();
        let mut msa1: MutatorSetAccumulator<Hasher> = MutatorSetAccumulator::default();
        let mut addition_record_0: AdditionRecord<Hasher> =
            msa0.commit(&1492u128.into(), &1522u128.into());
        let mut addition_record_1: AdditionRecord<Hasher> =
            msa1.commit(&1451u128.into(), &1480u128.into());

        // Verify behavior with empty mutator sets. All empty MS' are the same.
        assert!(
            addition_record_0.has_matching_aocl(&mut msa0.aocl),
            "Addition record made from MS accumulator must match"
        );
        assert!(
            addition_record_0.has_matching_aocl(&mut msa1.aocl),
            "Addition record made from equivalent MS accumulator must match (1)"
        );
        assert_ne!(
            addition_record_0.hash(),
            addition_record_1.hash(),
            "Two addition records with differing commitments but same MMR AOCLs must differ."
        );

        // Verify behavior with two different mutator sets, with different leaf count.
        msa0.add(&mut addition_record_0);
        assert!(
            !addition_record_1.has_matching_aocl(&mut msa0.aocl),
            "Addition record made from MS accumulator must match"
        );
        assert!(
            addition_record_1.has_matching_aocl(&mut msa1.aocl),
            "Addition record made from equivalent MS accumulator must match (2)"
        );

        // Verify behavior with two different mutator sets, with same leaf count.
        msa1.add(&mut addition_record_1);
        let mut new_addition_record_1: AdditionRecord<Hasher> =
            msa1.commit(&1957u128.into(), &1969u128.into());
        let mut new_addition_record_0: AdditionRecord<blake3::Hasher> =
            msa0.commit(&1957u128.into(), &1969u128.into());
        let mut nar1_snapshot = new_addition_record_1.aocl_snapshot.clone();
        assert!(new_addition_record_1.has_matching_aocl(&mut nar1_snapshot));
        assert!(!new_addition_record_1.has_matching_aocl(&mut new_addition_record_0.aocl_snapshot));
        assert!(!new_addition_record_1.has_matching_aocl(&mut msa0.aocl));
        assert!(new_addition_record_1.has_matching_aocl(&mut msa1.aocl));

        let mut nar0_snapshow = new_addition_record_0.aocl_snapshot.clone();
        assert!(new_addition_record_0.has_matching_aocl(&mut nar0_snapshow));
        assert!(!new_addition_record_0.has_matching_aocl(&mut new_addition_record_1.aocl_snapshot));

        assert_ne!(
            new_addition_record_0.hash(),
            new_addition_record_1.hash(),
            "Two addition records with same commitments but differing MMR AOCLs must differ."
        );
    }

    #[test]
    fn serialization_test() {
        type Hasher = RescuePrimeXlix<RP_DEFAULT_WIDTH>;
        let mut msa: MutatorSetAccumulator<Hasher> = MutatorSetAccumulator::default();
        let mut addition_record: AdditionRecord<Hasher> =
            msa.commit(&1492u128.to_digest(), &1522u128.to_digest());
        let json = serde_json::to_string(&addition_record).unwrap();
        let mut s_back = serde_json::from_str::<AdditionRecord<Hasher>>(&json).unwrap();
        assert_eq!(addition_record.commitment, s_back.commitment);
        assert!(addition_record.has_matching_aocl(&mut s_back.aocl_snapshot));
    }
}
