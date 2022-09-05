use serde::{Deserialize, Serialize};

use twenty_first::util_types::simple_hasher::{self, ToDigest};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct AdditionRecord<H: simple_hasher::Hasher> {
    pub canonical_commitment: H::Digest,
}

impl<H> AdditionRecord<H>
where
    u128: ToDigest<<H as simple_hasher::Hasher>::Digest>,
    H: simple_hasher::Hasher,
{
    pub fn new(canonical_commitment: H::Digest) -> Self {
        Self {
            canonical_commitment,
        }
    }

    pub fn hash(&self) -> H::Digest {
        self.canonical_commitment.clone()
    }
}

#[cfg(test)]
mod addition_record_tests {
    use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
    use twenty_first::shared_math::rescue_prime_xlix::{RescuePrimeXlix, RP_DEFAULT_WIDTH};

    use super::*;

    #[test]
    fn hash_identity_test() {
        type Hasher = blake3::Hasher;

        let mut msa0: MutatorSetAccumulator<Hasher> = MutatorSetAccumulator::default();
        let mut msa1: MutatorSetAccumulator<Hasher> = MutatorSetAccumulator::default();
        let addition_record_0: AdditionRecord<Hasher> =
            msa0.commit(&1492u128.into(), &1522u128.into());
        let addition_record_1: AdditionRecord<Hasher> =
            msa1.commit(&1492u128.into(), &1522u128.into());
        assert_eq!(
            addition_record_0.hash(),
            addition_record_1.hash(),
            "Two addition records with same commitments and same MMR AOCLs must agree."
        );
    }

    #[test]
    fn hash_negative_test() {
        type Hasher = blake3::Hasher;

        let mut msa0: MutatorSetAccumulator<Hasher> = MutatorSetAccumulator::default();
        let mut msa1: MutatorSetAccumulator<Hasher> = MutatorSetAccumulator::default();
        let addition_record_0: AdditionRecord<Hasher> =
            msa0.commit(&1492u128.into(), &1522u128.into());
        let addition_record_1: AdditionRecord<Hasher> =
            msa1.commit(&1451u128.into(), &1480u128.into());

        // Verify behavior with empty mutator sets. All empty MS' are the same.
        assert_ne!(
            addition_record_0.hash(),
            addition_record_1.hash(),
            "Two addition records with differing commitments but same MMR AOCLs must differ."
        );
    }

    #[test]
    fn serialization_test() {
        type Hasher = RescuePrimeXlix<RP_DEFAULT_WIDTH>;
        let mut msa: MutatorSetAccumulator<Hasher> = MutatorSetAccumulator::default();
        let addition_record: AdditionRecord<Hasher> =
            msa.commit(&1492u128.to_digest(), &1522u128.to_digest());
        let json = serde_json::to_string(&addition_record).unwrap();
        let s_back = serde_json::from_str::<AdditionRecord<Hasher>>(&json).unwrap();
        assert_eq!(
            addition_record.canonical_commitment,
            s_back.canonical_commitment
        );
    }
}
