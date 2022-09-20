use serde::{Deserialize, Serialize};

use twenty_first::util_types::simple_hasher::{Hashable, Hasher};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct AdditionRecord<H: Hasher> {
    pub canonical_commitment: H::Digest,
}

impl<H: Hasher> AdditionRecord<H>
where
    u128: Hashable<<H as Hasher>::T>,
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
    use twenty_first::shared_math::rescue_prime_regular::RescuePrimeRegular;

    use super::*;

    #[test]
    fn hash_identity_test() {
        type H = RescuePrimeRegular;
        let hasher = H::new();

        let mut msa0: MutatorSetAccumulator<H> = MutatorSetAccumulator::default();
        let addition_record_0: AdditionRecord<H> = msa0.set_commitment.commit(
            &hasher.hash_sequence(&1492u128.to_sequence()),
            &hasher.hash_sequence(&1522u128.to_sequence()),
        );

        let mut msa1: MutatorSetAccumulator<H> = MutatorSetAccumulator::default();
        let addition_record_1: AdditionRecord<H> = msa1.set_commitment.commit(
            &hasher.hash_sequence(&1492u128.to_sequence()),
            &hasher.hash_sequence(&1522u128.to_sequence()),
        );

        assert_eq!(
            addition_record_0.hash(),
            addition_record_1.hash(),
            "Two addition records with same commitments and same MMR AOCLs must agree."
        );

        let mut msa3: MutatorSetAccumulator<H> = MutatorSetAccumulator::default();
        let addition_record_1: AdditionRecord<H> = msa3.set_commitment.commit(
            &hasher.hash_sequence(&1451u128.to_sequence()),
            &hasher.hash_sequence(&1480u128.to_sequence()),
        );

        // Verify behavior with empty mutator sets. All empty MS' are the same.
        assert_ne!(
            addition_record_0.hash(),
            addition_record_1.hash(),
            "Two addition records with differing commitments but same MMR AOCLs must differ."
        );
    }

    #[test]
    fn serialization_test() {
        type Hasher = RescuePrimeRegular;
        let mut msa: MutatorSetAccumulator<Hasher> = MutatorSetAccumulator::default();
        let hasher = Hasher::new();
        let item = hasher.hash_sequence(&1492u128.to_sequence());
        let randomness = hasher.hash_sequence(&1522u128.to_sequence());
        let addition_record: AdditionRecord<Hasher> = msa.set_commitment.commit(&item, &randomness);
        let json = serde_json::to_string(&addition_record).unwrap();
        let s_back = serde_json::from_str::<AdditionRecord<Hasher>>(&json).unwrap();
        assert_eq!(
            addition_record.canonical_commitment,
            s_back.canonical_commitment
        );
    }
}
