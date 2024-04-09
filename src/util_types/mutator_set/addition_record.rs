use crate::prelude::twenty_first;

use arbitrary::Arbitrary;
use get_size::GetSize;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use twenty_first::shared_math::bfield_codec::BFieldCodec;
use twenty_first::shared_math::tip5::Digest;

#[derive(
    Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, GetSize, BFieldCodec, Arbitrary,
)]
pub struct AdditionRecord {
    pub canonical_commitment: Digest,
}

impl AdditionRecord {
    pub fn new(canonical_commitment: Digest) -> Self {
        Self {
            canonical_commitment,
        }
    }
}

pub fn pseudorandom_addition_record(seed: [u8; 32]) -> AdditionRecord {
    let mut rng: StdRng = SeedableRng::from_seed(seed);
    let ar: Digest = rng.gen();
    AdditionRecord {
        canonical_commitment: ar,
    }
}

#[cfg(test)]
mod addition_record_tests {

    use rand::random;
    use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;

    use crate::{models::blockchain::shared::Hash, util_types::mutator_set::commit};

    use super::*;

    #[test]
    fn get_size_test() {
        let addition_record_0: AdditionRecord = commit(
            Hash::hash(&1492u128),
            Hash::hash(&1522u128),
            Hash::hash(&1521u128),
        );

        assert_eq!(std::mem::size_of::<Digest>(), addition_record_0.get_size());
    }

    #[test]
    fn hash_identity_test() {
        let addition_record_0: AdditionRecord = commit(
            Hash::hash(&1492u128),
            Hash::hash(&1522u128),
            Hash::hash(&1521u128),
        );

        let addition_record_1: AdditionRecord = commit(
            Hash::hash(&1492u128),
            Hash::hash(&1522u128),
            Hash::hash(&1521u128),
        );

        assert_eq!(
            Hash::hash(&addition_record_0),
            Hash::hash(&addition_record_1),
            "Two addition records with same commitments and same MMR AOCLs must agree."
        );

        let addition_record_2: AdditionRecord = commit(
            Hash::hash(&1451u128),
            Hash::hash(&1480u128),
            Hash::hash(&1481u128),
        );

        // Verify behavior with empty mutator sets. All empty MS' are the same.
        assert_ne!(
            Hash::hash(&addition_record_0),
            Hash::hash(&addition_record_2),
            "Two addition records with differing commitments but same MMR AOCLs must differ."
        );
    }

    #[test]
    fn serialization_test() {
        let item = Hash::hash(&1492u128);
        let sender_randomness = Hash::hash(&1522u128);
        let receiver_digest = Hash::hash(&1583u128);
        let addition_record: AdditionRecord = commit(item, sender_randomness, receiver_digest);
        let json = serde_json::to_string(&addition_record).unwrap();
        let s_back = serde_json::from_str::<AdditionRecord>(&json).unwrap();
        assert_eq!(
            addition_record.canonical_commitment,
            s_back.canonical_commitment
        );
    }

    #[test]
    fn bfieldcodec_test() {
        let addition_record = AdditionRecord {
            canonical_commitment: random(),
        };

        let encoded = addition_record.encode();
        let decoded = *AdditionRecord::decode(&encoded).unwrap();
        assert_eq!(addition_record, decoded);
    }

    #[test]
    fn bfieldcodec_test_on_vecs() {
        for i in 0..5 {
            let addition_records = vec![
                AdditionRecord {
                    canonical_commitment: random(),
                };
                i
            ];
            let encoded = addition_records.encode();
            let decoded = *Vec::<AdditionRecord>::decode(&encoded).unwrap();
            assert_eq!(addition_records, decoded);
        }
    }
}
