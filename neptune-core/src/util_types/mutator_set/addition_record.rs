use std::fmt::Display;

#[cfg(any(test, feature = "arbitrary-impls"))]
use arbitrary::Arbitrary;
use get_size2::GetSize;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::TasmObject;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;
use tasm_lib::twenty_first::tip5::digest::Digest;

#[derive(
    Clone,
    Copy,
    Debug,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Hash,
    GetSize,
    BFieldCodec,
    TasmObject,
)]
#[cfg_attr(any(test, feature = "arbitrary-impls"), derive(Arbitrary))]
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

impl Display for AdditionRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.canonical_commitment)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use rand::random;
    use tasm_lib::prelude::Tip5;

    use super::*;
    use crate::util_types::mutator_set::commit;

    #[test]
    fn get_size_test() {
        let addition_record_0: AdditionRecord = commit(
            Tip5::hash(&1492u128),
            Tip5::hash(&1522u128),
            Tip5::hash(&1521u128),
        );

        assert_eq!(std::mem::size_of::<Digest>(), addition_record_0.get_size());
    }

    #[test]
    fn hash_identity_test() {
        let addition_record_0: AdditionRecord = commit(
            Tip5::hash(&1492u128),
            Tip5::hash(&1522u128),
            Tip5::hash(&1521u128),
        );

        let addition_record_1: AdditionRecord = commit(
            Tip5::hash(&1492u128),
            Tip5::hash(&1522u128),
            Tip5::hash(&1521u128),
        );

        assert_eq!(
            Tip5::hash(&addition_record_0),
            Tip5::hash(&addition_record_1),
            "Two addition records with same commitments and same MMR AOCLs must agree."
        );

        let addition_record_2: AdditionRecord = commit(
            Tip5::hash(&1451u128),
            Tip5::hash(&1480u128),
            Tip5::hash(&1481u128),
        );

        // Verify behavior with empty mutator sets. All empty MS' are the same.
        assert_ne!(
            Tip5::hash(&addition_record_0),
            Tip5::hash(&addition_record_2),
            "Two addition records with differing commitments but same MMR AOCLs must differ."
        );
    }

    #[test]
    fn serialization_test() {
        let item = Tip5::hash(&1492u128);
        let sender_randomness = Tip5::hash(&1522u128);
        let receiver_digest = Tip5::hash(&1583u128);
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
