use get_size::GetSize;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::chunk::Chunk;
use twenty_first::shared_math::b_field_element::BFieldElement;
use twenty_first::util_types::algebraic_hasher::{AlgebraicHasher, Hashable};
use twenty_first::util_types::mmr::mmr_membership_proof::MmrMembershipProof;

#[derive(Clone, Debug, Serialize, Deserialize, GetSize)]
pub struct ChunkDictionary<H: AlgebraicHasher> {
    // {chunk index => (MMR membership proof for the whole chunk to which index belongs, chunk value)}
    pub dictionary: HashMap<u64, (MmrMembershipProof<H>, Chunk)>,
}

impl<H: AlgebraicHasher> PartialEq for ChunkDictionary<H> {
    fn eq(&self, other: &Self) -> bool {
        self.dictionary == other.dictionary
    }
}

impl<H: AlgebraicHasher> Eq for ChunkDictionary<H> {}

impl<H: AlgebraicHasher> ChunkDictionary<H> {
    pub fn new(dictionary: HashMap<u64, (MmrMembershipProof<H>, Chunk)>) -> Self {
        Self { dictionary }
    }
}

impl<H: AlgebraicHasher> Default for ChunkDictionary<H> {
    fn default() -> Self {
        Self {
            dictionary: HashMap::new(),
        }
    }
}

impl<H: AlgebraicHasher> Hashable for ChunkDictionary<H> {
    fn to_sequence(&self) -> Vec<BFieldElement> {
        self.dictionary
            .keys()
            .sorted()
            .flat_map(|key| {
                [
                    key.to_sequence(),
                    self.dictionary[key].0.to_sequence(),
                    self.dictionary[key].1.to_sequence(),
                ]
            })
            .flatten()
            .collect()
    }
}

#[cfg(test)]
mod chunk_dict_tests {
    use crate::util_types::mutator_set::shared::CHUNK_SIZE;

    use twenty_first::shared_math::other::random_elements;
    use twenty_first::shared_math::tip5::{Digest, Tip5};
    use twenty_first::test_shared::mmr::get_rustyleveldb_ammr_from_digests;
    use twenty_first::util_types::mmr::mmr_membership_proof::MmrMembershipProof;

    use super::*;

    #[test]
    fn hash_test() {
        type H = Tip5;

        let chunkdict0 = ChunkDictionary::<H>::default();
        let chunkdict00 = ChunkDictionary::<H>::default();
        assert_eq!(H::hash(&chunkdict0), H::hash(&chunkdict00));

        // Insert elements
        let num_leaves = 3;
        let leaf_hashes: Vec<Digest> = random_elements(num_leaves);
        let mut archival_mmr = get_rustyleveldb_ammr_from_digests(leaf_hashes);

        let key1: u64 = 898989;
        let mp1: MmrMembershipProof<H> = archival_mmr.prove_membership(1).0;
        let chunk1: Chunk = {
            Chunk {
                relative_indices: (0..CHUNK_SIZE).collect(),
            }
        };
        let value1 = (mp1, chunk1);
        let chunkdict1 = ChunkDictionary::<H>::new(HashMap::from([(key1, value1.clone())]));

        // Insert two more element and verify that the hash is deterministic which implies that the
        // elements in the preimage are sorted deterministically.
        let key2: u64 = 8989;
        let mp2: MmrMembershipProof<H> = archival_mmr.prove_membership(2).0;
        let mut chunk2 = Chunk::empty_chunk();
        chunk2.insert(CHUNK_SIZE / 2 + 1);
        let value2 = (mp2, chunk2);
        let chunkdict2 = ChunkDictionary::<H>::new(HashMap::from([
            (key1, value1.clone()),
            (key2, value2.clone()),
        ]));

        let key3: u64 = 89;
        let chunkdict3 = ChunkDictionary::<H>::new(HashMap::from([
            (key1, value1.clone()),
            (key2, value2.clone()),
            (key3, value2.clone()),
        ]));

        assert_ne!(H::hash(&chunkdict0), H::hash(&chunkdict1));
        assert_ne!(H::hash(&chunkdict0), H::hash(&chunkdict2));
        assert_ne!(H::hash(&chunkdict0), H::hash(&chunkdict3));
        assert_ne!(H::hash(&chunkdict1), H::hash(&chunkdict2));
        assert_ne!(H::hash(&chunkdict1), H::hash(&chunkdict3));
        assert_ne!(H::hash(&chunkdict2), H::hash(&chunkdict3));

        // Construct similar data structure to `two_elements` but insert key/value pairs in opposite order
        let chunkdict3_alt = ChunkDictionary::<H>::new(HashMap::from([
            (key3, value2.clone()),
            (key1, value1.clone()),
            (key2, value2.clone()),
        ]));

        // Verify that keys are sorted deterministically when hashing chunk dictionary.
        // This test fails if the hash method does not sort the keys
        for _ in 0..10 {
            assert_eq!(H::hash(&chunkdict3), H::hash(&chunkdict3_alt));
        }

        // Negative: Construct data structure where the keys and values are switched
        let chunkdict3_switched = ChunkDictionary::<H>::new(HashMap::from([
            (key1, value2.clone()),
            (key2, value1),
            (key3, value2),
        ]));

        assert_ne!(H::hash(&chunkdict3), H::hash(&chunkdict3_switched));
    }

    #[test]
    fn serialization_test() {
        // TODO: You could argue that this test doesn't belong here, as it tests the behavior of
        // an imported library. I included it here, though, because the setup seems a bit clumsy
        // to me so far.
        type H = Tip5;
        let s_empty: ChunkDictionary<H> = ChunkDictionary::new(HashMap::new());
        let json = serde_json::to_string(&s_empty).unwrap();
        println!("json = {}", json);
        let s_back = serde_json::from_str::<ChunkDictionary<H>>(&json).unwrap();
        assert!(s_back.dictionary.is_empty());

        // Build a non-empty chunk dict and verify that it still works
        let key: u64 = 898989;
        let leaf_hashes: Vec<Digest> = random_elements(3);
        let mut archival_mmr = get_rustyleveldb_ammr_from_digests(leaf_hashes);
        let mp: MmrMembershipProof<H> = archival_mmr.prove_membership(1).0;
        let chunk = Chunk {
            relative_indices: (0..CHUNK_SIZE).collect(),
        };

        let s_non_empty =
            ChunkDictionary::<H>::new(HashMap::from([(key, (mp.clone(), chunk.clone()))]));
        let json_non_empty = serde_json::to_string(&s_non_empty).unwrap();
        println!("json_non_empty = {}", json_non_empty);
        let s_back_non_empty = serde_json::from_str::<ChunkDictionary<H>>(&json_non_empty).unwrap();
        assert!(!s_back_non_empty.dictionary.is_empty());
        assert!(s_back_non_empty.dictionary.contains_key(&key));
        assert_eq!((mp, chunk), s_back_non_empty.dictionary[&key]);
    }
}
