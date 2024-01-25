use crate::prelude::{triton_vm, twenty_first};

use anyhow::bail;
use get_size::GetSize;
use itertools::Itertools;
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use triton_vm::prelude::Digest;
use twenty_first::shared_math::bfield_codec::BFieldCodec;

use super::chunk::Chunk;
use twenty_first::shared_math::b_field_element::BFieldElement;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;
use twenty_first::util_types::mmr::mmr_membership_proof::MmrMembershipProof;

#[derive(Clone, Debug, Serialize, Deserialize, GetSize, PartialEq, Eq)]
pub struct ChunkDictionary<H: AlgebraicHasher> {
    // {chunk index => (MMR membership proof for the whole chunk to which index belongs, chunk value)}
    pub dictionary: HashMap<u64, (MmrMembershipProof<H>, Chunk)>,
}

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

impl<H: AlgebraicHasher> BFieldCodec for ChunkDictionary<H> {
    type Error = anyhow::Error;

    fn encode(&self) -> Vec<BFieldElement> {
        let mut string = vec![BFieldElement::new(self.dictionary.keys().len() as u64)];
        for key in self.dictionary.keys().sorted() {
            string.append(&mut key.encode());
            let mut membership_proof_encoded = self.dictionary[key].0.encode();
            string.push(BFieldElement::new(membership_proof_encoded.len() as u64));
            string.append(&mut membership_proof_encoded);
            let mut chunk_encoded = self.dictionary[key].1.encode();
            string.push(BFieldElement::new(chunk_encoded.len() as u64));
            string.append(&mut chunk_encoded);
        }
        string
    }

    fn decode(sequence: &[BFieldElement]) -> anyhow::Result<Box<Self>> {
        if sequence.is_empty() {
            bail!("Cannot decode empty sequence of BFieldElements as ChunkDictionary");
        }
        let num_entries = sequence[0].value() as usize;
        let mut read_index = 1;
        let mut dictionary = HashMap::new();
        for _ in 0..num_entries {
            // read key
            let key_length = 2;
            if sequence.len() < read_index + key_length {
                bail!("Cannot decode sequence of BFieldElements as ChunkDictionary: missing key");
            }
            let key = *u64::decode(&sequence[read_index..read_index + key_length])?;
            read_index += key_length;

            // read membership proof
            if sequence.len() <= read_index {
                bail!("Cannot decode sequence of BFieldElements as ChunkDictionary: missing membership proof");
            }
            let memproof_length = sequence[read_index].value() as usize;
            read_index += 1;
            let membership_proof = *MmrMembershipProof::<H>::decode(
                &sequence[read_index..read_index + memproof_length],
            )?;
            read_index += memproof_length;

            // read chunk
            if sequence.len() <= read_index {
                bail!("Cannot decode sequence of BFieldElements as ChunkDictionary: missing chunk");
            }
            let chunk_length = sequence[read_index].value() as usize;
            read_index += 1;
            let chunk = *Chunk::decode(&sequence[read_index..read_index + chunk_length])?;
            read_index += chunk_length;

            dictionary.insert(key, (membership_proof, chunk));
        }

        Ok(Box::new(ChunkDictionary { dictionary }))
    }

    fn static_length() -> Option<usize> {
        None
    }
}

/// Generate pseudorandom chunk dictionary from the given seed, for testing purposes.
pub fn pseudorandom_chunk_dictionary<H: AlgebraicHasher>(seed: [u8; 32]) -> ChunkDictionary<H> {
    let mut rng: StdRng = SeedableRng::from_seed(seed);

    let mut dictionary = HashMap::new();
    for _ in 0..37 {
        let key = rng.next_u64();
        let authpath: Vec<Digest> = (0..rng.gen_range(0..6)).map(|_| rng.gen()).collect_vec();
        let chunk: Vec<u32> = (0..rng.gen_range(0..17)).map(|_| rng.gen()).collect_vec();

        dictionary.insert(
            key,
            (
                MmrMembershipProof::new(key, authpath),
                Chunk {
                    relative_indices: chunk,
                },
            ),
        );
    }
    ChunkDictionary::<H>::new(dictionary)
}

#[cfg(test)]
mod chunk_dict_tests {
    use crate::util_types::mutator_set::shared::CHUNK_SIZE;
    use crate::util_types::test_shared::mutator_set::random_chunk_dictionary;

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
        let archival_mmr = get_rustyleveldb_ammr_from_digests(leaf_hashes);

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
        let archival_mmr = get_rustyleveldb_ammr_from_digests(leaf_hashes);
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

    #[test]
    fn test_chunk_dictionary_decode() {
        type H = Tip5;
        let chunk_dictionary = random_chunk_dictionary::<H>();

        let encoded = chunk_dictionary.encode();
        let decoded = *ChunkDictionary::decode(&encoded).unwrap();

        assert_eq!(chunk_dictionary, decoded);
    }
}
