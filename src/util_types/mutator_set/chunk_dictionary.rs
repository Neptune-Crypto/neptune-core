use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::chunk::Chunk;
use crate::{
    shared_math::b_field_element::BFieldElement,
    util_types::{
        mmr,
        simple_hasher::{self, ToDigest},
    },
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChunkDictionary<H: simple_hasher::Hasher + Sized> {
    // {chunk index => (membership proof for the whole chunk to which bit belongs, chunk value)}
    pub dictionary: HashMap<u128, (mmr::mmr_membership_proof::MmrMembershipProof<H>, Chunk)>,
}

impl<H: simple_hasher::Hasher> PartialEq for ChunkDictionary<H> {
    fn eq(&self, other: &Self) -> bool {
        self.dictionary == other.dictionary
    }
}

impl<H: simple_hasher::Hasher> ChunkDictionary<H>
where
    u128: ToDigest<<H as simple_hasher::Hasher>::Digest>,
    Vec<BFieldElement>: ToDigest<H::Digest>,
{
    pub fn default() -> ChunkDictionary<H> {
        Self {
            dictionary: HashMap::new(),
        }
    }

    pub fn hash(&self) -> H::Digest {
        let mut keys: Vec<u128> = self.dictionary.clone().into_keys().collect();
        keys.sort_unstable();
        let hasher = H::new();

        let mut preimage: Vec<H::Digest> = vec![];
        for key in keys {
            preimage.push(key.to_digest());
            preimage.push(self.dictionary[&key].0.hash());
            preimage.push(self.dictionary[&key].1.hash(&hasher));
        }

        hasher.hash_many(&preimage)
    }
}

#[cfg(test)]
mod chunk_dict_tests {
    use crate::{
        shared_math::{
            b_field_element::BFieldElement,
            rescue_prime_xlix::{RescuePrimeXlix, RP_DEFAULT_OUTPUT_SIZE, RP_DEFAULT_WIDTH},
        },
        util_types::{
            mmr::{
                archival_mmr::ArchivalMmr, mmr_membership_proof::MmrMembershipProof, mmr_trait::Mmr,
            },
            mutator_set::shared::{BITS_PER_U32, CHUNK_SIZE},
            simple_hasher::Hasher,
        },
    };

    use super::*;

    #[test]
    fn hash_test() {
        type Hasher = RescuePrimeXlix<RP_DEFAULT_WIDTH>;
        type HM = HashMap<u128, (mmr::mmr_membership_proof::MmrMembershipProof<Hasher>, Chunk)>;
        let empty0: ChunkDictionary<Hasher> = ChunkDictionary {
            dictionary: HashMap::new(),
        };
        let empty1: ChunkDictionary<Hasher> = ChunkDictionary {
            dictionary: HashMap::new(),
        };
        assert_eq!(empty0.hash(), empty1.hash());

        // Insert elements
        let rp = RescuePrimeXlix::new();
        let leaf_hashes: Vec<Vec<BFieldElement>> = (1001..1001 + 3)
            .map(|x| rp.hash(&vec![BFieldElement::new(x as u64)], RP_DEFAULT_OUTPUT_SIZE))
            .collect();
        let archival_mmr =
            ArchivalMmr::<RescuePrimeXlix<RP_DEFAULT_WIDTH>>::new(leaf_hashes.clone());
        let mp0: MmrMembershipProof<RescuePrimeXlix<RP_DEFAULT_WIDTH>> =
            archival_mmr.prove_membership(1).0;
        let chunk0 = Chunk {
            bits: [0xFFFFFFFFu32; CHUNK_SIZE / BITS_PER_U32],
        };

        let key0 = 898989u128;
        let mut hash_map = HM::new();
        hash_map.insert(key0, (mp0.clone(), chunk0));
        let one_element: ChunkDictionary<Hasher> = ChunkDictionary {
            dictionary: hash_map.clone(),
        };
        assert_ne!(empty0.hash(), one_element.hash());

        // Insert two more element and verify that the hash is deterministic which implies that the
        // elements in the preimage are sorted deterministically.
        let key1 = 8989u128;
        let mp1: MmrMembershipProof<RescuePrimeXlix<RP_DEFAULT_WIDTH>> =
            archival_mmr.prove_membership(2).0;
        let mut chunk1 = Chunk {
            bits: [0x00u32; CHUNK_SIZE / BITS_PER_U32],
        };
        chunk1.bits[CHUNK_SIZE / (2 * BITS_PER_U32) + 1] = 0x01u32;
        hash_map.insert(key1, (mp1.clone(), chunk1));
        let two_elements: ChunkDictionary<Hasher> = ChunkDictionary {
            dictionary: hash_map.clone(),
        };
        assert_ne!(empty0.hash(), two_elements.hash());
        assert_ne!(one_element.hash(), two_elements.hash());

        let key2 = 89u128;
        hash_map.insert(key2, (mp1.clone(), chunk1));
        let three_elements: ChunkDictionary<Hasher> = ChunkDictionary {
            dictionary: hash_map.clone(),
        };

        // Construct similar data structure to `two_elements` but insert key/value pairs in opposite order
        let mut new_hash_map = HM::new();
        new_hash_map.insert(key1, (mp1.clone(), chunk1));
        new_hash_map.insert(key2, (mp1.clone(), chunk1));
        new_hash_map.insert(key0, (mp0.clone(), chunk0));
        let three_elements_alt: ChunkDictionary<Hasher> = ChunkDictionary {
            dictionary: new_hash_map.clone(),
        };

        // Verify that keys are sorted deterministically when hashing chunk dictionary.
        // This test fails if the hash method does not sort the keys
        for _ in 0..10 {
            assert_eq!(three_elements.hash(), three_elements_alt.hash());
        }
    }

    #[test]
    fn serialization_test() {
        // TODO: You could argue that this test doesn't belong here, as it tests the behavior of
        // an imported library. I included it here, though, because the setup seems a bit clumsy
        // to me so far.
        type Hasher = RescuePrimeXlix<RP_DEFAULT_WIDTH>;
        type HM = HashMap<u128, (mmr::mmr_membership_proof::MmrMembershipProof<Hasher>, Chunk)>;
        let mut hash_map: HM = HashMap::new();
        let s_empty: ChunkDictionary<Hasher> = ChunkDictionary {
            dictionary: hash_map.clone(),
        };
        let json = serde_json::to_string(&s_empty).unwrap();
        println!("json = {}", json);
        let s_back = serde_json::from_str::<ChunkDictionary<Hasher>>(&json).unwrap();
        assert!(s_back.dictionary.is_empty());

        // Build a non-empty chunk dict and verify that it still works
        let rp = RescuePrimeXlix::new();
        let leaf_hashes: Vec<Vec<BFieldElement>> = (1001..1001 + 3)
            .map(|x| rp.hash(&vec![BFieldElement::new(x as u64)], RP_DEFAULT_OUTPUT_SIZE))
            .collect();
        let archival_mmr =
            ArchivalMmr::<RescuePrimeXlix<RP_DEFAULT_WIDTH>>::new(leaf_hashes.clone());
        let mp: MmrMembershipProof<RescuePrimeXlix<RP_DEFAULT_WIDTH>> =
            archival_mmr.prove_membership(1).0;
        let chunk = Chunk {
            bits: [0xFFFFFFFFu32; CHUNK_SIZE / BITS_PER_U32],
        };

        let key = 898989u128;
        hash_map.insert(key, (mp.clone(), chunk));
        let s_non_empty: ChunkDictionary<Hasher> = ChunkDictionary {
            dictionary: hash_map,
        };
        let json_non_empty = serde_json::to_string(&s_non_empty).unwrap();
        println!("json_non_empty = {}", json_non_empty);
        let s_back_non_empty =
            serde_json::from_str::<ChunkDictionary<Hasher>>(&json_non_empty).unwrap();
        assert!(!s_back_non_empty.dictionary.is_empty());
        assert!(s_back_non_empty.dictionary.contains_key(&key));
        assert_eq!((mp, chunk), s_back_non_empty.dictionary[&key]);
    }
}
