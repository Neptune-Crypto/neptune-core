use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::chunk::Chunk;
use crate::util_types::{mmr, simple_hasher};

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

impl<H: simple_hasher::Hasher> ChunkDictionary<H> {
    pub fn default() -> ChunkDictionary<H> {
        Self {
            dictionary: HashMap::new(),
        }
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
