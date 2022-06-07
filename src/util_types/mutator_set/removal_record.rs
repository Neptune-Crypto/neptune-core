use serde_big_array;
use serde_big_array::BigArray;
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;

use super::{
    chunk_dictionary::ChunkDictionary,
    set_commitment::{SetCommitment, NUM_TRIALS},
    shared::bit_indices_to_hash_map,
};
use crate::{
    shared_math::b_field_element::BFieldElement,
    util_types::{
        mmr::mmr_trait::Mmr,
        simple_hasher::{self, ToDigest},
    },
};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RemovalRecord<H: simple_hasher::Hasher> {
    #[serde(with = "BigArray")]
    pub bit_indices: [u128; NUM_TRIALS],
    pub target_chunks: ChunkDictionary<H>,
}

impl<H> RemovalRecord<H>
where
    u128: ToDigest<<H as simple_hasher::Hasher>::Digest>,
    Vec<BFieldElement>: ToDigest<<H as simple_hasher::Hasher>::Digest>,
    H: simple_hasher::Hasher,
{
    pub fn validate<M>(&self, mutator_set: &SetCommitment<H, M>) -> bool
    where
        M: Mmr<H>,
    {
        let peaks = mutator_set.swbf_inactive.get_peaks();
        self.target_chunks.dictionary.iter().all(|(_i, (p, c))| {
            p.verify(
                &peaks,
                &c.hash::<H>(&H::new()),
                mutator_set.swbf_inactive.count_leaves(),
            )
            .0
        })
    }

    /// Returns a hashmap from chunk index to chunk.
    pub fn get_chunk_index_to_bit_indices(&self) -> HashMap<u128, Vec<u128>> {
        bit_indices_to_hash_map(&self.bit_indices)
    }
}

#[cfg(test)]
mod removal_record_tests {
    use itertools::Itertools;
    use rand::{thread_rng, RngCore};

    use crate::{
        shared_math::{
            b_field_element::BFieldElement,
            rescue_prime_xlix::{RescuePrimeXlix, RP_DEFAULT_OUTPUT_SIZE, RP_DEFAULT_WIDTH},
            traits::GetRandomElements,
        },
        util_types::{
            blake3_wrapper,
            mutator_set::{
                mutator_set_accumulator::MutatorSetAccumulator,
                removal_record::RemovalRecord,
                set_commitment::{CHUNK_SIZE, NUM_TRIALS},
            },
            simple_hasher::Hasher,
        },
        utils::has_unique_elements,
    };

    #[test]
    fn get_chunk_index_to_bit_indices_test() {
        // Create a removal record
        type H = blake3::Hasher;
        type Digest = blake3_wrapper::Blake3Hash;
        let hasher = H::new();
        let mut prng = thread_rng();
        let accumulator: MutatorSetAccumulator<H> = MutatorSetAccumulator::default();
        let item = hasher.hash::<Digest>(&(prng.next_u64() as u128).into());
        let randomness = hasher.hash::<Digest>(&(prng.next_u64() as u128).into());
        let mp = accumulator.prove(&item, &randomness, true);
        let removal_record: RemovalRecord<H> = accumulator.drop(&item.into(), &mp);
        let chunks2bits = removal_record.get_chunk_index_to_bit_indices();

        // Verify that no indices are repeated in the hash map
        let mut all_bits: Vec<u128> = chunks2bits.clone().into_values().concat();
        all_bits.sort_unstable();
        let mut cached_bits = mp.cached_bits.unwrap();
        cached_bits.sort_unstable();
        assert_eq!(cached_bits.to_vec(), all_bits);
        assert!(has_unique_elements(all_bits.clone()));
        all_bits.dedup();
        assert_eq!(NUM_TRIALS, all_bits.len());

        // Verify that the hash map has put the indices into the correct buckets
        for (key, values) in chunks2bits {
            for value in values {
                assert!((value - key * CHUNK_SIZE as u128) < CHUNK_SIZE as u128);
            }
        }
    }

    #[test]
    fn serialization_test() {
        // TODO: You could argue that this test doesn't belong here, as it tests the behavior of
        // an imported library. I included it here, though, because the setup seems a bit clumsy
        // to me so far.
        type H = RescuePrimeXlix<RP_DEFAULT_WIDTH>;
        let hasher = H::new();
        let mut prng = thread_rng();
        let accumulator: MutatorSetAccumulator<H> = MutatorSetAccumulator::default();
        let item = hasher.hash(
            &BFieldElement::random_elements(3, &mut prng),
            RP_DEFAULT_OUTPUT_SIZE,
        );
        let randomness = hasher.hash(
            &BFieldElement::random_elements(3, &mut prng),
            RP_DEFAULT_OUTPUT_SIZE,
        );
        let mp = accumulator.prove(&item, &randomness, true);
        let removal_record: RemovalRecord<H> = accumulator.drop(&item.into(), &mp);

        let json: String = serde_json::to_string(&removal_record).unwrap();
        let s_back = serde_json::from_str::<RemovalRecord<H>>(&json).unwrap();
        // assert_eq!(s_back, removal_record);
    }
}
