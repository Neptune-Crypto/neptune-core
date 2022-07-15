use serde_big_array;
use serde_big_array::BigArray;
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;

use super::{
    chunk_dictionary::ChunkDictionary,
    set_commitment::SetCommitment,
    shared::{bit_indices_to_hash_map, NUM_TRIALS},
};
use crate::{
    shared_math::b_field_element::BFieldElement,
    util_types::{
        mmr::mmr_trait::Mmr,
        simple_hasher::{self, ToDigest},
    },
};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
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
    pub fn validate<M>(&self, mutator_set: &mut SetCommitment<H, M>) -> bool
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

    // Return a digest of the removal record
    pub fn hash(&self) -> H::Digest {
        // This method assumes that the bit_indices field is sorted. If they are not,
        // then this method's output will not be deterministic. So we need a test for that,
        // that the bit indices are sorted. This is what `verify_that_bit_indices_are_sorted_test`
        // verifies.

        let preimage: Vec<H::Digest> = self.get_preimage();
        let hasher = H::new();

        hasher.hash_many(&preimage)
    }

    fn get_preimage(&self) -> Vec<H::Digest> {
        let mut preimage: Vec<H::Digest> = vec![];
        for bi in self.bit_indices.iter() {
            preimage.push(bi.to_digest());
        }
        preimage.push(self.target_chunks.hash());

        preimage
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
                shared::{CHUNK_SIZE, NUM_TRIALS},
            },
            simple_hasher::Hasher,
        },
        utils::{self, has_unique_elements},
    };

    #[test]
    fn verify_that_hash_preimage_elements_are_unique_test() {
        type H = blake3::Hasher;
        type Digest = blake3_wrapper::Blake3Hash;
        let hasher = H::new();
        let mut prng = thread_rng();
        let mut accumulator: MutatorSetAccumulator<H> = MutatorSetAccumulator::default();
        let item = hasher.hash::<Digest>(&(prng.next_u64() as u128).into());
        let randomness = hasher.hash::<Digest>(&(prng.next_u64() as u128).into());
        let mp = accumulator.prove(&item, &randomness, true);
        let removal_record: RemovalRecord<H> = accumulator.drop(&item.into(), &mp);

        let preimage = removal_record.get_preimage();
        assert_eq!(NUM_TRIALS + 1, preimage.len());
        assert!(utils::has_unique_elements(preimage));
    }

    #[test]
    fn verify_that_bit_indices_are_sorted_test() {
        type H = blake3::Hasher;
        type Digest = blake3_wrapper::Blake3Hash;
        let hasher = H::new();
        let mut prng = thread_rng();
        let mut accumulator: MutatorSetAccumulator<H> = MutatorSetAccumulator::default();
        let item = hasher.hash::<Digest>(&(prng.next_u64() as u128).into());
        let randomness = hasher.hash::<Digest>(&(prng.next_u64() as u128).into());
        let mp = accumulator.prove(&item, &randomness, true);
        let removal_record: RemovalRecord<H> = accumulator.drop(&item.into(), &mp);

        let bit_indices = removal_record.bit_indices;
        let mut bit_indices_sorted = bit_indices.clone();
        bit_indices_sorted.sort_unstable();
        assert_eq!(
            bit_indices, bit_indices_sorted,
            "bit indices must sorted in the removal record"
        );

        // Alternative way of checking that the indices are sorted (thanks, IRC)
        assert!(
            bit_indices.windows(2).all(|s| s[0] < s[1]),
            "bit-indices must be sorted"
        );
    }

    #[test]
    fn hash_test() {
        type H = blake3::Hasher;
        type Digest = blake3_wrapper::Blake3Hash;
        let hasher = H::new();
        let mut prng = thread_rng();
        let mut accumulator: MutatorSetAccumulator<H> = MutatorSetAccumulator::default();
        let item = hasher.hash::<Digest>(&(prng.next_u64() as u128).into());
        let randomness = hasher.hash::<Digest>(&(prng.next_u64() as u128).into());
        let mp = accumulator.prove(&item, &randomness, true);
        let removal_record: RemovalRecord<H> = accumulator.drop(&item.into(), &mp);
        let mut removal_record_alt: RemovalRecord<H> = removal_record.clone();
        assert_eq!(
            removal_record.hash(),
            removal_record_alt.hash(),
            "Same removal record must hash to same value"
        );
        removal_record_alt.bit_indices[NUM_TRIALS / 4] += 1;

        // Sanity check (theoretically, a collission in the bit indices could have happened)
        assert!(
            utils::has_unique_elements(removal_record_alt.bit_indices),
            "Sanity check to ensure that bit indices are still all unique"
        );
        assert_ne!(
            removal_record.hash(),
            removal_record_alt.hash(),
            "Changing a bit index must produce a new hash"
        );
    }

    #[test]
    fn get_chunk_index_to_bit_indices_test() {
        // Create a removal record
        type H = blake3::Hasher;
        type Digest = blake3_wrapper::Blake3Hash;
        let hasher = H::new();
        let mut prng = thread_rng();
        let mut accumulator: MutatorSetAccumulator<H> = MutatorSetAccumulator::default();
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
        let mut accumulator: MutatorSetAccumulator<H> = MutatorSetAccumulator::default();
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
        assert_eq!(s_back.bit_indices, removal_record.bit_indices);
        assert_eq!(s_back.target_chunks, removal_record.target_chunks);
    }
}
