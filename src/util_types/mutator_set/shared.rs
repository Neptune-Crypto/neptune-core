use std::collections::{HashMap, HashSet};

use twenty_first::shared_math::b_field_element::BFIELD_ZERO;
use twenty_first::shared_math::rescue_prime_digest::{Digest, DIGEST_LENGTH};
use twenty_first::util_types::algebraic_hasher::{AlgebraicHasher, SpongeHasher};
use twenty_first::util_types::mmr::mmr_membership_proof::MmrMembershipProof;

use super::chunk_dictionary::ChunkDictionary;
use super::removal_record::RemovalRecord;

pub const WINDOW_SIZE: u32 = 1 << 20;
pub const CHUNK_SIZE: u32 = 1 << 12;
pub const BATCH_SIZE: u32 = 1 << 3;
pub const NUM_TRIALS: u32 = 45;

pub fn indices_to_hash_map(all_indices: &[u128; NUM_TRIALS as usize]) -> HashMap<u64, Vec<u128>> {
    let mut chunkidx_to_indices_dict: HashMap<u64, Vec<u128>> = HashMap::new();
    all_indices
        .iter()
        .map(|bi| ((bi / CHUNK_SIZE as u128) as u64, bi))
        .for_each(|(chunk_index, index)| {
            chunkidx_to_indices_dict
                .entry(chunk_index)
                .or_insert_with(Vec::new)
                .push(*index);
        });

    chunkidx_to_indices_dict
}

pub fn sponge_from_item_randomness<H: SpongeHasher + AlgebraicHasher>(
    item: &Digest,
    randomness: &Digest,
) -> <H as SpongeHasher>::SpongeState {
    let mut seed = [BFIELD_ZERO; 10];
    seed[..DIGEST_LENGTH].copy_from_slice(&item.values());
    seed[DIGEST_LENGTH..].copy_from_slice(&randomness.values());
    let mut sponge_state = <H as SpongeHasher>::init();
    H::absorb(&mut sponge_state, &seed);
    sponge_state
}

/// This function is factored out because it is shared by `update_from_remove`
/// and `batch_update_from_remove`.
/// Return value 0:
/// A hash set of indices, showing which indices are into the chunk dictionaries
/// which have modified chunks.
/// Return value 1:
/// A list of (old membership proof, new digest) where the membership proof
/// is how it looks before applying the removal record, and the digest is how
/// it looks after applying the removal record.
/// This function updates the chunks that are present in the `chunk_dictionaries`
/// input argument, but not the associated membership proofs. That must be handled
/// by the caller.
#[allow(clippy::type_complexity)]
pub fn get_batch_mutation_argument_for_removal_record<H: AlgebraicHasher>(
    removal_record: &RemovalRecord<H>,
    chunk_dictionaries: &mut [&mut ChunkDictionary<H>],
) -> (HashSet<usize>, Vec<(MmrMembershipProof<H>, Digest)>) {
    let mut mutation_argument_hash_map: HashMap<u64, (MmrMembershipProof<H>, Digest)> =
        HashMap::new();
    let rem_record_chunkidx_to_indices_dict: HashMap<u64, Vec<u128>> =
        removal_record.get_chunkidx_to_indices_dict();

    // `mutated_chunks_by_input_indices` records the indices into the input `chunk_dictionaries` slice
    // that shows which elements contain mutated chunks.
    let mut mutated_chunks_by_input_indices: HashSet<usize> = HashSet::new();
    for (chunk_index, indices) in rem_record_chunkidx_to_indices_dict.iter() {
        for (i, chunk_dictionary) in chunk_dictionaries.iter_mut().enumerate() {
            match chunk_dictionary.dictionary.get_mut(chunk_index) {
                // Leaf and its membership proof exists in own membership proof (in `chunk_dictionaries`)
                Some((mp, chunk)) => {
                    for index in indices.iter() {
                        let index = (index % CHUNK_SIZE as u128) as u32;
                        mutated_chunks_by_input_indices.insert(i);
                        chunk.insert(index);
                    }

                    // If this leaf/membership proof pair has not already been collected,
                    // then store it as a mutation argument. This assumes that all membership
                    // proofs in all chunk dictionaries are valid.
                    // We can calculate the hash value of the updated chunk since all indices
                    // have been applied to the chunk in the above loop.
                    // Inserted into the mutation_argument_hash_map is the updated chunk and its
                    // *old* (non-updated) MMR membership proof.
                    if !mutation_argument_hash_map.contains_key(chunk_index) {
                        mutation_argument_hash_map
                            .insert(*chunk_index, (mp.to_owned(), H::hash(chunk)));
                    }
                }

                // Leaf does not exists in own membership proof, so we get it from the removal record
                None => {
                    match removal_record.target_chunks.dictionary.get(chunk_index) {
                        None => {
                            // This should mean that the index is in the active part of the
                            // SWBF. But we have no way of checking that AFAIK. So we just continue.
                            continue;
                        }
                        Some((mp, chunk)) => {
                            // Since the chunk does not exist in the membership proof, we do not need
                            // to update any chunk value. We only need the new chunk value for the
                            // mutation argument (2nd element of returned tuple), so we only need to
                            // calculate it once.
                            if !mutation_argument_hash_map.contains_key(chunk_index) {
                                let mut target_chunk = chunk.to_owned();
                                for index in indices.iter() {
                                    target_chunk.insert((index % CHUNK_SIZE as u128) as u32);
                                }

                                // Since all indices have been applied to the chunk in the above
                                // for-loop, we can calculate the hash of the updated chunk now.
                                mutation_argument_hash_map
                                    .insert(*chunk_index, (mp.to_owned(), H::hash(&target_chunk)));
                            }
                        }
                    };
                }
            };
        }
    }

    (
        mutated_chunks_by_input_indices,
        mutation_argument_hash_map.into_values().collect(),
    )
}
