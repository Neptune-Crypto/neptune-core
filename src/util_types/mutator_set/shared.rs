use std::collections::{HashMap, HashSet};

use twenty_first::{
    shared_math::rescue_prime_digest::Digest,
    util_types::{
        algebraic_hasher::AlgebraicHasher, mmr::mmr_membership_proof::MmrMembershipProof,
    },
};

use super::{chunk_dictionary::ChunkDictionary, removal_record::RemovalRecord};

pub const BITS_PER_U32: usize = 32;
pub const WINDOW_SIZE: usize = 1 << 20;
pub const CHUNK_SIZE: usize = 1 << 12;
pub const BATCH_SIZE: usize = 1 << 3;
pub const NUM_TRIALS: usize = 45;

pub fn bit_indices_to_hash_map(all_bit_indices: &[u128; NUM_TRIALS]) -> HashMap<u128, Vec<u128>> {
    let mut chunk_index_to_bit_indices: HashMap<u128, Vec<u128>> = HashMap::new();
    all_bit_indices
        .iter()
        .map(|bi| (bi / CHUNK_SIZE as u128, bi))
        .for_each(|(k, v)| {
            chunk_index_to_bit_indices
                .entry(k)
                .or_insert_with(Vec::new)
                .push(*v);
        });

    chunk_index_to_bit_indices
}

/// and mutate the chunk dictionary chunk values.
/// This function is factored out because it is shared by `update_from_remove`
/// and `batch_update_from_remove`.
#[allow(clippy::type_complexity)]
pub fn get_batch_mutation_argument_for_removal_record<H: AlgebraicHasher>(
    removal_record: &RemovalRecord<H>,
    chunk_dictionaries: &mut [&mut ChunkDictionary<H>],
) -> (HashSet<usize>, Vec<(MmrMembershipProof<H>, Digest)>) {
    let mut mutation_argument_hash_map: HashMap<u128, (MmrMembershipProof<H>, Digest)> =
        HashMap::new();
    let rem_record_chunk_idx_to_bit_indices: HashMap<u128, Vec<u128>> =
        removal_record.get_chunk_index_to_bit_indices();

    let mut mutated_chunks_by_input_indices: HashSet<usize> = HashSet::new();
    for (chunk_index, bit_indices) in rem_record_chunk_idx_to_bit_indices.iter() {
        for (i, chunk_dictionary) in chunk_dictionaries.iter_mut().enumerate() {
            match chunk_dictionary.dictionary.get_mut(chunk_index) {
                // Leaf exists in own membership proof
                Some((mp, chunk)) => {
                    for bit_index in bit_indices.iter() {
                        let index = (bit_index % CHUNK_SIZE as u128) as usize;
                        if !chunk.get_bit(index) {
                            mutated_chunks_by_input_indices.insert(i);
                        }
                        chunk.set_bit(index);
                    }

                    // If this leaf/membership proof pair has not already been collected,
                    // then store it as a mutation argument. This assumes that all membership
                    // proofs in all chunk dictionaries are valid.
                    if !mutation_argument_hash_map.contains_key(chunk_index) {
                        mutation_argument_hash_map
                            .insert(*chunk_index, (mp.to_owned(), H::hash(chunk)));
                    }
                }

                // Leaf does not exists in own membership proof, so we get it from the removal record
                None => {
                    match removal_record.target_chunks.dictionary.get(chunk_index) {
                        None => {
                            // This should mean that bit index is in the active part of the
                            // SWBF. But we have no way of checking that AFAIK. So we just continue.
                            continue;
                        }
                        Some((mp, chunk)) => {
                            let mut target_chunk = chunk.to_owned();
                            for bit_index in bit_indices.iter() {
                                target_chunk.set_bit((bit_index % CHUNK_SIZE as u128) as usize);
                            }

                            if !mutation_argument_hash_map.contains_key(chunk_index) {
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
