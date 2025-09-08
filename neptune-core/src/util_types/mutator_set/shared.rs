use std::collections::HashMap;
use std::collections::HashSet;

use itertools::Itertools;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;
use tasm_lib::twenty_first::util_types::mmr::mmr_membership_proof::MmrMembershipProof;

use super::removal_record::chunk_dictionary::ChunkDictionary;
use super::removal_record::RemovalRecord;

pub const WINDOW_SIZE: u32 = 1 << 20;
pub const CHUNK_SIZE: u32 = 1 << 12;
pub const BATCH_SIZE: u32 = 1 << 3;
pub const NUM_TRIALS: u32 = 45;

/// Given a set of absolute indices, return a hashmap of
/// {chunk_index => absolute_indices}
/// where the values are sorted after chunk index, i.e. put in the correct
/// chunk bucket.
pub fn indices_to_hash_map(all_indices: &[u128; NUM_TRIALS as usize]) -> HashMap<u64, Vec<u128>> {
    all_indices
        .iter()
        .map(|bi| ((bi / u128::from(CHUNK_SIZE)) as u64, *bi))
        .fold(HashMap::new(), |mut acc, (chunk_index, index)| {
            acc.entry(chunk_index).or_default().push(index);
            acc
        })
}

/// Prepare a batch-modification with necessary authentication data
/// to update the chunk dictionaries of mutator set membership proofs
/// under application of a removal record.
///
/// Parameters:
///  - `removal_record`: a reference to the removal record that is
///    being applied.
///  - `chunk_dictionaries`: a slice of (mutable references to)
///    the chunk dictionaries into which the new indices are added.
///
/// Returns:
///  - 0: A hash set of indices, showing which indices are into the chunk dictionaries
///    which have modified chunks.
///  - 1: A list of (old membership proof, new digest) where the membership proof
///    is how it looks before applying the removal record, and the digest is how
///    it looks after applying the removal record.
///
/// This function updates the chunks that are present in the `chunk_dictionaries`
/// input argument, but not the associated membership proofs. That must be handled
/// by the caller.
///
/// This function is factored out because it is shared by `update_from_remove`
/// and `batch_update_from_remove`.
pub fn get_batch_mutation_argument_for_removal_record(
    removal_record: &RemovalRecord,
    chunk_dictionaries: &mut [&mut ChunkDictionary],
) -> (HashSet<usize>, Vec<(u64, MmrMembershipProof, Digest)>) {
    // chunk index -> (mmr mp, chunk hash)
    let mut batch_modification_hash_map: HashMap<u64, (MmrMembershipProof, Digest)> =
        HashMap::new();
    // `mutated_chunk_dictionaries` records the indices into the
    // input `chunk_dictionaries` slice that shows which elements
    // contain modified chunks.
    let mut mutated_chunk_dictionaries: HashSet<usize> = HashSet::new();
    for (chunk_index, indices) in &removal_record.get_chunkidx_to_indices_dict() {
        for (i, chunk_dictionary) in chunk_dictionaries.iter_mut().enumerate() {
            match chunk_dictionary.get_mut(chunk_index) {
                // Leaf and its MMR-membership proof exists in own MS-membership proof (in `chunk_dictionaries`)
                Some((mmr_mp, chunk)) => {
                    for index in indices {
                        let relative_index = (index % u128::from(CHUNK_SIZE)) as u32;
                        mutated_chunk_dictionaries.insert(i);
                        chunk.insert(relative_index);
                    }

                    // If this leaf/membership proof pair has not already been collected,
                    // then store it as a mutation argument. This assumes that all membership
                    // proofs in all chunk dictionaries are valid.
                    // We can calculate the hash value of the updated chunk since all indices
                    // have been applied to the chunk in the above loop.
                    // Inserted into the mutation_argument_hash_map is the updated chunk and its
                    // *old* (non-updated) MMR membership proof.
                    if !batch_modification_hash_map.contains_key(chunk_index) {
                        batch_modification_hash_map
                            .insert(*chunk_index, (mmr_mp.to_owned(), Tip5::hash(chunk)));
                    }
                }

                // Leaf does not exists in own membership proof, so we get it from the removal record
                None => {
                    match removal_record.target_chunks.get(chunk_index) {
                        None => {
                            // This should mean that the index is in the active part of the
                            // SWBF. But we have no way of checking that AFAIK. So we just continue.
                        }
                        Some((mp, chunk)) => {
                            // Since the chunk does not exist in the membership proof, we do not need
                            // to update any chunk value. We only need the new chunk value for the
                            // mutation argument (2nd element of returned tuple), so we only need to
                            // calculate it once.
                            if !batch_modification_hash_map.contains_key(chunk_index) {
                                let mut target_chunk = chunk.to_owned();
                                for index in indices {
                                    target_chunk.insert((index % u128::from(CHUNK_SIZE)) as u32);
                                }

                                // Since all indices have been applied to the chunk in the above
                                // for-loop, we can calculate the hash of the updated chunk now.
                                batch_modification_hash_map.insert(
                                    *chunk_index,
                                    (mp.to_owned(), Tip5::hash(&target_chunk)),
                                );
                            }
                        }
                    };
                }
            };
        }
    }

    (
        mutated_chunk_dictionaries,
        batch_modification_hash_map
            .into_iter()
            .map(|(i, (p, l))| (i, p, l))
            .collect(),
    )
}

/// Prepare a batch-modification with necessary authentication data
/// to update the chunk dictionaries of mutator set membership proofs
/// under *reversion* of a removal record.
///
/// Parameters:
///  - `removal_record`: a reference to the removal record that is
///    being applied.
///  - `chunk_dictionaries`: a slice of the chunk dictionaries from
///    which the new indices are *removed*.
///
/// Returns:
///  - 0: A hash set of indices, showing which indices are into the chunk dictionaries
///    which have modified chunks.
///  - 1: A list of (old membership proof, new digest) where the membership proof
///    is how it looks before applying the removal record, and the digest is how
///    it looks after applying the removal record.
///
/// This function updates the chunks that are present in the `chunk_dictionaries`
/// input argument.
/// It does not update the associated membership proofs. That must be handled
/// by the caller also.
///
/// This function is factored out because it is shared by
/// `revert_update_from_remove` and `batch_revert_update_from_remove`.
pub fn prepare_authenticated_batch_modification_for_removal_record_reversion(
    removal_record: &RemovalRecord,
    chunk_dictionaries: &mut [&mut ChunkDictionary],
) -> (HashSet<usize>, Vec<(u64, MmrMembershipProof, Digest)>) {
    // chunk index -> (mmr mp, chunk hash)
    let mut batch_modification_hash_map: HashMap<u64, (MmrMembershipProof, Digest)> =
        HashMap::new();

    // `mutated_chunk_dictionaries` records the indices in `chunk_dictionaries`
    // of modified chunks.
    let mut mutated_chunk_dictionaries: HashSet<usize> = HashSet::new();

    for (chunk_index, indices) in &removal_record.get_chunkidx_to_indices_dict() {
        for (i, chunk_dictionary) in chunk_dictionaries.iter_mut().enumerate() {
            match chunk_dictionary.get_mut(chunk_index) {
                // Leaf and its MMR-membership proof exists in own MS-membership proof (via `chunk_dictionaries`)
                Some((mmr_mp, chunk)) => {
                    for index in indices {
                        let relative_index = (index % u128::from(CHUNK_SIZE)) as u32;
                        mutated_chunk_dictionaries.insert(i);
                        chunk.remove_once(relative_index);
                    }

                    // Insert into the mutation_argument_hash_map the updated chunk and its
                    // *old* (before reversion) MMR membership proof.
                    if !batch_modification_hash_map.contains_key(chunk_index) {
                        batch_modification_hash_map
                            .insert(*chunk_index, (mmr_mp.to_owned(), Tip5::hash(chunk)));
                    }
                }

                // Leaf does not exists in own membership proof, so
                // we get it from the removal record. But since we
                // want the leaf values to revert to, we should *not*
                // add the indices supplied by the removal record.
                None => {
                    match removal_record.target_chunks.get(chunk_index) {
                        None => {
                            // This should mean that the index is in the active part of the
                            // SWBF. But we have no way of checking that AFAIK. So we just continue.
                        }
                        Some((mp, chunk)) => {
                            // Since the chunk does not exist in the membership proof, we do not need
                            // to update any chunk value. We only need the new chunk value for the
                            // mutation argument (2nd element of returned tuple), so we only need to
                            // calculate it once.
                            if !batch_modification_hash_map.contains_key(chunk_index) {
                                let target_chunk = chunk.to_owned();

                                // Since all indices have been applied to the chunk in the above
                                // for-loop, we can calculate the hash of the updated chunk now.
                                batch_modification_hash_map.insert(
                                    *chunk_index,
                                    (mp.to_owned(), Tip5::hash(&target_chunk)),
                                );
                            }
                        }
                    };
                }
            };
        }
    }

    (
        mutated_chunk_dictionaries,
        batch_modification_hash_map
            .iter()
            .map(|(i, (p, l))| (*i, p.clone(), *l))
            .collect_vec(),
    )
}
