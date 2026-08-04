use std::collections::HashMap;
use std::collections::HashSet;

use itertools::Itertools;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;
use tasm_lib::twenty_first::util_types::mmr::mmr_membership_proof::MmrMembershipProof;

use super::removal_record::chunk::Chunk;
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

/// Given a batch of removal records, return a hashmap of
/// {chunk_index => absolute_indices} with the indices of the entire batch
/// put in the correct chunk buckets. Multiplicities are preserved.
fn combined_chunkidx_to_indices_dict(removal_records: &[RemovalRecord]) -> HashMap<u64, Vec<u128>> {
    let mut chunkidx_to_indices: HashMap<u64, Vec<u128>> = HashMap::new();
    for removal_record in removal_records {
        for (chunk_index, indices) in removal_record.get_chunkidx_to_indices_dict() {
            chunkidx_to_indices
                .entry(chunk_index)
                .or_default()
                .extend(indices);
        }
    }

    chunkidx_to_indices
}

/// Shared implementation of
/// [`get_batch_mutation_argument_for_removal_records`] and
/// [`prepare_authenticated_batch_modification_for_removal_records_reversion`],
/// parameterized over the chunk mutation: inserting the batch's indices
/// (application) or removing them (reversion).
///
/// Iterates each chunk dictionary once and looks its entries up in the
/// combined index map, rather than scanning all dictionaries per mutated
/// chunk; the batches can be large in both dimensions.
fn batch_mutation_argument_for_removal_records<F: Fn(&mut Chunk, &[u128])>(
    removal_records: &[RemovalRecord],
    chunk_dictionaries: &mut [&mut ChunkDictionary],
    mutate_chunk: F,
) -> (HashSet<usize>, Vec<(u64, MmrMembershipProof, Digest)>) {
    let chunkidx_to_indices = combined_chunkidx_to_indices_dict(removal_records);

    // chunk index -> (mmr mp, chunk hash)
    let mut batch_modification_hash_map: HashMap<u64, (MmrMembershipProof, Digest)> =
        HashMap::new();
    // `mutated_chunk_dictionaries` records the indices into the
    // input `chunk_dictionaries` slice that shows which elements
    // contain modified chunks.
    let mut mutated_chunk_dictionaries: HashSet<usize> = HashSet::new();
    for (i, chunk_dictionary) in chunk_dictionaries.iter_mut().enumerate() {
        for (chunk_index, (mmr_mp, chunk)) in chunk_dictionary.iter_mut() {
            let Some(indices) = chunkidx_to_indices.get(chunk_index) else {
                continue;
            };
            mutated_chunk_dictionaries.insert(i);
            mutate_chunk(chunk, indices);

            // Since all of the batch's indices have been applied to the
            // chunk, the hash of the fully mutated chunk can be calculated
            // now. Inserted into the mutation argument is the mutated chunk
            // and its *old* (non-mutated) MMR membership proof.
            if !batch_modification_hash_map.contains_key(chunk_index) {
                batch_modification_hash_map
                    .insert(*chunk_index, (mmr_mp.to_owned(), Tip5::hash(chunk)));
            }
        }
    }

    // For leafs that exist in no chunk dictionary, the authentication data is
    // read from the removal records instead. Their chunk values are synced to
    // the same state as the chunk dictionaries, so the mutation applies to
    // the sourced chunks too. Indices whose chunk the removal records don't
    // have either should be in the active part of the SWBF, where no leaf
    // needs mutating.
    if batch_modification_hash_map.len() < chunkidx_to_indices.len() {
        let record_chunks: HashMap<u64, &(MmrMembershipProof, Chunk)> = removal_records
            .iter()
            .flat_map(|removal_record| removal_record.target_chunks.iter())
            .map(|(chunk_index, authenticated_chunk)| (*chunk_index, authenticated_chunk))
            .collect();
        for (chunk_index, indices) in &chunkidx_to_indices {
            if batch_modification_hash_map.contains_key(chunk_index) {
                continue;
            }
            let Some((mp, chunk)) = record_chunks.get(chunk_index) else {
                continue;
            };
            let mut target_chunk = chunk.to_owned();
            mutate_chunk(&mut target_chunk, indices);

            batch_modification_hash_map
                .insert(*chunk_index, (mp.to_owned(), Tip5::hash(&target_chunk)));
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
/// or removal records under application of a batch of removal records.
///
/// Like [`get_batch_mutation_argument_for_removal_record`], but handles the
/// application of any number of removal records with a single mutation
/// argument, i.e. a single batch-mutation of the MMR membership proofs. The
/// combined mutation is well-defined because the chunk modifications of the
/// individual applications commute: each only inserts indices into chunks.
///
/// The applied removal records must be synced to the same mutator-set state
/// as the chunk dictionaries.
pub fn get_batch_mutation_argument_for_removal_records(
    removal_records: &[RemovalRecord],
    chunk_dictionaries: &mut [&mut ChunkDictionary],
) -> (HashSet<usize>, Vec<(u64, MmrMembershipProof, Digest)>) {
    batch_mutation_argument_for_removal_records(removal_records, chunk_dictionaries, {
        |chunk, indices| {
            let relative_indices = indices
                .iter()
                .map(|index| (index % u128::from(CHUNK_SIZE)) as u32)
                .collect_vec();
            chunk.insert_many(&relative_indices);
        }
    })
}

/// Prepare a batch-modification with necessary authentication data
/// to update the chunk dictionaries of mutator set membership proofs
/// or removal records under *reversion* of a batch of removal records.
///
/// Like
/// [`prepare_authenticated_batch_modification_for_removal_record_reversion`],
/// but handles the reversion of any number of removal records with a single
/// mutation argument, i.e. a single batch-mutation of the MMR membership
/// proofs.
///
/// Unlike the one-record version, which takes the reverted record in its
/// as-applied form, the reverted removal records here must be synced to the
/// same mutator-set state as the chunk dictionaries — the state *after* the
/// application of the entire batch, including themselves.
pub fn prepare_authenticated_batch_modification_for_removal_records_reversion(
    removal_records: &[RemovalRecord],
    chunk_dictionaries: &mut [&mut ChunkDictionary],
) -> (HashSet<usize>, Vec<(u64, MmrMembershipProof, Digest)>) {
    batch_mutation_argument_for_removal_records(removal_records, chunk_dictionaries, {
        |chunk, indices| {
            for index in indices {
                chunk.remove_once((index % u128::from(CHUNK_SIZE)) as u32);
            }
        }
    })
}

/// Prepare a batch-modification with necessary authentication data
/// to update the chunk dictionaries of mutator set membership proofs
/// or removal records under *reversion* of a removal record.
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
