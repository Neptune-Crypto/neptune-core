use std::collections::HashMap;
use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::ops::IndexMut;

#[cfg(any(test, feature = "arbitrary-impls"))]
use arbitrary::Arbitrary;
use get_size2::GetSize;
use itertools::Itertools;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Tip5;
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;
use tasm_lib::twenty_first::tip5::digest::Digest;
use tasm_lib::twenty_first::util_types::mmr;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
use tasm_lib::twenty_first::util_types::mmr::mmr_membership_proof::MmrMembershipProof;
use tasm_lib::twenty_first::util_types::mmr::mmr_trait::LeafMutation;
use tasm_lib::twenty_first::util_types::mmr::mmr_trait::Mmr;

use super::addition_record::AdditionRecord;
use super::commit;
use super::mutator_set_accumulator::MutatorSetAccumulator;
use super::removal_record::absolute_index_set::AbsoluteIndexSet;
use super::removal_record::chunk_dictionary::ChunkDictionary;
use super::removal_record::RemovalRecord;
use super::shared::get_batch_mutation_argument_for_removal_record;
use super::shared::prepare_authenticated_batch_modification_for_removal_record_reversion;
use super::shared::BATCH_SIZE;
use super::shared::CHUNK_SIZE;
use crate::MutatorSetError;

impl Error for MembershipProofError {}

impl fmt::Display for MembershipProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MembershipProofError {
    AlreadyExistingChunk(u64),
    MissingChunkOnUpdateFromAdd(u64),
}

// In order to store this structure in the database, it needs to be serializable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, GetSize, BFieldCodec, TasmObject)]
#[cfg_attr(any(test, feature = "arbitrary-impls"), derive(Arbitrary))]
pub struct MsMembershipProof {
    pub sender_randomness: Digest,
    pub receiver_preimage: Digest,
    pub auth_path_aocl: MmrMembershipProof,
    pub aocl_leaf_index: u64,
    pub target_chunks: ChunkDictionary,
}

impl MsMembershipProof {
    pub fn addition_record(&self, item: Digest) -> AdditionRecord {
        commit(item, self.sender_randomness, self.receiver_preimage.hash())
    }

    /// Compute the indices that will be added to the SWBF if this item is removed.
    pub fn compute_indices(&self, item: Digest) -> AbsoluteIndexSet {
        AbsoluteIndexSet::compute(
            item,
            self.sender_randomness,
            self.receiver_preimage,
            self.aocl_leaf_index,
        )
    }

    /// Update a list of membership proofs in anticipation of an addition. If successful,
    /// return (wrapped in an Ok) a vector of all indices of updated membership proofs.
    pub fn batch_update_from_addition(
        membership_proofs: &mut [&mut Self],
        own_items: &[Digest],
        mutator_set: &MutatorSetAccumulator,
        addition_record: &AdditionRecord,
    ) -> Result<Vec<usize>, Box<dyn Error>> {
        assert!(
            membership_proofs
                .iter()
                .all(|mp| mp.aocl_leaf_index < mutator_set.aocl.num_leafs()),
            "No AOCL data index can point outside of provided mutator set. aocl leaf count: {}; mp leaf indices: {}",
            mutator_set.aocl.num_leafs(),
            membership_proofs.iter().map(|x| x.aocl_leaf_index.to_string()).join(",")
        );
        assert_eq!(
            membership_proofs.len(),
            own_items.len(),
            "Function must be called with same number of membership proofs and items. Got {} items and {} membership proofs", own_items.len(), membership_proofs.len()
        );

        debug_assert!(membership_proofs
            .iter()
            .all(|msmp| msmp
                .target_chunks
                .iter()
                .all(|(chunk_index, (mmr_mp, chunk))| mmr_mp.verify(
                    *chunk_index,
                    Tip5::hash(chunk),
                    &mutator_set.swbf_inactive.peaks(),
                    mutator_set.swbf_inactive.num_leafs()
                ))));

        let new_item_index = mutator_set.aocl.num_leafs();

        // Update AOCL MMR membership proofs
        let leaf_indices = membership_proofs
            .iter()
            .map(|msmp| msmp.aocl_leaf_index)
            .collect_vec();
        let indices_for_mps_updated_from_append = MmrMembershipProof::batch_update_from_append(
            &mut membership_proofs
                .iter_mut()
                .map(|msmp| &mut msmp.auth_path_aocl)
                .collect::<Vec<_>>(),
            &leaf_indices,
            new_item_index,
            addition_record.canonical_commitment,
            &mutator_set.aocl.peaks(),
        );

        // if window does not slide, we are done
        if !MutatorSetAccumulator::window_slides(new_item_index) {
            return Ok(indices_for_mps_updated_from_append);
        }

        let new_item_index2 = mutator_set.aocl.num_leafs();

        // window does slide
        let next_batch_index = new_item_index2 / u64::from(BATCH_SIZE);
        let current_batch_index = next_batch_index - 1;
        assert_eq!(
            current_batch_index,
            mutator_set.swbf_inactive.num_leafs(),
            "Number of SWBF MMR leafs must match current batch index"
        );
        let new_chunk = mutator_set.swbf_active.slid_chunk();
        let new_chunk_digest: Digest = Tip5::hash(&new_chunk);

        // Insert the new chunk digest into the accumulator-version of the
        // SWBF MMR to get its authentication path. It's important to convert the MMR
        // to an MMR Accumulator here, since we don't want to drag around or clone
        // a whole archival MMR for this operation, as the archival MMR can be in the
        // size of gigabytes, whereas the MMR accumulator should be in the size of
        // kilobytes.
        let mut updated_mmra: MmrAccumulator = mutator_set.swbf_inactive.to_accumulator();
        let new_chunk_auth_path: MmrMembershipProof = updated_mmra.append(new_chunk_digest);

        // Collect all indices for all membership proofs that are being updated
        // Notice that this is a *very* expensive operation if the indices are
        // not already known. I.e., the `None` case below is very expensive.
        let mut chunk_index_to_mp_index: HashMap<u64, Vec<usize>> = HashMap::new();
        membership_proofs
            .iter()
            .zip(own_items.iter())
            .enumerate()
            .for_each(|(i, (mp, &item))| {
                let absolute_indices = AbsoluteIndexSet::compute(
                    item,
                    mp.sender_randomness,
                    mp.receiver_preimage,
                    mp.aocl_leaf_index,
                );
                for chunk_index in absolute_indices
                    .to_array()
                    .iter()
                    .map(|x| (*x / u128::from(CHUNK_SIZE)) as u64)
                    .unique()
                {
                    chunk_index_to_mp_index
                        .entry(chunk_index)
                        .or_default()
                        .push(i)
                }
            });

        // Find the indices of the mutator set membership proofs whose
        // `target_chunks` field needs a new dictionary entry for the slid chunk.
        let indices_for_mps_with_new_chunk_dictionary_entry: Vec<usize> =
            match chunk_index_to_mp_index.get(&current_batch_index) {
                Some(vals) => vals.clone(),
                None => vec![],
            };

        // Find the membership proofs that have dictionary entry MMR membership proofs that need
        // to be updated because of the window sliding. We just
        let mut mps_for_batch_append: HashSet<usize> = HashSet::new();
        for (chunk_index, mp_indices) in chunk_index_to_mp_index {
            if chunk_index < current_batch_index {
                for mp_index in mp_indices {
                    mps_for_batch_append.insert(mp_index);
                }
            }
        }

        // Perform the updates

        // First insert the new entry into the chunk dictionary for the membership
        // proofs that need it.
        for i in &indices_for_mps_with_new_chunk_dictionary_entry {
            membership_proofs.index_mut(*i).target_chunks.insert(
                current_batch_index,
                (new_chunk_auth_path.clone(), new_chunk.clone()),
            );
        }

        // Collect those MMR membership proofs for chunks whose authentication
        // path might need to be updated due to the insertion of a new leaf in the
        // SWBF MMR.
        // This is a bit ugly and a bit slower than it could be. To prevent this
        // for-loop, you probably could collect the `Vec<&mut mp>` in the code above,
        // instead of just collecting the indices into the membership proof vector.
        // It is, however, quite acceptable that many of the MMR membership proofs are
        // repeated since the MMR `batch_update_from_append` handles this optimally.
        // So relegating that bookkeeping to this function instead would not be more
        // efficient.
        let mut mmr_membership_proofs_for_append: Vec<
            &mut mmr::mmr_membership_proof::MmrMembershipProof,
        > = vec![];

        // The `mmr_mp_index_to_ms_mp_index` variable remembers
        // which MMR membership proofs that map to MS membership proofs. This is
        // required to return the indices of the MS membership proofs that have been updated
        // by this function call.
        let mut mmr_mp_index_to_ms_mp_index = vec![];
        let mut mmr_membership_indices = vec![];
        for (i, mp) in membership_proofs.iter_mut().enumerate() {
            if mps_for_batch_append.contains(&i) {
                for (chunk_index, (mmr_mp, _chunk)) in mp.target_chunks.iter_mut() {
                    if *chunk_index != current_batch_index {
                        mmr_membership_proofs_for_append.push(mmr_mp);
                        mmr_membership_indices.push(*chunk_index);
                        mmr_mp_index_to_ms_mp_index.push(i as u64);
                    }
                }
            }
        }

        let indices_for_modified_paths =
            mmr::mmr_membership_proof::MmrMembershipProof::batch_update_from_append(
                &mut mmr_membership_proofs_for_append,
                &mmr_membership_indices,
                mutator_set.swbf_inactive.num_leafs(),
                new_chunk_digest,
                &mutator_set.swbf_inactive.peaks(),
            );

        let mut indices_for_mps_with_updated_swbf_auth_paths = vec![];
        for j in indices_for_modified_paths {
            indices_for_mps_with_updated_swbf_auth_paths
                .push(mmr_mp_index_to_ms_mp_index[j] as usize);
        }

        // Gather the indices the are returned. These indices indicate which membership
        // proofs that have been mutated.
        let mut all_mutated_mp_indices = [
            indices_for_mps_updated_from_append,
            indices_for_mps_with_updated_swbf_auth_paths,
            indices_for_mps_with_new_chunk_dictionary_entry,
        ]
        .concat();
        all_mutated_mp_indices.sort_unstable();
        all_mutated_mp_indices.dedup();

        Ok(all_mutated_mp_indices)
    }

    /// Update a membership proof in anticipation of an addition to the set and
    /// return, wrapped in a `Result`, whether something was updated.
    pub fn update_from_addition(
        &mut self,
        own_item: Digest,
        mutator_set: &MutatorSetAccumulator,
        addition_record: &AdditionRecord,
    ) -> Result<bool, Box<dyn Error>> {
        assert!(self.aocl_leaf_index < mutator_set.aocl.num_leafs());
        let new_item_aocl_index = mutator_set.aocl.num_leafs();

        // Update AOCL MMR membership proof
        let aocl_mp_updated = self.auth_path_aocl.update_from_append(
            self.aocl_leaf_index,
            mutator_set.aocl.num_leafs(),
            addition_record.canonical_commitment,
            &mutator_set.aocl.peaks(),
        );

        // if window does not slide, we are done
        if !MutatorSetAccumulator::window_slides(new_item_aocl_index) {
            return Ok(aocl_mp_updated);
        }

        // window does slide
        let new_chunk = mutator_set.swbf_active.slid_chunk();
        let new_chunk_digest: Digest = Tip5::hash(&new_chunk);

        // Get Bloom filter indices by recalculating them.
        let all_indices = AbsoluteIndexSet::compute(
            own_item,
            self.sender_randomness,
            self.receiver_preimage,
            self.aocl_leaf_index,
        )
        .to_array();
        let chunk_indices_set: HashSet<u64> = all_indices
            .map(|bi| (bi / u128::from(CHUNK_SIZE)) as u64)
            .into_iter()
            .collect::<HashSet<u64>>();

        // Insert the new SWBF leaf into a duplicate of the SWBFI MMRA to get
        // the new leaf's authentication path.
        let mut swbfi_mmra: MmrAccumulator = mutator_set.swbf_inactive.to_accumulator();
        let new_leaf_index = swbfi_mmra.num_leafs();
        let new_auth_path: mmr::mmr_membership_proof::MmrMembershipProof =
            swbfi_mmra.append(new_chunk_digest);

        let mut swbf_chunk_dictionary_updated = false;
        let batch_index = new_item_aocl_index / u64::from(BATCH_SIZE);
        let old_window_start_batch_index = batch_index - 1;

        // Sanity check: assert that the new SWBFI leaf index agrees with the
        // batch index of the old window. If these disagree, then the mutator
        // set accumulator is in an inconsistent state.
        assert_eq!(
            new_leaf_index, old_window_start_batch_index,
            "corrupt mutator set accumulator"
        );
        'outer: for chunk_index in chunk_indices_set {
            // Update for indices that are in the inactive part of the SWBF.
            // Here the MMR membership proofs of the chunks must be updated.
            if chunk_index < old_window_start_batch_index {
                let mp = match self.target_chunks.get_mut(&chunk_index) {
                    // If this record is not found, the MembershipProof is in a broken
                    // state.
                    None => {
                        return Err(Box::new(MembershipProofError::MissingChunkOnUpdateFromAdd(
                            chunk_index,
                        )))
                    }
                    Some((m, _chnk)) => m,
                };
                let swbf_chunk_dict_updated_local: bool = mp.update_from_append(
                    chunk_index,
                    mutator_set.swbf_inactive.num_leafs(),
                    new_chunk_digest,
                    &mutator_set.swbf_inactive.peaks(),
                );
                swbf_chunk_dictionary_updated =
                    swbf_chunk_dictionary_updated || swbf_chunk_dict_updated_local;

                continue 'outer;
            }

            // if index is in the part that is becoming inactive, add a dictionary entry
            if chunk_index == new_leaf_index {
                if self.target_chunks.contains_key(&chunk_index) {
                    return Err(Box::new(MembershipProofError::AlreadyExistingChunk(
                        chunk_index,
                    )));
                }

                // add dictionary entry
                self.target_chunks
                    .insert(chunk_index, (new_auth_path.clone(), new_chunk.clone()));
                swbf_chunk_dictionary_updated = true;
            }

            // If `chunk_index` refers to indices that are still in the active window, do nothing.
        }

        Ok(swbf_chunk_dictionary_updated || aocl_mp_updated)
    }

    /// Resets a membership proof to its state prior to updating it
    /// with one or many addition records, given only
    /// the state of the mutator set kernel prior to adding them.
    pub fn revert_update_from_batch_addition(
        &mut self,
        previous_mutator_set: &MutatorSetAccumulator,
    ) {
        // calculate AOCL MMR MP length
        let previous_leaf_count = previous_mutator_set.aocl.num_leafs();
        assert!(
            previous_leaf_count > self.aocl_leaf_index,
            "Cannot revert a membership proof for an item to back its state before the item was added to the mutator set."
        );
        let aocl_discrepancies = self.aocl_leaf_index ^ previous_leaf_count;
        let aocl_mt_height = u128::from(aocl_discrepancies).ilog2();

        // trim to length
        while self.auth_path_aocl.authentication_path.len() > aocl_mt_height as usize {
            self.auth_path_aocl.authentication_path.pop();
        }

        // remove chunks from unslid windows
        let swbfi_leaf_count = previous_mutator_set.swbf_inactive.num_leafs();
        self.target_chunks.retain(|(k, _v)| *k < swbfi_leaf_count);

        // iterate over all retained chunk authentication paths
        for (k, (mp, _chnk)) in self.target_chunks.iter_mut() {
            // calculate length
            let chunk_discrepancies = swbfi_leaf_count ^ *k;
            let chunk_mt_height = u128::from(chunk_discrepancies).ilog2();

            // trim to length
            while mp.authentication_path.len() > chunk_mt_height as usize {
                mp.authentication_path.pop();
            }
        }
    }

    /// Update multiple membership proofs from one remove operation. Returns the indices of the membership proofs
    /// that have been mutated.
    pub fn batch_update_from_remove(
        membership_proofs: &mut [&mut Self],
        removal_record: &RemovalRecord,
    ) -> Result<Vec<usize>, Box<dyn Error>> {
        // Set all chunk values to the new values and calculate the mutation argument
        // for the batch updating of the MMR membership proofs.
        let mut chunk_dictionaries: Vec<&mut ChunkDictionary> = membership_proofs
            .iter_mut()
            .map(|mp| &mut mp.target_chunks)
            .collect();
        let (mutated_chunks_by_mp_indices, mutation_argument) =
            get_batch_mutation_argument_for_removal_record(removal_record, &mut chunk_dictionaries);

        // Collect all the MMR membership proofs from the chunk dictionaries.
        // Also keep track of which MS membership proof they came from, so the
        // function can report back which MS membership proofs that have been
        // mutated.
        // The chunk values contained in the MS membership proof's chunk dictionary has already
        // been updated by the `get_batch_mutation_argument_for_removal_record` function.
        let mut own_mmr_mps: Vec<&mut mmr::mmr_membership_proof::MmrMembershipProof> = vec![];
        let mut leaf_indices = vec![];
        let mut mmr_mp_index_to_input_index: Vec<usize> = vec![];
        for (i, chunk_dict) in chunk_dictionaries.iter_mut().enumerate() {
            for (chunk_index, (mp, _)) in chunk_dict.iter_mut() {
                own_mmr_mps.push(mp);
                leaf_indices.push(*chunk_index);
                mmr_mp_index_to_input_index.push(i);
            }
        }

        // Perform the batch mutation of the MMR membership proofs
        let mutated_mmr_mps =
            mmr::mmr_membership_proof::MmrMembershipProof::batch_update_from_batch_leaf_mutation(
                &mut own_mmr_mps,
                &leaf_indices,
                mutation_argument
                    .iter()
                    .map(|(i, p, l)| LeafMutation::new(*i, *l, p.clone()))
                    .collect_vec(),
            );

        // Keep track of which MS membership proofs that were mutated. This is all those membership
        // proofs which have a mutated chunk
        let mut ret: Vec<usize> = mutated_chunks_by_mp_indices.into_iter().collect();
        for index in mutated_mmr_mps {
            ret.push(mmr_mp_index_to_input_index[index]);
        }
        ret.sort_unstable();
        ret.dedup();

        Ok(ret)
    }

    pub fn update_from_remove(&mut self, removal_record: &RemovalRecord) -> bool {
        // Removing items does not slide the active window. We only
        // need to take into account new indices in the sparse Bloom
        // filter, and only in the inactive part. Specifically: we
        // need to update the chunks and their membership proofs.

        // Set all chunk values to the new values and calculate the mutation argument
        // for the batch updating of the MMR membership proofs.
        let mut chunk_dictionaries = vec![&mut self.target_chunks];
        let (mutated_chunk_dictionary_index, mutation_argument) =
            get_batch_mutation_argument_for_removal_record(removal_record, &mut chunk_dictionaries);

        // update membership proofs
        // Note that *all* membership proofs must be updated. It's not sufficient to update
        // those whose leaf has changed, since an authentication path changes if *any* leaf
        // in the same Merkle tree (under the same MMR peak) changes.
        // It would be sufficient to only update the membership proofs that live in the Merkle
        // trees that have been updated, but it probably will not give a measurable speedup
        // since this change would not reduce the amount of hashing needed
        let chunk_mmr_lis = self
            .target_chunks
            .iter()
            .map(|(chunk_index, (_, _))| *chunk_index)
            .collect_vec();
        let mut chunk_mmr_mps: Vec<&mut mmr::mmr_membership_proof::MmrMembershipProof> = self
            .target_chunks
            .iter_mut()
            .map(|(_, (mmr_mp, _))| mmr_mp)
            .collect();

        let mutated_mmr_mp_indices: Vec<usize> =
            mmr::mmr_membership_proof::MmrMembershipProof::batch_update_from_batch_leaf_mutation(
                &mut chunk_mmr_mps,
                &chunk_mmr_lis,
                mutation_argument
                    .iter()
                    .map(|(i, p, l)| LeafMutation::new(*i, *l, p.clone()))
                    .collect_vec(),
            );

        !mutated_mmr_mp_indices.is_empty() || !mutated_chunk_dictionary_index.is_empty()
    }

    /// Reverts a membership proof to its state prior to updating it
    /// with a removal record.
    ///
    /// Returns `true` iff the membership proof changed.
    pub fn revert_update_from_remove(&mut self, removal_record: &RemovalRecord) -> bool {
        // The logic here is essentially the same as in
        // `update_from_remove` but with the new and old chunks
        // swapped.

        // Set all chunk values to the old values and prepare
        // for batch updating of the MMR membership proofs.
        let mut chunk_dictionaries = vec![&mut self.target_chunks];
        let (mutated_chunk_dictionary_index, batch_membership) =
            prepare_authenticated_batch_modification_for_removal_record_reversion(
                removal_record,
                &mut chunk_dictionaries,
            );

        // update MMR membership proofs
        // Note that *all* MMR membership proofs must be updated. It's not sufficient to update
        // those whose leaf has changed, since an authentication path changes if *any* leaf
        // in the same Merkle tree (under the same MMR peak) changes.
        let chunk_mmr_lis = self
            .target_chunks
            .iter()
            .map(|(leaf_index, (_, _))| *leaf_index)
            .collect_vec();
        let mut chunk_mmr_mps: Vec<&mut mmr::mmr_membership_proof::MmrMembershipProof> = self
            .target_chunks
            .iter_mut()
            .map(|(_, (mmr_mp, _))| mmr_mp)
            .collect();

        let mutated_mmr_mp_indices: Vec<usize> =
            mmr::mmr_membership_proof::MmrMembershipProof::batch_update_from_batch_leaf_mutation(
                &mut chunk_mmr_mps,
                &chunk_mmr_lis,
                batch_membership
                    .iter()
                    .map(|(i, p, l)| LeafMutation::new(*i, *l, p.clone()))
                    .collect_vec(),
            );

        !mutated_mmr_mp_indices.is_empty() || !mutated_chunk_dictionary_index.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexedAoclAuthPath {
    pub leaf_index: u64,
    pub auth_path: MmrMembershipProof,
}

/// Data structure for returning components of a mutator set membership proof
/// from an archival state, without callee learning more than the unmined
/// transaction reveals, namely a fuzzy timestamp of the input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MsMembershipProofPrivacyPreserving {
    pub aocl_auth_paths: Vec<IndexedAoclAuthPath>,
    pub target_chunks: ChunkDictionary,
}

impl MsMembershipProofPrivacyPreserving {
    /// Build the required membership proof by supplying the correct AOCL leaf
    /// index to extract the right MMR authentication path and the missing
    /// cryptographic data.
    pub fn extract_ms_membership_proof(
        self,
        aocl_leaf_index: u64,
        sender_randomness: Digest,
        receiver_preimage: Digest,
    ) -> Result<MsMembershipProof, Box<dyn Error>> {
        let aocl_mmr = self
            .aocl_auth_paths
            .into_iter()
            .find(|x| x.leaf_index == aocl_leaf_index)
            .map(|x| x.auth_path);
        let Some(aocl_mmr) = aocl_mmr else {
            return Err(Box::new(
                MutatorSetError::RequestedAoclAuthPathNotContainedInResponse {
                    request_aocl_leaf_index: aocl_leaf_index,
                },
            ));
        };

        Ok(MsMembershipProof {
            sender_randomness,
            receiver_preimage,
            auth_path_aocl: aocl_mmr,
            aocl_leaf_index,
            target_chunks: self.target_chunks,
        })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub mod tests {
    use itertools::Itertools;
    use macro_rules_attr::apply;
    use proptest::prelude::*;
    use rand::random;
    use rand::seq::IndexedRandom;
    use rand::Rng;
    use tasm_lib::twenty_first::math::other::random_elements;
    use tasm_lib::twenty_first::util_types::mmr::mmr_membership_proof::MmrMembershipProof;

    use super::*;
    use crate::active_window::ActiveWindow;
    use crate::commit;
    use crate::removal_record::chunk::Chunk;
    use crate::test_shared::mock_item_and_randomnesses;
    use crate::test_utils::shared_tokio_runtime;

    #[test]
    fn mp_equality_test() {
        let mut rng = rand::rng();

        let (_item, sender_randomness, receiver_preimage) = mock_item_and_randomnesses();

        let base_mp = MsMembershipProof {
            sender_randomness,
            receiver_preimage,
            auth_path_aocl: MmrMembershipProof::new(vec![]),
            aocl_leaf_index: 0,
            target_chunks: ChunkDictionary::default(),
        };

        let mp_with_different_leaf_index = MsMembershipProof {
            sender_randomness,
            receiver_preimage,
            auth_path_aocl: MmrMembershipProof::new(vec![]),
            aocl_leaf_index: 100073,
            target_chunks: ChunkDictionary::default(),
        };

        let mp_with_different_sender_randomness = MsMembershipProof {
            sender_randomness: rng.random(),
            receiver_preimage,
            auth_path_aocl: MmrMembershipProof::new(vec![]),
            aocl_leaf_index: 0,
            target_chunks: ChunkDictionary::default(),
        };

        let mp_with_different_receiver_preimage = MsMembershipProof {
            receiver_preimage: rng.random(),
            sender_randomness,
            auth_path_aocl: MmrMembershipProof::new(vec![]),
            aocl_leaf_index: 0,
            target_chunks: ChunkDictionary::default(),
        };

        // Verify that a different data index (a different auth path) is a different MP
        assert_ne!(mp_with_different_leaf_index, base_mp);

        // Verify that different sender randomness is a different MP
        assert_ne!(mp_with_different_sender_randomness, base_mp);

        // Verify that different receiver preimage is a different MP
        assert_ne!(mp_with_different_receiver_preimage, base_mp);

        // Test that a different chunk dictionary results in a different MP
        // For this test to be performed, we first need an MMR membership proof and a chunk.

        // Construct an MMR with 7 leafs
        let mmr_digests = random_elements::<Digest>(7);
        let mut mmra: MmrAccumulator = MmrAccumulator::new_from_leafs(mmr_digests);

        // Get an MMR membership proof by adding the 8th leaf
        let zero_chunk = Chunk::empty_chunk();
        let mmr_mp = mmra.append(Tip5::hash(&zero_chunk));

        // Verify that the MMR membership proof has the expected length of 3 (sanity check)
        assert_eq!(3, mmr_mp.authentication_path.len());

        // Create a new mutator set membership proof with a non-empty chunk dictionary
        // and verify that it is considered a different membership proof
        let mut mp_mutated: MsMembershipProof = base_mp.clone();
        mp_mutated.target_chunks.insert(0, (mmr_mp, zero_chunk));
        assert_ne!(mp_mutated, base_mp);
    }

    #[test]
    fn serialization_test() {
        // This test belongs here since the serialization for `Option<[T; $len]>` is implemented
        // in this code base as a macro. So this is basically a test of that macro.
        let accumulator: MutatorSetAccumulator = MutatorSetAccumulator::default();
        for _ in 0..10 {
            let (item, sender_randomness, receiver_preimage) = mock_item_and_randomnesses();

            let mp = accumulator.prove(item, sender_randomness, receiver_preimage);

            let json: String = serde_json::to_string(&mp).unwrap();
            let mp_again = serde_json::from_str::<MsMembershipProof>(&json).unwrap();

            assert_eq!(mp_again.target_chunks, mp.target_chunks);
            assert_eq!(mp_again, mp);
        }
    }

    #[apply(shared_tokio_runtime)]
    async fn revert_update_from_addition_batches_test() {
        let mut msa: MutatorSetAccumulator = MutatorSetAccumulator::default();

        let mut rng = rand::rng();
        for _ in 0..10 {
            let init_size = rng.random_range(0..200);
            let first_batch_size = rng.random_range(0..200);
            let last_batch_size = rng.random_range(0..200);

            // Add `init_size` items to MSA
            for _ in 0..init_size {
                let item: Digest = random();
                let sender_randomness: Digest = random();
                let receiver_preimage: Digest = random();
                let addition_record = commit(item, sender_randomness, receiver_preimage.hash());
                msa.add(&addition_record);
            }

            // Add own item with associated membership proof that we want to keep updated
            let own_item: Digest = random();
            let own_sender_randomness: Digest = random();
            let own_receiver_preimage: Digest = random();
            let own_addition_record = commit(
                own_item,
                own_sender_randomness,
                own_receiver_preimage.hash(),
            );
            let mut own_mp = msa.prove(own_item, own_sender_randomness, own_receiver_preimage);
            msa.add(&own_addition_record);
            let msa_after_own_add = msa.clone();

            // Apply 1st batch of additions
            for _ in 0..first_batch_size {
                let item: Digest = random();
                let sender_randomness: Digest = random();
                let receiver_preimage: Digest = random();
                let addition_record = commit(item, sender_randomness, receiver_preimage.hash());
                own_mp
                    .update_from_addition(own_item, &msa, &addition_record)
                    .unwrap();
                msa.add(&addition_record);
                assert!(
                    msa.verify(own_item, &own_mp),
                    "Own mp must be valid after update"
                );
            }

            let msa_after_first_batch = msa.clone();

            // Apply 2nd batch of additions
            for _ in 0..last_batch_size {
                let item: Digest = random();
                let sender_randomness: Digest = random();
                let receiver_preimage: Digest = random();
                let addition_record = commit(item, sender_randomness, receiver_preimage.hash());
                own_mp
                    .update_from_addition(own_item, &msa, &addition_record)
                    .unwrap();
                msa.add(&addition_record);
                assert!(
                    msa.verify(own_item, &own_mp),
                    "Own mp must be valid after update"
                );
            }

            // revert last batch
            own_mp.revert_update_from_batch_addition(&msa_after_first_batch);
            assert!(msa_after_first_batch.verify(own_item, &own_mp));

            // revert first batch
            own_mp.revert_update_from_batch_addition(&msa_after_own_add);
            assert!(msa_after_own_add.verify(own_item, &own_mp));
        }
    }

    proptest::proptest! {
        #![proptest_config(ProptestConfig {
            cases: 100, .. ProptestConfig::default()
          })]
        #[test]
        fn test_decode_mutator_set_membership_proof(msmp in crate::strategies::msmembershipproof()) {
            let encoded = msmp.encode();
            let decoded: MsMembershipProof = *MsMembershipProof::decode(&encoded).unwrap();
            assert_eq!(msmp, decoded);
        }
    }

    #[test]
    fn batch_updates_on_small_mmr() {
        let mut rng = rand::rng();

        for remove_share in [0.01, 0.1, 0.4, 0.7, 0.99, 1.0] {
            let mut msa = MutatorSetAccumulator::default();
            let mut msmps = vec![];
            let mut items = vec![];
            let mut removed = vec![];
            for j in 0usize..usize::try_from(25 * BATCH_SIZE).unwrap() {
                println!("{j}");
                let item: Digest = rng.random();
                let sender_randomness: Digest = rng.random();
                let receiver_preimage: Digest = rng.random();
                let msmp = msa.prove(item, sender_randomness, receiver_preimage);
                let addition_record = commit(item, sender_randomness, receiver_preimage.hash());
                MsMembershipProof::batch_update_from_addition(
                    &mut msmps.iter_mut().collect_vec(),
                    &items,
                    &msa,
                    &addition_record,
                )
                .unwrap();
                msa.add(&addition_record);
                msmps.push(msmp);
                items.push(item);

                if rng.random_bool(remove_share) {
                    let not_removed = (0..=j).filter(|i| !removed.contains(i)).collect_vec();
                    let remove = *not_removed.choose(&mut rng).unwrap();
                    let remove_item = items[remove];
                    let remove_msmp = &msmps[remove];
                    let removal_record = msa.drop(remove_item, remove_msmp);
                    MsMembershipProof::batch_update_from_remove(
                        &mut msmps.iter_mut().collect_vec(),
                        &removal_record,
                    )
                    .unwrap();
                    assert!(msa.can_remove(&removal_record));
                    msa.remove(&removal_record);
                    removed.push(remove);
                }
            }

            for ((j, msmp), item) in msmps.into_iter().enumerate().zip(items) {
                if removed.contains(&j) {
                    assert!(
                        !msa.verify(item, &msmp),
                        "index {j} must fail to verify since it was removed."
                    );
                } else {
                    assert!(
                        msa.verify(item, &msmp),
                        "index {j} must verify since it was never removed."
                    );
                }
            }
        }
    }

    #[test]
    #[should_panic(expected = "corrupt mutator set accumulator")]
    fn update_from_addition_fails_for_inconsistent_mutator_set_accumulator() {
        let mut rng = rand::rng();
        let aocl_leaf_count = 42966841942012423_u64;
        let aocl_peaks = (0..aocl_leaf_count.count_ones())
            .map(|_| rng.random::<Digest>())
            .collect_vec();
        let swbfi_leaf_count = (aocl_leaf_count / u64::from(BATCH_SIZE)) + 1;
        let swbfi_peaks = (0..swbfi_leaf_count.count_ones())
            .map(|_| rng.random::<Digest>())
            .collect_vec();
        let swbf_active = ActiveWindow::new();

        // Note that we are bypassing the mutator set accumulator constructor,
        // which guarantees that the leaf counts are in sync.
        let mut mutator_set_accumulator = MutatorSetAccumulator {
            aocl: MmrAccumulator::init(aocl_peaks, aocl_leaf_count),
            swbf_inactive: MmrAccumulator::init(swbfi_peaks, swbfi_leaf_count),
            swbf_active,
        };

        let (own_item, sender_randomness, receiver_preimage) =
            rng.random::<(Digest, Digest, Digest)>();
        let own_addition_record = commit(own_item, sender_randomness, receiver_preimage.hash());
        let mut msmp =
            mutator_set_accumulator.prove(own_item, sender_randomness, receiver_preimage);
        mutator_set_accumulator.add(&own_addition_record);

        // aocl leaf count is now 42966841942012424_u64

        let other_addition_record = AdditionRecord::new(rng.random::<Digest>());

        msmp.update_from_addition(own_item, &mutator_set_accumulator, &other_addition_record)
            .expect("update from add should always work");
    }
}
