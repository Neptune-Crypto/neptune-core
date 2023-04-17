use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt;
use std::ops::IndexMut;
use twenty_first::shared_math::tip5::Digest;

use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;
use twenty_first::util_types::mmr;
use twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
use twenty_first::util_types::mmr::mmr_trait::Mmr;

use super::addition_record::AdditionRecord;
use super::chunk_dictionary::ChunkDictionary;
use super::mutator_set_accumulator::MutatorSetAccumulator;
use super::mutator_set_kernel::{get_swbf_indices, MutatorSetKernel};
use super::removal_record::AbsoluteIndexSet;
use super::removal_record::RemovalRecord;
use super::shared::{
    generate_authenticated_batch_modification_for_removal_record_reversion,
    get_batch_mutation_argument_for_removal_record, BATCH_SIZE, CHUNK_SIZE,
};
use super::transfer_ms_membership_proof::TransferMsMembershipProof;

impl Error for MembershipProofError {}

impl fmt::Display for MembershipProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(PartialEq, Eq, Debug)]
pub enum MembershipProofError {
    AlreadyExistingChunk(u64),
    MissingChunkOnUpdateFromAdd(u64),
    MissingChunkOnUpdateFromRemove(u64),
    MissingChunkOnRevertUpdateFromAdd(u64),
}

// In order to store this structure in the database, it needs to be serializable. But it should not be
// transferred between peers as the `cached_indices` fields cannot be trusted and must be calculated by each peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MsMembershipProof<H: AlgebraicHasher> {
    pub randomness: Digest,
    pub auth_path_aocl: mmr::mmr_membership_proof::MmrMembershipProof<H>,
    pub target_chunks: ChunkDictionary<H>,

    // Cached indices are optional to store, but will prevent a lot of hashing in
    // later bookkeeping, such as updating the membership proof.
    // Warning: These indices should not be trusted and should only be calculated
    // locally. If they are trusted the soundness of the mutator set is compromised,
    // and if they are leaked the privacy is compromised.
    // #[serde(with = "CompositeBigArray")]
    pub cached_indices: Option<AbsoluteIndexSet>,
}

/// Convert a transfer version of the membership proof to one for internal use.
/// The important thing here is that `cached_indices` is not shared between peers.
impl<H: AlgebraicHasher> From<TransferMsMembershipProof<H>> for MsMembershipProof<H> {
    fn from(transfer: TransferMsMembershipProof<H>) -> Self {
        Self {
            randomness: transfer.randomness,
            auth_path_aocl: transfer.auth_path_aocl,
            target_chunks: transfer.target_chunks,
            cached_indices: None,
        }
    }
}

// This conversion is kept here to avoid circular dependencies -- not sure if we have
// to avoid that, though.
impl<H: AlgebraicHasher> From<MsMembershipProof<H>> for TransferMsMembershipProof<H> {
    fn from(mp: MsMembershipProof<H>) -> Self {
        Self {
            randomness: mp.randomness,
            auth_path_aocl: mp.auth_path_aocl,
            target_chunks: mp.target_chunks,
        }
    }
}

impl<H: AlgebraicHasher> PartialEq for MsMembershipProof<H> {
    // Equality for a membership proof does not look at cached indices, as they are just cached data
    // Whether they are set or not, does not change the membership proof.
    fn eq(&self, other: &Self) -> bool {
        self.randomness == other.randomness
            && self.auth_path_aocl == other.auth_path_aocl
            && self.target_chunks == other.target_chunks
    }
}

impl<H: AlgebraicHasher> MsMembershipProof<H> {
    /// Helper function to cache the indices so they don't have to be recalculated multiple times
    pub fn cache_indices(&mut self, item: &Digest) {
        let indices = get_swbf_indices::<H>(item, &self.randomness, self.auth_path_aocl.leaf_index);
        self.cached_indices = Some(AbsoluteIndexSet::new(&indices));
    }

    pub fn batch_update_from_addition<MMR: Mmr<H>>(
        membership_proofs: &mut [&mut Self],
        own_items: &[Digest],
        mutator_set: &MutatorSetKernel<H, MMR>,
        addition_record: &AdditionRecord,
    ) -> Result<Vec<usize>, Box<dyn Error>> {
        assert!(
            membership_proofs
                .iter()
                .all(|mp| mp.auth_path_aocl.leaf_index < mutator_set.aocl.count_leaves()),
            "No AOCL data index can point outside of provided mutator set"
        );
        assert_eq!(
            membership_proofs.len(),
            own_items.len(),
            "Function must be called with same number of membership proofs and items"
        );

        let new_item_index = mutator_set.aocl.count_leaves();

        // Update AOCL MMR membership proofs
        let indices_for_updated_mps =
            mmr::mmr_membership_proof::MmrMembershipProof::batch_update_from_append(
                &mut membership_proofs
                    .iter_mut()
                    .map(|x| &mut x.auth_path_aocl)
                    .collect::<Vec<_>>(),
                new_item_index,
                &addition_record.canonical_commitment,
                &mutator_set.aocl.get_peaks(),
            );

        // if window does not slide, we are done
        if !MutatorSetKernel::<H, MMR>::window_slides(new_item_index) {
            return Ok(indices_for_updated_mps);
        }

        // window does slide
        let batch_index = new_item_index / BATCH_SIZE as u64;
        let old_window_start_batch_index = batch_index - 1;
        let new_chunk = mutator_set.swbf_active.slid_chunk();
        let new_chunk_digest: Digest = H::hash(&new_chunk);

        // Insert the new chunk digest into the accumulator-version of the
        // SWBF MMR to get its authentication path. It's important to convert the MMR
        // to an MMR Accumulator here, since we don't want to drag around or clone
        // a whole archival MMR for this operation, as the archival MMR can be in the
        // size of gigabytes, whereas the MMR accumulator should be in the size of
        // kilobytes.
        let mut mmra: MmrAccumulator<H> = mutator_set.swbf_inactive.to_accumulator();
        let new_swbf_auth_path: mmr::mmr_membership_proof::MmrMembershipProof<H> =
            mmra.append(new_chunk_digest);

        // Collect all indices for all membership proofs that are being updated
        // Notice that this is a *very* expensive operation if the indices are
        // not already known. I.e., the `None` case below is very expensive.
        let mut chunk_index_to_mp_index: HashMap<u64, Vec<usize>> = HashMap::new();
        membership_proofs
            .iter()
            .zip(own_items.iter())
            .enumerate()
            .for_each(|(i, (mp, item))| {
                let indices = match &mp.cached_indices {
                    Some(bs) => bs.to_owned(),
                    None => {
                        let leaf_index = mp.auth_path_aocl.leaf_index;
                        let indices = get_swbf_indices::<H>(item, &mp.randomness, leaf_index);
                        AbsoluteIndexSet::new(&indices)
                    }
                };
                let chunks_set: HashSet<u64> = indices
                    .to_array()
                    .iter()
                    .map(|x| (x / CHUNK_SIZE as u128) as u64)
                    .collect();
                chunks_set.iter().for_each(|chnkidx| {
                    chunk_index_to_mp_index
                        .entry(*chnkidx)
                        .or_insert_with(Vec::new)
                        .push(i)
                });
            });

        // Find the membership proofs that need a new dictionary entry for the chunk that's being
        // added to the inactive part by this addition.
        let mps_for_new_chunk_dictionary_entry: Vec<usize> =
            match chunk_index_to_mp_index.get(&old_window_start_batch_index) {
                Some(vals) => vals.clone(),
                None => vec![],
            };

        // Find the membership proofs that have dictionary entry MMR membership proofs that need
        // to be updated because of the window sliding. We just
        let mut mps_for_batch_append: HashSet<usize> = HashSet::new();
        for (chunk_index, mp_indices) in chunk_index_to_mp_index.into_iter() {
            if chunk_index < old_window_start_batch_index {
                for mp_index in mp_indices {
                    mps_for_batch_append.insert(mp_index);
                }
            }
        }

        // Perform the updates

        // First insert the new entry into the chunk dictionary for the membership
        // proofs that need it.
        for i in mps_for_new_chunk_dictionary_entry.iter() {
            membership_proofs
                .index_mut(*i)
                .target_chunks
                .dictionary
                .insert(
                    old_window_start_batch_index,
                    (new_swbf_auth_path.clone(), new_chunk.clone()),
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
            &mut mmr::mmr_membership_proof::MmrMembershipProof<H>,
        > = vec![];

        // The `mmr_membership_proof_index_to_membership_proof_index` variable is to remember
        // which parts of the MMR membership proofs that map to MS membership proofs. This is
        // required to return the indices of the MS membership proofs that have been updated
        // by this function call.
        let mut mmr_membership_proof_index_to_membership_proof_index: Vec<usize> = vec![];
        for (i, mp) in membership_proofs.iter_mut().enumerate() {
            if mps_for_batch_append.contains(&i) {
                for (_, (mmr_mp, _chnk)) in mp.target_chunks.dictionary.iter_mut() {
                    mmr_membership_proofs_for_append.push(mmr_mp);
                    mmr_membership_proof_index_to_membership_proof_index.push(i);
                }
            }
        }

        let indices_for_mutated_values =
            mmr::mmr_membership_proof::MmrMembershipProof::<H>::batch_update_from_append(
                &mut mmr_membership_proofs_for_append,
                mutator_set.swbf_inactive.count_leaves(),
                &new_chunk_digest,
                &mutator_set.swbf_inactive.get_peaks(),
            );
        let mut swbf_mutated_indices: Vec<usize> = vec![];
        for j in indices_for_mutated_values {
            swbf_mutated_indices.push(mmr_membership_proof_index_to_membership_proof_index[j]);
        }

        // Gather the indices the are returned. These indices indicate which membership
        // proofs that have been mutated.
        let mut all_mutated_mp_indices: Vec<usize> = vec![
            swbf_mutated_indices,
            indices_for_updated_mps,
            mps_for_new_chunk_dictionary_entry,
        ]
        .concat();
        all_mutated_mp_indices.sort_unstable();
        all_mutated_mp_indices.dedup();

        Ok(all_mutated_mp_indices)
    }

    /**
     * update_from_addition
     * Updates a membership proof in anticipation of an addition to the set.
     */
    pub fn update_from_addition(
        &mut self,
        own_item: &Digest,
        mutator_set: &MutatorSetAccumulator<H>,
        addition_record: &AdditionRecord,
    ) -> Result<bool, Box<dyn Error>> {
        assert!(self.auth_path_aocl.leaf_index < mutator_set.kernel.aocl.count_leaves());
        let new_item_index = mutator_set.kernel.aocl.count_leaves();

        // Update AOCL MMR membership proof
        let aocl_mp_updated = self.auth_path_aocl.update_from_append(
            mutator_set.kernel.aocl.count_leaves(),
            &addition_record.canonical_commitment,
            &mutator_set.kernel.aocl.get_peaks(),
        );

        // if window does not slide, we are done
        if !MutatorSetKernel::<H, MmrAccumulator<H>>::window_slides(new_item_index) {
            return Ok(aocl_mp_updated);
        }

        // window does slide
        let new_chunk = mutator_set.kernel.swbf_active.slid_chunk();
        let new_chunk_digest: Digest = H::hash(&new_chunk);

        // Get indices from either the cached indices, or by recalculating them. Notice
        // that the latter is an expensive operation.
        let all_indices = match &self.cached_indices {
            Some(indices) => indices.to_array(),
            None => {
                get_swbf_indices::<H>(own_item, &self.randomness, self.auth_path_aocl.leaf_index)
            }
        };
        let chunk_indices_set: HashSet<u64> = all_indices
            .into_iter()
            .map(|bi| (bi / CHUNK_SIZE as u128) as u64)
            .collect::<HashSet<u64>>();

        // Get an accumulator-version of the MMR and insert the new SWBF leaf to get its
        // authentication path.
        // It's important to convert the MMR
        // to an MMR Accumulator here, since we don't want to drag around or clone
        // a whole archival MMR for this operation, as the archival MMR can be in the
        // size of gigabytes, whereas the MMR accumulator should be in the size of
        // kilobytes.
        let mut mmra: MmrAccumulator<H> = mutator_set.kernel.swbf_inactive.to_accumulator();
        let new_auth_path: mmr::mmr_membership_proof::MmrMembershipProof<H> =
            mmra.append(new_chunk_digest);

        let mut swbf_chunk_dictionary_updated = false;
        let batch_index = new_item_index / BATCH_SIZE as u64;
        let old_window_start_batch_index = batch_index - 1;
        let new_window_start_batch_index = batch_index;
        'outer: for chunk_index in chunk_indices_set.into_iter() {
            // Update for indices that are in the inactive part of the SWBF.
            // Here the MMR membership proofs of the chunks must be updated.
            if chunk_index < old_window_start_batch_index {
                let mp = match self.target_chunks.dictionary.get_mut(&chunk_index) {
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
                    mutator_set.kernel.swbf_inactive.count_leaves(),
                    &new_chunk_digest,
                    &mutator_set.kernel.swbf_inactive.get_peaks(),
                );
                swbf_chunk_dictionary_updated =
                    swbf_chunk_dictionary_updated || swbf_chunk_dict_updated_local;

                continue 'outer;
            }

            // if index is in the part that is becoming inactive, add a dictionary entry
            if old_window_start_batch_index <= chunk_index
                && chunk_index < new_window_start_batch_index
            {
                if self.target_chunks.dictionary.contains_key(&chunk_index) {
                    return Err(Box::new(MembershipProofError::AlreadyExistingChunk(
                        chunk_index,
                    )));
                }

                // add dictionary entry
                self.target_chunks
                    .dictionary
                    .insert(chunk_index, (new_auth_path.clone(), new_chunk.clone()));
                swbf_chunk_dictionary_updated = true;

                continue 'outer;
            }

            // If `chunk_index` refers to indices that are still in the active window, do nothing.
        }

        Ok(swbf_chunk_dictionary_updated || aocl_mp_updated)
    }

    /// Resets a membership proof to its state prior to updating it
    /// with an addition record, given the item it pertains to and
    /// the state of the mutator set kernel prior to adding it.
    pub fn revert_update_from_addition(
        &mut self,
        own_item: &Digest,
        previous_mutator_set: &MutatorSetAccumulator<H>,
    ) -> Result<bool, Box<dyn Error>> {
        // How can we even revert an addition when we aren't given
        // the addition record as input?
        // An addition record does not come with its aocl index
        // so we would have to assume it is being reverted in the
        // correct order. The AOCL index is the only piece of
        // information we need, but we can get it from the mutator
        // set kernel instead.
        // In fact, this number is equal to the number of leafs in
        // the AOCL MMR prior to adding the item.
        let aocl_index = previous_mutator_set.kernel.aocl.count_leaves();

        // Revert update to AOCL MMR membership proof.

        // MMR membership proofs can only grow (or not) under
        // additions, so under addition-reversions they can only
        // shrink (or not).

        // Find out if we have to shrink.
        let own_commitment = H::hash_pair(own_item, &self.randomness);
        assert!(previous_mutator_set.kernel.aocl.count_leaves() > self.auth_path_aocl.leaf_index);
        let mut valid = self
            .auth_path_aocl
            .verify(
                &previous_mutator_set.kernel.aocl.get_peaks(),
                &own_commitment,
                previous_mutator_set.kernel.aocl.count_leaves(),
            )
            .0;

        // If we have to shrink, shrink until valid or empty
        while !valid {
            let last_ap_elem = self.auth_path_aocl.authentication_path.pop();
            if last_ap_elem.is_none() {
                break;
            }
            valid = self
                .auth_path_aocl
                .verify(
                    &previous_mutator_set.kernel.aocl.get_peaks(),
                    &own_commitment,
                    previous_mutator_set.kernel.aocl.count_leaves(),
                )
                .0;
        }

        // If the addition record did not induce a window slide, then
        // we are done.
        if !MutatorSetKernel::<H, MmrAccumulator<H>>::window_slides(aocl_index) {
            return Ok(true);
        }

        // As a result of the window slide, two types of things may
        // have happened:
        //  1. Some of the membership proof's indices were moved from
        //     the active window into the new chunk.
        //  2. Some of the MS membership proof's existing chunks get
        //     updated MMR membership proofs.

        // The moved indices do not include indices from this
        // membership proof. So the net effect is a new chunk that
        // must be dropped for reversion, if it is even present.
        let swbfi_leaf_count = previous_mutator_set.kernel.swbf_inactive.count_leaves();
        self.target_chunks.dictionary.remove(&swbfi_leaf_count);

        assert!(self.target_chunks.dictionary.len() <= swbfi_leaf_count as usize);

        // The SWBF MMR membership proofs grew by 0 or more. So
        // find out which and trim them if necessary.
        for (_chunkidx_key, (mmr_mp, chunk)) in self.target_chunks.dictionary.iter_mut() {
            let mut already_valid = mmr_mp
                .verify(
                    &previous_mutator_set.kernel.swbf_inactive.get_peaks(),
                    &H::hash(chunk),
                    swbfi_leaf_count,
                )
                .0;
            while !already_valid {
                if mmr_mp.authentication_path.pop().is_none() {
                    break;
                }
                already_valid = mmr_mp
                    .verify(
                        &previous_mutator_set.kernel.swbf_inactive.get_peaks(),
                        &H::hash(chunk),
                        swbfi_leaf_count,
                    )
                    .0;
            }
        }

        Ok(true)
    }

    /// Update multiple membership proofs from one remove operation. Returns the indices of the membership proofs
    /// that have been mutated.
    pub fn batch_update_from_remove(
        membership_proofs: &mut [&mut Self],
        removal_record: &RemovalRecord<H>,
    ) -> Result<Vec<usize>, Box<dyn Error>> {
        // Set all chunk values to the new values and calculate the mutation argument
        // for the batch updating of the MMR membership proofs.
        let mut chunk_dictionaries: Vec<&mut ChunkDictionary<H>> = membership_proofs
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
        let mut own_mmr_mps: Vec<&mut mmr::mmr_membership_proof::MmrMembershipProof<H>> = vec![];
        let mut mmr_mp_index_to_input_index: Vec<usize> = vec![];
        for (i, chunk_dict) in chunk_dictionaries.iter_mut().enumerate() {
            for (_, (mp, _)) in chunk_dict.dictionary.iter_mut() {
                own_mmr_mps.push(mp);
                mmr_mp_index_to_input_index.push(i);
            }
        }

        // Perform the batch mutation of the MMR membership proofs
        let mutated_mmr_mps =
            mmr::mmr_membership_proof::MmrMembershipProof::batch_update_from_batch_leaf_mutation(
                &mut own_mmr_mps,
                mutation_argument,
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

    pub fn update_from_remove(
        &mut self,
        removal_record: &RemovalRecord<H>,
    ) -> Result<bool, Box<dyn Error>> {
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
        // trees that have been updated, but it probably will not give a measureable speedup
        // since this change would not reduce the amount of hashing needed
        let mut chunk_mmr_mps: Vec<&mut mmr::mmr_membership_proof::MmrMembershipProof<H>> = self
            .target_chunks
            .dictionary
            .iter_mut()
            .map(|(_, (mmr_mp, _))| mmr_mp)
            .collect();

        let mutated_mmr_mp_indices: Vec<usize> =
            mmr::mmr_membership_proof::MmrMembershipProof::batch_update_from_batch_leaf_mutation(
                &mut chunk_mmr_mps,
                mutation_argument,
            );

        Ok(!mutated_mmr_mp_indices.is_empty() || !mutated_chunk_dictionary_index.is_empty())
    }

    /// Resets a membership proof to its state prior to updating it
    /// with a removal record.
    pub fn revert_update_from_remove(
        &mut self,
        removal_record: &RemovalRecord<H>,
    ) -> Result<bool, Box<dyn Error>> {
        // The logic here is essentially the same as in
        // `update_from_remove` but with the new and old chunks
        // swapped.

        // Set all chunk values to the old values and calculate the mutation argument
        // for the batch updating of the MMR membership proofs.
        let mut chunk_dictionaries = vec![&mut self.target_chunks];
        let (mutated_chunk_dictionary_index, batch_membership) =
            generate_authenticated_batch_modification_for_removal_record_reversion(
                removal_record,
                &mut chunk_dictionaries,
            );

        // update MMR membership proofs
        // Note that *all* MMR membership proofs must be updated. It's not sufficient to update
        // those whose leaf has changed, since an authentication path changes if *any* leaf
        // in the same Merkle tree (under the same MMR peak) changes.
        let mut chunk_mmr_mps: Vec<&mut mmr::mmr_membership_proof::MmrMembershipProof<H>> = self
            .target_chunks
            .dictionary
            .iter_mut()
            .map(|(_, (mmr_mp, _))| mmr_mp)
            .collect();

        let mutated_mmr_mp_indices: Vec<usize> =
            mmr::mmr_membership_proof::MmrMembershipProof::batch_update_from_batch_leaf_mutation(
                &mut chunk_mmr_mps,
                batch_membership,
            );

        Ok(!mutated_mmr_mp_indices.is_empty() || !mutated_chunk_dictionary_index.is_empty())
    }
}

#[cfg(test)]
mod ms_proof_tests {

    use super::*;
    use crate::test_shared::mutator_set::{empty_rustyleveldbvec_ams, make_item_and_randomness};
    use crate::util_types::mutator_set::archival_mutator_set::ArchivalMutatorSet;
    use crate::util_types::mutator_set::chunk::Chunk;
    use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
    use crate::util_types::mutator_set::mutator_set_trait::MutatorSet;
    use crate::util_types::mutator_set::shared::NUM_TRIALS;
    use itertools::Either;
    use num_traits::Zero;
    use rand::{random, thread_rng, RngCore};
    use twenty_first::shared_math::other::random_elements;
    use twenty_first::shared_math::tip5::Tip5;
    use twenty_first::util_types::mmr::mmr_membership_proof::MmrMembershipProof;

    #[test]
    fn mp_cache_indices_test() {
        type H = Tip5;

        let mut accumulator = MutatorSetAccumulator::<H>::default();
        let (item, randomness) = make_item_and_randomness();
        let mut mp = accumulator.kernel.prove(&item, &randomness, false);

        // Verify that indices are not cached, then cache them with the helper function
        assert!(mp.cached_indices.is_none());
        mp.cache_indices(&item);
        assert!(mp.cached_indices.is_some());

        // Verify that cached indices are the same as those generated from a new membership proof
        // made with the `cache_indices` argument set to true.
        let mp_generated_with_cached_indices = accumulator.kernel.prove(&item, &randomness, true);
        assert_eq!(
            mp_generated_with_cached_indices.cached_indices,
            mp.cached_indices
        );
    }

    #[test]
    fn mp_equality_test() {
        type H = Tip5;

        let (randomness, other_randomness) = make_item_and_randomness();

        let mp_with_cached_indices = MsMembershipProof::<H> {
            randomness,
            auth_path_aocl: MmrMembershipProof::<H>::new(0, vec![]),
            target_chunks: ChunkDictionary::default(),
            cached_indices: Some(AbsoluteIndexSet::new(&[1u128; NUM_TRIALS as usize])),
        };

        let mp_without_cached_indices = MsMembershipProof::<H> {
            randomness,
            auth_path_aocl: MmrMembershipProof::<H>::new(0, vec![]),
            target_chunks: ChunkDictionary::default(),
            cached_indices: None,
        };

        let mp_with_different_data_index = MsMembershipProof::<H> {
            randomness,
            auth_path_aocl: MmrMembershipProof::<H>::new(100073, vec![]),
            target_chunks: ChunkDictionary::default(),
            cached_indices: None,
        };

        let mp_with_different_randomness = MsMembershipProof::<H> {
            randomness: other_randomness,
            auth_path_aocl: MmrMembershipProof::<H>::new(0, vec![]),
            target_chunks: ChunkDictionary::default(),
            cached_indices: None,
        };

        // Verify that the caching of indices does not change the equality value of a membership proof
        assert_eq!(mp_with_cached_indices, mp_without_cached_indices);

        // Verify that a different data index (a different auth path) is a different MP
        assert_ne!(mp_with_different_data_index, mp_with_cached_indices);

        // Verify that different randomness is a different MP
        assert_ne!(mp_with_different_randomness, mp_with_cached_indices);

        // Test that a different chunk dictionary results in a different MP
        // For this test to be performed, we first need an MMR membership proof and a chunk.

        // Construct an MMR with 7 leafs
        let mmr_digests = random_elements::<Digest>(7);
        let mut mmra: MmrAccumulator<H> = MmrAccumulator::new(mmr_digests);

        // Get an MMR membership proof by adding the 8th leaf
        let zero_chunk = Chunk::empty_chunk();
        let mmr_mp = mmra.append(H::hash(&zero_chunk));

        // Verify that the MMR membership proof has the expected length of 3 (sanity check)
        assert_eq!(3, mmr_mp.authentication_path.len());

        // Create a new mutator set membership proof with a non-empty chunk dictionary
        // and verify that it is considered a different membership proof
        let mut mp_mutated: MsMembershipProof<H> = mp_with_cached_indices.clone();
        mp_mutated
            .target_chunks
            .dictionary
            .insert(0, (mmr_mp, zero_chunk));
        assert_ne!(mp_mutated, mp_with_cached_indices);
        assert_ne!(mp_mutated, mp_without_cached_indices);
    }

    #[test]
    fn serialization_test() {
        // This test belongs here since the serialization for `Option<[T; $len]>` is implemented
        // in this code base as a macro. So this is basically a test of that macro.
        type H = Tip5;
        let mut accumulator: MutatorSetAccumulator<H> = MutatorSetAccumulator::default();
        for _ in 0..10 {
            let (item, randomness) = make_item_and_randomness();

            let mp_with_cached_indices = accumulator.kernel.prove(&item, &randomness, true);
            assert!(mp_with_cached_indices.cached_indices.is_some());

            let json_cached: String = serde_json::to_string(&mp_with_cached_indices).unwrap();
            let s_back_cached = serde_json::from_str::<MsMembershipProof<H>>(&json_cached).unwrap();
            assert!(s_back_cached.cached_indices.is_some());
            assert!(!s_back_cached
                .cached_indices
                .as_ref()
                .unwrap()
                .to_array()
                .iter()
                .all(|x| x.is_zero()));
            assert_eq!(
                s_back_cached.cached_indices,
                mp_with_cached_indices.cached_indices
            );
            assert_eq!(
                s_back_cached.target_chunks,
                mp_with_cached_indices.target_chunks
            );

            let mp_no_cached_indices = accumulator.kernel.prove(&item, &randomness, false);
            assert!(mp_no_cached_indices.cached_indices.is_none());

            let json_no_cached: String = serde_json::to_string(&mp_no_cached_indices).unwrap();
            let s_back_no_cached =
                serde_json::from_str::<MsMembershipProof<H>>(&json_no_cached).unwrap();
            assert!(s_back_no_cached.cached_indices.is_none());
            assert_eq!(
                s_back_no_cached.cached_indices,
                mp_no_cached_indices.cached_indices
            );
            assert_eq!(
                s_back_no_cached.target_chunks,
                mp_no_cached_indices.target_chunks
            );
        }
    }

    #[test]
    fn revert_update_from_remove_test() {
        type H = Tip5;
        let n = 100;
        let mut rng = thread_rng();

        let own_index = rng.next_u32() as usize % n;
        let mut own_membership_proof = None;
        let mut own_item = None;

        // set up mutator set
        let (mut archival_mutator_set, _): (ArchivalMutatorSet<H, _, _>, _) =
            empty_rustyleveldbvec_ams();
        let mut membership_proofs: Vec<(Digest, MsMembershipProof<Tip5>)> = vec![];

        // add items
        for i in 0..n {
            let item: Digest = random();
            let randomness: Digest = random();
            let addition_record = archival_mutator_set.commit(&item, &randomness);

            for (oi, mp) in membership_proofs.iter_mut() {
                mp.update_from_addition(oi, &archival_mutator_set.accumulator(), &addition_record)
                    .expect("Could not update membership proof from addition.");
            }

            let membership_proof = archival_mutator_set.prove(&item, &randomness, false);
            if i == own_index {
                own_membership_proof = Some(membership_proof);
                own_item = Some(item);
            } else {
                membership_proofs.push((item, membership_proof));
                if i > own_index {
                    own_membership_proof
                        .as_mut()
                        .unwrap()
                        .update_from_addition(
                            own_item.as_ref().unwrap(),
                            &archival_mutator_set.accumulator(),
                            &addition_record,
                        )
                        .expect("Could not update membership proof from addition record.");
                }
            }

            archival_mutator_set.add(&addition_record);
        }
        println!("Added {n} items.");

        // assert that own mp is valid
        assert!(
            archival_mutator_set.verify(&own_item.unwrap(), own_membership_proof.as_ref().unwrap())
        );

        // Assert that all other mps are valid
        for (itm, mp) in membership_proofs.iter() {
            assert!(archival_mutator_set.verify(itm, mp));
        }

        // generate some removal records
        let mut removal_records = vec![];
        for (item, membership_proof) in membership_proofs.into_iter() {
            if rng.next_u32() % 2 == 1 {
                let removal_record = archival_mutator_set.drop(&item, &membership_proof);
                removal_records.push(removal_record);
            }
        }
        let cutoff_point = rng.next_u32() as usize % removal_records.len();
        let mut membership_proof_snapshot = None;

        // apply removal records
        for i in 0..removal_records.len() {
            let (immutable_records, mutable_records) = removal_records.split_at_mut(i + 1);
            let applied_removal_record = immutable_records.last().unwrap();

            RemovalRecord::batch_update_from_remove(
                &mut mutable_records.iter_mut().collect::<Vec<_>>(),
                applied_removal_record,
            )
            .expect("Could not apply removal record.");

            own_membership_proof
                .as_mut()
                .unwrap()
                .update_from_remove(applied_removal_record)
                .expect("Could not update membership proof from removal record");

            archival_mutator_set.remove(applied_removal_record);

            if i + 1 == cutoff_point {
                membership_proof_snapshot = Some(own_membership_proof.as_ref().unwrap().clone());
            }
        }

        println!("Removed {} items.", removal_records.len());

        // assert valid
        assert!(
            archival_mutator_set.verify(&own_item.unwrap(), own_membership_proof.as_ref().unwrap())
        );

        // revert some removal records
        let mut reversions = removal_records[cutoff_point..].to_vec();
        reversions.reverse();
        for revert_removal_record in reversions.iter() {
            own_membership_proof
                .as_mut()
                .unwrap()
                .revert_update_from_remove(revert_removal_record)
                .expect("Could not revert update from removal record.");

            archival_mutator_set.revert_remove(revert_removal_record);

            // keep other removal records up-to-date?
            // - nah, we don't need them for anything anymore
        }

        println!("Reverted {} removals.", reversions.len());

        // assert valid
        assert!(
            archival_mutator_set.verify(&own_item.unwrap(), own_membership_proof.as_ref().unwrap())
        );

        // assert same as snapshot before application-and-reversion
        assert_eq!(
            own_membership_proof.unwrap(),
            membership_proof_snapshot.unwrap()
        );
    }

    #[test]
    fn revert_update_from_addition_test() {
        type H = Tip5;
        let mut rng = thread_rng();
        let n = rng.next_u32() as usize % 100 + 1;
        // let n = 55;

        let own_index = rng.next_u32() as usize % n;
        // let own_index = 8;
        let mut own_membership_proof = None;
        let mut own_item = None;

        // set up mutator set
        let (mut archival_mutator_set, _): (ArchivalMutatorSet<H, _, _>, _) =
            empty_rustyleveldbvec_ams::<H>();

        // add items
        let mut addition_records = vec![];
        for i in 0..n {
            let item: Digest = random();
            let randomness: Digest = random();
            let addition_record = archival_mutator_set.commit(&item, &randomness);
            addition_records.push(addition_record.clone());

            let membership_proof = archival_mutator_set.prove(&item, &randomness, true);
            match i.cmp(&own_index) {
                std::cmp::Ordering::Less => {}
                std::cmp::Ordering::Equal => {
                    own_membership_proof = Some(membership_proof);
                    own_item = Some(item);
                }
                std::cmp::Ordering::Greater => {
                    assert!(archival_mutator_set.verify(
                        own_item.as_ref().unwrap(),
                        own_membership_proof.as_ref().unwrap()
                    ));
                    assert!(archival_mutator_set.accumulator().verify(
                        own_item.as_ref().unwrap(),
                        own_membership_proof.as_ref().unwrap()
                    ));
                    own_membership_proof
                        .as_mut()
                        .unwrap()
                        .update_from_addition(
                            own_item.as_ref().unwrap(),
                            &archival_mutator_set.accumulator(),
                            &addition_record,
                        )
                        .expect("Could not update membership proof from addition record.");
                }
            }

            let mutator_set_before = archival_mutator_set.accumulator();
            archival_mutator_set.add(&addition_record);

            if i > own_index {
                let own_item = own_item.as_ref().unwrap().to_owned();
                assert!(archival_mutator_set
                    .kernel
                    .verify(&own_item, own_membership_proof.as_ref().unwrap(),));

                let mut memproof = own_membership_proof.as_ref().unwrap().clone();

                assert!(archival_mutator_set.kernel.verify(&own_item, &memproof,));

                memproof
                    .revert_update_from_addition(&own_item, &mutator_set_before)
                    .expect("Could not revert update to own membership proof from addition.");

                assert!(mutator_set_before.verify(&own_item, &memproof));
                // assert!(previous_mutator_set.set_commitment.verify(own_item, self));
            }
        }
        println!("Added {n} items.");

        // revert additions
        let (_petrified, revertible) = addition_records.split_at(own_index + 1);
        for addition_record in revertible.iter().rev() {
            archival_mutator_set.revert_add(addition_record);
            own_membership_proof
                .as_mut()
                .unwrap()
                .revert_update_from_addition(
                    own_item.as_ref().unwrap(),
                    &archival_mutator_set.accumulator(),
                )
                .expect("Could not batch revert update from addition.");

            assert!(archival_mutator_set.verify(
                own_item.as_ref().unwrap(),
                own_membership_proof.as_ref().unwrap()
            ));
        }
    }

    #[test]
    fn revert_updates_mixed_test() {
        type H = Tip5;
        let n = 50;
        let margin = 10;
        let mut rng = thread_rng();

        let (mut mutator_set, _): (ArchivalMutatorSet<H, _, _>, _) =
            empty_rustyleveldbvec_ams::<H>();

        let own_index = rng.next_u32() as usize % 10;
        let mut own_item = Digest::default();
        let mut iamp_index = 0;

        let mut rates = HashMap::<String, f64>::new();
        rates.insert("additions".to_owned(), 0.7);
        rates.insert("removals".to_owned(), 0.3);
        rates.insert(
            "reversions".to_owned(),
            1.0 - rates.get("additions").unwrap() - rates.get("removals").unwrap(),
        );

        let mut items_and_membership_proofs: Vec<(Digest, MsMembershipProof<H>)> = vec![];
        let mut records: Vec<Either<AdditionRecord, RemovalRecord<H>>> = vec![];

        for i in 0..1000 {
            let sample: f64 = random();
            if sample <= rates["additions"] || i == own_index {
                println!("addition");

                // generate item and randomness
                let item: Digest = random();
                let randomness: Digest = random();

                // generate addition record
                let addition_record = mutator_set.commit(&item, &randomness);

                // record membership proof
                let membership_proof = mutator_set.prove(&item, &randomness, false);

                // update existing membership proof
                for (it, mp) in items_and_membership_proofs.iter_mut() {
                    mp.update_from_addition(it, &mutator_set.accumulator(), &addition_record)
                        .expect("Could not update membership proof from addition.");
                }

                // apply record
                mutator_set.add(&addition_record);

                // record record
                records.push(Either::Left(addition_record));

                // if own record, set iamp index and own item
                if i == own_index {
                    iamp_index = items_and_membership_proofs.len();
                    own_item = item;
                }

                // record item, membership proof paiur
                items_and_membership_proofs.push((item, membership_proof));

                // if too many items are in the mutator set, revise rates
                if items_and_membership_proofs.len() > n + margin && i > n {
                    *rates.get_mut("additions").unwrap() = 0.3;
                    *rates.get_mut("removals").unwrap() = 0.5;
                    *rates.get_mut("reversions").unwrap() =
                        1.0 - rates.get("additions").unwrap() - rates.get("removals").unwrap();
                }
            } else if sample > rates["additions"] && sample <= rates["removals"] {
                println!("removal");

                // sample index of item and membership proof to remove,
                // but not the index of the own item
                let mut index = iamp_index;
                while index == iamp_index {
                    index = rng.next_u32() as usize % items_and_membership_proofs.len()
                }

                // remove the indicated item and membership proof
                let (item, membership_proof) = items_and_membership_proofs.remove(index);
                if iamp_index > index {
                    iamp_index -= 1;
                }

                // generate a removal record
                let removal_record = mutator_set.drop(&item, &membership_proof);

                // update the other membership proofs with the removal record
                for (_, mp) in items_and_membership_proofs.iter_mut() {
                    mp.update_from_remove(&removal_record)
                        .expect("Could not update from remove.");
                }

                // remove the item from the membership proof
                mutator_set.remove(&removal_record);

                // record record
                records.push(Either::Right(removal_record));

                // if there are too few items in the mutator set, revise rates
                if items_and_membership_proofs.len() < n - margin && i > n {
                    *rates.get_mut("additions").unwrap() = 0.5;
                    *rates.get_mut("removals").unwrap() = 0.3;
                    *rates.get_mut("reversions").unwrap() =
                        1.0 - rates.get("additions").unwrap() - rates.get("removals").unwrap();
                }
            } else {
                println!("reversion");
                let max_reversions = items_and_membership_proofs.len() - iamp_index;
                if max_reversions > 0 {
                    let num_reversions = rng.next_u32() as usize % max_reversions;

                    for _ in 0..num_reversions {
                        items_and_membership_proofs.pop();
                        if let Some(record) = records.pop() {
                            match record {
                                Either::Left(addition_record) => {
                                    mutator_set.revert_add(&addition_record);
                                    for (i, mp) in items_and_membership_proofs.iter_mut() {
                                        mp.revert_update_from_addition(
                                            i,
                                            &mutator_set.accumulator(),
                                        )
                                        .expect("Could not revert add.");
                                    }
                                }
                                Either::Right(removal_record) => {
                                    mutator_set.revert_remove(&removal_record);
                                    for (_, mp) in items_and_membership_proofs.iter_mut() {
                                        mp.revert_update_from_remove(&removal_record)
                                            .expect("Could not revert remove.");
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if i > own_index {
                assert_eq!(own_item, items_and_membership_proofs[iamp_index].0);
                assert!(mutator_set.verify(&own_item, &items_and_membership_proofs[iamp_index].1));
            }
        }
    }
}
