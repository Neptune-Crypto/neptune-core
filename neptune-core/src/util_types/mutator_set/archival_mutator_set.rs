use std::collections::HashMap;
use std::error::Error;

use itertools::Itertools;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Tip5;
use tasm_lib::twenty_first::tip5::digest::Digest;
use tasm_lib::twenty_first::util_types::mmr;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;

use super::active_window::ActiveWindow;
use super::addition_record::AdditionRecord;
use super::ms_membership_proof::MsMembershipProof;
use super::mutator_set_accumulator::MutatorSetAccumulator;
use super::removal_record::chunk::Chunk;
use super::removal_record::chunk_dictionary::ChunkDictionary;
use super::removal_record::RemovalRecord;
use super::shared::BATCH_SIZE;
use super::shared::CHUNK_SIZE;
use crate::application::database::storage::storage_vec::traits::*;
use crate::protocol::consensus::block::block_height::BlockHeight;
use crate::util_types::archival_mmr::ArchivalMmr;
use crate::util_types::mutator_set::archival_mutator_set::mmr::mmr_membership_proof::MmrMembershipProof;
use crate::util_types::mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
use crate::util_types::mutator_set::MutatorSetError;

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
    pub(crate) aocl_auth_paths: Vec<IndexedAoclAuthPath>,
    target_chunks: ChunkDictionary,
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

/// Data structure for returning components of a mutator set membership proof in
/// a privacy preserving manner. Includes information about the tip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseMsMembershipProofPrivacyPreserving {
    pub tip_height: BlockHeight,
    pub tip_hash: Digest,
    pub tip_mutator_set: MutatorSetAccumulator,
    pub membership_proofs: Vec<MsMembershipProofPrivacyPreserving>,
}

#[derive(Debug, Clone)]
pub struct ArchivalMutatorSet<MmrStorage, ChunkStorage>
where
    MmrStorage: StorageVec<Digest> + Send + Sync,
    ChunkStorage: StorageVec<Chunk> + Send + Sync,
{
    pub aocl: ArchivalMmr<MmrStorage>,
    pub swbf_inactive: ArchivalMmr<MmrStorage>,
    pub swbf_active: ActiveWindow,
    pub chunks: ChunkStorage,
}

impl<MmrStorage, ChunkStorage> ArchivalMutatorSet<MmrStorage, ChunkStorage>
where
    MmrStorage: StorageVec<Digest> + Send + Sync,
    ChunkStorage: StorageVec<Chunk> + StorageVecStream<Chunk> + Send + Sync,
{
    pub async fn prove(
        &self,
        item: Digest,
        sender_randomness: Digest,
        receiver_preimage: Digest,
    ) -> MsMembershipProof {
        MutatorSetAccumulator::new(
            &self.aocl.peaks().await,
            self.aocl.num_leafs().await,
            &self.swbf_inactive.peaks().await,
            &self.swbf_active.clone(),
        )
        .prove(item, sender_randomness, receiver_preimage)
    }

    pub async fn verify(&self, item: Digest, membership_proof: &MsMembershipProof) -> bool {
        let accumulator = self.accumulator().await;
        accumulator.verify(item, membership_proof)
    }

    pub async fn drop(&self, item: Digest, membership_proof: &MsMembershipProof) -> RemovalRecord {
        let accumulator = self.accumulator().await;
        accumulator.drop(item, membership_proof)
    }

    pub async fn add(&mut self, addition_record: &AdditionRecord) {
        let new_chunk: Option<(u64, Chunk)> = self.add_helper(addition_record).await;
        match new_chunk {
            None => (),
            Some((chunk_index, chunk)) => {
                // Sanity check to verify that we agree on the index
                assert_eq!(
                    chunk_index,
                    self.chunks.len().await,
                    "Length/index must agree when inserting a chunk into an archival node"
                );
                self.chunks.push(chunk).await;
            }
        }
    }

    pub async fn remove(&mut self, removal_record: &RemovalRecord) {
        let new_chunks: HashMap<u64, Chunk> = self.remove_helper(removal_record).await;
        self.chunks.set_many(new_chunks).await;
    }

    pub async fn hash(&self) -> Digest {
        self.accumulator().await.hash()
    }

    /// Apply a list of removal records while keeping a list of mutator set
    /// membership proofs up-to-date.
    pub async fn batch_remove(&mut self, removal_records: Vec<RemovalRecord>) {
        let batch_index = self.get_batch_index_async().await;
        let active_window_start = batch_index * u128::from(CHUNK_SIZE);

        // Collect all indices that that are set by the removal records
        let all_removal_records_indices: Vec<u128> = removal_records
            .iter()
            .map(|x| x.absolute_indices.to_vec())
            .concat();

        // Loop over all indices from removal records in order to create a
        // mapping {chunk index => chunk mutation } where "chunk mutation" has
        // the type of `Chunk` but only represents the values which are set by
        // the removal records being handled.
        let mut chunkidx_to_chunk_difference_dict: HashMap<u64, Chunk> = HashMap::new();
        for index in all_removal_records_indices {
            if index >= active_window_start {
                let relative_index = (index - active_window_start) as u32;
                self.swbf_active.insert(relative_index);
            } else {
                chunkidx_to_chunk_difference_dict
                    .entry((index / u128::from(CHUNK_SIZE)) as u64)
                    .or_insert_with(Chunk::empty_chunk)
                    .insert((index % u128::from(CHUNK_SIZE)) as u32);
            }
        }

        // Collect all affected chunks as they look before these removal records
        // are applied. These chunks are part of the removal records, so we
        // fetch them there.
        let mut new_chunks: HashMap<u64, Chunk> = HashMap::new();
        for removal_record in removal_records {
            for (chunk_index, (_, chunk)) in removal_record.target_chunks.dictionary {
                debug_assert!(
                    new_chunks
                        .get(&chunk_index)
                        .is_none_or(|chk| Tip5::hash(chk) == Tip5::hash(&chunk)),
                    "Sanity check: All removal records must agree on chunks"
                );
                new_chunks.insert(chunk_index, chunk);
            }
        }

        // Apply the removal records: the new chunk is obtained by adding the
        // chunk difference
        for (chunk_index, chunk) in &mut new_chunks {
            let new_chunk = chunk
                .clone()
                .combine(chunkidx_to_chunk_difference_dict[chunk_index].clone());
            *chunk = new_chunk.clone();
            self.chunks.set(*chunk_index, new_chunk).await;
        }

        // the Bloom filter such that we can apply a batch-update operation to
        // the MMR through which this part of the Bloom filter is represented.
        let swbf_inactive_mutation_data: Vec<(u64, Digest)> = new_chunks
            .into_iter()
            .map(|(idx, chk)| (idx, Tip5::hash(&chk)))
            .collect();

        // Apply the batch-update to the inactive part of the sliding window Bloom filter.
        // This updates both the inactive part of the SWBF and the MMR membership proofs
        self.swbf_inactive
            .batch_mutate_leaf_and_update_mps(&mut [], swbf_inactive_mutation_data)
            .await;
    }

    /// Clear the mutator set: revert all operations so as to bring it into a
    /// brand new state.
    pub(crate) async fn clear(&mut self) {
        self.aocl.prune_to_num_leafs(0).await;
        self.swbf_inactive.prune_to_num_leafs(0).await;
        self.swbf_active.sbf.clear();
        self.chunks.clear().await;
    }
}

impl<MmrStorage, ChunkStorage> ArchivalMutatorSet<MmrStorage, ChunkStorage>
where
    MmrStorage: StorageVec<Digest> + Send + Sync,
    ChunkStorage: StorageVec<Chunk> + StorageVecStream<Chunk> + Send + Sync,
{
    pub async fn new_empty(
        aocl: MmrStorage,
        swbf_inactive: MmrStorage,
        chunks: ChunkStorage,
    ) -> Self {
        assert_eq!(0, aocl.len().await);
        assert_eq!(0, swbf_inactive.len().await);
        assert_eq!(0, chunks.len().await);
        let aocl: ArchivalMmr<MmrStorage> = ArchivalMmr::new(aocl).await;
        let swbf_inactive: ArchivalMmr<MmrStorage> = ArchivalMmr::new(swbf_inactive).await;
        Self {
            aocl,
            swbf_inactive,
            swbf_active: ActiveWindow::new(),
            chunks,
        }
    }

    /// Returns an authentication path for an element in the append-only commitment list
    pub async fn get_aocl_authentication_path(
        &self,
        index: u64,
    ) -> Result<mmr::mmr_membership_proof::MmrMembershipProof, Box<dyn Error>> {
        if self.aocl.num_leafs().await <= index {
            return Err(Box::new(MutatorSetError::RequestedAoclAuthPathOutOfBounds(
                (index, self.aocl.num_leafs().await),
            )));
        }

        Ok(self.aocl.prove_membership_async(index).await)
    }

    /// Returns an authentication path for a chunk in the sliding window Bloom filter
    pub async fn get_chunk_and_auth_path(
        &self,
        chunk_index: u64,
    ) -> Result<(mmr::mmr_membership_proof::MmrMembershipProof, Chunk), Box<dyn Error>> {
        if self.swbf_inactive.num_leafs().await <= chunk_index {
            return Err(Box::new(MutatorSetError::RequestedSwbfAuthPathOutOfBounds(
                (chunk_index, self.swbf_inactive.num_leafs().await),
            )));
        }

        let chunk_auth_path: mmr::mmr_membership_proof::MmrMembershipProof =
            self.swbf_inactive.prove_membership_async(chunk_index).await;

        // This check should never fail. It would mean that chunks are missing but that the
        // archival MMR has the membership proof for the chunk. That would be a programming
        // error.
        assert!(
            self.chunks.len().await > chunk_index,
            "Chunks must be known if its authentication path is known."
        );
        let chunk = self.chunks.get(chunk_index).await;

        Ok((chunk_auth_path, chunk))
    }

    /// Restore membership_proof. If called on someone else's UTXO, this leaks privacy. In this case,
    /// caller is better off using `get_aocl_authentication_path` and `get_chunk_and_auth_path` for the
    /// relevant indices.
    pub async fn restore_membership_proof(
        &self,
        item: Digest,
        sender_randomness: Digest,
        receiver_preimage: Digest,
        aocl_leaf_index: u64,
    ) -> Result<MsMembershipProof, Box<dyn Error>> {
        if self.aocl.is_empty().await {
            return Err(Box::new(MutatorSetError::MutatorSetIsEmpty));
        }

        let auth_path_aocl = self.get_aocl_authentication_path(aocl_leaf_index).await?;
        let swbf_indices =
            AbsoluteIndexSet::compute(item, sender_randomness, receiver_preimage, aocl_leaf_index);

        let batch_index = self.get_batch_index_async().await;
        let window_start = batch_index * u128::from(CHUNK_SIZE);

        let chunk_indices: Vec<u64> = swbf_indices
            .to_array()
            .iter()
            .filter(|bi| **bi < window_start)
            .map(|bi| (*bi / u128::from(CHUNK_SIZE)) as u64)
            .collect();
        let mut target_chunks: ChunkDictionary = ChunkDictionary::default();

        // This is maximum 45 chunks, so it's OK to get all at once. No need
        // to have a stream. Stream didn't work when this function was called
        // from RPC server, so we just collect all here.
        let chunks = self.chunks.get_many(&chunk_indices).await;

        for (chunk_index, chunk) in chunk_indices.into_iter().zip_eq(chunks) {
            assert!(
                self.chunks.len().await > chunk_index,
                "Chunks must be known if its authentication path is known."
            );
            let chunk_membership_proof: mmr::mmr_membership_proof::MmrMembershipProof =
                self.swbf_inactive.prove_membership_async(chunk_index).await;
            target_chunks.insert(chunk_index, (chunk_membership_proof, chunk.to_owned()));
        }

        Ok(MsMembershipProof {
            auth_path_aocl,
            sender_randomness: sender_randomness.to_owned(),
            receiver_preimage: receiver_preimage.to_owned(),
            target_chunks,
            aocl_leaf_index,
        })
    }

    /// Restore a mutator set membership proof in a privacy-preserving manner,
    /// only leaking a fuzzy-timestamp.
    pub(crate) async fn restore_membership_proof_privacy_preserving(
        &self,
        absolute_indices: AbsoluteIndexSet,
    ) -> Result<MsMembershipProofPrivacyPreserving, Box<dyn Error>> {
        let mut aocl_auth_paths = vec![];
        let num_aocl_leafs = self.aocl.num_leafs().await;
        let (aocl_index_min, aocl_index_max) = absolute_indices.aocl_range()?;

        if aocl_index_min >= num_aocl_leafs {
            return Err(Box::new(MutatorSetError::RequestedAoclAuthPathOutOfBounds(
                (aocl_index_min, num_aocl_leafs),
            )));
        }

        // Do not attempt to read past end of AOCL leafs. In other words:
        // restrict AOCL authentication paths to those actually present in
        // mutator set.
        let aocl_index_max = std::cmp::min(aocl_index_max, num_aocl_leafs.saturating_sub(1));
        for leaf_index in aocl_index_min..=aocl_index_max {
            let auth_path = self.get_aocl_authentication_path(leaf_index).await?;
            let auth_path = IndexedAoclAuthPath {
                leaf_index,
                auth_path,
            };
            aocl_auth_paths.push(auth_path);
        }

        let mut target_chunks = vec![];
        let batch_index: u64 = self.get_batch_index_async().await.try_into().unwrap();

        for absolute_bf_index in absolute_indices.to_array() {
            let chunk_index: u64 = (absolute_bf_index / u128::from(CHUNK_SIZE)).try_into()?;

            // No auth path exists if chunk is part of active window
            if chunk_index >= batch_index {
                continue;
            }

            // Avoid repeating chunk indices in dictionary.
            if target_chunks
                .iter()
                .any(|(chk_idx, _)| *chk_idx == chunk_index)
            {
                continue;
            }

            target_chunks.push((
                chunk_index,
                self.get_chunk_and_auth_path(chunk_index).await?,
            ));
        }

        Ok(MsMembershipProofPrivacyPreserving {
            aocl_auth_paths,
            target_chunks: ChunkDictionary::new(target_chunks),
        })
    }

    /// Revert the `RemovalRecord` by removing the indices that
    /// were inserted by it. These live in either the active window, or
    /// in a relevant chunk.
    ///
    /// # Panics
    ///
    /// - If the supplied removal record does not have all its index set, i.e.
    ///   if the supplied removal record was not already applied to the mutator
    ///   set.
    pub async fn revert_remove(&mut self, removal_record: &RemovalRecord) {
        let removal_record_indices: Vec<u128> = removal_record.absolute_indices.to_vec();
        let batch_index = self.get_batch_index_async().await;
        let active_window_start = batch_index * u128::from(CHUNK_SIZE);
        let mut chunkidx_to_difference_dict: HashMap<u64, Chunk> = HashMap::new();

        // Populate the dictionary by iterating over all the removal
        // record's indices and inserting them into the correct
        // chunk in the dictionary, if the index is in the inactive
        // part. Otherwise, remove the index from the active window.
        for rr_index in removal_record_indices {
            if rr_index >= active_window_start {
                let relative_index = (rr_index - active_window_start) as u32;
                self.swbf_active.remove(relative_index);
            } else {
                let chunkidx = (rr_index / u128::from(CHUNK_SIZE)) as u64;
                let relative_index = (rr_index % u128::from(CHUNK_SIZE)) as u32;
                chunkidx_to_difference_dict
                    .entry(chunkidx)
                    .or_insert_with(Chunk::empty_chunk)
                    .insert(relative_index);
            }
        }

        for (chunk_index, revert_chunk) in chunkidx_to_difference_dict {
            // For each chunk, subtract the difference from the chunk.
            let previous_chunk = self.chunks.get(chunk_index).await;
            let mut new_chunk = previous_chunk;
            new_chunk.subtract(revert_chunk.clone());

            // update archival mmr
            self.swbf_inactive
                .mutate_leaf(chunk_index, Tip5::hash(&new_chunk))
                .await;

            self.chunks.set(chunk_index, new_chunk).await;
        }
    }

    /// Determine whether the given `AdditionRecord` can be reversed.
    /// Equivalently, determine if it was added last.
    pub async fn add_is_reversible(&mut self, addition_record: &AdditionRecord) -> bool {
        let leaf_index = self.aocl.num_leafs().await - 1;
        let digest = self.aocl.get_leaf_async(leaf_index).await;
        addition_record.canonical_commitment == digest
    }

    /// Revert the `AdditionRecord`s in a block by
    ///
    /// - Removing the last leaf in the append-only commitment list
    /// - If at a boundary where the active window slides, remove a chunk
    ///   from the inactive window, and slide window back by putting the
    ///   last inactive chunk in the active window.
    pub async fn revert_add(&mut self, addition_record: &AdditionRecord) {
        let removed_add_index = self.aocl.num_leafs().await - 1;

        // 1. Remove last leaf from AOCL
        let digest = self.aocl.remove_last_leaf_async().await.unwrap();
        assert_eq!(addition_record.canonical_commitment, digest);

        // 2. Possibly shrink bloom filter by moving a chunk back into active window
        //
        // This happens when the batch index changes (i.e. every `BATCH_SIZE` addition).
        if !MutatorSetAccumulator::window_slides_back(removed_add_index) {
            return;
        }

        // 2.a. Remove a chunk from inactive window
        let _digest = self.swbf_inactive.remove_last_leaf_async().await;
        let last_inactive_chunk = self.chunks.pop().await.unwrap();

        // 2.b. Slide active window back by putting `last_inactive_chunk` back
        self.swbf_active.slide_window_back(&last_inactive_chunk);
    }

    /// Determine whether the index `index` is set in the Bloom
    /// filter, whether in the active window, or in some chunk.
    pub async fn bloom_filter_contains(&mut self, index: u128) -> bool {
        let batch_index = self.get_batch_index_async().await;
        let active_window_start = batch_index * u128::from(CHUNK_SIZE);

        if index >= active_window_start {
            let relative_index = (index - active_window_start) as u32;
            self.swbf_active.contains(relative_index)
        } else {
            let chunk_index = (index / u128::from(CHUNK_SIZE)) as u64;
            let relative_index = (index % u128::from(CHUNK_SIZE)) as u32;
            let relevant_chunk = self.chunks.get(chunk_index).await;
            relevant_chunk.contains(relative_index)
        }
    }

    pub async fn accumulator(&self) -> MutatorSetAccumulator {
        MutatorSetAccumulator {
            aocl: MmrAccumulator::init(self.aocl.peaks().await, self.aocl.num_leafs().await),
            swbf_inactive: MmrAccumulator::init(
                self.swbf_inactive.peaks().await,
                self.swbf_inactive.num_leafs().await,
            ),
            swbf_active: self.swbf_active.clone(),
        }
    }

    /// The number of times the active window has slid. Equal to the number of
    /// leafs in the inactive part of the sliding-window Bloom filter.
    pub async fn get_batch_index_async(&self) -> u128 {
        u128::from(self.aocl.num_leafs().await.saturating_sub(1)) / u128::from(BATCH_SIZE)
    }

    /// Helper function. Like `add` but also returns the chunk that
    /// was added to the inactive SWBF if the window slid (and None
    /// otherwise) since this is needed by the archival version of
    /// the mutator set.
    pub async fn add_helper(&mut self, addition_record: &AdditionRecord) -> Option<(u64, Chunk)> {
        // Notice that `add` cannot return a membership proof since `add` cannot know the
        // randomness that was used to create the commitment. This randomness can only be know
        // by the sender and/or receiver of the UTXO. And `add` must be run be all nodes keeping
        // track of the mutator set.

        // add to list
        let item_index = self.aocl.num_leafs().await;
        self.aocl
            .append(addition_record.canonical_commitment.to_owned())
            .await; // ignore auth path

        if !Self::window_slides(item_index) {
            return None;
        }

        // if window slides, update filter
        // First update the inactive part of the SWBF, the SWBF MMR
        let new_chunk: Chunk = self.swbf_active.slid_chunk();
        let chunk_digest: Digest = Tip5::hash(&new_chunk);
        let new_chunk_index = self.swbf_inactive.num_leafs().await;
        self.swbf_inactive.append(chunk_digest).await; // ignore auth path

        // Then move window to the right, equivalent to moving values
        // inside window to the left.
        self.swbf_active.slide_window();

        // Return the chunk that was added to the inactive part of the SWBF.
        // This chunk is needed by the Archival mutator set. The Regular
        // mutator set can ignore it.
        Some((new_chunk_index, new_chunk))
    }

    /// Determine if the window slides before absorbing an item,
    /// given the index of the to-be-added item.
    pub fn window_slides(added_index: u64) -> bool {
        added_index != 0 && added_index.is_multiple_of(u64::from(BATCH_SIZE))

        // example cases:
        //  - index == 0 we don't care about
        //  - index == 1 does not generate a slide
        //  - index == n * BATCH_SIZE generates a slide for any n
    }

    /// Remove a record and return the chunks that have been updated in this process,
    /// after applying the update. Does not mutate the removal record.
    pub async fn remove_helper(&mut self, removal_record: &RemovalRecord) -> HashMap<u64, Chunk> {
        let batch_index = self.get_batch_index_async().await;
        let active_window_start = batch_index * u128::from(CHUNK_SIZE);

        // insert all indices
        let mut new_target_chunks: ChunkDictionary = removal_record.target_chunks.clone();
        let chunkindices_to_indices_dict: HashMap<u64, Vec<u128>> =
            removal_record.get_chunkidx_to_indices_dict();

        for (chunk_index, indices) in chunkindices_to_indices_dict {
            if chunk_index >= batch_index as u64 {
                // index is in the active part, so insert it in the active part of the Bloom filter
                for index in indices {
                    let relative_index = (index - active_window_start) as u32;
                    self.swbf_active.insert(relative_index);
                }

                continue;
            }

            // If chunk index is not in the active part, insert the index into the relevant chunk
            let new_target_chunks_clone = new_target_chunks.clone();
            let count_leaves = self.aocl.num_leafs().await;
            let relevant_chunk = new_target_chunks
                .get_mut(&chunk_index)
                .unwrap_or_else(|| {
                    panic!(
                        "Can't get chunk index {chunk_index} from removal record dictionary! dictionary: {:?}\nAOCL size: {}\nbatch index: {}\nRemoval record: {:?}",
                        new_target_chunks_clone,
                        count_leaves,
                        batch_index,
                        removal_record
                    )
                });
            for index in indices {
                let relative_index = (index % u128::from(CHUNK_SIZE)) as u32;
                relevant_chunk.1.insert(relative_index);
            }
        }

        // update mmr
        // to do this, we need to keep track of all membership proofs
        // If we want to update the membership proof with this removal, we
        // could use the below function.
        self.swbf_inactive
            .batch_mutate_leaf_and_update_mps(&mut [], new_target_chunks.indices_and_leafs())
            .await;

        new_target_chunks.indices_and_chunks().into_iter().collect()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use itertools::Itertools;
    use macro_rules_attr::apply;
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::SeedableRng;

    use super::*;
    use crate::tests::shared_tokio_runtime;
    use crate::util_types::mutator_set::commit;
    use crate::util_types::mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
    use crate::util_types::mutator_set::shared::BATCH_SIZE;
    use crate::util_types::mutator_set::shared::NUM_TRIALS;
    use crate::util_types::test_shared::mutator_set::empty_rusty_mutator_set;
    use crate::util_types::test_shared::mutator_set::mock_item_and_randomnesses;

    #[apply(shared_tokio_runtime)]
    async fn archival_set_commitment_test() {
        let mut rms = empty_rusty_mutator_set().await;
        let archival_mutator_set = rms.ams_mut();
        let num_additions = 65;

        let mut membership_proofs: Vec<MsMembershipProof> = vec![];
        let mut items: Vec<Digest> = vec![];

        for i in 0..num_additions {
            let (item, sender_randomness, receiver_preimage) = mock_item_and_randomnesses();

            let addition_record = commit(item, sender_randomness, receiver_preimage.hash());
            let membership_proof = archival_mutator_set
                .prove(item, sender_randomness, receiver_preimage)
                .await;

            let res = MsMembershipProof::batch_update_from_addition(
                &mut membership_proofs.iter_mut().collect::<Vec<_>>(),
                &items,
                &archival_mutator_set.accumulator().await,
                &addition_record,
            );
            assert!(res.is_ok());

            archival_mutator_set.add(&addition_record).await;
            assert!(archival_mutator_set.verify(item, &membership_proof).await);

            // Verify that we can just read out the same membership proofs from the
            // archival MMR as those we get through the membership proof book keeping.
            let archival_membership_proof = archival_mutator_set
                .restore_membership_proof(item, sender_randomness, receiver_preimage, i)
                .await
                .unwrap();
            assert_eq!(
                archival_membership_proof, membership_proof,
                "Membership proof from archive and accumulator must agree"
            );

            let archival_membership_proof_alt = archival_mutator_set
                .restore_membership_proof_privacy_preserving(membership_proof.compute_indices(item))
                .await
                .unwrap()
                .extract_ms_membership_proof(i, sender_randomness, receiver_preimage)
                .unwrap();
            assert_eq!(archival_membership_proof, archival_membership_proof_alt);

            // For good measure (because I don't trust MP's equality operator sufficiently) I test that the target chunks also agree
            assert_eq!(
                archival_membership_proof.target_chunks,
                membership_proof.target_chunks
            );

            membership_proofs.push(membership_proof);
            items.push(item);
        }
    }

    #[apply(shared_tokio_runtime)]
    async fn archival_mutator_set_revert_add_test() {
        let mut rms = empty_rusty_mutator_set().await;
        let archival_mutator_set = rms.ams_mut();

        // Repeatedly insert `AdditionRecord` into empty MutatorSet and revert it
        //
        // This does not reach the sliding window, and the MutatorSet reverts back
        // to being empty on every iteration.
        for _ in 0..2 * BATCH_SIZE {
            let (item, addition_record, membership_proof) =
                prepare_random_addition(archival_mutator_set).await;

            let commitment_before_add = archival_mutator_set.hash().await;
            archival_mutator_set.add(&addition_record).await;
            assert!(archival_mutator_set.verify(item, &membership_proof).await);

            archival_mutator_set.revert_add(&addition_record).await;
            let commitment_after_revert = archival_mutator_set.hash().await;
            assert!(!archival_mutator_set.verify(item, &membership_proof).await);
            assert_eq!(commitment_before_add, commitment_after_revert);
        }

        let n_iterations = 10 * BATCH_SIZE as usize;
        let mut records = Vec::with_capacity(n_iterations);
        let mut commitments_before = Vec::with_capacity(n_iterations);

        // Insert a number of `AdditionRecord`s into MutatorSet and assert their membership.
        for _ in 0..n_iterations {
            let record = prepare_random_addition(archival_mutator_set).await;
            let (item, addition_record, membership_proof) = record.clone();
            records.push(record);
            commitments_before.push(archival_mutator_set.hash().await);
            archival_mutator_set.add(&addition_record).await;
            assert!(archival_mutator_set.verify(item, &membership_proof).await);
        }

        assert_eq!(n_iterations, records.len());

        // Revert these `AdditionRecord`s in reverse order and assert they're no longer members.
        //
        // This reaches the sliding window every `BATCH_SIZE` iteration.
        for (item, addition_record, membership_proof) in records.into_iter().rev() {
            archival_mutator_set.revert_add(&addition_record).await;
            let commitment_after_revert = archival_mutator_set.hash().await;
            assert!(!archival_mutator_set.verify(item, &membership_proof).await);

            let commitment_before_add = commitments_before.pop().unwrap();
            assert_eq!(
                commitment_before_add,
                commitment_after_revert,
                "Commitment to MutatorSet from before adding should be valid after reverting adding"
            );
        }
    }

    #[apply(shared_tokio_runtime)]
    async fn bloom_filter_is_reversible() {
        // With the `3086841408u32` seed a collision is generated at i = 1 and i = 38, on index 510714
        let seed_integer = 3086841408u32;
        let seed = seed_integer.to_be_bytes();
        let mut seed_as_bytes = [0u8; 32];
        for i in 0..32 {
            seed_as_bytes[i] = seed[i % 4];
        }

        let mut seeded_rng = StdRng::from_seed(seed_as_bytes);

        let mut rms = empty_rusty_mutator_set().await;
        let archival_mutator_set = rms.ams_mut();

        // Also keep track of a mutator set accumulator to verify that this uses an invertible Bloom filter
        let mut msa = MutatorSetAccumulator::default();

        let mut items = vec![];
        let mut mps = vec![];
        let mut saw_collision_at = None;
        let mut all_indices: HashMap<u128, usize> = HashMap::default();
        let added_items = 50;
        for current_item in 0..added_items {
            let (item, addition_record, membership_proof) =
                prepare_seeded_prng_addition(archival_mutator_set, &mut seeded_rng).await;

            // Update all MPs
            MsMembershipProof::batch_update_from_addition(
                &mut mps.iter_mut().collect_vec(),
                &items.iter().copied().collect_vec(),
                &archival_mutator_set.accumulator().await,
                &addition_record,
            )
            .unwrap();

            items.push(item);
            mps.push(membership_proof.clone());

            archival_mutator_set.add(&addition_record).await;
            msa.add(&addition_record);

            let indices = membership_proof.compute_indices(item).to_vec();

            for index in indices {
                let seen_before = all_indices.insert(index, current_item);
                if let Some(colliding_item) = seen_before {
                    saw_collision_at = Some(((colliding_item, current_item), index))
                }
            }
        }

        let Some(saw_collision_at) = saw_collision_at else {
            panic!("Collision must be generated with seeded RNG");
        };

        println!("collision: {saw_collision_at:?}");

        // Verify that the MPs with colliding indices are still valid
        {
            let ms = &msa;
            assert!(
                ms.verify(
                    items[saw_collision_at.0 .0],
                    &mps[saw_collision_at.0 .0].clone()
                ),
                "First colliding MS MP must be valid"
            );
            assert!(
                ms.verify(
                    items[saw_collision_at.0 .1],
                    &mps[saw_collision_at.0 .1].clone()
                ),
                "Second colliding MS MP must be valid"
            );
        }
        {
            let ms = &archival_mutator_set;
            assert!(
                ms.verify(
                    items[saw_collision_at.0 .0],
                    &mps[saw_collision_at.0 .0].clone()
                )
                .await,
                "First colliding MS MP must be valid"
            );
            assert!(
                ms.verify(
                    items[saw_collision_at.0 .1],
                    &mps[saw_collision_at.0 .1].clone()
                )
                .await,
                "Second colliding MS MP must be valid"
            );
        }

        // Remove 1st colliding element
        assert!(
            !archival_mutator_set
                .bloom_filter_contains(saw_collision_at.1)
                .await,
            "Bloom filter must be empty when no removal records have been applied"
        );
        let digest_before_removal = archival_mutator_set.hash().await;
        let rem0 = archival_mutator_set
            .drop(items[saw_collision_at.0 .0], &mps[saw_collision_at.0 .0])
            .await;
        archival_mutator_set.remove(&rem0).await;
        msa.remove(&rem0);
        assert!(
            archival_mutator_set
                .bloom_filter_contains(saw_collision_at.1)
                .await,
            "Bloom filter must have collision bit set after 1st removal"
        );

        // Update all MPs
        MsMembershipProof::batch_update_from_remove(&mut mps.iter_mut().collect_vec(), &rem0)
            .unwrap();
        {
            let ms = &msa;
            assert!(
                !ms.verify(
                    items[saw_collision_at.0 .0],
                    &mps[saw_collision_at.0 .0].clone()
                ),
                "First colliding MS MP must be invalid after removal"
            );
        }
        {
            let ms = &archival_mutator_set;
            assert!(
                !ms.verify(
                    items[saw_collision_at.0 .0],
                    &mps[saw_collision_at.0 .0].clone()
                )
                .await,
                "First colliding MS MP must be invalid after removal"
            );
        }

        // Remove 2nd colliding element
        let rem1 = archival_mutator_set
            .drop(items[saw_collision_at.0 .1], &mps[saw_collision_at.0 .1])
            .await;
        archival_mutator_set.remove(&rem1).await;
        msa.remove(&rem1);
        assert!(
            archival_mutator_set
                .bloom_filter_contains(saw_collision_at.1)
                .await,
            "Bloom filter must have collision bit set after 2nd removal"
        );

        // Update all MPs
        MsMembershipProof::batch_update_from_remove(&mut mps.iter_mut().collect_vec(), &rem1)
            .unwrap();
        {
            let ms = &msa;
            assert!(
                !ms.verify(
                    items[saw_collision_at.0 .1],
                    &mps[saw_collision_at.0 .1].clone()
                ),
                "Second colliding MS MP must be invalid after removal"
            );
        }
        {
            let ms = &archival_mutator_set;
            assert!(
                !ms.verify(
                    items[saw_collision_at.0 .1],
                    &mps[saw_collision_at.0 .1].clone()
                )
                .await,
                "Second colliding MS MP must be invalid after removal"
            );
        }

        // Verify that AMS and MSA agree now that we know we have an index in the Bloom filter
        // that was set twice
        assert_eq!(archival_mutator_set.hash().await, msa.hash(), "Archival MS and MS accumulator must agree also with collisions in the Bloom filter indices");

        // Reverse 1st removal
        archival_mutator_set.revert_remove(&rem0).await;
        assert!(
            archival_mutator_set
                .bloom_filter_contains(saw_collision_at.1)
                .await,
            "Bloom filter must have collision bit set after 1st removal revert"
        );

        // Update all MPs
        for (i, (mp, &itm)) in mps.iter_mut().zip_eq(items.iter()).enumerate() {
            mp.revert_update_from_remove(&rem0);
            assert!(
                i == saw_collision_at.0 .1 || archival_mutator_set.verify(itm, mp).await,
                "MS MP must be valid after reversing a removal update"
            );
        }

        // Reverse 2nd removal
        archival_mutator_set.revert_remove(&rem1).await;
        assert!(
            !archival_mutator_set
                .bloom_filter_contains(saw_collision_at.1)
                .await,
            "Bloom filter must not have collision bit set after 2nd removal revert"
        );

        // Update all MPs
        for (mp, &itm) in mps.iter_mut().zip_eq(items.iter()) {
            mp.revert_update_from_remove(&rem1);
            assert!(
                archival_mutator_set.verify(itm, mp).await,
                "MS MP must be valid after reversing a removal update"
            );
        }

        assert_eq!(digest_before_removal, archival_mutator_set.hash().await, "Digest of archival MS must agree before removals and after reversion of those removals");
        assert_eq!(
            added_items,
            mps.len(),
            "number of membership proofs must be as expected"
        );
    }

    #[should_panic(expected = "Decremented integer is already zero.")]
    #[apply(shared_tokio_runtime)]
    async fn revert_remove_from_active_bloom_filter_panic() {
        let mut rms = empty_rusty_mutator_set().await;
        let archival_mutator_set = rms.ams_mut();
        let record = prepare_random_addition(archival_mutator_set).await;
        let (item, addition_record, membership_proof) = record;
        archival_mutator_set.add(&addition_record).await;

        let removal_record = archival_mutator_set.drop(item, &membership_proof).await;

        // This next line should panic, as we're attempting to remove an index that is not present
        // in the active window
        archival_mutator_set.revert_remove(&removal_record).await;
    }

    #[should_panic(expected = "Attempted to remove index that was not present in chunk.")]
    #[apply(shared_tokio_runtime)]
    async fn revert_remove_invalid_panic() {
        let mut rms = empty_rusty_mutator_set().await;
        let archival_mutator_set = rms.ams_mut();

        for _ in 0..2 * BATCH_SIZE {
            let (_item, addition_record, _membership_proof) =
                prepare_random_addition(archival_mutator_set).await;
            archival_mutator_set.add(&addition_record).await;
        }

        let mut fake_indices = [2u128; NUM_TRIALS as usize];
        fake_indices[0] = 0;
        let fake_removal_record = RemovalRecord {
            absolute_indices: AbsoluteIndexSet::new(fake_indices),
            target_chunks: ChunkDictionary::default(),
        };

        // This next line should panic, as we're attempting to remove an index that is not present
        // in the inactive part of the Bloom filter
        archival_mutator_set
            .revert_remove(&fake_removal_record)
            .await;
    }

    #[apply(shared_tokio_runtime)]
    async fn archival_mutator_set_revert_remove_test() {
        let mut rms = empty_rusty_mutator_set().await;
        let archival_mutator_set = rms.ams_mut();
        let n_iterations = 11 * BATCH_SIZE as usize;
        let mut records = Vec::with_capacity(n_iterations);

        // Insert a number of `AdditionRecord`s into MutatorSet and assert their membership.
        for _ in 0..n_iterations {
            let record = prepare_random_addition(archival_mutator_set).await;
            let (item, addition_record, membership_proof) = record.clone();
            records.push(record);
            archival_mutator_set.add(&addition_record).await;
            assert!(archival_mutator_set.verify(item, &membership_proof).await);
        }

        for (idx, (item, _addition_record, expired_membership_proof)) in
            records.into_iter().rev().enumerate()
        {
            println!("revert_remove() #{}", idx);
            let restored_membership_proof = archival_mutator_set
                .restore_membership_proof(
                    item,
                    expired_membership_proof.sender_randomness,
                    expired_membership_proof.receiver_preimage,
                    expired_membership_proof.aocl_leaf_index,
                )
                .await
                .unwrap();
            assert!(
                archival_mutator_set
                    .verify(item, &restored_membership_proof)
                    .await
            );

            let removal_record = archival_mutator_set
                .drop(item, &restored_membership_proof)
                .await;
            let commitment_before_remove = archival_mutator_set.hash().await;
            archival_mutator_set.remove(&removal_record).await;
            assert!(
                !archival_mutator_set
                    .verify(item, &restored_membership_proof)
                    .await
            );

            archival_mutator_set.revert_remove(&removal_record).await;
            let commitment_after_revert = archival_mutator_set.hash().await;
            assert_eq!(commitment_before_remove, commitment_after_revert);
            assert!(
                archival_mutator_set
                    .verify(item, &restored_membership_proof)
                    .await
            );
        }
    }

    #[apply(shared_tokio_runtime)]
    async fn archival_set_batch_remove_simple_test() {
        let mut rms = empty_rusty_mutator_set().await;
        let archival_mutator_set = rms.ams_mut();

        let num_additions = 130;

        let mut membership_proofs: Vec<MsMembershipProof> = vec![];
        let mut items: Vec<Digest> = vec![];

        for _ in 0..num_additions {
            let (item, sender_randomness, receiver_preimage) = mock_item_and_randomnesses();

            let addition_record = commit(item, sender_randomness, receiver_preimage.hash());
            let membership_proof = archival_mutator_set
                .prove(item, sender_randomness, receiver_preimage)
                .await;

            MsMembershipProof::batch_update_from_addition(
                &mut membership_proofs.iter_mut().collect::<Vec<_>>(),
                &items,
                &archival_mutator_set.accumulator().await,
                &addition_record,
            )
            .expect("MS membership update must work");

            archival_mutator_set.add(&addition_record).await;

            membership_proofs.push(membership_proof);
            items.push(item);
        }

        let mut removal_records: Vec<RemovalRecord> = vec![];
        for (mp, &item) in membership_proofs.iter().zip_eq(items.iter()) {
            removal_records.push(archival_mutator_set.drop(item, mp).await);
        }

        for (mp, &item) in membership_proofs.iter().zip_eq(items.iter()) {
            assert!(archival_mutator_set.verify(item, mp).await);
        }
        archival_mutator_set.batch_remove(removal_records).await;
        for (mp, &item) in membership_proofs.iter().zip_eq(items.iter()) {
            assert!(!archival_mutator_set.verify(item, mp).await);
        }
    }

    #[apply(shared_tokio_runtime)]
    async fn archival_set_batch_remove_dynamic_test() {
        let num_additions = 45 * BATCH_SIZE;

        let mut ams_batch = empty_rusty_mutator_set().await;
        let ams_batch = ams_batch.ams_mut();
        let mut ams_separate = empty_rusty_mutator_set().await;
        let ams_separate = ams_separate.ams_mut();
        for remove_factor in [0.0, 0.05, 0.2, 0.6, 0.95, 1.0] {
            println!("remove_factor: {remove_factor}");
            let mut membership_proofs: Vec<MsMembershipProof> = vec![];
            let mut items: Vec<Digest> = vec![];
            for _ in 0..num_additions {
                let (item, sender_randomness, receiver_preimage) = mock_item_and_randomnesses();

                let addition_record = commit(item, sender_randomness, receiver_preimage.hash());
                let membership_proof = ams_batch
                    .prove(item, sender_randomness, receiver_preimage)
                    .await;

                MsMembershipProof::batch_update_from_addition(
                    &mut membership_proofs.iter_mut().collect::<Vec<_>>(),
                    &items,
                    &ams_batch.accumulator().await,
                    &addition_record,
                )
                .expect("MS membership update must work");

                ams_batch.add(&addition_record).await;
                ams_separate.add(&addition_record).await;

                membership_proofs.push(membership_proof);
                items.push(item);
            }

            assert_eq!(ams_separate.hash().await, ams_batch.hash().await);

            let mut rng = rand::rng();
            let mut skipped_removes: Vec<bool> = vec![];
            let mut removal_records: Vec<RemovalRecord> = vec![];
            for (mp, &item) in membership_proofs.iter().zip_eq(items.iter()) {
                let skipped = rng.random_range(0.0..1.0) < remove_factor;
                skipped_removes.push(skipped);
                if !skipped {
                    removal_records.push(ams_batch.drop(item, mp).await);
                }
            }

            for (mp, &item) in membership_proofs.iter().zip_eq(items.iter()) {
                assert!(ams_batch.verify(item, mp).await);
                assert!(ams_separate.verify(item, mp).await);
            }

            let commitment_prior_to_removal = ams_batch.hash().await;
            ams_batch.batch_remove(removal_records.clone()).await;

            let mut applied_rrs = removal_records.clone();
            while let Some(rr) = applied_rrs.pop() {
                RemovalRecord::batch_update_from_remove(
                    &mut applied_rrs.iter_mut().collect_vec(),
                    &rr,
                );
                MsMembershipProof::batch_update_from_remove(
                    &mut membership_proofs.iter_mut().collect_vec(),
                    &rr,
                )
                .unwrap();
                ams_separate.remove(&rr).await;
            }

            // Ensure both AMSs are in the same state.
            assert_eq!(ams_separate.hash().await, ams_batch.hash().await);

            for ((mp, &item), skipped) in membership_proofs
                .iter()
                .zip_eq(items.iter())
                .zip_eq(skipped_removes.into_iter())
            {
                // If this removal record was not applied, then the membership proof must verify
                if skipped {
                    assert!(
                        ams_separate.verify(item, mp).await,
                        "Item was not removed so msmp must be valid"
                    );
                    assert!(
                        ams_batch.verify(item, mp).await,
                        "Item was not removed so msmp must be valid"
                    );
                } else {
                    assert!(
                        !ams_separate.verify(item, mp).await,
                        "Item was removed so msmp must be invalid"
                    );
                    assert!(
                        !ams_batch.verify(item, mp).await,
                        "Item was removed so msmp must be invalid"
                    );
                }
            }

            // Verify that removal record indices were applied. If not, below function call will crash.
            for removal_record in &removal_records {
                ams_batch.revert_remove(removal_record).await;
                ams_separate.revert_remove(removal_record).await;
            }

            // Verify that mutator set before and after removal are the same
            assert_eq!(
                commitment_prior_to_removal,
                ams_batch.hash().await,
                "Mutator set \"batch\" must return to previous state when reverting removes."
            );
            assert_eq!(
                commitment_prior_to_removal,
                ams_separate.hash().await,
                "Mutator set \"separate\" must return to previous state when reverting removes."
            );
        }
    }

    async fn prepare_seeded_prng_addition<
        MmrStorage: StorageVec<Digest> + Send + Sync,
        ChunkStorage: StorageVec<Chunk> + Send + Sync,
    >(
        archival_mutator_set: &mut ArchivalMutatorSet<MmrStorage, ChunkStorage>,
        rng: &mut StdRng,
    ) -> (Digest, AdditionRecord, MsMembershipProof) {
        let item: Digest = rng.random();
        let sender_randomness: Digest = rng.random();
        let receiver_preimage: Digest = rng.random();
        let addition_record = commit(item, sender_randomness, receiver_preimage.hash());
        let membership_proof = archival_mutator_set
            .prove(item, sender_randomness, receiver_preimage)
            .await;

        (item, addition_record, membership_proof)
    }

    async fn prepare_random_addition<
        MmrStorage: StorageVec<Digest> + Send + Sync,
        ChunkStorage: StorageVec<Chunk> + Send + Sync,
    >(
        archival_mutator_set: &mut ArchivalMutatorSet<MmrStorage, ChunkStorage>,
    ) -> (Digest, AdditionRecord, MsMembershipProof) {
        let (item, sender_randomness, receiver_preimage) = mock_item_and_randomnesses();
        let addition_record = commit(item, sender_randomness, receiver_preimage.hash());
        let membership_proof = archival_mutator_set
            .prove(item, sender_randomness, receiver_preimage)
            .await;

        (item, addition_record, membership_proof)
    }
}
