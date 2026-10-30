use std::collections::HashMap;
use std::error::Error;

use itertools::Itertools;
use neptune_archival_mmr::ArchivalMmr;
use neptune_database::storage::storage_vec::traits::*;
use neptune_mutator_set::active_window::ActiveWindow;
use neptune_mutator_set::addition_record::AdditionRecord;
use neptune_mutator_set::ms_membership_proof::IndexedAoclAuthPath;
use neptune_mutator_set::ms_membership_proof::MsMembershipProof;
use neptune_mutator_set::ms_membership_proof::MsMembershipProofPrivacyPreserving;
use neptune_mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use neptune_mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
use neptune_mutator_set::removal_record::chunk::Chunk;
use neptune_mutator_set::removal_record::chunk_dictionary::ChunkDictionary;
use neptune_mutator_set::removal_record::RemovalRecord;
use neptune_mutator_set::shared::BATCH_SIZE;
use neptune_mutator_set::shared::CHUNK_SIZE;
use neptune_mutator_set::shared::WINDOW_SIZE;
use neptune_mutator_set::MutatorSetError;
use tasm_lib::prelude::Tip5;
use tasm_lib::twenty_first::tip5::digest::Digest;
use tasm_lib::twenty_first::util_types::mmr;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;

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

    pub async fn remove(
        &mut self,
        absolute_indices: AbsoluteIndexSet,
    ) -> Result<(), AbsoluteIndexSet> {
        self.batch_remove(&[absolute_indices]).await
    }

    /// Apply these index sets to the Bloom filter, as removal records with
    /// them would: the active window directly, the inactive chunks read,
    /// changed, hashed and written as one batch, with one batch mutation of
    /// the MMR over them.
    ///
    /// Nothing is applied if any index set is a double spend. In that case, the
    /// offending index set is returned.
    pub async fn batch_remove(
        &mut self,
        index_sets: &[AbsoluteIndexSet],
    ) -> Result<(), AbsoluteIndexSet> {
        match self.apply_index_sets(index_sets, true).await {
            Some(double_spend) => Err(double_spend),
            None => Ok(()),
        }
    }

    /// Undo [`Self::batch_remove`] of these index sets.
    ///
    /// # Panics
    ///
    /// If an index is not set, that is, if the index sets were not applied.
    pub async fn revert_batch_remove(&mut self, index_sets: &[AbsoluteIndexSet]) {
        self.apply_index_sets(index_sets, false).await;
    }

    /// Abstract, internal method for either applying or reverting the
    /// application of a collection of absolute index sets.
    ///
    /// When applying, checks for double spends. If one is found, the mutator
    /// set is left untouched, and the offending index set is returned.
    async fn apply_index_sets(
        &mut self,
        index_sets: &[AbsoluteIndexSet],
        insert: bool,
    ) -> Option<AbsoluteIndexSet> {
        let batch_index = self.get_batch_index_async().await;
        let active_window_start = batch_index * u128::from(CHUNK_SIZE);

        let mut active: Vec<u32> = vec![];
        let mut per_chunk: HashMap<u64, Vec<u32>> = HashMap::new();
        for index in index_sets.iter().flat_map(|index_set| index_set.iter()) {
            if index >= active_window_start {
                active.push(
                    u32::try_from(index - active_window_start)
                        .expect("Relative index for active window must be valid u32"),
                );
            } else {
                per_chunk
                    .entry((index / u128::from(CHUNK_SIZE)) as u64)
                    .or_default()
                    .push((index % u128::from(CHUNK_SIZE)) as u32);
            }
        }

        let (chunk_indices, relative_indices): (Vec<u64>, Vec<Vec<u32>>) =
            per_chunk.into_iter().unzip();
        let mut chunks = self.chunks.get_many(&chunk_indices).await;

        if insert {
            let chunk_position: HashMap<u64, usize> = chunk_indices
                .iter()
                .enumerate()
                .map(|(position, &chunk_index)| (chunk_index, position))
                .collect();
            let is_set = |index: u128| {
                if index >= active_window_start {
                    self.swbf_active
                        .contains((index - active_window_start) as u32)
                } else {
                    let position = chunk_position[&((index / u128::from(CHUNK_SIZE)) as u64)];
                    chunks[position].contains((index % u128::from(CHUNK_SIZE)) as u32)
                }
            };
            let mut multiplicity: HashMap<u128, u32> = HashMap::new();
            for index in index_sets.iter().flat_map(|index_set| index_set.iter()) {
                *multiplicity.entry(index).or_default() += 1;
            }

            let already_set = |index_set: &AbsoluteIndexSet| {
                let mut own: HashMap<u128, u32> = HashMap::new();
                for index in index_set.iter() {
                    *own.entry(index).or_default() += 1;
                }
                !own.into_iter()
                    // If just *one* index was not set, and touched only by this
                    // index set, then it's not a double spend.
                    .any(|(index, own_count)| multiplicity[&index] == own_count && !is_set(index))
            };
            if let Some(double_spend) = index_sets.iter().find(|index_set| already_set(index_set)) {
                return Some(*double_spend);
            }
        }

        if insert {
            self.swbf_active.insert_many(&active);
        } else {
            for relative_index in active {
                self.swbf_active.remove(relative_index);
            }
        }

        for (chunk, relative_indices) in chunks.iter_mut().zip(&relative_indices) {
            if insert {
                chunk.insert_many(relative_indices);
            } else {
                chunk.subtract(Chunk::from_slice(relative_indices));
            }
        }

        // Calculate the new leaf values
        let leafs = chunk_indices
            .iter()
            .zip(&chunks)
            .map(|(chunk_index, chunk)| (*chunk_index, Tip5::hash(chunk)))
            .collect_vec();
        self.swbf_inactive.batch_mutate_leaf(leafs).await;
        self.chunks
            .set_many(chunk_indices.into_iter().zip(chunks))
            .await;
        None
    }

    pub async fn hash(&self) -> Digest {
        self.accumulator().await.hash()
    }

    /// Clear the mutator set: revert all operations so as to bring it into a
    /// brand new state.
    pub async fn clear(&mut self) {
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

    /// Restore membership_proof. If called on someone else's UTXO, this leaks
    /// privacy. In this case, caller is better off using
    /// `restore_membership_proof_privacy_preserving`.
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
        let target_chunks = self.chunk_dictionary(swbf_indices).await;

        Ok(MsMembershipProof {
            auth_path_aocl,
            sender_randomness: sender_randomness.to_owned(),
            receiver_preimage: receiver_preimage.to_owned(),
            target_chunks,
            aocl_leaf_index,
        })
    }

    /// The chunks for the inactive SWBF that the indices belong to, along with
    /// the chunks authentication paths.
    pub async fn chunk_dictionary(&self, absolute_indices: AbsoluteIndexSet) -> ChunkDictionary {
        let window_start = self.get_batch_index_async().await * u128::from(CHUNK_SIZE);
        let chunk_indices = absolute_indices
            .iter()
            .filter(|index| *index < window_start)
            .map(|index| (index / u128::from(CHUNK_SIZE)) as u64)
            .sorted()
            .dedup()
            .collect_vec();
        let mut target_chunks = ChunkDictionary::default();

        // This is maximum 45 chunks, so it's OK to get all at once. No need
        // to have a stream. Stream didn't work when this function was called
        // from RPC server, so we just collect all here.
        let chunks = self.chunks.get_many(&chunk_indices).await;
        for (chunk_index, chunk) in chunk_indices.into_iter().zip_eq(chunks) {
            let chunk_membership_proof =
                self.swbf_inactive.prove_membership_async(chunk_index).await;
            target_chunks.insert(chunk_index, (chunk_membership_proof, chunk));
        }
        target_chunks
    }

    /// Restore a mutator set membership proof in a privacy-preserving manner,
    /// only leaking a fuzzy-timestamp.
    pub async fn restore_membership_proof_privacy_preserving(
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
            aocl_auth_paths.push(auth_path); // TODO: After tarpc gets deprecated, use indexed-kind like on json-rpc.
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

    pub async fn revert_remove(&mut self, absolute_indices: AbsoluteIndexSet) {
        self.revert_batch_remove(&[absolute_indices]).await;
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

    /// Return true if index is set in the Bloom filter. Uses only one database
    /// lookup as opposed to the naive implementation which would need two.
    ///
    /// Returns false if the index is a future index. So this function can never
    /// panic if the mutator set is well-formed.
    #[inline]
    async fn bloom_filter_contains_inner(&self, index: u128, active_window_start: u128) -> bool {
        if index >= active_window_start {
            // Ensure index is actually inside the active window. If not, it
            // is a future index. Index must be valid u32.
            let Ok(relative_index) = u32::try_from(index - active_window_start) else {
                return false;
            };
            if relative_index >= WINDOW_SIZE {
                return false;
            }

            self.swbf_active.contains(relative_index)
        } else {
            let chunk_index = (index / u128::from(CHUNK_SIZE)) as u64;
            let relative_index = (index % u128::from(CHUNK_SIZE)) as u32;
            if relative_index >= CHUNK_SIZE {
                return false;
            }

            let relevant_chunk = self.chunks.get(chunk_index).await;
            relevant_chunk.contains(relative_index)
        }
    }

    /// Returns true iff all indices in the absolute index set are set.
    ///
    /// Returns false if any index is a future index.
    #[inline]
    pub async fn absolute_index_set_was_applied(&self, absolute_indices: AbsoluteIndexSet) -> bool {
        let batch_index = self.get_batch_index_async().await;
        let active_window_start = batch_index * u128::from(CHUNK_SIZE);

        // Returns once the first not-set index is found. Should be optimal
        // from a performance perspective.
        for index in absolute_indices.iter() {
            if !self
                .bloom_filter_contains_inner(index, active_window_start)
                .await
            {
                return false;
            }
        }

        true
    }

    /// Determine whether the index `index` is set in the Bloom
    /// filter, whether in the active window, or in some chunk.
    pub async fn bloom_filter_contains(&self, index: u128) -> bool {
        let batch_index = self.get_batch_index_async().await;
        let active_window_start = batch_index * u128::from(CHUNK_SIZE);

        self.bloom_filter_contains_inner(index, active_window_start)
            .await
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
    #[inline]
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
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use itertools::Itertools;
    use macro_rules_attr::apply;
    use neptune_mutator_set::commit;
    use neptune_mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
    use neptune_mutator_set::shared::NUM_TRIALS;
    use neptune_mutator_set::test_shared::mock_item_and_randomnesses;
    use rand::rngs::StdRng;
    use rand::RngExt;
    use rand::SeedableRng;
    use tasm_lib::twenty_first::util_types::mmr::mmr_trait::Mmr;

    use super::*;
    use crate::test_shared::empty_rusty_mutator_set;
    use crate::test_utils::shared_tokio_runtime;

    #[apply(shared_tokio_runtime)]
    async fn index_set_checkers_cannot_panic() {
        let rms = empty_rusty_mutator_set().await;
        let archival_mutator_set = rms.ams();
        let future_absolute_index_set0 =
            AbsoluteIndexSet::new_raw(1 << 32, [0; NUM_TRIALS as usize]);
        assert!(
            !archival_mutator_set
                .absolute_index_set_was_applied(future_absolute_index_set0)
                .await
        );
        let future_absolute_index_set1 =
            AbsoluteIndexSet::new_raw(u128::from(WINDOW_SIZE), [0; NUM_TRIALS as usize]);
        assert!(
            !archival_mutator_set
                .absolute_index_set_was_applied(future_absolute_index_set1)
                .await
        );
        assert!(!archival_mutator_set.bloom_filter_contains(u128::MAX).await);
        assert!(
            !archival_mutator_set
                .bloom_filter_contains(u128::from(u64::MAX))
                .await
        );
        assert!(
            !archival_mutator_set
                .bloom_filter_contains(u128::from(u32::MAX))
                .await
        );
        assert!(
            !archival_mutator_set
                .bloom_filter_contains(u128::from(WINDOW_SIZE) + 1)
                .await
        );
        assert!(
            !archival_mutator_set
                .bloom_filter_contains(u128::from(WINDOW_SIZE))
                .await
        );
        assert!(
            !archival_mutator_set
                .bloom_filter_contains(u128::from(WINDOW_SIZE) - 1)
                .await
        );
        assert!(!archival_mutator_set.bloom_filter_contains(0u128).await);
    }

    #[apply(shared_tokio_runtime)]
    async fn far_future_index_is_not_in_active_window() {
        let mut rms = empty_rusty_mutator_set().await;
        let ams = rms.ams_mut();
        ams.swbf_active.insert(5);

        assert!(ams.bloom_filter_contains(5).await);
        assert!(!ams.bloom_filter_contains((1u128 << 32) + 5).await);
        assert!(!ams.bloom_filter_contains((1u128 << 64) + 5).await);
        assert!(!ams.bloom_filter_contains((1u128 << 96) + 5).await);
    }

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

        assert!(
            !archival_mutator_set
                .absolute_index_set_was_applied(rem0.absolute_indices)
                .await
        );
        archival_mutator_set
            .remove(rem0.absolute_indices)
            .await
            .unwrap();
        assert!(
            archival_mutator_set
                .absolute_index_set_was_applied(rem0.absolute_indices)
                .await
        );

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

        assert!(
            !archival_mutator_set
                .absolute_index_set_was_applied(rem1.absolute_indices)
                .await
        );
        archival_mutator_set
            .remove(rem1.absolute_indices)
            .await
            .unwrap();
        assert!(
            archival_mutator_set
                .absolute_index_set_was_applied(rem1.absolute_indices)
                .await
        );

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
        archival_mutator_set
            .revert_remove(rem0.absolute_indices)
            .await;
        assert!(
            !archival_mutator_set
                .absolute_index_set_was_applied(rem0.absolute_indices)
                .await
        );
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
        assert!(
            archival_mutator_set
                .absolute_index_set_was_applied(rem1.absolute_indices)
                .await
        );
        archival_mutator_set
            .revert_remove(rem1.absolute_indices)
            .await;
        assert!(
            !archival_mutator_set
                .absolute_index_set_was_applied(rem1.absolute_indices)
                .await
        );
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
        archival_mutator_set
            .revert_remove(removal_record.absolute_indices)
            .await;
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
            .revert_remove(fake_removal_record.absolute_indices)
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

            assert!(
                !archival_mutator_set
                    .absolute_index_set_was_applied(removal_record.absolute_indices)
                    .await
            );
            archival_mutator_set
                .remove(removal_record.absolute_indices)
                .await
                .unwrap();
            assert!(
                !archival_mutator_set
                    .verify(item, &restored_membership_proof)
                    .await
            );
            assert!(
                archival_mutator_set
                    .absolute_index_set_was_applied(removal_record.absolute_indices)
                    .await
            );

            archival_mutator_set
                .revert_remove(removal_record.absolute_indices)
                .await;
            assert!(
                !archival_mutator_set
                    .absolute_index_set_was_applied(removal_record.absolute_indices)
                    .await
            );
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
    async fn batch_remove_agrees_with_the_accumulator_and_reverts() {
        let mut rms = empty_rusty_mutator_set().await;
        let ams = rms.ams_mut();
        let mut membership_proofs: Vec<MsMembershipProof> = vec![];
        let mut items: Vec<Digest> = vec![];
        for _ in 0..45 * BATCH_SIZE {
            let (item, sender_randomness, receiver_preimage) = mock_item_and_randomnesses();
            let addition_record = commit(item, sender_randomness, receiver_preimage.hash());
            let membership_proof = ams.prove(item, sender_randomness, receiver_preimage).await;
            MsMembershipProof::batch_update_from_addition(
                &mut membership_proofs.iter_mut().collect::<Vec<_>>(),
                &items,
                &ams.accumulator().await,
                &addition_record,
            )
            .expect("MS membership update must work");
            ams.add(&addition_record).await;
            membership_proofs.push(membership_proof);
            items.push(item);
        }
        let mut removal_records = vec![];
        for (mp, &item) in membership_proofs.iter().zip_eq(&items) {
            removal_records.push(ams.drop(item, mp).await);
        }
        let index_sets = removal_records
            .iter()
            .map(|rr| rr.absolute_indices)
            .collect_vec();
        let before = ams.hash().await;
        let mut accumulator = ams.accumulator().await;
        accumulator.batch_remove(removal_records, &mut []);

        ams.batch_remove(&index_sets).await.unwrap();
        assert_eq!(accumulator.hash(), ams.hash().await);
        for (mp, &item) in membership_proofs.iter().zip_eq(&items) {
            assert!(!ams.verify(item, mp).await);
        }

        ams.revert_batch_remove(&index_sets).await;
        assert_eq!(before, ams.hash().await);
        for (mp, &item) in membership_proofs.iter().zip_eq(&items) {
            assert!(ams.verify(item, mp).await);
        }
    }

    #[apply(shared_tokio_runtime)]
    async fn batch_remove_rejects_a_double_spend() {
        let mut rms = empty_rusty_mutator_set().await;
        let ams = rms.ams_mut();
        let mut membership_proofs: Vec<MsMembershipProof> = vec![];
        let mut items: Vec<Digest> = vec![];
        for _ in 0..45 * BATCH_SIZE {
            let (item, sender_randomness, receiver_preimage) = mock_item_and_randomnesses();
            let addition_record = commit(item, sender_randomness, receiver_preimage.hash());
            let membership_proof = ams.prove(item, sender_randomness, receiver_preimage).await;
            MsMembershipProof::batch_update_from_addition(
                &mut membership_proofs.iter_mut().collect::<Vec<_>>(),
                &items,
                &ams.accumulator().await,
                &addition_record,
            )
            .expect("MS membership update must work");
            ams.add(&addition_record).await;
            membership_proofs.push(membership_proof);
            items.push(item);
        }
        // The first items' indices reach into the inactive chunks.
        let first = ams
            .drop(items[0], &membership_proofs[0])
            .await
            .absolute_indices;
        let second = ams
            .drop(items[1], &membership_proofs[1])
            .await
            .absolute_indices;
        ams.batch_remove(&[first]).await.unwrap();
        let after_first = ams.hash().await;

        assert_eq!(Err(first), ams.batch_remove(&[first]).await);
        assert_eq!(Err(first), ams.batch_remove(&[second, first]).await);
        assert_eq!(Err(second), ams.batch_remove(&[second, second]).await);
        assert_eq!(after_first, ams.hash().await, "nothing applied");

        ams.batch_remove(&[second]).await.unwrap();
        assert!(!ams.verify(items[1], &membership_proofs[1]).await);
    }

    #[apply(shared_tokio_runtime)]
    async fn swbfi_prefix_peaks_are_the_peaks_after_removals() {
        let mut rms = empty_rusty_mutator_set().await;
        let ams = rms.ams_mut();
        let mut membership_proofs: Vec<MsMembershipProof> = vec![];
        let mut items: Vec<Digest> = vec![];
        for _ in 0..45 * BATCH_SIZE {
            let (item, sender_randomness, receiver_preimage) = mock_item_and_randomnesses();
            let addition_record = commit(item, sender_randomness, receiver_preimage.hash());
            let membership_proof = ams.prove(item, sender_randomness, receiver_preimage).await;
            MsMembershipProof::batch_update_from_addition(
                &mut membership_proofs.iter_mut().collect::<Vec<_>>(),
                &items,
                &ams.accumulator().await,
                &addition_record,
            )
            .expect("MS membership update must work");
            ams.add(&addition_record).await;
            membership_proofs.push(membership_proof);
            items.push(item);
        }
        let mut removal_records = vec![];
        for (mp, &item) in membership_proofs.iter().zip_eq(&items).step_by(7) {
            removal_records.push(ams.drop(item, mp).await);
        }
        let index_sets = removal_records
            .iter()
            .map(|rr| rr.absolute_indices)
            .collect_vec();
        let before = ams.accumulator().await;
        let mut after_removals = before.clone();
        after_removals.batch_remove(removal_records, &mut []);

        ams.batch_remove(&index_sets).await.unwrap();
        for _ in 0..3 * BATCH_SIZE {
            let (item, sender_randomness, receiver_preimage) = mock_item_and_randomnesses();
            ams.add(&commit(item, sender_randomness, receiver_preimage.hash()))
                .await;
        }

        let peaks_after_removals = after_removals.swbf_inactive.peaks();
        assert_ne!(before.swbf_inactive.peaks(), peaks_after_removals);
        assert_ne!(ams.swbf_inactive.peaks().await, peaks_after_removals);
        assert_eq!(
            peaks_after_removals,
            ams.swbf_inactive
                .peaks_at(before.swbf_inactive.num_leafs())
                .await
        );
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
        let index_sets = removal_records
            .iter()
            .map(|rr| rr.absolute_indices)
            .collect_vec();
        archival_mutator_set
            .batch_remove(&index_sets)
            .await
            .unwrap();
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
            let index_sets = removal_records
                .iter()
                .map(|rr| rr.absolute_indices)
                .collect_vec();
            ams_batch.batch_remove(&index_sets).await.unwrap();

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
                ams_separate.remove(rr.absolute_indices).await.unwrap();
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
                ams_batch
                    .revert_remove(removal_record.absolute_indices)
                    .await;
                ams_separate
                    .revert_remove(removal_record.absolute_indices)
                    .await;
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
