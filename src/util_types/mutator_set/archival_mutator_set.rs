use crate::database::storage::storage_vec::traits::*;
use crate::models::blockchain::shared::Hash;
use crate::prelude::twenty_first;

use std::collections::{BTreeSet, HashMap};
use std::error::Error;

use twenty_first::shared_math::tip5::Digest;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;
use twenty_first::util_types::mmr;
use twenty_first::util_types::mmr::mmr_membership_proof::MmrMembershipProof;

use crate::util_types::mmr::traits::*;
use crate::util_types::mmr::ArchivalMmr;
use crate::util_types::mmr::MmrAccumulator;

use super::active_window::ActiveWindow;
use super::addition_record::AdditionRecord;
use super::chunk::Chunk;
use super::chunk_dictionary::ChunkDictionary;
use super::ms_membership_proof::MsMembershipProof;
use super::mutator_set_accumulator::MutatorSetAccumulator;
use super::mutator_set_kernel::{get_swbf_indices, MutatorSetKernel, MutatorSetKernelError};
use super::mutator_set_trait::*;
use super::removal_record::RemovalRecord;
use super::shared::CHUNK_SIZE;

pub struct ArchivalMutatorSet<MmrStorage, ChunkStorage>
where
    MmrStorage: StorageVec<Digest> + Send + Sync,
    ChunkStorage: StorageVec<Chunk> + Send + Sync,
{
    pub kernel: MutatorSetKernel<ArchivalMmr<Hash, MmrStorage>>,
    pub chunks: ChunkStorage,
}

#[async_trait::async_trait]
impl<MmrStorage, ChunkStorage> MutatorSetAsync for ArchivalMutatorSet<MmrStorage, ChunkStorage>
where
    MmrStorage: StorageVec<Digest> + Send + Sync,
    ChunkStorage: StorageVec<Chunk> + StorageVecStream<Chunk> + Send + Sync,
{
    async fn prove(
        &mut self,
        item: Digest,
        sender_randomness: Digest,
        receiver_preimage: Digest,
    ) -> MsMembershipProof {
        self.kernel
            .prove(item, sender_randomness, receiver_preimage)
            .await
    }

    async fn verify(&self, item: Digest, membership_proof: &MsMembershipProof) -> bool {
        self.kernel.verify(item, membership_proof).await
    }

    fn drop(&self, item: Digest, membership_proof: &MsMembershipProof) -> RemovalRecord {
        self.kernel.drop(item, membership_proof)
    }

    async fn add(&mut self, addition_record: &AdditionRecord) {
        let new_chunk: Option<(u64, Chunk)> = self.kernel.add_helper(addition_record).await;
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

    async fn remove(&mut self, removal_record: &RemovalRecord) {
        let new_chunks: HashMap<u64, Chunk> = self.kernel.remove_helper(removal_record).await;
        self.chunks.set_many(new_chunks).await;
    }

    async fn hash(&self) -> Digest {
        self.accumulator().await.hash().await
    }

    /// Apply a list of removal records while keeping a list of mutator-set membership proofs
    /// updated
    async fn batch_remove(
        &mut self,
        removal_records: Vec<RemovalRecord>,
        preserved_membership_proofs: &mut [&mut MsMembershipProof],
    ) {
        let chunk_index_to_chunk_mutation = self
            .kernel
            .batch_remove(removal_records, preserved_membership_proofs)
            .await;

        self.chunks.set_many(chunk_index_to_chunk_mutation).await
    }
}

/// Methods that only work when implementing using archival MMRs as the underlying two MMRs
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
        let aocl: ArchivalMmr<Hash, MmrStorage> = ArchivalMmr::new(aocl).await;
        let swbf_inactive: ArchivalMmr<Hash, MmrStorage> = ArchivalMmr::new(swbf_inactive).await;
        Self {
            kernel: MutatorSetKernel {
                aocl,
                swbf_inactive,
                swbf_active: ActiveWindow::new(),
            },
            chunks,
        }
    }

    /// Returns an authentication path for an element in the append-only commitment list
    pub async fn get_aocl_authentication_path(
        &self,
        index: u64,
    ) -> Result<MmrMembershipProof<Hash>, Box<dyn Error>> {
        if self.kernel.aocl.count_leaves().await <= index {
            return Err(Box::new(
                MutatorSetKernelError::RequestedAoclAuthPathOutOfBounds((
                    index,
                    self.kernel.aocl.count_leaves().await,
                )),
            ));
        }

        Ok(self.kernel.aocl.prove_membership(index).await.0)
    }

    /// Returns an authentication path for a chunk in the sliding window Bloom filter
    pub async fn get_chunk_and_auth_path(
        &self,
        chunk_index: u64,
    ) -> Result<(mmr::mmr_membership_proof::MmrMembershipProof<Hash>, Chunk), Box<dyn Error>> {
        if self.kernel.swbf_inactive.count_leaves().await <= chunk_index {
            return Err(Box::new(
                MutatorSetKernelError::RequestedSwbfAuthPathOutOfBounds((
                    chunk_index,
                    self.kernel.swbf_inactive.count_leaves().await,
                )),
            ));
        }

        let chunk_auth_path: MmrMembershipProof<Hash> = self
            .kernel
            .swbf_inactive
            .prove_membership(chunk_index)
            .await
            .0;

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
        aocl_index: u64,
    ) -> Result<MsMembershipProof, Box<dyn Error>> {
        if self.kernel.aocl.is_empty().await {
            return Err(Box::new(MutatorSetKernelError::MutatorSetIsEmpty));
        }

        let auth_path_aocl = self.get_aocl_authentication_path(aocl_index).await?;
        let swbf_indices = get_swbf_indices(item, sender_randomness, receiver_preimage, aocl_index);

        let batch_index = self.kernel.get_batch_index().await;
        let window_start = batch_index as u128 * CHUNK_SIZE as u128;

        let chunk_indices: BTreeSet<u64> = swbf_indices
            .iter()
            .filter(|bi| **bi < window_start)
            .map(|bi| (*bi / CHUNK_SIZE as u128) as u64)
            .collect();
        let mut target_chunks: ChunkDictionary = ChunkDictionary::default();

        let stream = self.chunks.stream_many(chunk_indices).await;
        pin_mut!(stream); // needed for iteration

        while let Some((chunk_index, chunk)) = stream.next().await {
            assert!(
                self.chunks.len().await > chunk_index,
                "Chunks must be known if its authentication path is known."
            );
            let chunk_membership_proof: mmr::mmr_membership_proof::MmrMembershipProof<Hash> = self
                .kernel
                .swbf_inactive
                .prove_membership(chunk_index)
                .await
                .0;
            target_chunks
                .dictionary
                .insert(chunk_index, (chunk_membership_proof, chunk.to_owned()));
        }

        Ok(MsMembershipProof {
            auth_path_aocl,
            sender_randomness: sender_randomness.to_owned(),
            receiver_preimage: receiver_preimage.to_owned(),
            target_chunks,
        })
    }

    /// Revert the `RemovalRecord` by removing the indices that
    /// were inserted by it. These live in either the active window, or
    /// in a relevant chunk.
    pub async fn revert_remove(&mut self, removal_record: &RemovalRecord) {
        let removal_record_indices: Vec<u128> = removal_record.absolute_indices.to_vec();
        let batch_index = self.kernel.get_batch_index().await;
        let active_window_start = batch_index as u128 * CHUNK_SIZE as u128;
        let mut chunkidx_to_difference_dict: HashMap<u64, Chunk> = HashMap::new();

        // Populate the dictionary by iterating over all the removal
        // record's indices and inserting them into the correct
        // chunk in the dictionary, if the index is in the inactive
        // part. Otherwise, remove the index from the active window.
        for rr_index in removal_record_indices {
            if rr_index >= active_window_start {
                let relative_index = (rr_index - active_window_start) as u32;
                self.kernel.swbf_active.remove(relative_index);
            } else {
                let chunkidx = (rr_index / CHUNK_SIZE as u128) as u64;
                let relative_index = (rr_index % CHUNK_SIZE as u128) as u32;
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
            self.kernel
                .swbf_inactive
                .mutate_leaf_raw(chunk_index, Hash::hash(&new_chunk))
                .await;

            self.chunks.set(chunk_index, new_chunk).await;
        }
    }

    /// Determine whether the given `AdditionRecord` can be reversed.
    /// Equivalently, determine if it was added last.
    pub async fn add_is_reversible(&mut self, addition_record: &AdditionRecord) -> bool {
        let leaf_index = self.kernel.aocl.count_leaves().await - 1;
        let digest = self.kernel.aocl.get_leaf(leaf_index).await;
        addition_record.canonical_commitment == digest
    }

    /// Revert the `AdditionRecord`s in a block by
    ///
    /// - Removing the last leaf in the append-only commitment list
    /// - If at a boundary where the active window slides, remove a chunk
    ///   from the inactive window, and slide window back by putting the
    ///   last inactive chunk in the active window.
    pub async fn revert_add(&mut self, addition_record: &AdditionRecord) {
        let removed_add_index = self.kernel.aocl.count_leaves().await - 1;

        // 1. Remove last leaf from AOCL
        let digest = self.kernel.aocl.remove_last_leaf().await.unwrap();
        assert_eq!(addition_record.canonical_commitment, digest);

        // 2. Possibly shrink bloom filter by moving a chunk back into active window
        //
        // This happens when the batch index changes (i.e. every `BATCH_SIZE` addition).
        if !MutatorSetKernel::<ArchivalMmr<Hash, MmrStorage>>::window_slides_back(removed_add_index)
        {
            return;
        }

        // 2.a. Remove a chunk from inactive window
        let _digest = self.kernel.swbf_inactive.remove_last_leaf().await;
        let last_inactive_chunk = self.chunks.pop().await.unwrap();

        // 2.b. Slide active window back by putting `last_inactive_chunk` back
        self.kernel
            .swbf_active
            .slide_window_back(&last_inactive_chunk);
    }

    /// Determine whether the index `index` is set in the Bloom
    /// filter, whether in the active window, or in some chunk.
    pub async fn bloom_filter_contains(&mut self, index: u128) -> bool {
        let batch_index = self.kernel.get_batch_index().await;
        let active_window_start = batch_index as u128 * CHUNK_SIZE as u128;

        if index >= active_window_start {
            let relative_index = (index - active_window_start) as u32;
            self.kernel.swbf_active.contains(relative_index)
        } else {
            let chunk_index = (index / CHUNK_SIZE as u128) as u64;
            let relative_index = (index % CHUNK_SIZE as u128) as u32;
            let relevant_chunk = self.chunks.get(chunk_index).await;
            relevant_chunk.contains(relative_index)
        }
    }

    pub async fn accumulator(&self) -> MutatorSetAccumulator {
        let set_commitment = MutatorSetKernel::<MmrAccumulator<Hash>> {
            aocl: MmrAccumulator::init(
                self.kernel.aocl.get_peaks().await,
                self.kernel.aocl.count_leaves().await,
            ),
            swbf_inactive: MmrAccumulator::init(
                self.kernel.swbf_inactive.get_peaks().await,
                self.kernel.swbf_inactive.count_leaves().await,
            ),
            swbf_active: self.kernel.swbf_active.clone(),
        };
        MutatorSetAccumulator {
            kernel: set_commitment,
        }
    }
}

#[cfg(test)]
mod archival_mutator_set_tests {
    use itertools::Itertools;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    use crate::util_types::mutator_set::mutator_set_trait::commit;
    use crate::util_types::mutator_set::removal_record::AbsoluteIndexSet;
    use crate::util_types::mutator_set::shared::{BATCH_SIZE, NUM_TRIALS};
    use crate::util_types::test_shared::mutator_set::{
        empty_rusty_mutator_set, make_item_and_randomnesses,
    };

    use super::*;

    #[tokio::test]
    async fn archival_set_commitment_test() {
        let mut rms = empty_rusty_mutator_set().await;
        let archival_mutator_set = rms.ams_mut();
        let num_additions = 65;

        let mut membership_proofs: Vec<MsMembershipProof> = vec![];
        let mut items: Vec<Digest> = vec![];

        for i in 0..num_additions {
            let (item, sender_randomness, receiver_preimage) = make_item_and_randomnesses();

            let addition_record = commit(item, sender_randomness, receiver_preimage.hash::<Hash>());
            let membership_proof = archival_mutator_set
                .prove(item, sender_randomness, receiver_preimage)
                .await;

            let res = MsMembershipProof::batch_update_from_addition(
                &mut membership_proofs.iter_mut().collect::<Vec<_>>(),
                &items,
                &archival_mutator_set.kernel,
                &addition_record,
            )
            .await;
            assert!(res.is_ok());

            archival_mutator_set.add(&addition_record).await;
            assert!(archival_mutator_set.verify(item, &membership_proof).await);

            // Verify that we can just read out the same membership proofs from the
            // archival MMR as those we get through the membership proof book keeping.
            let archival_membership_proof = match archival_mutator_set
                .restore_membership_proof(item, sender_randomness, receiver_preimage, i)
                .await
            {
                Err(err) => panic!(
                    "Failed to get membership proof from archival mutator set: {}",
                    err
                ),
                Ok(mp) => mp,
            };
            assert_eq!(
                archival_membership_proof, membership_proof,
                "Membership proof from archive and accumulator must agree"
            );

            // For good measure (because I don't trust MP's equality operator sufficiently) I test that the target chunks also agree
            assert_eq!(
                archival_membership_proof.target_chunks,
                membership_proof.target_chunks
            );

            membership_proofs.push(membership_proof);
            items.push(item);
        }
    }

    #[tokio::test]
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

    #[tokio::test]
    async fn bloom_filter_is_reversible() {
        // With the `3086841408u32` seed a collission is generated at i = 1 and i = 38, on index 510714
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
        let mut saw_collission_at = None;
        let mut all_indices: HashMap<u128, usize> = HashMap::default();
        let added_items = 50;
        for current_item in 0..added_items {
            let (item, addition_record, membership_proof) =
                prepare_seeded_prng_addition(archival_mutator_set, &mut seeded_rng).await;

            // Update all MPs
            MsMembershipProof::batch_update_from_addition(
                &mut mps.iter_mut().collect_vec(),
                &items.iter().cloned().collect_vec(),
                &archival_mutator_set.accumulator().await.kernel,
                &addition_record,
            )
            .await
            .unwrap();

            items.push(item);
            mps.push(membership_proof.clone());

            archival_mutator_set.add(&addition_record).await;
            msa.add(&addition_record).await;

            let indices = membership_proof.compute_indices(item).to_vec();

            for index in indices {
                let seen_before = all_indices.insert(index, current_item);
                if let Some(colliding_item) = seen_before {
                    saw_collission_at = Some(((colliding_item, current_item), index))
                }
            }
        }

        let saw_collission_at = if let Some(collission) = saw_collission_at {
            collission
        } else {
            panic!("Collission must be generated with seeded RNG");
        };

        println!("collission: {saw_collission_at:?}");

        // Verify that the MPs with colliding indices are still valid
        {
            let ms = &msa;
            assert!(
                ms.verify(
                    items[saw_collission_at.0 .0],
                    &mps[saw_collission_at.0 .0].clone()
                )
                .await,
                "First colliding MS MP must be valid"
            );
            assert!(
                ms.verify(
                    items[saw_collission_at.0 .1],
                    &mps[saw_collission_at.0 .1].clone()
                )
                .await,
                "Second colliding MS MP must be valid"
            );
        }
        {
            let ms = &archival_mutator_set;
            assert!(
                ms.verify(
                    items[saw_collission_at.0 .0],
                    &mps[saw_collission_at.0 .0].clone()
                )
                .await,
                "First colliding MS MP must be valid"
            );
            assert!(
                ms.verify(
                    items[saw_collission_at.0 .1],
                    &mps[saw_collission_at.0 .1].clone()
                )
                .await,
                "Second colliding MS MP must be valid"
            );
        }

        // Remove 1st colliding element
        assert!(
            !archival_mutator_set
                .bloom_filter_contains(saw_collission_at.1)
                .await,
            "Bloom filter must be empty when no removal records have been applied"
        );
        let digest_before_removal = archival_mutator_set.hash().await;
        let rem0 =
            archival_mutator_set.drop(items[saw_collission_at.0 .0], &mps[saw_collission_at.0 .0]);
        archival_mutator_set.remove(&rem0).await;
        msa.remove(&rem0).await;
        assert!(
            archival_mutator_set
                .bloom_filter_contains(saw_collission_at.1)
                .await,
            "Bloom filter must have collission bit set after 1st removal"
        );

        // Update all MPs
        MsMembershipProof::batch_update_from_remove(&mut mps.iter_mut().collect_vec(), &rem0)
            .unwrap();
        {
            let ms = &msa;
            assert!(
                !ms.verify(
                    items[saw_collission_at.0 .0],
                    &mps[saw_collission_at.0 .0].clone()
                )
                .await,
                "First colliding MS MP must be invalid after removal"
            );
        }
        {
            let ms = &archival_mutator_set;
            assert!(
                !ms.verify(
                    items[saw_collission_at.0 .0],
                    &mps[saw_collission_at.0 .0].clone()
                )
                .await,
                "First colliding MS MP must be invalid after removal"
            );
        }

        // Remove 2nd colliding element
        let rem1 =
            archival_mutator_set.drop(items[saw_collission_at.0 .1], &mps[saw_collission_at.0 .1]);
        archival_mutator_set.remove(&rem1).await;
        msa.remove(&rem1).await;
        assert!(
            archival_mutator_set
                .bloom_filter_contains(saw_collission_at.1)
                .await,
            "Bloom filter must have collission bit set after 2nd removal"
        );

        // Update all MPs
        MsMembershipProof::batch_update_from_remove(&mut mps.iter_mut().collect_vec(), &rem1)
            .unwrap();
        {
            let ms = &msa;
            assert!(
                !ms.verify(
                    items[saw_collission_at.0 .1],
                    &mps[saw_collission_at.0 .1].clone()
                )
                .await,
                "Second colliding MS MP must be invalid after removal"
            );
        }
        {
            let ms = &archival_mutator_set;
            assert!(
                !ms.verify(
                    items[saw_collission_at.0 .1],
                    &mps[saw_collission_at.0 .1].clone()
                )
                .await,
                "Second colliding MS MP must be invalid after removal"
            );
        }

        // Verify that AMS and MSA agree now that we know we have an index in the Bloom filter
        // that was set twice
        assert_eq!(archival_mutator_set.hash().await, msa.hash().await, "Archival MS and MS accumulator must agree also with collissions in the Bloom filter indices");

        // Reverse 1st removal
        archival_mutator_set.revert_remove(&rem0).await;
        assert!(
            archival_mutator_set
                .bloom_filter_contains(saw_collission_at.1)
                .await,
            "Bloom filter must have collission bit set after 1st removal revert"
        );

        // Update all MPs
        for (i, (mp, &itm)) in mps.iter_mut().zip_eq(items.iter()).enumerate() {
            mp.revert_update_from_remove(&rem0).unwrap();
            assert!(
                i == saw_collission_at.0 .1 || archival_mutator_set.verify(itm, mp).await,
                "MS MP must be valid after reversing a removal update"
            );
        }

        // Reverse 2nd removal
        archival_mutator_set.revert_remove(&rem1).await;
        assert!(
            !archival_mutator_set
                .bloom_filter_contains(saw_collission_at.1)
                .await,
            "Bloom filter must not have collission bit set after 2nd removal revert"
        );

        // Update all MPs
        for (mp, &itm) in mps.iter_mut().zip_eq(items.iter()) {
            mp.revert_update_from_remove(&rem1).unwrap();
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
    #[tokio::test]
    async fn revert_remove_from_active_bloom_filter_panic() {
        let mut rms = empty_rusty_mutator_set().await;
        let archival_mutator_set = rms.ams_mut();
        let record = prepare_random_addition(archival_mutator_set).await;
        let (item, addition_record, membership_proof) = record;
        archival_mutator_set.add(&addition_record).await;

        let removal_record = archival_mutator_set.drop(item, &membership_proof);

        // This next line should panic, as we're attempting to remove an index that is not present
        // in the active window
        archival_mutator_set.revert_remove(&removal_record).await;
    }

    #[should_panic(expected = "Attempted to remove index that was not present in chunk.")]
    #[tokio::test]
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
            absolute_indices: AbsoluteIndexSet::new(&fake_indices),
            target_chunks: ChunkDictionary::default(),
        };

        // This next line should panic, as we're attempting to remove an index that is not present
        // in the inactive part of the Bloom filter
        archival_mutator_set
            .revert_remove(&fake_removal_record)
            .await;
    }

    #[tokio::test]
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
                    expired_membership_proof.auth_path_aocl.leaf_index,
                )
                .await
                .unwrap();
            assert!(
                archival_mutator_set
                    .verify(item, &restored_membership_proof)
                    .await
            );

            let removal_record = archival_mutator_set.drop(item, &restored_membership_proof);
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

    #[tokio::test]
    async fn archival_set_batch_remove_simple_test() {
        let mut rms = empty_rusty_mutator_set().await;
        let archival_mutator_set = rms.ams_mut();

        let num_additions = 130;

        let mut membership_proofs: Vec<MsMembershipProof> = vec![];
        let mut items: Vec<Digest> = vec![];

        for _ in 0..num_additions {
            let (item, sender_randomness, receiver_preimage) = make_item_and_randomnesses();

            let addition_record = commit(item, sender_randomness, receiver_preimage.hash::<Hash>());
            let membership_proof = archival_mutator_set
                .prove(item, sender_randomness, receiver_preimage)
                .await;

            MsMembershipProof::batch_update_from_addition(
                &mut membership_proofs.iter_mut().collect::<Vec<_>>(),
                &items,
                &archival_mutator_set.kernel,
                &addition_record,
            )
            .await
            .expect("MS membership update must work");

            archival_mutator_set.add(&addition_record).await;

            membership_proofs.push(membership_proof);
            items.push(item);
        }

        let mut removal_records: Vec<RemovalRecord> = vec![];
        for (mp, &item) in membership_proofs.iter().zip_eq(items.iter()) {
            removal_records.push(archival_mutator_set.drop(item, mp));
        }

        for (mp, &item) in membership_proofs.iter().zip_eq(items.iter()) {
            assert!(archival_mutator_set.verify(item, mp).await);
        }
        archival_mutator_set
            .batch_remove(removal_records, &mut [])
            .await;
        for (mp, &item) in membership_proofs.iter().zip_eq(items.iter()) {
            assert!(!archival_mutator_set.verify(item, mp).await);
        }
    }

    #[tokio::test]
    async fn archival_set_batch_remove_dynamic_test() {
        let mut rms = empty_rusty_mutator_set().await;
        let archival_mutator_set = rms.ams_mut();

        let num_additions = 4 * BATCH_SIZE;

        for remove_factor in [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0] {
            let mut membership_proofs: Vec<MsMembershipProof> = vec![];
            let mut items: Vec<Digest> = vec![];
            for _ in 0..num_additions {
                let (item, sender_randomness, receiver_preimage) = make_item_and_randomnesses();

                let addition_record =
                    commit(item, sender_randomness, receiver_preimage.hash::<Hash>());
                let membership_proof = archival_mutator_set
                    .prove(item, sender_randomness, receiver_preimage)
                    .await;

                MsMembershipProof::batch_update_from_addition(
                    &mut membership_proofs.iter_mut().collect::<Vec<_>>(),
                    &items,
                    &archival_mutator_set.kernel,
                    &addition_record,
                )
                .await
                .expect("MS membership update must work");

                archival_mutator_set.add(&addition_record).await;

                membership_proofs.push(membership_proof);
                items.push(item);
            }

            let mut rng = rand::thread_rng();
            let mut skipped_removes: Vec<bool> = vec![];
            let mut removal_records: Vec<RemovalRecord> = vec![];
            for (mp, &item) in membership_proofs.iter().zip_eq(items.iter()) {
                let skipped = rng.gen_range(0.0..1.0) < remove_factor;
                skipped_removes.push(skipped);
                if !skipped {
                    removal_records.push(archival_mutator_set.drop(item, mp));
                }
            }

            for (mp, &item) in membership_proofs.iter().zip_eq(items.iter()) {
                assert!(archival_mutator_set.verify(item, mp).await);
            }

            let commitment_prior_to_removal = archival_mutator_set.hash().await;
            archival_mutator_set
                .batch_remove(
                    removal_records.clone(),
                    &mut membership_proofs.iter_mut().collect::<Vec<_>>(),
                )
                .await;

            for ((mp, &item), skipped) in membership_proofs
                .iter()
                .zip_eq(items.iter())
                .zip_eq(skipped_removes.into_iter())
            {
                // If this removal record was not applied, then the membership proof must verify
                assert_eq!(skipped, archival_mutator_set.verify(item, mp).await);
            }

            // Verify that removal record indices were applied. If not, below function call will crash.
            for removal_record in removal_records.iter() {
                archival_mutator_set.revert_remove(removal_record).await;
            }

            // Verify that mutator set before and after removal are the same
            assert_eq!(commitment_prior_to_removal, archival_mutator_set.hash().await, "After reverting the removes, mutator set's commitment must equal the one before elements were removed.");
        }
    }

    async fn prepare_seeded_prng_addition<
        MmrStorage: StorageVec<Digest> + Send + Sync,
        ChunkStorage: StorageVec<Chunk> + Send + Sync,
    >(
        archival_mutator_set: &mut ArchivalMutatorSet<MmrStorage, ChunkStorage>,
        rng: &mut StdRng,
    ) -> (Digest, AdditionRecord, MsMembershipProof) {
        let item: Digest = rng.gen();
        let sender_randomness: Digest = rng.gen();
        let receiver_preimage: Digest = rng.gen();
        let addition_record = commit(item, sender_randomness, receiver_preimage.hash::<Hash>());
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
        let (item, sender_randomness, receiver_preimage) = make_item_and_randomnesses();
        let addition_record = commit(item, sender_randomness, receiver_preimage.hash::<Hash>());
        let membership_proof = archival_mutator_set
            .prove(item, sender_randomness, receiver_preimage)
            .await;

        (item, addition_record, membership_proof)
    }
}
