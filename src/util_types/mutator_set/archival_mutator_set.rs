use std::collections::{HashMap, HashSet};
use std::error::Error;
use twenty_first::shared_math::rescue_prime_digest::Digest;
use twenty_first::util_types::storage_vec::StorageVec;

use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;
use twenty_first::util_types::mmr;
use twenty_first::util_types::mmr::archival_mmr::ArchivalMmr;
use twenty_first::util_types::mmr::mmr_trait::Mmr;

use super::active_window::ActiveWindow;
use super::addition_record::AdditionRecord;
use super::chunk::Chunk;
use super::chunk_dictionary::ChunkDictionary;
use super::ms_membership_proof::MsMembershipProof;
use super::mutator_set_kernel::{get_swbf_indices, MutatorSetKernel, MutatorSetKernelError};
use super::mutator_set_trait::MutatorSet;
use super::removal_record::{AbsoluteIndexSet, RemovalRecord};
use super::shared::CHUNK_SIZE;

pub struct ArchivalMutatorSet<H, MmrStorage, ChunkStorage>
where
    H: AlgebraicHasher,
    MmrStorage: StorageVec<Digest>,
    ChunkStorage: StorageVec<Chunk>,
{
    pub kernel: MutatorSetKernel<H, ArchivalMmr<H, MmrStorage>>,
    pub chunks: ChunkStorage,
}

impl<H, MmrStorage, ChunkStorage> MutatorSet<H> for ArchivalMutatorSet<H, MmrStorage, ChunkStorage>
where
    H: AlgebraicHasher,
    MmrStorage: StorageVec<Digest>,
    ChunkStorage: StorageVec<Chunk>,
{
    fn prove(
        &mut self,
        item: &Digest,
        randomness: &Digest,
        cache_indices: bool,
    ) -> MsMembershipProof<H> {
        self.kernel.prove(item, randomness, cache_indices)
    }

    fn verify(&mut self, item: &Digest, membership_proof: &MsMembershipProof<H>) -> bool {
        self.kernel.verify(item, membership_proof)
    }

    fn commit(&mut self, item: &Digest, randomness: &Digest) -> AdditionRecord {
        self.kernel.commit(item, randomness)
    }

    fn drop(&mut self, item: &Digest, membership_proof: &MsMembershipProof<H>) -> RemovalRecord<H> {
        self.kernel.drop(item, membership_proof)
    }

    fn add(&mut self, addition_record: &mut AdditionRecord) {
        let new_chunk: Option<(u64, Chunk)> = self.kernel.add_helper(addition_record);
        match new_chunk {
            None => (),
            Some((chunk_index, chunk)) => {
                // Sanity check to verify that we agree on the index
                assert_eq!(
                    chunk_index,
                    self.chunks.len(),
                    "Length/index must agree when inserting a chunk into an archival node"
                );
                self.chunks.push(chunk);
            }
        }
    }

    fn remove(&mut self, removal_record: &RemovalRecord<H>) {
        let new_chunks: HashMap<u64, Chunk> = self.kernel.remove_helper(removal_record);
        for (chunk_index, chunk) in new_chunks {
            self.chunks.set(chunk_index, chunk);
        }
    }

    fn get_commitment(&mut self) -> Digest {
        let aocl_mmr_bagged = self.kernel.aocl.bag_peaks();
        let inactive_swbf_bagged = self.kernel.swbf_inactive.bag_peaks();
        let active_swbf_bagged = H::hash(&self.kernel.swbf_active);

        H::hash_pair(
            &aocl_mmr_bagged,
            &H::hash_pair(&inactive_swbf_bagged, &active_swbf_bagged),
        )
    }

    /// Apply a list of removal records while keeping a list of mutator-set membership proofs
    /// updated
    fn batch_remove(
        &mut self,
        removal_records: Vec<RemovalRecord<H>>,
        preserved_membership_proofs: &mut [&mut MsMembershipProof<H>],
    ) {
        let chunk_index_to_chunk_mutation = self
            .kernel
            .batch_remove(removal_records, preserved_membership_proofs);

        for (chnk_idx, new_chunk_value) in chunk_index_to_chunk_mutation {
            self.chunks.set(chnk_idx, new_chunk_value);
        }
    }
}

/// Methods that only work when implementing using archival MMRs as the underlying two MMRs
impl<H, MmrStorage, ChunkStorage> ArchivalMutatorSet<H, MmrStorage, ChunkStorage>
where
    H: AlgebraicHasher,
    MmrStorage: StorageVec<Digest>,
    ChunkStorage: StorageVec<Chunk>,
{
    pub fn new_empty(aocl: MmrStorage, swbf_inactive: MmrStorage, chunks: ChunkStorage) -> Self {
        assert_eq!(0, aocl.len());
        assert_eq!(0, swbf_inactive.len());
        assert_eq!(0, chunks.len());
        let aocl: ArchivalMmr<H, MmrStorage> = ArchivalMmr::new(aocl);
        let swbf_inactive: ArchivalMmr<H, MmrStorage> = ArchivalMmr::new(swbf_inactive);
        Self {
            kernel: MutatorSetKernel {
                aocl,
                swbf_inactive,
                swbf_active: ActiveWindow::new(),
            },
            chunks,
        }
    }

    pub fn new_or_restore(
        aocl: MmrStorage,
        swbf_inactive: MmrStorage,
        chunks: ChunkStorage,
        active_window: ActiveWindow<H>,
    ) -> Self {
        let aocl: ArchivalMmr<H, MmrStorage> = ArchivalMmr::new(aocl);
        let swbf_inactive: ArchivalMmr<H, MmrStorage> = ArchivalMmr::new(swbf_inactive);

        Self {
            kernel: MutatorSetKernel {
                aocl,
                swbf_inactive,
                swbf_active: active_window,
            },
            chunks,
        }
    }

    /// Returns an authentication path for an element in the append-only commitment list
    pub fn get_aocl_authentication_path(
        &mut self,
        index: u64,
    ) -> Result<mmr::mmr_membership_proof::MmrMembershipProof<H>, Box<dyn Error>> {
        if self.kernel.aocl.count_leaves() <= index {
            return Err(Box::new(
                MutatorSetKernelError::RequestedAoclAuthPathOutOfBounds((
                    index,
                    self.kernel.aocl.count_leaves(),
                )),
            ));
        }

        Ok(self.kernel.aocl.prove_membership(index).0)
    }

    /// Returns an authentication path for a chunk in the sliding window Bloom filter
    pub fn get_chunk_and_auth_path(
        &mut self,
        chunk_index: u64,
    ) -> Result<(mmr::mmr_membership_proof::MmrMembershipProof<H>, Chunk), Box<dyn Error>> {
        if self.kernel.swbf_inactive.count_leaves() <= chunk_index {
            return Err(Box::new(
                MutatorSetKernelError::RequestedSwbfAuthPathOutOfBounds((
                    chunk_index,
                    self.kernel.swbf_inactive.count_leaves(),
                )),
            ));
        }

        let chunk_auth_path: mmr::mmr_membership_proof::MmrMembershipProof<H> =
            self.kernel.swbf_inactive.prove_membership(chunk_index).0;

        // This check should never fail. It would mean that chunks are missing but that the
        // archival MMR has the membership proof for the chunk. That would be a programming
        // error.
        assert!(
            self.chunks.len() > chunk_index,
            "Chunks must be known if its authentication path is known."
        );
        let chunk = self.chunks.get(chunk_index);

        Ok((chunk_auth_path, chunk))
    }

    /// Restore membership_proof. If called on someone else's UTXO, this leaks privacy. In this case,
    /// caller is better off using `get_aocl_authentication_path` and `get_chunk_and_auth_path` for the
    /// relevant indices.
    pub fn restore_membership_proof(
        &mut self,
        item: &Digest,
        randomness: &Digest,
        aocl_index: u64,
    ) -> Result<MsMembershipProof<H>, Box<dyn Error>> {
        if self.kernel.aocl.is_empty() {
            return Err(Box::new(MutatorSetKernelError::MutatorSetIsEmpty));
        }

        let auth_path_aocl = self.get_aocl_authentication_path(aocl_index)?;
        let swbf_indices = get_swbf_indices::<H>(item, randomness, aocl_index);

        let batch_index = self.kernel.get_batch_index();
        let window_start = batch_index as u128 * CHUNK_SIZE as u128;

        let chunk_indices: HashSet<u64> = swbf_indices
            .iter()
            .filter(|bi| **bi < window_start)
            .map(|bi| (*bi / CHUNK_SIZE as u128) as u64)
            .collect();
        let mut target_chunks: ChunkDictionary<H> = ChunkDictionary::default();
        for chunk_index in chunk_indices {
            assert!(
                self.chunks.len() > chunk_index,
                "Chunks must be known if its authentication path is known."
            );
            let chunk = self.chunks.get(chunk_index);
            let chunk_membership_proof: mmr::mmr_membership_proof::MmrMembershipProof<H> =
                self.kernel.swbf_inactive.prove_membership(chunk_index).0;
            target_chunks
                .dictionary
                .insert(chunk_index, (chunk_membership_proof, chunk.to_owned()));
        }

        Ok(MsMembershipProof {
            auth_path_aocl,
            randomness: randomness.to_owned(),
            target_chunks,
            cached_indices: Some(AbsoluteIndexSet::new(&swbf_indices)),
        })
    }

    /// Revert the `RemovalRecord`s in a block by removing the indices that
    /// were inserted by the removal record. These live in either the active window, or
    /// in a relevant chunk.
    ///
    /// Fails if attempting to remove an index that wasn't set.
    pub fn revert_remove(&mut self, removal_record_indices: Vec<u128>) {
        let batch_index = self.kernel.get_batch_index();
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
            let previous_chunk = self.chunks.get(chunk_index);
            let mut new_chunk = previous_chunk;
            new_chunk.subtract(revert_chunk.clone());
            self.chunks.set(chunk_index, new_chunk.clone());

            // update archival mmr
            self.kernel
                .swbf_inactive
                .mutate_leaf_raw(chunk_index, H::hash(&new_chunk));
        }
    }

    /// Determine whether the given `AdditionRecord` can be reversed.
    /// Equivalently, determine if it was added last.
    pub fn add_is_reversible(&mut self, addition_record: &AdditionRecord) -> bool {
        let leaf_index = self.kernel.aocl.count_leaves() - 1;
        let digest = self.kernel.aocl.get_leaf(leaf_index);
        addition_record.canonical_commitment == digest
    }

    /// Revert the `AdditionRecord`s in a block by
    ///
    /// - Removing the last leaf in the append-only commitment list
    /// - If at a boundary where the active window slides, remove a chunk
    ///   from the inactive window, and slide window back by putting the
    ///   last inactive chunk in the active window.
    pub fn revert_add(&mut self, addition_record: &AdditionRecord) {
        let removed_add_index = self.kernel.aocl.count_leaves() - 1;

        // 1. Remove last leaf from AOCL
        let digest = self.kernel.aocl.remove_last_leaf().unwrap();
        assert_eq!(addition_record.canonical_commitment, digest);

        // 2. Possibly shrink bloom filter by moving a chunk back into active window
        //
        // This happens when the batch index changes (i.e. every `BATCH_SIZE` addition).
        if !MutatorSetKernel::<H, ArchivalMmr<H, MmrStorage>>::window_slides_back(removed_add_index)
        {
            return;
        }

        // 2.a. Remove a chunk from inactive window
        let _digest = self.kernel.swbf_inactive.remove_last_leaf();
        let last_inactive_chunk = self.chunks.pop().unwrap();

        // 2.b. Slide active window back by putting `last_inactive_chunk` back
        self.kernel
            .swbf_active
            .slide_window_back(&last_inactive_chunk);
    }

    /// Determine whether the index `index` is set in the Bloom
    /// filter, whether in the active window, or in some chunk.
    pub fn bloom_filter_contains(&mut self, index: u128) -> bool {
        let batch_index = self.kernel.get_batch_index();
        let active_window_start = batch_index as u128 * CHUNK_SIZE as u128;

        if index >= active_window_start {
            let relative_index = (index - active_window_start) as u32;
            self.kernel.swbf_active.contains(relative_index)
        } else {
            let chunk_index = (index / CHUNK_SIZE as u128) as u64;
            let relative_index = (index % CHUNK_SIZE as u128) as u32;
            let relevant_chunk = self.chunks.get(chunk_index);
            relevant_chunk.contains(relative_index)
        }
    }

    // /// Flush the databases. Does not persist the active window as this lives in memory. The caller
    // /// must persist the active window seperately.
    // pub fn flush(&mut self) {
    //     self.chunks.flush();
    //     self.set_commitment.aocl.flush();
    //     self.set_commitment.swbf_inactive.flush();
    // }
}

#[cfg(test)]
mod archival_mutator_set_tests {
    use itertools::Itertools;
    use rand::Rng;
    use twenty_first::shared_math::rescue_prime_regular::RescuePrimeRegular;

    use crate::test_shared::mutator_set::{empty_rustyleveldbvec_ams, make_item_and_randomness};
    use crate::util_types::mutator_set::shared::BATCH_SIZE;

    use super::*;

    #[test]
    fn archival_set_commitment_test() {
        type H = RescuePrimeRegular;
        let (mut archival_mutator_set, _): (ArchivalMutatorSet<H, _, _>, _) =
            empty_rustyleveldbvec_ams();

        let num_additions = 65;

        let mut membership_proofs: Vec<MsMembershipProof<H>> = vec![];
        let mut items: Vec<Digest> = vec![];

        for i in 0..num_additions {
            let (item, randomness) = make_item_and_randomness();

            let mut addition_record = archival_mutator_set.commit(&item, &randomness);
            let membership_proof = archival_mutator_set.prove(&item, &randomness, false);

            let res = MsMembershipProof::batch_update_from_addition(
                &mut membership_proofs.iter_mut().collect::<Vec<_>>(),
                &items,
                &mut archival_mutator_set.kernel,
                &addition_record,
            );
            assert!(res.is_ok());

            archival_mutator_set.add(&mut addition_record);
            assert!(archival_mutator_set.verify(&item, &membership_proof));

            // Verify that we can just read out the same membership proofs from the
            // archival MMR as those we get through the membership proof book keeping.
            let archival_membership_proof =
                match archival_mutator_set.restore_membership_proof(&item, &randomness, i) {
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

    #[test]
    fn archival_mutator_set_revert_add_test() {
        type H = RescuePrimeRegular;

        let (mut archival_mutator_set, _): (ArchivalMutatorSet<H, _, _>, _) =
            empty_rustyleveldbvec_ams();

        // Repeatedly insert `AdditionRecord` into empty MutatorSet and revert it
        //
        // This does not reach the sliding window, and the MutatorSet reverts back
        // to being empty on every iteration.
        for _ in 0..2 * BATCH_SIZE {
            let (item, mut addition_record, membership_proof) =
                prepare_random_addition(&mut archival_mutator_set);

            let commitment_before_add = archival_mutator_set.get_commitment();
            archival_mutator_set.add(&mut addition_record);
            assert!(archival_mutator_set.verify(&item, &membership_proof));

            archival_mutator_set.revert_add(&addition_record);
            let commitment_after_revert = archival_mutator_set.get_commitment();
            assert!(!archival_mutator_set.verify(&item, &membership_proof));
            assert_eq!(commitment_before_add, commitment_after_revert);
        }

        let n_iterations = 10 * BATCH_SIZE as usize;
        let mut records = Vec::with_capacity(n_iterations);
        let mut commitments_before = Vec::with_capacity(n_iterations);

        // Insert a number of `AdditionRecord`s into MutatorSet and assert their membership.
        for _ in 0..n_iterations {
            let record = prepare_random_addition(&mut archival_mutator_set);
            let (item, mut addition_record, membership_proof) = record.clone();
            records.push(record);
            commitments_before.push(archival_mutator_set.get_commitment());
            archival_mutator_set.add(&mut addition_record);
            assert!(archival_mutator_set.verify(&item, &membership_proof));
        }

        assert_eq!(n_iterations, records.len());

        // Revert these `AdditionRecord`s in reverse order and assert they're no longer members.
        //
        // This reaches the sliding window every `BATCH_SIZE` iteration.
        for (item, addition_record, membership_proof) in records.into_iter().rev() {
            archival_mutator_set.revert_add(&addition_record);
            let commitment_after_revert = archival_mutator_set.get_commitment();
            assert!(!archival_mutator_set.verify(&item, &membership_proof));

            let commitment_before_add = commitments_before.pop().unwrap();
            assert_eq!(
                commitment_before_add,
                commitment_after_revert,
                "Commitment to MutatorSet from before adding should be valid after reverting adding"
            );
        }
    }

    #[should_panic(expected = "Decremented integer is already zero.")]
    #[test]
    fn revert_remove_from_active_bloom_filter_panic() {
        type H = blake3::Hasher;

        let (mut archival_mutator_set, _): (ArchivalMutatorSet<H, _, _>, _) =
            empty_rustyleveldbvec_ams();
        let record = prepare_random_addition(&mut archival_mutator_set);
        let (item, mut addition_record, membership_proof) = record;
        archival_mutator_set.add(&mut addition_record);

        let removal_record = archival_mutator_set.drop(&item, &membership_proof);

        // This next line should panic, as we're attempting to remove an index that is not present
        // in the active window
        archival_mutator_set.revert_remove(removal_record.absolute_indices.to_vec());
    }

    #[should_panic(expected = "Attempted to remove index that was not present in chunk.")]
    #[test]
    fn revert_remove_from_inactive_bloom_filter_panic() {
        type H = blake3::Hasher;

        let (mut archival_mutator_set, _): (ArchivalMutatorSet<H, _, _>, _) =
            empty_rustyleveldbvec_ams();

        for _ in 0..2 * BATCH_SIZE {
            let (_item, mut addition_record, _membership_proof) =
                prepare_random_addition(&mut archival_mutator_set);
            archival_mutator_set.add(&mut addition_record);
        }

        // This next line should panic, as we're attempting to remove an index that is not present
        // in the inactive part of the Bloom filter
        archival_mutator_set.revert_remove(vec![0, 2]);
    }

    #[test]
    fn archival_mutator_set_revert_remove_test() {
        type H = blake3::Hasher;

        let (mut archival_mutator_set, _): (ArchivalMutatorSet<H, _, _>, _) =
            empty_rustyleveldbvec_ams();

        let n_iterations = 11 * BATCH_SIZE as usize;
        let mut records = Vec::with_capacity(n_iterations);

        // Insert a number of `AdditionRecord`s into MutatorSet and assert their membership.
        for _ in 0..n_iterations {
            let record = prepare_random_addition(&mut archival_mutator_set);
            let (item, mut addition_record, membership_proof) = record.clone();
            records.push(record);
            archival_mutator_set.add(&mut addition_record);
            assert!(archival_mutator_set.verify(&item, &membership_proof));
        }

        for (idx, (item, _addition_record, expired_membership_proof)) in
            records.into_iter().rev().enumerate()
        {
            println!("revert_remove() #{}", idx);
            let restored_membership_proof = archival_mutator_set
                .restore_membership_proof(
                    &item,
                    &expired_membership_proof.randomness,
                    expired_membership_proof.auth_path_aocl.leaf_index,
                )
                .unwrap();
            assert!(archival_mutator_set.verify(&item, &restored_membership_proof));

            let removal_record = archival_mutator_set.drop(&item, &restored_membership_proof);
            let commitment_before_remove = archival_mutator_set.get_commitment();
            archival_mutator_set.remove(&removal_record);
            assert!(!archival_mutator_set.verify(&item, &restored_membership_proof));

            archival_mutator_set.revert_remove(removal_record.absolute_indices.to_vec());
            let commitment_after_revert = archival_mutator_set.get_commitment();
            assert_eq!(commitment_before_remove, commitment_after_revert);
            assert!(archival_mutator_set.verify(&item, &restored_membership_proof));
        }
    }

    #[test]
    fn archival_set_batch_remove_simple_test() {
        type H = blake3::Hasher;
        let (mut archival_mutator_set, _): (ArchivalMutatorSet<H, _, _>, _) =
            empty_rustyleveldbvec_ams();

        let num_additions = 130;

        let mut membership_proofs: Vec<MsMembershipProof<H>> = vec![];
        let mut items: Vec<Digest> = vec![];

        for _ in 0..num_additions {
            let (item, randomness) = make_item_and_randomness();

            let mut addition_record = archival_mutator_set.commit(&item, &randomness);
            let membership_proof = archival_mutator_set.prove(&item, &randomness, false);

            MsMembershipProof::batch_update_from_addition(
                &mut membership_proofs.iter_mut().collect::<Vec<_>>(),
                &items,
                &mut archival_mutator_set.kernel,
                &addition_record,
            )
            .expect("MS membership update must work");

            archival_mutator_set.add(&mut addition_record);

            membership_proofs.push(membership_proof);
            items.push(item);
        }

        let mut removal_records: Vec<RemovalRecord<H>> = vec![];
        for (mp, item) in membership_proofs.iter().zip_eq(items.iter()) {
            removal_records.push(archival_mutator_set.drop(item, mp));
        }

        for (mp, item) in membership_proofs.iter().zip_eq(items.iter()) {
            assert!(archival_mutator_set.verify(item, mp));
        }
        archival_mutator_set.batch_remove(removal_records, &mut []);
        for (mp, item) in membership_proofs.iter().zip_eq(items.iter()) {
            assert!(!archival_mutator_set.verify(item, mp));
        }
    }

    #[test]
    fn archival_set_batch_remove_dynamic_test() {
        type H = blake3::Hasher;
        let (mut archival_mutator_set, _): (ArchivalMutatorSet<H, _, _>, _) =
            empty_rustyleveldbvec_ams();

        let num_additions = 4 * BATCH_SIZE;

        for remove_factor in [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0] {
            let mut membership_proofs: Vec<MsMembershipProof<H>> = vec![];
            let mut items: Vec<Digest> = vec![];
            for _ in 0..num_additions {
                let (item, randomness) = make_item_and_randomness();

                let mut addition_record = archival_mutator_set.commit(&item, &randomness);
                let membership_proof = archival_mutator_set.prove(&item, &randomness, false);

                MsMembershipProof::batch_update_from_addition(
                    &mut membership_proofs.iter_mut().collect::<Vec<_>>(),
                    &items,
                    &mut archival_mutator_set.kernel,
                    &addition_record,
                )
                .expect("MS membership update must work");

                archival_mutator_set.add(&mut addition_record);

                membership_proofs.push(membership_proof);
                items.push(item);
            }

            let mut rng = rand::thread_rng();
            let mut skipped_removes: Vec<bool> = vec![];
            let mut removal_records: Vec<RemovalRecord<H>> = vec![];
            for (_, (mp, item)) in membership_proofs.iter().zip_eq(items.iter()).enumerate() {
                let skipped = rng.gen_range(0.0..1.0) < remove_factor;
                skipped_removes.push(skipped);
                if !skipped {
                    removal_records.push(archival_mutator_set.drop(item, mp));
                }
            }

            for (mp, item) in membership_proofs.iter().zip_eq(items.iter()) {
                assert!(archival_mutator_set.verify(item, mp));
            }

            let commitment_prior_to_removal = archival_mutator_set.get_commitment();
            archival_mutator_set.batch_remove(
                removal_records.clone(),
                &mut membership_proofs.iter_mut().collect::<Vec<_>>(),
            );

            for ((mp, item), skipped) in membership_proofs
                .iter()
                .zip_eq(items.iter())
                .zip_eq(skipped_removes.into_iter())
            {
                // If this removal record was not applied, then the membership proof must verify
                assert!(skipped == archival_mutator_set.verify(item, mp));
            }

            // Verify that removal record indices were applied. If not, below function call will crash.
            let all_removal_record_indices = removal_records
                .iter()
                .map(|x| x.absolute_indices.to_vec())
                .concat();
            archival_mutator_set.revert_remove(all_removal_record_indices);

            // Verify that mutator set before and after removal are the same
            assert_eq!(commitment_prior_to_removal, archival_mutator_set.get_commitment(), "After reverting the removes, mutator set's commitment must equal the one before elements were removed.");
        }
    }

    fn prepare_random_addition<
        H: AlgebraicHasher,
        MmrStorage: StorageVec<Digest>,
        ChunkStorage: StorageVec<Chunk>,
    >(
        archival_mutator_set: &mut ArchivalMutatorSet<H, MmrStorage, ChunkStorage>,
    ) -> (Digest, AdditionRecord, MsMembershipProof<H>) {
        let (item, randomness) = make_item_and_randomness();
        let addition_record = archival_mutator_set.kernel.commit(&item, &randomness);
        let membership_proof = archival_mutator_set.prove(&item, &randomness, true);

        (item, addition_record, membership_proof)
    }
}
