use rusty_leveldb::{LdbIterator, DB};
use std::{
    collections::{HashMap, HashSet},
    error::Error,
};
use twenty_first::util_types::{
    database_vector::DatabaseVector,
    mmr::{self, archival_mmr::ArchivalMmr, mmr_trait::Mmr},
    simple_hasher::{Hashable, Hasher},
};

use super::{
    active_window::ActiveWindow,
    addition_record::AdditionRecord,
    chunk::Chunk,
    chunk_dictionary::ChunkDictionary,
    ms_membership_proof::MsMembershipProof,
    mutator_set_trait::MutatorSet,
    removal_record::RemovalRecord,
    set_commitment::{get_swbf_indices, SetCommitment, SetCommitmentError},
    shared::{BATCH_SIZE, CHUNK_SIZE},
};

pub struct ArchivalMutatorSet<H: Hasher>
where
    u128: Hashable<<H as Hasher>::T>,
{
    pub set_commitment: SetCommitment<H, ArchivalMmr<H>>,
    pub chunks: DatabaseVector<Chunk>,
}

impl<H: Hasher> MutatorSet<H> for ArchivalMutatorSet<H>
where
    u128: Hashable<<H as Hasher>::T>,
{
    fn prove(
        &mut self,
        item: &<H as Hasher>::Digest,
        randomness: &<H as Hasher>::Digest,
        store_bits: bool,
    ) -> MsMembershipProof<H> {
        self.set_commitment.prove(item, randomness, store_bits)
    }

    fn verify(
        &mut self,
        item: &<H as Hasher>::Digest,
        membership_proof: &MsMembershipProof<H>,
    ) -> bool {
        self.set_commitment.verify(item, membership_proof)
    }

    fn commit(
        &mut self,
        item: &<H as Hasher>::Digest,
        randomness: &<H as Hasher>::Digest,
    ) -> AdditionRecord<H> {
        self.set_commitment.commit(item, randomness)
    }

    fn drop(
        &mut self,
        item: &<H as Hasher>::Digest,
        membership_proof: &MsMembershipProof<H>,
    ) -> RemovalRecord<H> {
        self.set_commitment.drop(item, membership_proof)
    }

    fn add(&mut self, addition_record: &mut AdditionRecord<H>) {
        let new_chunk: Option<(u128, Chunk)> = self.set_commitment.add_helper(addition_record);
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

    fn remove(&mut self, removal_record: &RemovalRecord<H>) -> Option<Vec<u128>> {
        let (new_chunks, diff_indices): (HashMap<u128, Chunk>, Vec<u128>) =
            self.set_commitment.remove_helper(removal_record);
        for (chunk_index, chunk) in new_chunks {
            self.chunks.set(chunk_index, chunk);
        }

        Some(diff_indices)
    }

    fn get_commitment(&mut self) -> <H as Hasher>::Digest {
        let aocl_mmr_bagged = self.set_commitment.aocl.bag_peaks();
        let inactive_swbf_bagged = self.set_commitment.swbf_inactive.bag_peaks();
        let active_swbf_bagged = self.set_commitment.swbf_active.hash();
        let hasher = H::new();
        hasher.hash_many(&[aocl_mmr_bagged, inactive_swbf_bagged, active_swbf_bagged])
    }
}

/// Methods that only work when implementing using archival MMRs as the underlying two MMRs
impl<H: Hasher> ArchivalMutatorSet<H>
where
    u128: Hashable<<H as Hasher>::T>,
{
    pub fn new_empty(aocl_mmr_db: DB, swbf_inactive_mmr_db: DB, chunks_db: DB) -> Self {
        let aocl: ArchivalMmr<H> = ArchivalMmr::new(aocl_mmr_db);
        let swbf_inactive: ArchivalMmr<H> = ArchivalMmr::new(swbf_inactive_mmr_db);
        Self {
            set_commitment: SetCommitment {
                aocl,
                swbf_inactive,
                swbf_active: ActiveWindow::default(),
            },
            chunks: DatabaseVector::new(chunks_db),
        }
    }

    pub fn new_or_restore(
        mut aocl_mmr_db: DB,
        mut swbf_inactive_mmr_db: DB,
        mut chunks_db: DB,
        mut active_window_db: DB,
    ) -> Self {
        let aocl_is_empty = aocl_mmr_db.new_iter().unwrap().next().is_none();
        let aocl: ArchivalMmr<H> = if aocl_is_empty {
            ArchivalMmr::new(aocl_mmr_db)
        } else {
            ArchivalMmr::restore(aocl_mmr_db)
        };

        let swbf_inactive_is_empty = swbf_inactive_mmr_db.new_iter().unwrap().next().is_none();
        let swbf_inactive: ArchivalMmr<H> = if swbf_inactive_is_empty {
            ArchivalMmr::new(swbf_inactive_mmr_db)
        } else {
            ArchivalMmr::restore(swbf_inactive_mmr_db)
        };

        let chunks_is_empty = chunks_db.new_iter().unwrap().next().is_none();
        let chunks: DatabaseVector<Chunk> = if chunks_is_empty {
            DatabaseVector::new(chunks_db)
        } else {
            DatabaseVector::restore(chunks_db)
        };

        let active_window_is_empty = active_window_db.new_iter().unwrap().next().is_none();
        let active_window: ActiveWindow<H> = if active_window_is_empty {
            ActiveWindow::default()
        } else {
            ActiveWindow::restore_from_database(active_window_db)
        };

        Self {
            set_commitment: SetCommitment {
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
        index: u128,
    ) -> Result<mmr::mmr_membership_proof::MmrMembershipProof<H>, Box<dyn Error>> {
        if self.set_commitment.aocl.count_leaves() <= index {
            return Err(Box::new(
                SetCommitmentError::RequestedAoclAuthPathOutOfBounds((
                    index,
                    self.set_commitment.aocl.count_leaves(),
                )),
            ));
        }

        Ok(self.set_commitment.aocl.prove_membership(index).0)
    }

    /// Returns an authentication path for a chunk in the sliding window Bloom filter
    pub fn get_chunk_and_auth_path(
        &mut self,
        chunk_index: u128,
    ) -> Result<(mmr::mmr_membership_proof::MmrMembershipProof<H>, Chunk), Box<dyn Error>> {
        if self.set_commitment.swbf_inactive.count_leaves() <= chunk_index {
            return Err(Box::new(
                SetCommitmentError::RequestedSwbfAuthPathOutOfBounds((
                    chunk_index,
                    self.set_commitment.swbf_inactive.count_leaves(),
                )),
            ));
        }

        let chunk_auth_path: mmr::mmr_membership_proof::MmrMembershipProof<H> = self
            .set_commitment
            .swbf_inactive
            .prove_membership(chunk_index)
            .0;
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
        item: &H::Digest,
        randomness: &H::Digest,
        index: u128,
    ) -> Result<MsMembershipProof<H>, Box<dyn Error>> {
        if self.set_commitment.aocl.is_empty() {
            return Err(Box::new(SetCommitmentError::MutatorSetIsEmpty));
        }

        let auth_path_aocl = self.get_aocl_authentication_path(index)?;
        let bits = get_swbf_indices::<H>(item, randomness, index);

        let batch_index = (self.set_commitment.aocl.count_leaves() - 1) / BATCH_SIZE as u128;
        let window_start = batch_index * CHUNK_SIZE as u128;

        let chunk_indices: HashSet<u128> = bits
            .iter()
            .filter(|bi| **bi < window_start)
            .map(|bi| *bi / CHUNK_SIZE as u128)
            .collect();
        let mut target_chunks: ChunkDictionary<H> = ChunkDictionary::default();
        for chunk_index in chunk_indices {
            assert!(
                self.chunks.len() > chunk_index,
                "Chunks must be known if its authentication path is known."
            );
            let chunk = self.chunks.get(chunk_index);
            let chunk_membership_proof: mmr::mmr_membership_proof::MmrMembershipProof<H> = self
                .set_commitment
                .swbf_inactive
                .prove_membership(chunk_index)
                .0;
            target_chunks
                .dictionary
                .insert(chunk_index, (chunk_membership_proof, chunk.to_owned()));
        }

        Ok(MsMembershipProof {
            auth_path_aocl,
            randomness: randomness.to_owned(),
            target_chunks,
            cached_bits: Some(bits),
        })
    }

    /// Revert the `RemovalRecord`s in a block by unsetting the bits that
    /// were actually flipped. These live in either the active window, or
    /// in a relevant chunk.
    ///
    /// Fails if attempting to unset a bit that wasn't set.
    pub fn revert_remove(&mut self, diff_indices: Vec<u128>) {
        let hasher = H::new();
        for bit_index in diff_indices {
            assert!(
                self.unset_bloom_filter_bit(bit_index, &hasher),
                "Bloom filter bit must be set when reverting remove()"
            );
        }
    }

    /// Revert the `AdditionRecord`s in a block by
    ///
    /// - Removing the last leaf in the append-only commitment list
    /// - If at a boundary where the active window slides, remove a chunk
    ///   from the inactive window, and slide window back by putting the
    ///   last inactive chunk in the active window.
    pub fn revert_add(&mut self, addition_record: &AdditionRecord<H>) {
        let removed_add_index = self.set_commitment.aocl.count_leaves() - 1;

        // 1. Remove last leaf from AOCL
        let digest = self.set_commitment.aocl.remove_last_leaf().unwrap();
        assert_eq!(addition_record.canonical_commitment, digest);

        // 2. Possibly shrink bloom filter by moving a chunk back into active window
        //
        // This happens when the batch index changes (i.e. every `BATCH_SIZE` addition).
        if !SetCommitment::<H, ArchivalMmr<H>>::window_slides_back(removed_add_index) {
            return;
        }

        // 2.a. Remove a chunk from inactive window
        let _digest = self.set_commitment.swbf_inactive.remove_last_leaf();
        let last_inactive_chunk = self.chunks.pop().unwrap();

        // 2.b. Slide active window back by putting `last_inactive_chunk` back
        self.set_commitment
            .swbf_active
            .slide_window_back(&last_inactive_chunk);
    }

    /// Retrieves the Bloom filter bit with a given `bit_index` in
    /// either the active window, or in the relevant chunk.
    pub fn get_bloom_filter_bit(&mut self, bit_index: u128) -> bool {
        let batch_index = (self.set_commitment.aocl.count_leaves() - 1) / BATCH_SIZE as u128;
        let active_window_start = batch_index * CHUNK_SIZE as u128;

        if bit_index >= active_window_start {
            let relative_index = (bit_index - active_window_start) as usize;
            self.set_commitment.swbf_active.get_bit(relative_index)
        } else {
            let chunk_index = bit_index / CHUNK_SIZE as u128;
            let relative_index = (bit_index % CHUNK_SIZE as u128) as usize;
            let relevant_chunk = self.chunks.get(chunk_index);
            relevant_chunk.get_bit(relative_index)
        }
    }

    /// Unsets the Bloom filter bit with a given `bit_index` in
    /// either the active window, or in the relevant chunk.
    ///
    /// Returns
    /// - `true` if the bit was flipped from 1 to 0,
    /// - `false` if the bit was already unset (0).
    pub fn unset_bloom_filter_bit(&mut self, bit_index: u128, hasher: &H) -> bool {
        let batch_index = (self.set_commitment.aocl.count_leaves() - 1) / BATCH_SIZE as u128;
        let active_window_start = batch_index * CHUNK_SIZE as u128;

        if bit_index >= active_window_start {
            let relative_index = (bit_index - active_window_start) as usize;
            let was_set = self.set_commitment.swbf_active.get_bit(relative_index);
            self.set_commitment.swbf_active.unset_bit(relative_index);
            was_set
        } else {
            let chunk_index = bit_index / CHUNK_SIZE as u128;
            let relative_index = (bit_index % CHUNK_SIZE as u128) as usize;
            let mut relevant_chunk = self.chunks.get(chunk_index);
            let was_set = relevant_chunk.get_bit(relative_index);
            relevant_chunk.unset_bit(relative_index);
            self.chunks.set(chunk_index, relevant_chunk);
            self.set_commitment
                .swbf_inactive
                .mutate_leaf_raw(chunk_index, relevant_chunk.hash::<H>(hasher));
            was_set
        }
    }

    /// Flush the DatabaseVector (chunks)
    pub fn flush(&mut self) {
        self.chunks.flush();
        self.set_commitment.aocl.flush();
        self.set_commitment.swbf_inactive.flush();
    }
}

#[cfg(test)]
mod archival_mutator_set_tests {
    use super::*;
    use crate::test_shared::mutator_set::{empty_archival_ms, make_item_and_randomness_for_rp};
    use rand::distributions::Standard;
    use rand::prelude::Distribution;
    use twenty_first::shared_math::other::random_elements;
    use twenty_first::shared_math::rescue_prime_regular::RescuePrimeRegular;
    use twenty_first::util_types::simple_hasher::Hasher;

    #[test]
    fn new_or_restore_test() {
        type H = RescuePrimeRegular;
        let opt = rusty_leveldb::in_memory();
        let chunks_db = DB::open("chunks", opt.clone()).unwrap();
        let aocl_mmr_db = DB::open("aocl", opt.clone()).unwrap();
        let swbf_inactive_mmr_db = DB::open("swbf_inactive", opt.clone()).unwrap();
        let active_window_db = DB::open("active_window", opt.clone()).unwrap();

        let mut archival_mutator_set = ArchivalMutatorSet::<H>::new_or_restore(
            aocl_mmr_db,
            swbf_inactive_mmr_db,
            chunks_db,
            active_window_db,
        );

        let (item, randomness) = make_item_and_randomness_for_rp();

        let mut addition_record = archival_mutator_set.commit(&item, &randomness);
        let membership_proof = archival_mutator_set.prove(&item, &randomness, false);
        archival_mutator_set.add(&mut addition_record);
        assert!(archival_mutator_set.verify(&item, &membership_proof));

        let removal_record: RemovalRecord<H> = archival_mutator_set.drop(&item, &membership_proof);
        let diff_bits: Vec<u128> = archival_mutator_set.remove(&removal_record).unwrap();
        assert_eq!(
            removal_record.bit_indices.to_vec(),
            diff_bits,
            "diff bits must be equal to bit indices when Bloom filter is empty"
        );

        // Let's store the active window back to the database and create
        // a new archival object from the databases it contains and then check
        // that this archival MS contains the same values
        let active_window_db = DB::open("active_window", opt.clone()).unwrap();
        let active_window_db = archival_mutator_set
            .set_commitment
            .swbf_active
            .store_to_database(active_window_db);
        drop(archival_mutator_set);
        let chunks_db = DB::open("chunks", opt.clone()).unwrap();
        let aocl_mmr_db = DB::open("aocl", opt.clone()).unwrap();
        let swbf_inactive_mmr_db = DB::open("swbf_inactive", opt).unwrap();
        let mut archival_mutator_set = ArchivalMutatorSet::new_or_restore(
            aocl_mmr_db,
            swbf_inactive_mmr_db,
            chunks_db,
            active_window_db,
        );
        assert!(!archival_mutator_set.verify(&item, &membership_proof));
    }

    #[test]
    fn archival_set_commitment_test() {
        type H = RescuePrimeRegular;
        let mut archival_mutator_set: ArchivalMutatorSet<H> = empty_archival_ms();

        let num_additions = 65;

        let mut membership_proofs: Vec<MsMembershipProof<H>> = vec![];
        let mut items: Vec<<H as Hasher>::Digest> = vec![];

        for i in 0..num_additions {
            let (item, randomness) = make_item_and_randomness_for_rp();

            let mut addition_record = archival_mutator_set.commit(&item, &randomness);
            let membership_proof = archival_mutator_set.prove(&item, &randomness, false);

            let res = MsMembershipProof::batch_update_from_addition(
                &mut membership_proofs.iter_mut().collect::<Vec<_>>(),
                &items,
                &mut archival_mutator_set.set_commitment,
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

        let mut archival_mutator_set: ArchivalMutatorSet<H> = empty_archival_ms();

        // Repeatedly insert `AdditionRecord` into empty MutatorSet and revert it
        //
        // This does not reach the sliding window, and the MutatorSet reverts back
        // to being empty on every iteration.
        for _ in 0..2 * BATCH_SIZE {
            let (item, mut addition_record, membership_proof) =
                make_random_addition(&mut archival_mutator_set);

            let commitment_before_add = archival_mutator_set.get_commitment();
            archival_mutator_set.add(&mut addition_record);
            assert!(archival_mutator_set.verify(&item, &membership_proof));

            archival_mutator_set.revert_add(&addition_record);
            let commitment_after_revert = archival_mutator_set.get_commitment();
            assert!(!archival_mutator_set.verify(&item, &membership_proof));
            assert_eq!(commitment_before_add, commitment_after_revert);
        }

        let n_iterations = 10 * BATCH_SIZE;
        let mut records = Vec::with_capacity(n_iterations);
        let mut commitments_before = Vec::with_capacity(n_iterations);

        // Insert a number of `AdditionRecord`s into MutatorSet and assert their membership.
        for _ in 0..n_iterations {
            let record = make_random_addition(&mut archival_mutator_set);
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

    #[test]
    fn archival_mutator_set_revert_remove_test() {
        type H = RescuePrimeRegular;

        let mut archival_mutator_set: ArchivalMutatorSet<H> = empty_archival_ms();

        let n_iterations = 10 * BATCH_SIZE;
        let mut records = Vec::with_capacity(n_iterations);
        let mut commitments_before = Vec::with_capacity(n_iterations);

        // Insert a number of `AdditionRecord`s into MutatorSet and assert their membership.
        for _ in 0..n_iterations {
            let record = make_random_addition(&mut archival_mutator_set);
            let (item, mut addition_record, membership_proof) = record.clone();
            records.push(record);
            commitments_before.push(archival_mutator_set.get_commitment());
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
                    expired_membership_proof.auth_path_aocl.data_index,
                )
                .unwrap();
            assert!(archival_mutator_set.verify(&item, &restored_membership_proof));

            let removal_record = archival_mutator_set.drop(&item, &restored_membership_proof);
            let commitment_before_remove = archival_mutator_set.get_commitment();
            let diff_indices = archival_mutator_set.remove(&removal_record).unwrap();
            println!("diff_indices = {:?}", diff_indices);
            assert!(!archival_mutator_set.verify(&item, &restored_membership_proof));

            archival_mutator_set.revert_remove(diff_indices);
            let commitment_after_revert = archival_mutator_set.get_commitment();
            assert_eq!(commitment_before_remove, commitment_after_revert);
            assert!(archival_mutator_set.verify(&item, &restored_membership_proof));
        }
    }

    fn make_random_addition<H: Hasher>(
        archival_mutator_set: &mut ArchivalMutatorSet<H>,
    ) -> (H::Digest, AdditionRecord<H>, MsMembershipProof<H>)
    where
        u128: Hashable<<H as Hasher>::T>,
        Standard: Distribution<<H as Hasher>::T>,
    {
        let random_elements = random_elements(6);
        let item: <H as Hasher>::Digest = H::new().hash_sequence(&random_elements[0..3]);
        let randomness: <H as Hasher>::Digest = H::new().hash_sequence(&random_elements[3..6]);

        let addition_record = archival_mutator_set
            .set_commitment
            .commit(&item, &randomness);
        let membership_proof = archival_mutator_set.prove(&item, &randomness, true);

        (item, addition_record, membership_proof)
    }
}
