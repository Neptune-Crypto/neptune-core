use rusty_leveldb::{LdbIterator, DB};
use std::{
    collections::{HashMap, HashSet},
    error::Error,
};
use twenty_first::util_types::{
    database_vector::DatabaseVector,
    mmr::{
        self, archival_mmr::ArchivalMmr, mmr_membership_proof::MmrMembershipProof, mmr_trait::Mmr,
    },
    simple_hasher::{Hashable, Hasher},
};

use crate::util_types::mutator_set::shared::NUM_TRIALS;

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

    /// Apply a list of removal records while keeping a list of mutator-set membership proofs
    /// updated
    fn batch_remove(
        &mut self,
        mut removal_records: Vec<RemovalRecord<H>>,
        preserved_membership_proofs: &mut Vec<&mut MsMembershipProof<H>>,
    ) -> Option<Vec<u128>> {
        let batch_index = (self.set_commitment.aocl.count_leaves() - 1) / BATCH_SIZE as u128;
        let active_window_start = batch_index * CHUNK_SIZE as u128;

        // Collect all bits that that are set by the removal records
        let all_removal_records_bits: HashSet<u128> = removal_records
            .iter()
            .flat_map(|x| x.bit_indices.to_vec())
            .collect();

        // Keep track of which bits are flipped in the Bloom filter. This value
        // is returned to allow rollback of blocks.
        // TODO: It would be cool if we get these through xor-operations
        // instead.
        let mut changed_indices: Vec<u128> = Vec::with_capacity(all_removal_records_bits.len());

        // Loop over all bits from removal records in order to create a mapping
        // {chunk index => chunk mutation } where "chunk mutation" has the type of
        // `Chunk` but only represents the values which are set by the removal records
        // being handled. We do this since we can then apply bit-wise OR with the
        // "chunk mutations" and the existing chunk values in the sliding window
        // Bloom filter.
        let mut chunk_index_to_chunk_mutation: HashMap<u128, Chunk> = HashMap::new();
        all_removal_records_bits.iter().for_each(|bit_index| {
            if *bit_index >= active_window_start {
                let relative_index = (bit_index - active_window_start) as usize;
                if !self.set_commitment.swbf_active.get_bit(relative_index) {
                    changed_indices.push(*bit_index);
                }

                self.set_commitment.swbf_active.set_bit(relative_index);
            } else {
                chunk_index_to_chunk_mutation
                    .entry(bit_index / CHUNK_SIZE as u128)
                    .or_insert_with(Chunk::default)
                    .set_bit(*bit_index as usize % CHUNK_SIZE);
            }
        });

        // Collect all affected chunks as they look before these removal records are applied
        // These could be fetched from both `self` (archival mutator set) and from the removal
        // records. Here, we fetch them from the removal records.
        let mut mutation_data_preimage: HashMap<u128, (&mut Chunk, MmrMembershipProof<H>)> =
            HashMap::new();
        for removal_record in removal_records.iter_mut() {
            for (chunk_index, (mmr_mp, chunk)) in removal_record.target_chunks.dictionary.iter_mut()
            {
                let chunk_hash = chunk.hash(&H::new());
                let prev_val =
                    mutation_data_preimage.insert(*chunk_index, (chunk, mmr_mp.to_owned()));

                // Sanity check that all removal records agree on both chunks and MMR membership
                // proofs.
                match prev_val {
                    Some((c, mm)) => assert!(mm == *mmr_mp && chunk_hash == c.hash(&H::new())),
                    None => (),
                }
            }
        }

        // Apply the bit-flipping operation that calculates Bloom filter values after
        // applying the removal records
        for (chunk_index, (chunk, _)) in mutation_data_preimage.iter_mut() {
            let mut flipped_bits = chunk.clone();
            **chunk = chunk.or(chunk_index_to_chunk_mutation[chunk_index]);

            flipped_bits.xor(**chunk);

            for j in 0..CHUNK_SIZE as u128 {
                if flipped_bits.get_bit(j as usize) {
                    changed_indices.push(j + chunk_index * CHUNK_SIZE as u128);
                }
            }
        }

        // Set the chunk values in the membership proofs that we want to preserve to the
        // newly calculated chunk values where the bit-wise OR has been applied.
        // This is done by looping over all membership proofs and checking if they contain
        // any of the chunks that are affected by the removal records.
        for mp in preserved_membership_proofs.iter_mut() {
            for (chunk_index, (_, chunk)) in mp.target_chunks.dictionary.iter_mut() {
                if mutation_data_preimage.contains_key(chunk_index) {
                    *chunk = mutation_data_preimage[chunk_index].0.to_owned();
                }
            }
        }

        // Calculate the digests of the affected leafs in the inactive part of the sliding-window
        // Bloom filter such that we can apply a batch-update operation to the MMR through which
        // this part of the Bloom filter is represented.
        let hasher = H::new();
        let mutation_data: Vec<_> = mutation_data_preimage
            .into_values()
            .map(|x| (x.1, x.0.hash(&hasher)))
            .collect();

        // Create a vector of pointers to the MMR-membership part of the mutator set membership
        // proofs that we want to preserve. This is used as input to a batch-call to the
        // underlying MMR.
        let mut preseved_mmr_membership_proofs: Vec<&mut MmrMembershipProof<H>> =
            preserved_membership_proofs
                .iter_mut()
                .flat_map(|x| {
                    x.target_chunks
                        .dictionary
                        .iter_mut()
                        .map(|y| &mut y.1 .0)
                        .collect::<Vec<_>>()
                })
                .collect();

        // Apply the batch-update to the inactive part of the sliding window Bloom filter.
        self.set_commitment
            .swbf_inactive
            .batch_mutate_leaf_and_update_mps(
                &mut preseved_mmr_membership_proofs,
                mutation_data.clone(),
            );
        for (chnk_idx, new_chunk_value) in chunk_index_to_chunk_mutation {
            self.chunks.set(chnk_idx, new_chunk_value);
        }

        Some(changed_indices)
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
        let batch_index = (self.set_commitment.aocl.count_leaves() - 1) / BATCH_SIZE as u128;
        let active_window_start = batch_index * CHUNK_SIZE as u128;
        let mut unset_bit_encountered = false;
        let mut chunk_index_to_revert_chunk: HashMap<u128, Chunk> = HashMap::new();

        for diff_index in diff_indices {
            if diff_index >= active_window_start {
                let relative_index = (diff_index - active_window_start) as usize;
                unset_bit_encountered |= !self.set_commitment.swbf_active.get_bit(relative_index);
                self.set_commitment.swbf_active.unset_bit(relative_index);
            } else {
                let chunk_index = diff_index / CHUNK_SIZE as u128;
                let index_in_chunk = (diff_index % CHUNK_SIZE as u128) as usize;
                chunk_index_to_revert_chunk
                    .entry(chunk_index)
                    .or_insert_with(Chunk::default)
                    .set_bit(index_in_chunk);
            }
        }

        let hasher = H::new();
        for (chunk_index, revert_chunk) in chunk_index_to_revert_chunk {
            // The bits in the chunk are flipped using xor as they must be set before this
            // function call. So bits at the indices that we wish to flip must be set (1 or true)
            // in both the `revert_chunk` and in the `previous_chunk`.
            let previous_chunk = self.chunks.get(chunk_index);
            let mut new_chunk = previous_chunk;
            new_chunk.xor(revert_chunk);
            self.set_commitment
                .swbf_inactive
                .mutate_leaf_raw(chunk_index, new_chunk.hash::<H>(&hasher));
            self.chunks.set(chunk_index, new_chunk);

            // To check if a bit was set in `revert_chunk` that was not set in previous_chunk, we can
            // do a bit-wise AND on the `revert_chunk` and the updated `new_chunk`. If this is
            // non-zero it means that a bit was set in `revert_chunk` but not in `previous_chunk`.
            // If this is the case, then we have attempted to revert an unset bit, and that is an
            // error.
            unset_bit_encountered |= !revert_chunk.and(new_chunk).is_unset();
        }

        assert!(
            !unset_bit_encountered,
            "Caller may not attempt to unset a bit that was not set"
        );
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

    /// Flush the databases. Does not persist the active window as this lives in memory. The caller
    /// must persist the active window seperately.
    pub fn flush(&mut self) {
        self.chunks.flush();
        self.set_commitment.aocl.flush();
        self.set_commitment.swbf_inactive.flush();
    }
}

#[cfg(test)]
mod archival_mutator_set_tests {
    use super::*;
    use crate::test_shared::mutator_set::{
        empty_archival_ms, make_item_and_randomness_for_blake3, make_item_and_randomness_for_rp,
    };
    use itertools::Itertools;
    use rand::distributions::Standard;
    use rand::prelude::Distribution;
    use rand::Rng;
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
                prepare_random_addition(&mut archival_mutator_set);

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

    #[should_panic(expected = "Caller may not attempt to unset a bit that was not set")]
    #[test]
    fn revert_remove_from_active_bloom_filter_panic() {
        type H = blake3::Hasher;

        let mut archival_mutator_set: ArchivalMutatorSet<H> = empty_archival_ms();
        let record = prepare_random_addition(&mut archival_mutator_set);
        let (item, mut addition_record, membership_proof) = record.clone();
        archival_mutator_set.add(&mut addition_record);

        let removal_record = archival_mutator_set.drop(&item, &membership_proof);

        // This next line should panic, as we're attempting to unflip an unset bit
        // in the active window
        archival_mutator_set.revert_remove(removal_record.bit_indices.to_vec());
    }

    #[should_panic(expected = "Caller may not attempt to unset a bit that was not set")]
    #[test]
    fn revert_remove_from_inactive_bloom_filter_panic() {
        type H = blake3::Hasher;

        let mut archival_mutator_set: ArchivalMutatorSet<H> = empty_archival_ms();

        for _ in 0..2 * BATCH_SIZE {
            let (_item, mut addition_record, _membership_proof) =
                prepare_random_addition(&mut archival_mutator_set);
            archival_mutator_set.add(&mut addition_record);
        }

        // This next line should panic, as we're attempting to unflip an unset bit
        // in the inactive part of the Bloom filter
        archival_mutator_set.revert_remove(vec![0, 2]);
    }

    #[test]
    fn archival_mutator_set_revert_remove_test() {
        type H = blake3::Hasher;

        let mut archival_mutator_set: ArchivalMutatorSet<H> = empty_archival_ms();

        let n_iterations = 11 * BATCH_SIZE;
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

    #[test]
    fn archival_set_batch_remove_simple_test() {
        type H = blake3::Hasher;
        let mut archival_mutator_set: ArchivalMutatorSet<H> = empty_archival_ms();

        let num_additions = 130;

        let mut membership_proofs: Vec<MsMembershipProof<H>> = vec![];
        let mut items: Vec<<H as Hasher>::Digest> = vec![];

        for _ in 0..num_additions {
            let (item, randomness) = make_item_and_randomness_for_blake3();

            let mut addition_record = archival_mutator_set.commit(&item, &randomness);
            let membership_proof = archival_mutator_set.prove(&item, &randomness, false);

            MsMembershipProof::batch_update_from_addition(
                &mut membership_proofs.iter_mut().collect::<Vec<_>>(),
                &items,
                &mut archival_mutator_set.set_commitment,
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
        archival_mutator_set.batch_remove(removal_records, &mut vec![]);
        for (mp, item) in membership_proofs.iter().zip_eq(items.iter()) {
            assert!(!archival_mutator_set.verify(item, mp));
        }
    }

    #[test]
    fn archival_set_batch_remove_dynamic_test() {
        type H = blake3::Hasher;
        let mut archival_mutator_set: ArchivalMutatorSet<H> = empty_archival_ms();

        let num_additions = 4 * BATCH_SIZE;

        for remove_factor in [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0] {
            let mut membership_proofs: Vec<MsMembershipProof<H>> = vec![];
            let mut items: Vec<<H as Hasher>::Digest> = vec![];
            for _ in 0..num_additions {
                let (item, randomness) = make_item_and_randomness_for_blake3();

                let mut addition_record = archival_mutator_set.commit(&item, &randomness);
                let membership_proof = archival_mutator_set.prove(&item, &randomness, false);

                MsMembershipProof::batch_update_from_addition(
                    &mut membership_proofs.iter_mut().collect::<Vec<_>>(),
                    &items,
                    &mut archival_mutator_set.set_commitment,
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
            let changed_indices: Vec<u128> = archival_mutator_set
                .batch_remove(removal_records, &mut membership_proofs.iter_mut().collect())
                .unwrap();

            for ((mp, item), skipped) in membership_proofs
                .iter()
                .zip_eq(items.iter())
                .zip_eq(skipped_removes.into_iter())
            {
                // If this removal record was not applied, then the membership proof must verify
                assert!(skipped == archival_mutator_set.verify(item, mp));
            }

            // Check the return value: That all reported bits were actually flipped.
            // This function call should panic if that was not the case.
            archival_mutator_set.revert_remove(changed_indices);

            // Verify that mutator set before and after removal are the same
            assert_eq!(commitment_prior_to_removal, archival_mutator_set.get_commitment(), "After reverting the removes, mutator set's commitment must equal the one before elements were removed.");
        }
    }

    fn prepare_random_addition<H: Hasher>(
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
