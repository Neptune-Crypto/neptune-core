use rusty_leveldb::{LdbIterator, DB};
use std::{
    collections::{HashMap, HashSet},
    error::Error,
};
use twenty_first::{
    shared_math::b_field_element::BFieldElement,
    util_types::{
        database_vector::DatabaseVector,
        mmr::{self, archival_mmr::ArchivalMmr, mmr_trait::Mmr},
        simple_hasher::{Hasher, ToDigest},
    },
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

pub struct ArchivalMutatorSet<H>
where
    u128: ToDigest<<H as Hasher>::Digest>,
    Vec<BFieldElement>: ToDigest<<H as Hasher>::Digest>,
    H: Hasher,
{
    set_commitment: SetCommitment<H, ArchivalMmr<H>>,
    chunks: DatabaseVector<Chunk>,
}

impl<H> MutatorSet<H> for ArchivalMutatorSet<H>
where
    u128: ToDigest<<H as Hasher>::Digest>,
    Vec<BFieldElement>: ToDigest<<H as Hasher>::Digest>,
    H: Hasher,
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

    fn remove(&mut self, removal_record: &RemovalRecord<H>) {
        let new_chunks: HashMap<u128, Chunk> = self.set_commitment.remove_helper(removal_record);
        for (chunk_index, chunk) in new_chunks {
            self.chunks.set(chunk_index, chunk);
        }
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
impl<H> ArchivalMutatorSet<H>
where
    u128: ToDigest<<H as Hasher>::Digest>,
    Vec<BFieldElement>: ToDigest<<H as Hasher>::Digest>,
    H: Hasher,
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
        let bits = get_swbf_indices(&H::new(), item, randomness, index);

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
}

#[cfg(test)]
mod archival_mutator_set_tests {
    use crate::test_shared::mutator_set::empty_archival_ms;
    use rand::prelude::*;
    use twenty_first::util_types::{blake3_wrapper, simple_hasher::Hasher};

    use super::*;

    #[test]
    fn new_or_restore_test() {
        type Hasher = blake3::Hasher;
        let hasher = Hasher::new();
        let opt = rusty_leveldb::in_memory();
        let chunks_db = DB::open("chunks", opt.clone()).unwrap();
        let aocl_mmr_db = DB::open("aocl", opt.clone()).unwrap();
        let swbf_inactive_mmr_db = DB::open("swbf_inactive", opt.clone()).unwrap();
        let active_window_db = DB::open("active_window", opt.clone()).unwrap();

        let mut archival_mutator_set: ArchivalMutatorSet<Hasher> =
            ArchivalMutatorSet::new_or_restore(
                aocl_mmr_db,
                swbf_inactive_mmr_db,
                chunks_db,
                active_window_db,
            );

        let mut rng = thread_rng();
        let item = hasher.hash(
            &(0..3)
                .map(|_| BFieldElement::new(rng.next_u64()))
                .collect::<Vec<_>>(),
        );
        let randomness = hasher.hash(
            &(0..3)
                .map(|_| BFieldElement::new(rng.next_u64()))
                .collect::<Vec<_>>(),
        );

        let mut addition_record = archival_mutator_set.commit(&item, &randomness);
        let membership_proof = archival_mutator_set.prove(&item, &randomness, false);
        archival_mutator_set.add(&mut addition_record);
        assert!(archival_mutator_set.verify(&item, &membership_proof));

        let mut removal_record: RemovalRecord<Hasher> =
            archival_mutator_set.drop(&item.into(), &membership_proof);
        archival_mutator_set.remove(&mut removal_record);

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
        let swbf_inactive_mmr_db = DB::open("swbf_inactive", opt.clone()).unwrap();
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
        type Hasher = blake3::Hasher;
        type Digest = blake3_wrapper::Blake3Hash;
        let hasher = Hasher::new();
        let mut archival_mutator_set: ArchivalMutatorSet<Hasher> = empty_archival_ms();

        let num_additions = 65;

        let mut membership_proofs: Vec<MsMembershipProof<Hasher>> = vec![];
        let mut items: Vec<Digest> = vec![];
        let mut rng = thread_rng();

        for i in 0..num_additions {
            let item = hasher.hash(
                &(0..3)
                    .map(|_| BFieldElement::new(rng.next_u64()))
                    .collect::<Vec<_>>(),
            );
            let randomness = hasher.hash(
                &(0..3)
                    .map(|_| BFieldElement::new(rng.next_u64()))
                    .collect::<Vec<_>>(),
            );

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
}
