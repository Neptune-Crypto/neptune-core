use std::{
    collections::{HashMap, HashSet},
    error::Error,
};

use crate::{
    shared_math::b_field_element::BFieldElement,
    util_types::{
        mmr::{self, archival_mmr::ArchivalMmr, mmr_trait::Mmr},
        simple_hasher::{Hasher, ToDigest},
    },
};

use super::{
    addition_record::AdditionRecord,
    chunk::Chunk,
    chunk_dictionary::ChunkDictionary,
    ms_membership_proof::MsMembershipProof,
    mutator_set_trait::MutatorSet,
    removal_record::RemovalRecord,
    set_commitment::{get_swbf_indices, SetCommitment, SetCommitmentError, BATCH_SIZE, CHUNK_SIZE},
};

pub struct ArchivalMutatorSet<H>
where
    u128: ToDigest<<H as Hasher>::Digest>,
    Vec<BFieldElement>: ToDigest<<H as Hasher>::Digest>,
    H: Hasher,
{
    set_commitment: SetCommitment<H, ArchivalMmr<H>>,
    chunks: HashMap<u128, Chunk>,
}

impl<H> MutatorSet<H> for ArchivalMutatorSet<H>
where
    u128: ToDigest<<H as Hasher>::Digest>,
    Vec<BFieldElement>: ToDigest<<H as Hasher>::Digest>,
    H: Hasher,
{
    fn default() -> Self {
        Self {
            set_commitment: SetCommitment::default(),
            chunks: HashMap::new(),
        }
    }

    fn prove(
        &self,
        item: &<H as Hasher>::Digest,
        randomness: &<H as Hasher>::Digest,
        store_bits: bool,
    ) -> MsMembershipProof<H> {
        self.set_commitment.prove(item, randomness, store_bits)
    }

    fn verify(
        &self,
        item: &<H as Hasher>::Digest,
        membership_proof: &MsMembershipProof<H>,
    ) -> bool {
        self.set_commitment.verify(item, membership_proof)
    }

    fn commit(
        &self,
        item: &<H as Hasher>::Digest,
        randomness: &<H as Hasher>::Digest,
    ) -> AdditionRecord<H> {
        self.set_commitment.commit(item, randomness)
    }

    fn drop(
        &self,
        item: &<H as Hasher>::Digest,
        membership_proof: &MsMembershipProof<H>,
    ) -> RemovalRecord<H> {
        self.set_commitment.drop(item, membership_proof)
    }

    fn add(&mut self, addition_record: &AdditionRecord<H>) {
        let new_chunk: Option<(u128, Chunk)> = self.set_commitment.add_helper(addition_record);
        match new_chunk {
            None => (),
            Some((chunk_index, chunk)) => {
                self.chunks.insert(chunk_index, chunk);
            }
        }
    }

    fn remove(&mut self, removal_record: &RemovalRecord<H>) {
        let new_chunks: HashMap<u128, Chunk> = self.set_commitment.remove_helper(removal_record);
        for (chunk_index, chunk) in new_chunks {
            self.chunks.insert(chunk_index, chunk);
        }
    }

    fn get_commitment(&self) -> <H as Hasher>::Digest {
        todo!()
    }
}

/// Methods that only work when implementing using archival MMRs as the underlying two MMRs
impl<H> ArchivalMutatorSet<H>
where
    u128: ToDigest<<H as Hasher>::Digest>,
    Vec<BFieldElement>: ToDigest<<H as Hasher>::Digest>,
    H: Hasher,
{
    /// Returns an authentication path for an element in the append-only commitment list
    pub fn get_aocl_authentication_path(
        &self,
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
        &self,
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
        let chunk: Chunk = match self.chunks.get(&chunk_index) {
            Some(chnk) => *chnk,
            None => {
                // This should never happen. It would mean that chunks are missing but that the
                // archival MMR has the membership proof for the chunk. That would be a programming
                // error.
                return Err(Box::new(
                    SetCommitmentError::RestoreMembershipProofDidNotFindChunkForChunkIndex,
                ));
            }
        };

        Ok((chunk_auth_path, chunk))
    }

    /// Restore membership_proof. If called on someone else's UTXO, this leaks privacy. In this case,
    /// caller is better off using `get_aocl_authentication_path` and `get_chunk_and_auth_path` for the
    /// relevant indices.
    pub fn restore_membership_proof(
        &self,
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
            let chunk: &Chunk = match self.chunks.get(&chunk_index) {
                Some(chnk) => chnk,
                None => {
                    return Err(Box::new(
                        SetCommitmentError::RestoreMembershipProofDidNotFindChunkForChunkIndex,
                    ))
                }
            };
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
    use crate::util_types::{blake3_wrapper, simple_hasher::Hasher};
    use rand::prelude::*;
    use rand_core::RngCore;

    use super::*;

    #[test]
    fn archival_set_commitment_test() {
        type Hasher = blake3::Hasher;
        type Digest = blake3_wrapper::Blake3Hash;
        let hasher = Hasher::new();
        let mut archival_mutator_set = ArchivalMutatorSet::<Hasher>::default();

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

            let addition_record = archival_mutator_set.commit(&item, &randomness);
            let membership_proof = archival_mutator_set.prove(&item, &randomness, false);

            let res = MsMembershipProof::batch_update_from_addition(
                &mut membership_proofs.iter_mut().collect::<Vec<_>>(),
                &items,
                &archival_mutator_set.set_commitment,
                &addition_record,
            );
            assert!(res.is_ok());

            archival_mutator_set.add(&addition_record);
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
