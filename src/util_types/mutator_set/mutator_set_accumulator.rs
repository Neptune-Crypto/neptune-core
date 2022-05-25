use crate::{
    shared_math::b_field_element::BFieldElement,
    util_types::{
        mmr::mmr_accumulator::MmrAccumulator,
        simple_hasher::{Hasher, ToDigest},
    },
};

use super::{
    addition_record::AdditionRecord, membership_proof::MembershipProof,
    mutator_set_trait::MutatorSet, removal_record::RemovalRecord, set_commitment::SetCommitment,
};

pub type MutatorSetAccumulator<H> = SetCommitment<H, MmrAccumulator<H>>;

impl<H: Hasher> MutatorSet<H> for MutatorSetAccumulator<H>
where
    u128: ToDigest<<H as Hasher>::Digest>,
    Vec<BFieldElement>: ToDigest<<H as Hasher>::Digest>,
    H: Hasher,
{
    fn default() -> Self {
        SetCommitment::default()
    }

    fn prove(
        &self,
        item: &H::Digest,
        randomness: &H::Digest,
        store_bits: bool,
    ) -> MembershipProof<H> {
        self.prove(item, randomness, store_bits)
    }

    fn verify(&self, item: &H::Digest, membership_proof: &MembershipProof<H>) -> bool {
        self.verify(item, membership_proof)
    }

    fn commit(&self, item: &H::Digest, randomness: &H::Digest) -> AdditionRecord<H> {
        self.commit(item, randomness)
    }

    fn drop(&self, item: &H::Digest, membership_proof: &MembershipProof<H>) -> RemovalRecord<H> {
        self.drop(item, membership_proof)
    }

    fn add(&mut self, addition_record: &AdditionRecord<H>) {
        self.add_helper(addition_record);
    }

    fn remove(&mut self, removal_record: &RemovalRecord<H>) {
        self.remove_helper(removal_record);
    }
}
