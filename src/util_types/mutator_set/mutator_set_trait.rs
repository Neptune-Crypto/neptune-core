use crate::util_types::simple_hasher::Hasher;

use super::{
    addition_record::AdditionRecord, membership_proof::MembershipProof,
    removal_record::RemovalRecord,
};

pub trait MutatorSet<H>
where
    H: Hasher,
{
    fn default() -> Self;
    fn prove(
        &self,
        item: &H::Digest,
        randomness: &H::Digest,
        store_bits: bool,
    ) -> MembershipProof<H>;
    fn verify(&self, item: &H::Digest, membership_proof: &MembershipProof<H>) -> bool;
    fn commit(&self, item: &H::Digest, randomness: &H::Digest) -> AdditionRecord<H>;
    fn drop(&self, item: &H::Digest, membership_proof: &MembershipProof<H>) -> RemovalRecord<H>;
    fn add(&mut self, addition_record: &AdditionRecord<H>);
    fn remove(&mut self, removal_record: &RemovalRecord<H>);
}
