use crate::models::blockchain::shared::Hash;
use crate::prelude::twenty_first;

use twenty_first::shared_math::tip5::Digest;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;

use super::addition_record::AdditionRecord;
use super::ms_membership_proof::MsMembershipProof;
use super::removal_record::RemovalRecord;

/// Generates an addition record from an item and explicit random-
/// ness. The addition record is itself a commitment to the item.
pub fn commit(item: Digest, sender_randomness: Digest, receiver_digest: Digest) -> AdditionRecord {
    let canonical_commitment =
        Hash::hash_pair(Hash::hash_pair(item, sender_randomness), receiver_digest);

    AdditionRecord::new(canonical_commitment)
}

pub trait MutatorSet {
    /// Generates a membership proof that will be valid when the item
    /// is added to the mutator set.
    fn prove(
        &mut self,
        item: Digest,
        sender_randomness: Digest,
        receiver_preimage: Digest,
    ) -> MsMembershipProof;

    fn verify(&self, item: Digest, membership_proof: &MsMembershipProof) -> bool;

    /// Generates a removal record with which to update the set commitment.
    fn drop(&self, item: Digest, membership_proof: &MsMembershipProof) -> RemovalRecord;

    /// Updates the set-commitment with an addition record.
    fn add(&mut self, addition_record: &AdditionRecord);

    /// Updates the mutator set so as to remove the item determined by
    /// its removal record.
    fn remove(&mut self, removal_record: &RemovalRecord);

    /// batch_remove
    /// Apply multiple removal records, and update a list of membership proofs to
    /// be valid after the application of these removal records.
    fn batch_remove(
        &mut self,
        removal_records: Vec<RemovalRecord>,
        preserved_membership_proofs: &mut [&mut MsMembershipProof],
    );

    /// hash
    /// Return single hash digest that commits to the entire mutator set
    fn hash(&self) -> Digest;
}

// #[allow(async_fn_in_trait)]
#[async_trait::async_trait]
pub trait MutatorSetAsync {
    /// Generates a membership proof that will be valid when the item
    /// is added to the mutator set.
    async fn prove(
        &mut self,
        item: Digest,
        sender_randomness: Digest,
        receiver_preimage: Digest,
    ) -> MsMembershipProof;

    async fn verify(&self, item: Digest, membership_proof: &MsMembershipProof) -> bool;

    /// Generates a removal record with which to update the set commitment.
    fn drop(&self, item: Digest, membership_proof: &MsMembershipProof) -> RemovalRecord;

    /// Updates the set-commitment with an addition record.
    async fn add(&mut self, addition_record: &AdditionRecord);

    /// Updates the mutator set so as to remove the item determined by
    /// its removal record.
    async fn remove(&mut self, removal_record: &RemovalRecord);

    /// batch_remove
    /// Apply multiple removal records, and update a list of membership proofs to
    /// be valid after the application of these removal records.
    async fn batch_remove(
        &mut self,
        removal_records: Vec<RemovalRecord>,
        preserved_membership_proofs: &mut [&mut MsMembershipProof],
    );

    /// hash
    /// Return single hash digest that commits to the entire mutator set
    async fn hash(&self) -> Digest;
}
