use twenty_first::util_types::simple_hasher::Hasher;

use super::{
    addition_record::AdditionRecord, ms_membership_proof::MsMembershipProof,
    removal_record::RemovalRecord,
};

pub trait MutatorSet<H>
where
    H: Hasher,
{
    /**
     * prove
     * Generates a membership proof that will be valid when the item
     * is added to the mutator set.
     */
    fn prove(
        &mut self,
        item: &H::Digest,
        randomness: &H::Digest,
        store_bits: bool,
    ) -> MsMembershipProof<H>;

    fn verify(&mut self, item: &H::Digest, membership_proof: &MsMembershipProof<H>) -> bool;

    /// Generates an addition record from an item and explicit random-
    /// ness. The addition record is itself a commitment to the item,
    /// but tailored to adding the item to the mutator set in its
    /// current state.
    fn commit(&mut self, item: &H::Digest, randomness: &H::Digest) -> AdditionRecord<H>;

    /**
     * drop
     * Generates a removal record with which to update the set commitment.
     */
    fn drop(
        &mut self,
        item: &H::Digest,
        membership_proof: &MsMembershipProof<H>,
    ) -> RemovalRecord<H>;

    ///   add
    ///   Updates the set-commitment with an addition record. The new
    ///   commitment represents the set $S union {c}$ ,
    ///   where S is the set represented by the old
    ///   commitment and c is the commitment to the new item AKA the
    ///   *addition record*.
    fn add(&mut self, addition_record: &mut AdditionRecord<H>);

    /// remove
    /// Updates the mutator set so as to remove the item determined by
    /// its removal record.
    /// Optionally returns a list of indices into the Bloom filter that
    /// were flipped from 0 to 1 by the `RemovalRecord`.
    fn remove(&mut self, removal_record: &RemovalRecord<H>) -> Option<Vec<u128>>;

    fn batch_remove(
        &mut self,
        removal_records: Vec<RemovalRecord<H>>,
        preserved_membership_proofs: &mut Vec<&mut MsMembershipProof<H>>,
    ) -> Option<Vec<u128>>;

    /// get_commitment
    /// Return a commitment to the entire mutator set
    fn get_commitment(&mut self) -> H::Digest;
}
