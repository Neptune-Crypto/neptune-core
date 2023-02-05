use twenty_first::shared_math::rescue_prime_digest::Digest;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;

use super::addition_record::AdditionRecord;
use super::ms_membership_proof::MsMembershipProof;
use super::removal_record::RemovalRecord;

pub trait MutatorSet<H: AlgebraicHasher> {
    /**
     * prove
     * Generates a membership proof that will be valid when the item
     * is added to the mutator set.
     */
    fn prove(
        &mut self,
        item: &Digest,
        randomness: &Digest,
        store_bits: bool,
    ) -> MsMembershipProof<H>;

    fn verify(&mut self, item: &Digest, membership_proof: &MsMembershipProof<H>) -> bool;

    /// Generates an addition record from an item and explicit random-
    /// ness. The addition record is itself a commitment to the item,
    /// but tailored to adding the item to the mutator set in its
    /// current state.
    fn commit(&mut self, item: &Digest, randomness: &Digest) -> AdditionRecord;

    /**
     * drop
     * Generates a removal record with which to update the set commitment.
     */
    fn drop(&mut self, item: &Digest, membership_proof: &MsMembershipProof<H>) -> RemovalRecord<H>;

    ///   add
    ///   Updates the set-commitment with an addition record. The new
    ///   commitment represents the set $S union {c}$ ,
    ///   where S is the set represented by the old
    ///   commitment and c is the commitment to the new item AKA the
    ///   *addition record*.
    fn add(&mut self, addition_record: &mut AdditionRecord);

    /// remove
    /// Updates the mutator set so as to remove the item determined by
    /// its removal record.
    fn remove(&mut self, removal_record: &RemovalRecord<H>);

    /// batch_remove
    /// Apply multiple removal records, and update a list of membership proofs to
    /// be valid after the application of these removal records.
    fn batch_remove(
        &mut self,
        removal_records: Vec<RemovalRecord<H>>,
        preserved_membership_proofs: &mut [&mut MsMembershipProof<H>],
    );

    /// get_commitment
    /// Return a commitment to the entire mutator set
    fn get_commitment(&mut self) -> Digest;
}
