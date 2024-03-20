use crate::twenty_first::shared_math::digest::Digest;
use crate::twenty_first::util_types::algebraic_hasher::AlgebraicHasher;
use crate::twenty_first::util_types::mmr::mmr_membership_proof::MmrMembershipProof;

use super::MmrAccumulator;

#[allow(async_fn_in_trait)]
pub trait Mmr<H: AlgebraicHasher> {
    /// Create a new MMR instanc from a list of hash digests. The supplied digests
    /// are the leaves of the MMR.

    // constructors cannot be part of the interface since the archival version requires a
    // database which we want the caller to create, and the accumulator does not need a
    // constructor.

    /// Calculate a single hash digest committing to the entire MMR.
    async fn bag_peaks(&self) -> Digest;

    /// Returns the peaks of the MMR, which are roots of the Merkle trees that constitute
    /// the MMR
    async fn get_peaks(&self) -> Vec<Digest>;

    /// Returns `true` iff the MMR has no leaves
    async fn is_empty(&self) -> bool;

    /// Returns the number of leaves in the MMR
    async fn count_leaves(&self) -> u64;

    /// Append a hash digest to the MMR
    async fn append(&mut self, new_leaf: Digest) -> MmrMembershipProof<H>;

    /// Mutate an existing leaf. It is the caller's responsibility that the
    /// membership proof is valid. If the membership proof is wrong, the MMR
    /// will end up in a broken state.
    async fn mutate_leaf(&mut self, old_membership_proof: &MmrMembershipProof<H>, new_leaf: Digest);

    /// Batch mutate an MMR while updating a list of membership proofs. Returns the indices of the
    /// membership proofs that have changed as a result of this operation.
    async fn batch_mutate_leaf_and_update_mps(
        &mut self,
        membership_proofs: &mut [&mut MmrMembershipProof<H>],
        mutation_data: Vec<(MmrMembershipProof<H>, Digest)>,
    ) -> Vec<usize>;

    /// Returns true if a list of leaf mutations and a list of appends results in the expected
    /// `new_peaks`.
    async fn verify_batch_update(
        &self,
        new_peaks: &[Digest],
        appended_leafs: &[Digest],
        leaf_mutations: &[(Digest, MmrMembershipProof<H>)],
    ) -> bool;

    /// Return an MMR accumulator containing only peaks and leaf count
    async fn to_accumulator(&self) -> MmrAccumulator<H>;
}
