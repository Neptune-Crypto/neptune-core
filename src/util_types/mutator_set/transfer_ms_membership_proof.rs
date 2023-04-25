use super::chunk_dictionary::ChunkDictionary;
use serde::{Deserialize, Serialize};

use twenty_first::shared_math::tip5::Digest;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;
use twenty_first::util_types::mmr::mmr_membership_proof::MmrMembershipProof;

/// Type to transfer membership proof without risking that `cached_indices` are shared between
/// peers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransferMsMembershipProof<H: AlgebraicHasher> {
    pub sender_randomness: Digest,
    pub receiver_preimage: Digest,
    pub auth_path_aocl: MmrMembershipProof<H>,
    pub target_chunks: ChunkDictionary<H>,
}

#[cfg(test)]
mod transfer_ms_membership_proof_tests {
    use crate::test_shared::mutator_set::insert_mock_item;
    use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
    use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
    use crate::util_types::mutator_set::mutator_set_kernel::MutatorSetKernel;
    use twenty_first::shared_math::tip5::Tip5;
    use twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;

    use super::*;

    #[test]
    fn serialization_test() {
        // You could argue that this test doesn't belong here, as it tests the behavior of
        // an imported library. I included it here, though, because the setup seems a bit clumsy
        // to me so far.
        type H = Tip5;
        type Mmr = MmrAccumulator<H>;
        type Ms = MutatorSetKernel<H, Mmr>;
        let mut mutator_set: Ms = MutatorSetAccumulator::<H>::default().kernel;

        let (mp, item) = insert_mock_item(&mut mutator_set);

        let transfer_mp: TransferMsMembershipProof<H> = mp.clone().into();
        let json = serde_json::to_string(&transfer_mp).unwrap();
        let s_back = serde_json::from_str::<TransferMsMembershipProof<H>>(&json).unwrap();
        let reconstructed_mp: MsMembershipProof<H> = s_back.into();
        mutator_set.verify(&item, &reconstructed_mp);
        assert_eq!(
            reconstructed_mp.sender_randomness,
            transfer_mp.sender_randomness
        );
        assert_eq!(mp.sender_randomness, transfer_mp.sender_randomness);
        assert_eq!(mp.auth_path_aocl, transfer_mp.auth_path_aocl);
        assert_eq!(mp.target_chunks, transfer_mp.target_chunks);
        assert!(reconstructed_mp.cached_indices.is_none());
    }
}
