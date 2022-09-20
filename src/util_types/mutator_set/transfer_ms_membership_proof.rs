use super::chunk_dictionary::ChunkDictionary;
use serde::{Deserialize, Serialize};

use twenty_first::util_types::{mmr, simple_hasher};

/// Type to transfer membership proof without risking that `cached_bits` are shared between
/// peers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TransferMsMembershipProof<H: simple_hasher::Hasher> {
    pub randomness: H::Digest,
    pub auth_path_aocl: mmr::mmr_membership_proof::MmrMembershipProof<H>,
    pub target_chunks: ChunkDictionary<H>,
}

#[cfg(test)]
mod transfer_ms_membership_proof_tests {
    use crate::test_shared::mutator_set::insert_item;
    use crate::util_types::mutator_set::{
        ms_membership_proof::MsMembershipProof, set_commitment::SetCommitment,
    };
    use twenty_first::{
        shared_math::rescue_prime_regular::RescuePrimeRegular,
        util_types::mmr::mmr_accumulator::MmrAccumulator,
    };

    use super::*;

    #[test]
    fn serialization_test() {
        // You could argue that this test doesn't belong here, as it tests the behavior of
        // an imported library. I included it here, though, because the setup seems a bit clumsy
        // to me so far.
        type Hasher = RescuePrimeRegular;
        type Mmr = MmrAccumulator<Hasher>;
        type Ms = SetCommitment<Hasher, Mmr>;
        let mut mutator_set = Ms::default();
        let (mp, item) = insert_item(&mut mutator_set);

        let transfer_mp: TransferMsMembershipProof<Hasher> = mp.clone().into();
        let json = serde_json::to_string(&transfer_mp).unwrap();
        let s_back = serde_json::from_str::<TransferMsMembershipProof<Hasher>>(&json).unwrap();
        let reconstructed_mp: MsMembershipProof<RescuePrimeRegular> = s_back.into();
        mutator_set.verify(&item, &reconstructed_mp);
        assert_eq!(reconstructed_mp.randomness, transfer_mp.randomness);
        assert_eq!(mp.randomness, transfer_mp.randomness);
        assert_eq!(mp.auth_path_aocl, transfer_mp.auth_path_aocl);
        assert_eq!(mp.target_chunks, transfer_mp.target_chunks);
        assert!(reconstructed_mp.cached_bits.is_none());
    }
}
