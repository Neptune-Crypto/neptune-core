use arbitrary::Arbitrary;
use get_size::GetSize;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::triton_vm::prelude::BFieldElement;
use tasm_lib::twenty_first::prelude::AlgebraicHasher;
use tasm_lib::Digest;
use twenty_first::math::bfield_codec::BFieldCodec;

use crate::models::blockchain::block::validity::transaction_is_valid::TransactionIsValid;
use crate::models::blockchain::block::Claim;
use crate::models::blockchain::block::Tip5;
use crate::prelude::twenty_first;

/// Encapsulates the claims proven by the block proof.
///
/// Every appendix claim has an identical input: the block body's hash; and an
/// identical output: the empty string.
///
/// The appendix is the keystone of soft-fork-friendly upgrades to the protocol.
/// The block proof establishes that all claims in the appendix are valid.
/// The appendix can softly be extended with new claims.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BFieldCodec, GetSize, Arbitrary)]
pub(crate) struct BlockAppendix {
    claims: Vec<Claim>,
}

impl BlockAppendix {
    pub(crate) fn new(claims: Vec<Claim>) -> Self {
        Self { claims }
    }

    pub(crate) fn claims_as_output(&self) -> Vec<BFieldElement> {
        self.claims
            .iter()
            .map(Tip5::hash)
            .flat_map(|d| d.values().to_vec())
            .collect()
    }

    /// Return the list of claims that this node requires for a block to be
    /// considered valid.
    pub(crate) fn consensus_claims(block_body_mast_hash: Digest) -> Vec<Claim> {
        // Add more claims here when softforking.
        let tx_is_valid = TransactionIsValid::claim(block_body_mast_hash);

        vec![tx_is_valid]
    }
}
