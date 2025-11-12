use std::ops::Deref;

#[cfg(any(test, feature = "arbitrary-impls"))]
use arbitrary::Arbitrary;
use get_size2::GetSize;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;
use tasm_lib::triton_vm::prelude::BFieldElement;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;

use super::block_body::BlockBody;
use crate::protocol::consensus::block::Claim;
use crate::protocol::consensus::block::Tip5;
use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
use crate::protocol::consensus::transaction::validity::single_proof::single_proof_claim;
use crate::protocol::proof_abstractions::mast_hash::MastHash;

pub(crate) const MAX_NUM_CLAIMS: usize = 500;

/// Encapsulates the claims proven by the block proof.
///
/// Every appendix claim has an identical input: the block body's hash; and an
/// identical output: the empty string.
///
/// The appendix is the keystone of soft-fork-friendly upgrades to the protocol.
/// The block proof establishes that all claims in the appendix are valid.
/// The appendix can softly be extended with new claims.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BFieldCodec, GetSize, Default)]
#[cfg_attr(any(test, feature = "arbitrary-impls"), derive(Arbitrary))]
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
    pub(crate) fn consensus_claims(
        block_body: &BlockBody,
        consensus_rule_set: ConsensusRuleSet,
    ) -> Vec<Claim> {
        // Add more claims here when softforking.
        let tx_is_valid = Self::transaction_validity_claim(
            block_body.transaction_kernel.mast_hash(),
            consensus_rule_set,
        );

        vec![tx_is_valid]
    }

    pub(crate) fn transaction_validity_claim(
        transaction_kernel_mast_hash: Digest,
        consensus_rule_set: ConsensusRuleSet,
    ) -> Claim {
        single_proof_claim(transaction_kernel_mast_hash, consensus_rule_set)
    }

    pub(crate) fn _claims(&self) -> &Vec<Claim> {
        &self.claims
    }
}

impl Deref for BlockAppendix {
    type Target = Vec<Claim>;

    fn deref(&self) -> &Self::Target {
        &self.claims
    }
}
