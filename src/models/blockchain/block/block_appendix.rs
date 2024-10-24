use get_size::GetSize;
use itertools::Itertools;
use serde::Deserialize;
use serde::Serialize;
use std::vec;
use tasm_lib::Digest;
use twenty_first::math::bfield_codec::BFieldCodec;

use super::block_body::BlockBody;
use crate::models::blockchain::block::validity::transaction_is_valid::TransactionIsValid;
use crate::models::blockchain::block::Claim;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
use crate::prelude::twenty_first;

/// Encapsulates the claims proven by the block proof.
///
/// Every appendix claim has an identical input: the block body's hash; and an
/// identical output: the empty string.
///
/// The appendix is the keystone of soft-fork-friendly upgrades to the protocol.
/// The block proof establishes that all claims in the appendix are valid.
/// The appendix can softly be extended with new claims.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BFieldCodec, GetSize)]
pub(crate) struct BlockAppendix {
    claims: Vec<Claim>,
}

impl BlockAppendix {
    pub(crate) fn new(claims: Vec<Claim>) -> Self {
        Self { claims }
    }

    fn claims_for_block_body(block_body_hash: Digest) -> Vec<Claim> {
        let block_body_hash_as_input = block_body_hash.reversed().values().to_vec();
        Self::consensus_programs()
            .into_iter()
            .map(|program| program.hash())
            .map(Claim::new)
            .map(|claim| claim.with_input(block_body_hash_as_input.clone()))
            .collect_vec()
    }

    pub(crate) fn consensus_programs() -> Vec<Box<dyn ConsensusProgram>> {
        vec![Box::new(TransactionIsValid)]
    }
}

impl From<&BlockBody> for BlockAppendix {
    fn from(body: &BlockBody) -> Self {
        Self::new(Self::claims_for_block_body(body.mast_hash()))
    }
}
