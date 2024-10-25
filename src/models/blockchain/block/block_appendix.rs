use arbitrary::Arbitrary;
use get_size::GetSize;
use serde::Deserialize;
use serde::Serialize;
use twenty_first::math::bfield_codec::BFieldCodec;

use crate::models::blockchain::block::Claim;
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
}
