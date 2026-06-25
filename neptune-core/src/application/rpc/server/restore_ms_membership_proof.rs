use serde::Deserialize;
use serde::Serialize;

use crate::api::export::BlockHeight;
use crate::api::export::Digest;
use crate::util_types::mutator_set::archival_mutator_set::MsMembershipProofPrivacyPreserving;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;

/// Data structure for returning components of a mutator set membership proof in
/// a privacy preserving manner. Includes information about the tip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseMsMembershipProofPrivacyPreserving {
    pub tip_height: BlockHeight,
    pub tip_hash: Digest,
    pub tip_mutator_set: MutatorSetAccumulator,
    pub membership_proofs: Vec<MsMembershipProofPrivacyPreserving>,
}
