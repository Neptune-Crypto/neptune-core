use neptune_mutator_set::archival_mutator_set::MsMembershipProofPrivacyPreserving;
use neptune_mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use neptune_primitives::block_height::BlockHeight;
use serde::Deserialize;
use serde::Serialize;

use crate::api::export::Digest;

/// Data structure for returning components of a mutator set membership proof in
/// a privacy preserving manner. Includes information about the tip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseMsMembershipProofPrivacyPreserving {
    pub tip_height: BlockHeight,
    pub tip_hash: Digest,
    pub tip_mutator_set: MutatorSetAccumulator,
    pub membership_proofs: Vec<MsMembershipProofPrivacyPreserving>,
}
