use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;

use crate::protocol::consensus::block::block_height::BlockHeight;
use crate::protocol::consensus::block::difficulty_control::ProofOfWork;
use crate::protocol::consensus::block::Block;

/// Used to tell peers that a new block has been found without having to
/// send the entire block
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerBlockNotification {
    pub hash: Digest,
    pub height: BlockHeight,
    pub(crate) cumulative_proof_of_work: ProofOfWork,
}

impl From<&Block> for PeerBlockNotification {
    fn from(block: &Block) -> Self {
        PeerBlockNotification {
            hash: block.hash(),
            height: block.kernel.header.height,
            cumulative_proof_of_work: block.kernel.header.cumulative_proof_of_work,
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::PeerBlockNotification;
    use crate::protocol::consensus::block::validity::block_primitive_witness::tests::deterministic_block_primitive_witness;

    #[test]
    fn block_notification_hash_matches_block_hash() {
        let witness = deterministic_block_primitive_witness();
        let a_block = witness.predecessor_block();
        let as_notification: PeerBlockNotification = a_block.into();
        assert_eq!(
            a_block.hash(),
            as_notification.hash,
            "Block notification hash must match block hash"
        );
    }
}
