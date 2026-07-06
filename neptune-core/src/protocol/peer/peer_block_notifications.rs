use neptune_consensus::block::Block;
use neptune_primitives::block_height::BlockHeight;
use neptune_primitives::difficulty_control::ProofOfWork;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;

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
    use neptune_consensus::block::validity::block_primitive_witness::deterministic_block_primitive_witness;
    use neptune_primitives::network::Network;

    use super::PeerBlockNotification;

    #[test]
    fn block_notification_hash_matches_block_hash() {
        let network = Network::Main;
        let witness = deterministic_block_primitive_witness(network);
        let a_block = witness.predecessor_block();
        let as_notification: PeerBlockNotification = a_block.into();
        assert_eq!(
            a_block.hash(),
            as_notification.hash,
            "Block notification hash must match block hash"
        );
    }
}
