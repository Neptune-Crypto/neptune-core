use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;

use crate::application::json_rpc::core::model::block::RpcBlock;
use crate::application::json_rpc::core::model::common::RpcNativeCurrencyAmount;
use crate::protocol::consensus::block::difficulty_control::Difficulty;
use crate::protocol::consensus::block::pow::PowMastPaths;
use crate::protocol::consensus::block::Block;

/// Data required to attempt to solve the proof-of-work puzzle that allows the
/// minting of the next block.
#[derive(Clone, Debug, Copy, Serialize, Deserialize)]
pub struct RpcBlockTemplateMetadata {
    /// The pre-PoW digest of the block, serving as the unique template ID.
    pub digest: Digest,

    /// Indicates whether template is invalid due to the presence of a new tip.
    /// Can be used to reset templates in pools that perform local checks before
    /// submitting a solution to the node.
    pub prev_block: Digest,

    /// The threshold digest that defines when a PoW solution is valid. The
    /// block's hash must be less than or equal to this value.
    pub threshold: Digest,

    /// The total reward, timelocked plus liquid, for a successful guess.
    pub total_guesser_reward: RpcNativeCurrencyAmount,

    // All fields public since used downstream by mining pool software.
    pub pow_mast_paths: PowMastPaths,
}

impl RpcBlockTemplateMetadata {
    /// Extracts template metadata assuming that the caller has already set the
    /// correct guesser digest.
    pub fn new(block_proposal: &Block, parent_difficulty: Difficulty) -> Self {
        let digest = block_proposal.hash();
        let prev_block = block_proposal.header().prev_block_digest;
        let threshold = parent_difficulty.target();
        let guesser_reward = block_proposal
            .body()
            .total_guesser_reward()
            .expect("Block proposal must have well-defined guesser reward");
        let auth_paths = block_proposal.pow_mast_paths();

        Self {
            digest,
            prev_block,
            threshold,
            total_guesser_reward: guesser_reward.into(),
            pow_mast_paths: auth_paths,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RpcBlockTemplate {
    pub block: RpcBlock,
    pub metadata: RpcBlockTemplateMetadata,
}

#[cfg(test)]
mod tests {
    use tasm_lib::twenty_first::bfe_array;

    use crate::application::json_rpc::core::model::block::header::RpcBlockPow;
    use crate::protocol::consensus::block::block_header::BlockPow;
    use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
    use crate::BFieldElement;

    use super::*;

    impl RpcBlockTemplateMetadata {
        pub fn solve(&self, consensus_rule_set: ConsensusRuleSet) -> RpcBlockPow {
            let guesser_buffer = BlockPow::preprocess(
                self.pow_mast_paths,
                None,
                consensus_rule_set,
                self.prev_block,
            );

            let index_picker_preimage = guesser_buffer.index_picker_preimage(&self.pow_mast_paths);

            let solution = (0u64..u64::MAX)
                .map(|i| {
                    let nonce = Digest(bfe_array![0, 0, 0, 0, i]);

                    BlockPow::guess(
                        &guesser_buffer,
                        &self.pow_mast_paths,
                        index_picker_preimage,
                        nonce,
                        self.threshold,
                    )
                })
                .find_map(|x| x)
                .expect("Should find solution within 2^{64} attempts");

            solution.into()
        }
    }
}
