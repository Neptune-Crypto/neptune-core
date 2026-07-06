use neptune_primitives::difficulty_control::Difficulty;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;
use tasm_lib::twenty_first::bfe_array;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;
use tracing::info;

use crate::block::block_header::BlockPow;
use crate::block::pow::LustrationStatus;
use crate::block::pow::PowMastPaths;
use crate::block::Block;
use crate::consensus_rule_set::ConsensusRuleSet;
use crate::type_scripts::native_currency_amount::NativeCurrencyAmount;

/// Data required to attempt to solve the proof-of-work puzzle that allows the
/// minting of the next block.
#[derive(Clone, Debug, Copy, Serialize, Deserialize)]
pub struct ProofOfWorkPuzzle {
    // All fields public since used downstream by mining pool software.
    /// The MAST paths that allow for fast guessing
    pub pow_mast_paths: PowMastPaths,

    /// The threshold digest that defines when a PoW solution is valid. The
    /// block's hash must be less than or equal to this value.
    pub threshold: Digest,

    /// The total reward, timelocked plus liquid, for a successful guess.
    pub total_guesser_reward: NativeCurrencyAmount,

    /// An identifier for the puzzle. Needed since more than one block proposal
    /// may be known for the next block. A commitment to the entire block
    /// kernel, apart from the PoW-field of the header.
    pub id: Digest,

    /// Indicates whether template is invalid due to the presence of a new tip.
    /// Can be used to reset templates in pools that perform local checks before
    /// submitting a solution to the node.
    pub prev_block: Digest,

    /// The lustration status that must be set in the PoW field for the block
    /// to be valid. Must be set prior to calculating the block's hash.
    /// Only to be used after hard-fork beta.
    pub lustration_status: Option<LustrationStatus>,

    /// The version field in the header.
    pub version: BFieldElement,
}

impl ProofOfWorkPuzzle {
    /// Return a PoW puzzle assuming that the caller has already set the correct
    /// guesser digest.
    ///
    /// # Warning
    /// - The provided difficulty will be used, regardless of the consensus
    ///   rule set. So it must be correct.
    // TODO: Remove 2nd argument when hardfork-beta is activated
    pub fn new(block_proposal: Block, difficulty: Difficulty) -> Self {
        let guesser_reward = block_proposal
            .body()
            .total_guesser_reward()
            .expect("Block proposal must have well-defined guesser reward");
        let auth_paths = block_proposal.pow_mast_paths();
        let threshold = difficulty.target();
        let prev_block = block_proposal.header().prev_block_digest;

        let id = Tip5::hash(&auth_paths);

        let lustration_status = block_proposal.header().pow.lustration_status().ok();

        Self {
            pow_mast_paths: auth_paths,
            threshold,
            total_guesser_reward: guesser_reward,
            id,
            prev_block,
            lustration_status,
            version: block_proposal.header().version,
        }
    }

    /// Solve a PoW from a puzzle.
    ///
    /// Takes a very long time and cannot be cancelled while running. Slow
    /// implementation, as it only uses one thread.
    pub fn solve(&self, consensus_rule_set: ConsensusRuleSet) -> BlockPow {
        assert!(
            !consensus_rule_set.memory_hard_pow(),
            "solving pre-hardfork-beta (memory-hard) proof-of-work is not supported"
        );

        info!("Now attempting to find valid nonce");
        let solution = (0u64..u64::MAX)
            .map(|i| {
                let nonce = Digest(bfe_array![0, 0, 0, 0, i]);
                BlockPow::guess(
                    &self.pow_mast_paths,
                    nonce,
                    self.threshold,
                    self.lustration_status,
                    Some(self.version),
                )
            })
            .find_map(|x| x)
            .expect("Should find solution within 2^{64} attempts");
        info!("Found valid nonce! nonce: {}", solution.nonce);

        solution
    }
}
