use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;
use tasm_lib::twenty_first::bfe_array;
use tracing::info;

use crate::application::rpc::server::BlockHeader;
use crate::application::rpc::server::NativeCurrencyAmount;
use crate::protocol::consensus::block::block_header::BlockPow;
use crate::protocol::consensus::block::pow::PowMastPaths;
use crate::BFieldElement;
use crate::Block;

/// Data required to attempt to solve the proof-of-work puzzle that allows the
/// minting of the next block.
#[derive(Clone, Debug, Copy, Serialize, Deserialize)]
pub struct ProofOfWorkPuzzle {
    // All fields public since used downstream by mining pool software.
    pub auth_paths: PowMastPaths,

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
}

impl ProofOfWorkPuzzle {
    /// Return a PoW puzzle assuming that the caller has already set the correct
    /// guesser digest.
    pub fn new(block_proposal: Block, latest_block_header: BlockHeader) -> Self {
        let guesser_reward = block_proposal
            .body()
            .total_guesser_reward()
            .expect("Block proposal must have well-defined guesser reward");
        let auth_paths = block_proposal.pow_mast_paths();
        let threshold = latest_block_header.difficulty.target();
        let prev_block = block_proposal.header().prev_block_digest;

        let id = Tip5::hash(&auth_paths);

        Self {
            auth_paths,
            threshold,
            total_guesser_reward: guesser_reward,
            id,
            prev_block,
        }
    }

    /// Solve a PoW from a puzzle.
    ///
    /// Takes a very long time and cannot be cancelled while running.
    pub fn solve(&self) -> BlockPow {
        use rayon::prelude::*;
        info!("Starting PoW preprocessing");
        let guesser_buffer = BlockPow::preprocess(self.auth_paths, None);
        info!("Done with PoW preprocessing");

        info!("Now attempting to find valid nonce");
        let solution = (0u64..u64::MAX)
            .into_par_iter()
            .map(|i| {
                let nonce = Digest(bfe_array![0, 0, 0, 0, i]);
                BlockPow::guess(&guesser_buffer, nonce, self.threshold)
            })
            .find_map_any(|x| x)
            .expect("Should find solution within 2^{64} attempts");
        info!("Found valid nonce! nonce: {}", solution.nonce);

        solution
    }
}
