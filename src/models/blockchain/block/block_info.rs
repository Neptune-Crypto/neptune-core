//! BlockInfo is a concise summary of a block intended for human
//! consumption/reporting in block explorers, cli, dashboard, etc.

use serde::Deserialize;
use serde::Serialize;
use twenty_first::math::digest::Digest;

use super::difficulty_control::Difficulty;
use super::difficulty_control::ProofOfWork;
use crate::models::blockchain::block::block_height::BlockHeight;
use crate::models::blockchain::block::Block;
use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::prelude::twenty_first;

/// Provides summary information about a Block
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockInfo {
    pub height: BlockHeight,
    pub digest: Digest,
    pub prev_block_digest: Digest,
    pub timestamp: Timestamp,
    pub cumulative_proof_of_work: ProofOfWork,
    pub difficulty: Difficulty,
    pub num_inputs: usize,
    pub num_outputs: usize,
    pub mining_reward: NeptuneCoins,
    pub fee: NeptuneCoins,
    pub is_genesis: bool,
    pub is_tip: bool,
    pub is_canonical: bool,
}

// note: this is used by neptune-cli block-info command.
impl std::fmt::Display for BlockInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let buf = String::new()
            + &format!("height: {}\n", self.height)
            + &format!("digest: {}\n", self.digest.to_hex())
            + &format!("prev_block_digest: {}\n", self.prev_block_digest.to_hex())
            + &format!("timestamp: {}\n", self.timestamp.standard_format())
            + &format!(
                "cumulative_proof_of_work: {}\n",
                self.cumulative_proof_of_work
            )
            + &format!("difficulty: {}\n", self.difficulty)
            + &format!("num_inputs: {}\n", self.num_inputs)
            + &format!("num_outputs: {}\n", self.num_outputs)
            + &format!("mining_reward: {}\n", self.mining_reward)
            + &format!("fee: {}\n", self.fee)
            + &format!("is_genesis: {}\n", self.is_genesis)
            + &format!("is_tip: {}\n", self.is_tip)
            + &format!("is_canonical: {}\n", self.is_canonical);

        write!(f, "{}", buf)
    }
}

impl BlockInfo {
    pub fn from_block_and_digests(
        block: &Block,
        genesis_digest: Digest,
        tip_digest: Digest,
        is_canonical: bool,
    ) -> Self {
        let body = block.body();
        let header = block.header();
        let digest = block.hash();
        Self {
            digest,
            prev_block_digest: header.prev_block_digest,
            height: header.height,
            timestamp: header.timestamp,
            difficulty: header.difficulty,
            cumulative_proof_of_work: header.cumulative_proof_of_work,
            num_inputs: body.transaction_kernel.inputs.len(),
            num_outputs: body.transaction_kernel.outputs.len(),
            fee: body.transaction_kernel.fee,
            mining_reward: crate::Block::block_subsidy(header.height),
            is_genesis: digest == genesis_digest,
            is_tip: digest == tip_digest,
            is_canonical,
        }
    }
}
