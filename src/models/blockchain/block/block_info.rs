//! BlockInfo is a concise summary of a block intended for human
//! consumption/reporting in block explorers, cli, dashboard, etc.

use serde::Deserialize;
use serde::Serialize;
use twenty_first::math::digest::Digest;
use twenty_first::prelude::U32s;

use crate::models::blockchain::block::block_height::BlockHeight;
use crate::models::blockchain::block::Block;
use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
use crate::models::consensus::timestamp::Timestamp;
use crate::prelude::twenty_first;

use super::block_header::PROOF_OF_WORK_COUNT_U32_SIZE;
use super::block_header::TARGET_DIFFICULTY_U32_SIZE;

/// Provides summary information about a Block
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockInfo {
    pub height: BlockHeight,
    pub digest: Digest,
    pub prev_block_digest: Digest,
    pub timestamp: Timestamp,
    pub proof_of_work_line: U32s<PROOF_OF_WORK_COUNT_U32_SIZE>,
    pub proof_of_work_family: U32s<PROOF_OF_WORK_COUNT_U32_SIZE>,
    pub difficulty: U32s<TARGET_DIFFICULTY_U32_SIZE>,
    pub num_inputs: usize,
    pub num_outputs: usize,
    pub num_uncle_blocks: usize,
    pub mining_reward: NeptuneCoins,
    pub fee: NeptuneCoins,
    pub is_genesis: bool,
    pub is_tip: bool,
}

// note: this is used by neptune-cli block-info command.
impl std::fmt::Display for BlockInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let buf = String::new()
            + &format!("height: {}\n", self.height)
            + &format!("digest: {}\n", self.digest.to_hex())
            + &format!("prev_block_digest: {}\n", self.prev_block_digest.to_hex())
            + &format!("timestamp: {}\n", self.timestamp.standard_format())
            + &format!("proof_of_work_line: {}\n", self.proof_of_work_line)
            + &format!("proof_of_work_family: {}\n", self.proof_of_work_family)
            + &format!("difficulty: {}\n", self.difficulty)
            + &format!("num_inputs: {}\n", self.num_inputs)
            + &format!("num_outputs: {}\n", self.num_outputs)
            + &format!("num_uncle_blocks: {}\n", self.num_uncle_blocks)
            + &format!("mining_reward: {}\n", self.mining_reward)
            + &format!("fee: {}\n", self.fee)
            + &format!("is_genesis: {}\n", self.is_genesis)
            + &format!("is_tip: {}\n", self.is_tip);

        write!(f, "{}", buf)
    }
}

impl BlockInfo {
    pub fn from_block_and_digests(
        block: &Block,
        genesis_digest: Digest,
        tip_digest: Digest,
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
            proof_of_work_line: header.proof_of_work_line,
            proof_of_work_family: header.proof_of_work_family,
            num_inputs: body.transaction.kernel.inputs.len(),
            num_outputs: body.transaction.kernel.outputs.len(),
            num_uncle_blocks: body.uncle_blocks.len(),
            fee: body.transaction.kernel.fee,
            mining_reward: crate::Block::get_mining_reward(header.height),
            is_genesis: digest == genesis_digest,
            is_tip: digest == tip_digest,
        }
    }
}
