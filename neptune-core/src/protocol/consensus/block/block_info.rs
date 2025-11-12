//! BlockInfo is a concise summary of a block intended for human
//! consumption/reporting in block explorers, cli, dashboard, etc.

use itertools::Itertools;
use rand::distr::Distribution;
use rand::distr::StandardUniform;
use rand::Rng;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::twenty_first::tip5::digest::Digest;

use super::difficulty_control::Difficulty;
use super::difficulty_control::ProofOfWork;
use crate::protocol::consensus::block::block_height::BlockHeight;
use crate::protocol::consensus::block::Block;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::protocol::proof_abstractions::timestamp::Timestamp;

/// Provides summary information about a Block
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockInfo {
    pub height: BlockHeight,

    /// Block size in number of
    /// [`BFieldElement`](tasm_lib::twenty_first::math::b_field_element::BFieldElement)s.
    pub size: usize,
    pub digest: Digest,
    pub prev_block_digest: Digest,
    pub timestamp: Timestamp,
    pub cumulative_proof_of_work: ProofOfWork,
    pub difficulty: Difficulty,
    pub num_inputs: usize,
    pub num_outputs: usize,
    pub num_announcements: usize,
    pub coinbase_amount: NativeCurrencyAmount,
    pub fee: NativeCurrencyAmount,
    pub is_genesis: bool,
    pub is_tip: bool,
    pub is_canonical: bool,
    pub sibling_blocks: Vec<Digest>, // blocks at same height
}

// note: this is used by neptune-cli block-info command.
impl std::fmt::Display for BlockInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let buf = String::new()
            + &format!("height: {}\n", self.height)
            + &format!("digest: {:x}\n", self.digest)
            + &format!("size: {}\n", self.size)
            + &format!("prev_block_digest: {:x}\n", self.prev_block_digest)
            + &format!("timestamp: {}\n", self.timestamp.standard_format())
            + &format!(
                "cumulative_proof_of_work: {}\n",
                self.cumulative_proof_of_work
            )
            + &format!("difficulty: {}\n", self.difficulty)
            + &format!("num_inputs: {}\n", self.num_inputs)
            + &format!("num_outputs: {}\n", self.num_outputs)
            + &format!("num_announcements: {}\n", self.num_announcements)
            + &format!("coinbase_amount: {}\n", self.coinbase_amount)
            + &format!("fee: {}\n", self.fee)
            + &format!("is_genesis: {}\n", self.is_genesis)
            + &format!("is_tip: {}\n", self.is_tip)
            + &format!("is_canonical: {}\n", self.is_canonical)
            + &format!(
                "sibling_blocks: {}\n",
                self.sibling_blocks.iter().map(|d| d.to_hex()).join(",")
            );

        write!(f, "{}", buf)
    }
}

impl BlockInfo {
    pub fn new(
        block: &Block,
        genesis_digest: Digest,
        tip_digest: Digest,
        sibling_blocks: Vec<Digest>, // other blocks at same height
        is_canonical: bool,
    ) -> Self {
        let body = block.body();
        let header = block.header();
        let digest = block.hash();
        Self {
            digest,
            prev_block_digest: header.prev_block_digest,
            height: header.height,
            size: block.size(),
            timestamp: header.timestamp,
            difficulty: header.difficulty,
            cumulative_proof_of_work: header.cumulative_proof_of_work,
            num_inputs: body.transaction_kernel.inputs.len(),
            num_outputs: body.transaction_kernel.outputs.len(),
            num_announcements: body.transaction_kernel.announcements.len(),
            fee: body.transaction_kernel.fee,
            coinbase_amount: block.coinbase_amount(),
            is_genesis: digest == genesis_digest,
            is_tip: digest == tip_digest,
            is_canonical,
            sibling_blocks,
        }
    }

    /// Returns expected (calculated) coinbase amount for this block's height.
    ///
    /// note that this calculated value may be more than the coinbase_amount
    /// field because a miner may choose to reward themself less than the
    /// calculated reward amount.
    pub fn expected_coinbase_amount(&self) -> NativeCurrencyAmount {
        Block::block_subsidy(self.height)
    }
}

impl Distribution<BlockInfo> for StandardUniform {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> BlockInfo {
        BlockInfo {
            height: rng.random(),
            size: rng.random_range(100_000..1_000_000),
            digest: rng.random(),
            prev_block_digest: rng.random(),
            timestamp: rng.random(),
            cumulative_proof_of_work: rng.random(),
            difficulty: rng.random(),
            num_inputs: rng.random_range(0..30),
            num_outputs: rng.random_range(0..10),
            num_announcements: rng.random_range(0..10),
            coinbase_amount: NativeCurrencyAmount::from_nau(
                (1i128 << rng.random_range(0..=8)) >> 1,
            ),
            fee: NativeCurrencyAmount::from_nau(
                rng.random_range(0..NativeCurrencyAmount::MAX_NAU) >> 20,
            ),
            is_genesis: rng.random(),
            is_tip: rng.random(),
            is_canonical: rng.random(),
            sibling_blocks: (0..rng.random_range(0..2))
                .map(|_| rng.random())
                .collect_vec(),
        }
    }
}
