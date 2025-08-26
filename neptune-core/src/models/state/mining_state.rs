use std::collections::HashMap;

use tasm_lib::prelude::Digest;

use super::mining_status::MiningStatus;
use crate::models::state::BlockProposal;
use crate::Block;

/// Cap to prevent cached block proposals from eating up all RAM. Should never
/// be reached unless node is under some form of attack.
pub const MAX_NUM_EXPORTED_BLOCK_PROPOSAL_STORED: usize = 10_000;

#[derive(Debug, Default)]
pub struct MiningState {
    /// The most profitable block proposal seen on the network. But not
    /// necessarily the one a guesser is guessing on as the proposal is only
    /// changed when the delta in reward meets a threshold. Only updateable by
    /// main loop.
    pub block_proposal: BlockProposal,

    /// The block proposals that were exported to external guessers. Not persisted. Only contains
    /// block proposals pertaining to the next block height. All other proposals are forgotten when
    /// a new block is received.
    pub(crate) exported_block_proposals: HashMap<Digest, Block>,

    /// Indicates whether the guessing or composing task is running, and if so,
    /// since when.
    // Only the mining task should write to this, anyone can read.
    pub(crate) mining_status: MiningStatus,
}
