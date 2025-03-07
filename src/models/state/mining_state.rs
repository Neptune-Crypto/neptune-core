use tasm_lib::prelude::Digest;

use super::mining_status::MiningStatus;
use crate::models::state::BlockProposal;
use crate::Block;
use std::collections::HashMap;

#[derive(Debug, Default)]
pub(crate) struct MiningState {
    /// The block proposal to which guessers contribute proof-of-work. Can only be updated by
    pub(crate) block_proposal: BlockProposal,

    /// The block proposals that were exported to external guessers. Not persisted. Only contains
    /// block proposals pertaining to the next block height. All other proposals are forgotten when
    /// a new block is received.
    pub(crate) exported_block_proposals: HashMap<Digest, Block>,

    /// Indicates whether the guessing or composing task is running, and if so,
    /// since when.
    // Only the mining task should write to this, anyone can read.
    pub(crate) mining_status: MiningStatus,
}
