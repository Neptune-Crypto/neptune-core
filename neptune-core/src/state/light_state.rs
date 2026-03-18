use std::sync::Arc;

use crate::protocol::consensus::block::Block;
use crate::protocol::proof_abstractions::timestamp::Timestamp;

// perf: we make LightState an Arc<LightStateInner> so it can be
// cheaply cloned and passed around, eg in
// channel messages.

/// LightState is a thread-safe struct representing the latest
/// accepted block, along with bookkeeping information about it
pub type LightState = Arc<LightStateInner>;
#[derive(Debug)]
pub(crate) struct LightStateInner {
    tip: Block,
    received_at: Timestamp,
    time_to_mine: Option<Timestamp>,
}

impl LightStateInner {
    fn new(block: Block) -> Self {
        Self {
            received_at: block.header().timestamp,
            tip: block,
            time_to_mine: None,
        }
    }

    pub(crate) fn update(&mut self, new_block: Block) {
        new_block.mutator_set_accumulator_after().expect("Stored block must have a valid MSA after.");

        self.time_to_mine = if new_block.header().prev_block_digest == self.tip.hash() {
            // Only set if new tip is direct descendant of previous tip
            Some(new_block.header().timestamp - self.tip.header().timestamp)
        } else {
            None
        };

        self.received_at = Timestamp::now();
        self.tip = new_block;
    }

    pub(crate) fn tip(&self) -> &Block {
        &self.tip
    }
}

impl From<Block> for LightState {
    fn from(tip: Block) -> LightState {
        Arc::new(LightStateInner::new(tip))
    }
}