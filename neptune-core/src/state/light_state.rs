use std::sync::Arc;

use crate::protocol::consensus::block::Block;
use crate::protocol::proof_abstractions::timestamp::Timestamp;

#[derive(Debug)]
pub(crate) struct LightStateInner {
    tip: Block,
    /// The time at which the current tip was accepted by the node.
    /// Note that this could change between restarts as blocks may be
    /// initially received from the network but later read from disk
    accepted_at: Timestamp,
    time_to_mine: Option<Timestamp>,
}

impl LightStateInner {
    fn new(block: Block) -> Self {
        Self {
            accepted_at: block.header().timestamp,
            tip: block,
            time_to_mine: None,
        }
    }


    fn tip(&self) -> &Block {
        &self.tip
    }

    fn time_to_mine(&self) -> Option<Timestamp> {
        self.time_to_mine
    }
}

// perf: we make LightState an Arc<LightStateInner> so it can be
// cheaply cloned and passed around, eg in
// channel messages.

/// LightState is a thread-safe struct representing the latest
/// accepted block, along with bookkeeping information about it
#[derive(Debug)]
pub struct LightState(Arc<LightStateInner>);

impl From<Block> for LightState {
    fn from(tip: Block) -> Self {
        Self(Arc::new(LightStateInner::new(tip)))
    }
}

impl LightState {
    /// retrieve the current tip.
    #[inline]
    pub fn tip(&self) -> &Block {
        self.0.tip()
    }

    /// retrieve the time-to-mine of the current tip, if available.
    ///
    /// This is only available if the current tip is a direct descendant of the previous tip.
    #[inline]
    pub fn tip_time_to_mine(&self) -> Option<Timestamp> {
        self.0.time_to_mine()
    }

    /// update the light state with a new block, which becomes the new tip.
    /// 
    /// Existing clones of the LightState will not see the new tip, readers should always retrieve it
    /// via the [`crate::state::GlobalState`].
    pub(crate) fn update(&mut self, new_block: Block) {
        new_block.mutator_set_accumulator_after().expect("Stored block must have a valid MSA after.");

        let time_to_mine = if new_block.header().prev_block_digest == self.tip().hash() {
            // Only set if new tip is direct descendant of previous tip
            Some(new_block.header().timestamp - self.tip().header().timestamp)
        } else {
            None
        };

        self.0 = Arc::new(LightStateInner {
            tip: new_block,
            time_to_mine,
            accepted_at: Timestamp::now(),
        });
    }
}

impl Clone for LightState {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}