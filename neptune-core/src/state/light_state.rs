use std::sync::Arc;

use crate::protocol::consensus::block::Block;
use crate::protocol::proof_abstractions::timestamp::Timestamp;

#[derive(Debug)]
pub(crate) struct LightStateInner {
    tip: Block,
    time_to_mine: Option<Timestamp>,
}

impl LightStateInner {
    fn new(block: Block) -> Self {
        Self {
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

    #[cfg(test)]
    fn tip_mut(&mut self) -> &mut Block {
        &mut self.tip
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
    pub fn update(&mut self, new_block: Block) {
        new_block
            .mutator_set_accumulator_after()
            .expect("Stored block must have a valid MSA after.");

        let time_to_mine = if new_block.header().prev_block_digest == self.tip().hash() {
            // Only set if new tip is direct descendant of previous tip
            Some(new_block.header().timestamp - self.tip().header().timestamp)
        } else {
            None
        };

        self.0 = Arc::new(LightStateInner {
            tip: new_block,
            time_to_mine,
        });
    }

    /// retrieve a mutable reference to the current tip.
    #[cfg(test)]
    pub fn tip_mut(&mut self) -> &mut Block {
        Arc::get_mut(&mut self.0)
            .expect("Cannot get mutable reference: LightState is shared elsewhere")
            .tip_mut()
    }
}

impl Clone for LightState {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {
    use super::*;
    use crate::application::config::network::Network;
    use crate::protocol::consensus::block::block_appendix::BlockAppendix;
    use crate::protocol::consensus::block::block_header::BlockHeader;
    use crate::protocol::consensus::block::Block;
    use crate::protocol::consensus::block::BlockProof;
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::SeedableRng;

    #[test]
    fn time_to_mine_works() {
        let previous_block = Block::genesis(Network::Main);
        let previous_block_hash = previous_block.hash();
        let new_timestamp = previous_block.header().timestamp + Timestamp::hours(1);
        let mut light_state = LightState::from(previous_block.clone());
        assert_eq!(light_state.tip().hash(), previous_block_hash);

        let new_block: Block = Block::new(
            BlockHeader::template_header(
                previous_block.clone().header(),
                previous_block_hash,
                new_timestamp,
                Timestamp::minutes(10),
            ),
            previous_block.body().clone(),
            BlockAppendix::default(),
            BlockProof::default(),
        );

        light_state.update(new_block);
        assert_eq!(light_state.tip_time_to_mine(), Some(Timestamp::hours(1)));
    }

    #[test]
    fn time_to_mine_should_be_missing_until_updated() {
        let previous_block = Block::genesis(Network::Main);
        let light_state = LightState::from(previous_block.clone());
        assert_eq!(light_state.tip_time_to_mine(), None);
    }

    #[test]
    fn time_to_mine_should_be_missing_if_tip_not_direct_descendant() {
        let mut rng: StdRng = SeedableRng::seed_from_u64(893423984254);
        let previous_block = Block::genesis(Network::Main);
        let previous_block_hash = previous_block.hash();
        let new_timestamp = previous_block.header().timestamp + Timestamp::hours(1);
        let mut light_state = LightState::from(previous_block);
        assert_eq!(light_state.tip().hash(), previous_block_hash);

        let mut new_block: Block = rng.random();

        new_block.set_header_timestamp_and_difficulty(new_timestamp, new_block.header().difficulty);

        light_state.update(new_block);
        assert_eq!(light_state.tip_time_to_mine(), None);
    }
}
