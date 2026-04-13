use crate::api::export::Network;
use crate::protocol::consensus::block::Block;
use crate::protocol::proof_abstractions::timestamp::Timestamp;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;

/// LightState represents the latest accepted block,
/// along with bookkeeping information about it
#[derive(Debug, Clone)]
pub struct LightState {
    /// The mutator set accumulator as it looks after the application of this
    /// block, after having added the guesser rewards.
    mutator_set_accumulator_after: MutatorSetAccumulator,

    /// A valid block that has the most accumulated proof-of-work of all blocks
    /// seen on the network.
    ///
    /// Usually just refers to the block with the highest block height, and the
    /// most-recently mined block. Often referred to as "the most canonical
    /// block".
    tip: Block,

    /// The timestamp difference between the tip and its immediate predecessor.
    ///
    /// Will only be set if the previous tip was the immediate predecessor of
    /// the current. In normal operations, this will be the time it took miners
    /// to find the current tip.
    time_to_mine: Option<Timestamp>,

    /// The network that the light state belongs to.
    ///
    /// Matches the network on which the node was started.
    network: Network,
}

impl LightState {
    /// Contruct a new light state, from a block.
    pub fn new(block: Block, network: Network) -> Self {
        Self {
            mutator_set_accumulator_after: block
                .mutator_set_accumulator_after()
                .expect("Block stored as tip must be valid"),
            tip: block,
            time_to_mine: None,
            network,
        }
    }

    /// A reference to the most canonical block seen on the network.
    pub fn tip(&self) -> &Block {
        &self.tip
    }

    /// Return the network on which this node runs.
    pub(super) fn network(&self) -> Network {
        self.network
    }

    /// Return the mutator set accumulator as it looks after the application of
    /// this block, after having added the guesser rewards.
    pub(super) fn tip_mutator_set_after(&self) -> MutatorSetAccumulator {
        self.mutator_set_accumulator_after.clone()
    }

    /// The time it took miners to mine the current tip.
    pub fn time_to_mine(&self) -> Option<Timestamp> {
        self.time_to_mine
    }

    /// update the light state with a new block, which becomes the new tip.
    pub fn update(&mut self, new_block: Block) {
        let time_to_mine = if new_block.header().prev_block_digest == self.tip.hash() {
            // Only set if new tip is direct descendant of previous tip
            Some(new_block.header().timestamp - self.tip.header().timestamp)
        } else {
            None
        };

        self.mutator_set_accumulator_after = new_block
            .mutator_set_accumulator_after()
            .expect("Stored block must have a valid MSA after.");

        self.tip = new_block;
        self.time_to_mine = time_to_mine;
    }

    #[cfg(test)]
    pub(crate) fn tip_mut(&mut self) -> &mut Block {
        &mut self.tip
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::SeedableRng;

    use super::*;
    use crate::application::config::network::Network;
    use crate::protocol::consensus::block::block_appendix::BlockAppendix;
    use crate::protocol::consensus::block::block_header::BlockHeader;
    use crate::protocol::consensus::block::Block;
    use crate::protocol::consensus::block::BlockProof;

    #[test]
    fn update_works() {
        let network = Network::Main;
        let previous_block = Block::genesis(network);
        let previous_block_hash = previous_block.hash();
        let new_timestamp = previous_block.header().timestamp + Timestamp::hours(1);
        let mut light_state = LightState::new(previous_block.clone(), network);
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
        assert_eq!(light_state.time_to_mine(), Some(Timestamp::hours(1)));
        assert_eq!(light_state.tip().header().timestamp, new_timestamp);
    }

    #[test]
    fn time_to_mine_should_be_missing_until_updated() {
        let network = Network::Main;
        let previous_block = Block::genesis(network);
        let light_state = LightState::new(previous_block.clone(), network);
        assert_eq!(light_state.time_to_mine(), None);
    }

    #[test]
    fn time_to_mine_should_be_missing_if_tip_not_direct_descendant() {
        let network = Network::Main;
        let mut rng: StdRng = SeedableRng::seed_from_u64(893423984254);
        let previous_block = Block::genesis(network);
        let previous_block_hash = previous_block.hash();
        let new_timestamp = previous_block.header().timestamp + Timestamp::hours(1);
        let mut light_state = LightState::new(previous_block, network);
        assert_eq!(light_state.tip().hash(), previous_block_hash);

        let mut new_block: Block = rng.random();

        new_block.set_header_timestamp_and_difficulty(new_timestamp, new_block.header().difficulty);

        light_state.update(new_block);
        assert_eq!(light_state.time_to_mine(), None);
    }
}
