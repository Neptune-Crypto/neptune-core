use neptune_archive::archival_state::ArchivalState;
use neptune_consensus::block::block_header::BlockHeader;
use neptune_consensus::block::guesser_receiver_data::GuesserReceiverData;
use neptune_consensus::block::pow::LustrationStatus;
use neptune_consensus::consensus_rule_set::ConsensusRuleSet;
use neptune_mempool::recent_mutator_sets::RecentMutatorSets;
use neptune_mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use neptune_primitives::block_height::BlockHeight;
use neptune_primitives::network::Network;
use tasm_lib::prelude::Digest;

use super::light_state::LightState;
use crate::Block;

/// `BlockChainState` provides an `Archival` variant
/// for full nodes and a `Light` variant for light nodes.
///
/// It provides a bit of abstraction over the chain state.
/// In particular, one can call `light_state()` and get
/// the current tip for either variant.
///
/// It is intended to be forward thinking for when we
/// actually implement a light node.
///
// silence possible clippy bug / false positive.
// see: https://github.com/rust-lang/rust-clippy/issues/9798
#[derive(Debug)]
pub enum BlockchainState {
    /// Archival blockchain state. Contains all historical blocks and book
    /// keeping information.
    Archival(Box<BlockchainArchivalState>),
    /// Light node blockchain state, current tip and some book
    /// keeping information
    Light(Box<LightState>),
}

impl BlockchainState {
    /// check if this is an archival node/state
    #[inline]
    pub fn is_archival_node(&self) -> bool {
        matches!(self, Self::Archival(_))
    }

    /// retrieve archival state.
    ///
    /// panics if called by a light node.
    #[inline]
    pub fn archival_state(&self) -> &ArchivalState {
        match self {
            Self::Archival(bac) => &bac.archival_state,
            Self::Light(_) => panic!("archival_state not available in LightState mode"),
        }
    }

    /// retrieve blockchain archival state.
    ///
    /// panics if called by a light node.
    #[inline]
    pub fn blockchain_archival_state(&self) -> &BlockchainArchivalState {
        match self {
            Self::Archival(bac) => bac,
            Self::Light(_) => panic!("archival_state not available in LightState mode"),
        }
    }

    /// retrieve mutable archival state.
    ///
    /// panics if called by a light node.
    #[inline]
    pub fn archival_state_mut(&mut self) -> &mut ArchivalState {
        match self {
            Self::Archival(bac) => &mut bac.archival_state,
            Self::Light(_) => panic!("archival_state not available in LightState mode"),
        }
    }

    /// retrieve light state, ie the current tip and book keeping information.
    #[inline]
    pub fn light_state(&self) -> &LightState {
        match self {
            Self::Archival(bac) => &bac.light_state,
            Self::Light(light_state) => light_state,
        }
    }

    #[inline]
    pub fn light_state_clone(&self) -> LightState {
        match self {
            Self::Archival(bac) => bac.light_state.clone(),
            Self::Light(light_state) => *light_state.clone(),
        }
    }

    /// retrieve mutable light state, ie the current tip.
    #[inline]
    pub fn light_state_mut(&mut self) -> &mut LightState {
        match self {
            Self::Archival(bac) => &mut bac.light_state,
            Self::Light(light_state) => light_state,
        }
    }

    /// shorthand for light_state().tip()
    #[inline]
    pub fn tip(&self) -> &Block {
        self.light_state().tip()
    }

    /// Return the mutator set after the specified block has been applied.
    pub async fn mutator_set_after_by_block_hash(
        &self,
        block_hash: Digest,
    ) -> Option<MutatorSetAccumulator> {
        // First look in light state.
        if let Some(msa) = self
            .light_state()
            .recent_mutator_sets()
            .mutator_set_by_block_digest(block_hash)
        {
            return Some(msa);
        }

        // Then look in archival state, if one such is maintained
        if !self.is_archival_node() {
            return None;
        }

        self.archival_state()
            .get_block(block_hash)
            .await
            .expect("Reading from archival state must work")
            .map(|block| {
                block
                    .mutator_set_accumulator_after()
                    .expect("Stored block must have valid MS after")
            })
    }

    /// The reveal of the inactive SWBF that a block on this proposal needs
    /// from this guesser, read from the archival state synced to the tip.
    /// None if the proposal is not on the tip, or the rules require none.
    pub async fn guesser_swbfi_reveal(
        &self,
        proposal_header: &BlockHeader,
        receiver_data: &GuesserReceiverData,
        network: Network,
    ) -> Option<(Digest, Vec<Digest>)> {
        let tip = self.tip();
        let rules = ConsensusRuleSet::infer_from(network, proposal_header.height);
        if tip.hash() != proposal_header.prev_block_digest
            || !rules.miners_must_prove_ams_knowledge(network)
        {
            return None;
        }
        self.archival_state()
            .guesser_swbfi_reveal(tip.hash(), receiver_data)
            .await
    }

    /// The mutator set accumulator as it looks after applying the tip block.
    ///
    /// Includes guesser reward outputs.
    pub(crate) fn tip_mutator_set_after(&self) -> MutatorSetAccumulator {
        self.light_state().tip_mutator_set_after()
    }

    /// The mutator set after the tip, and after recent ancestors.
    ///
    /// Cheap to clone.
    pub(crate) fn recent_mutator_sets(&self) -> &RecentMutatorSets {
        self.light_state().recent_mutator_sets()
    }

    /// Block height of current tip.
    pub fn tip_height(&self) -> BlockHeight {
        self.tip().header().height
    }

    /// Hash of current tip.
    pub(crate) fn tip_hash(&self) -> Digest {
        self.tip().hash()
    }

    /// Return the lustration status of the blockchain at the current tip.
    ///
    /// If the lustration rule is not yet active, returns None.
    ///
    /// # Panics
    /// - If lustration rules have been activated, but no lustration status can
    ///   be parsed from the tip. This would mean that the tip is not a valid
    ///   block.
    pub fn lustration_status(&self) -> Option<LustrationStatus> {
        // If the lustration status can be read from the header, the lustration
        // status must be set. Otherwise, this function reads
        let height = self.tip_height();
        if ConsensusRuleSet::first_lustration_block(self.light_state().network()) > height {
            return None;
        }

        let lustration_status = self
            .tip()
            .header()
            .pow
            .lustration_status()
            .expect("Lustration status must be parseable once lustration is active");

        Some(lustration_status)
    }

    /// Return the threshold that dictates which inputs must lustrate.
    ///
    /// If the lustration rule is not yet active, returns None, otherwise
    /// returns the AOCL leaf index for the last input that must lustrate. All
    /// AOCL leafs after the threshold do not need to lustrate.
    ///
    /// # Warning
    /// - The consensus rule is defined in terms of the absolute index set's
    ///   AOCL range, not in terms of the actual AOCL leaf index of the input
    ///   being spent, since the latter is only known to the transaction
    ///   initiator.
    ///
    /// # Panics
    /// - If lustration rules have been activated, but no lustration status can
    ///   be parsed from the tip. This would mean that the tip is not a valid
    ///   block.
    pub(crate) fn lustration_threshold(&self) -> Option<u64> {
        self.lustration_status()
            .map(|status| status.max_lustrating_aocl_leaf_index)
    }
}

/// The `BlockchainArchivalState` contains database access to block headers.
///
/// It is divided into `ArchivalState` and `LightState`.
#[derive(Debug)]
pub struct BlockchainArchivalState {
    /// Historical blockchain data, persisted
    pub(crate) archival_state: ArchivalState,

    /// The present tip.
    pub light_state: LightState,
}
