use std::collections::HashMap;

use itertools::Itertools;
use tasm_lib::prelude::Digest;
use tracing::info;

use super::mining_status::MiningStatus;
use crate::application::loops::mine_loop::coinbase_distribution::CoinbaseDistribution;
use crate::state::BlockProposal;
use crate::Block;

/// Cap to prevent cached block proposals from eating up all RAM. Should never
/// be reached unless node is under some form of attack.
pub const MAX_NUM_EXPORTED_BLOCK_PROPOSAL_STORED: usize = 10_000;

#[derive(Debug, Default)]
struct OverrideCoinbaseSettings {
    coinbase_distribution: Option<CoinbaseDistribution>,
}

/// State related to the mining (composing and guessing) of the next block.
#[derive(Debug, Default)]
pub struct MiningState {
    /// The most profitable block proposal seen on the network. But not
    /// necessarily the one a guesser is guessing on as the proposal is only
    /// changed when the delta in reward meets a threshold. Only updateable by
    /// main loop.
    pub block_proposal: BlockProposal,

    /// The block proposals that were exported to external guessers. Not
    /// persisted. Only contains block proposals pertaining to the next block
    /// height. All exported proposals are forgotten when a new block is
    /// received.
    pub(crate) exported_block_proposals: HashMap<Digest, Block>,

    /// Indicates whether the guessing or composing task is running, and if so,
    /// since when.
    // Only the mining task should write to this, anyone can read.
    pub(crate) mining_status: MiningStatus,

    /// Parameters used to override default coinbase behavior. Can e.g. be used
    /// to set a new coinbase distribution for the next block proposal produced
    /// on this node.
    override_coinbase_settings: OverrideCoinbaseSettings,
}

impl MiningState {
    pub(crate) fn overridden_coinbase_distribution(&self) -> Option<CoinbaseDistribution> {
        self.override_coinbase_settings
            .coinbase_distribution
            .as_ref()
            .map(|x| x.to_owned())
    }

    pub fn set_coinbase_distribution(&mut self, coinbase_distribution: CoinbaseDistribution) {
        info!(
            "Changing coinbase distribution to length of {}. Distribution:\n{}",
            coinbase_distribution.len(),
            coinbase_distribution
                .iter()
                .map(|x| {
                    let liq_or_tl = if x.timelocked { "timelocked" } else { "liquid" };
                    let fraction = x.fraction_in_promille;
                    format!("{fraction} / 1000, {liq_or_tl}; ")
                })
                .join("\n")
        );
        self.override_coinbase_settings.coinbase_distribution = Some(coinbase_distribution);
    }

    pub(crate) fn unset_coinbase_distribution(&mut self) {
        self.override_coinbase_settings.coinbase_distribution = None;
    }
}
