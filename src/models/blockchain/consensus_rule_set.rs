use strum_macros::EnumIter;

use super::block::BLOCK_HEIGHT_HF_1;
use super::block::BLOCK_HEIGHT_HF_2_MAINNET;
use super::block::BLOCK_HEIGHT_HF_2_NOT_MAINNET;
use super::block::MAX_NUM_INPUTS_OUTPUTS_PUB_ANNOUNCEMENTS_AFTER_HF_1;
use super::transaction::merge_version::MergeVersion;
use crate::api::export::BlockHeight;
use crate::api::export::Network;

/// Enumerates all possible sets of consensus rules.
///
/// Specifically, this enum captures *differences* between consensus rules,
/// across
///  - networks, and
///  - hard and soft forks triggered by blocks.
///
/// Consensus logic not captured by this encapsulation lives on
/// [`Transaction::is_valid`][super::transaction::Transaction::is_valid] and
/// ultimately [`Block::is_valid`][super::block::Block::is_valid].
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, Default, strum_macros::Display)]
pub enum ConsensusRuleSet {
    #[default]
    Genesis,
    HardFork1,
    HardFork2,
}

impl ConsensusRuleSet {
    /// Maximum block size in number of BFieldElements
    pub(crate) const fn max_block_size(&self) -> usize {
        match self {
            ConsensusRuleSet::Genesis => {
                // Old maximum block size in number of `BFieldElement`s.
                250_000
            }
            ConsensusRuleSet::HardFork1 | ConsensusRuleSet::HardFork2 => {
                // New maximum block size in number of `BFieldElement`s.
                //
                // This size is 8MB which should keep it feasible to run archival nodes for
                // many years without requiring excessive disk space. With an SWBF MMR of
                // height 20, this limit allows for 150-200 inputs per block.
                1_000_000
            }
        }
    }

    /// Infer the [`ConsensusRuleSet`] from the [`Network`] and the
    /// [`BlockHeight`]. The second argument is necessary to take into account
    /// planned hard or soft forks that activate at a given height. The first
    /// argument is necessary because the forks activate at different heights
    /// based on the network.
    pub(crate) fn infer_from(network: Network, block_height: BlockHeight) -> Self {
        match network {
            Network::Main => {
                if block_height < BLOCK_HEIGHT_HF_1 {
                    Self::Genesis
                } else if block_height < BLOCK_HEIGHT_HF_2_MAINNET {
                    Self::HardFork1
                } else {
                    Self::HardFork2
                }
            }
            Network::TestnetMock | Network::Beta | Network::Testnet | Network::RegTest => {
                match block_height {
                    h if h < BLOCK_HEIGHT_HF_2_NOT_MAINNET => Self::HardFork1,
                    _ => Self::HardFork2,
                }
            }
        }
    }

    /// Stipulates which version of the merge-branch in [`SingleProof`] is
    /// active.
    ///
    /// [`SingleProof`]: crate::models::blockchain::transaction::validity::single_proof::SingleProof
    pub(crate) const fn merge_version(&self) -> MergeVersion {
        match self {
            ConsensusRuleSet::Genesis | ConsensusRuleSet::HardFork1 => MergeVersion::Genesis,
            ConsensusRuleSet::HardFork2 => MergeVersion::HardFork2,
        }
    }

    pub(crate) fn max_num_inputs(&self) -> Option<usize> {
        match self {
            ConsensusRuleSet::Genesis => None,
            _ => Some(MAX_NUM_INPUTS_OUTPUTS_PUB_ANNOUNCEMENTS_AFTER_HF_1),
        }
    }
    pub(crate) fn max_num_outputs(&self) -> Option<usize> {
        match self {
            ConsensusRuleSet::Genesis => None,
            _ => Some(MAX_NUM_INPUTS_OUTPUTS_PUB_ANNOUNCEMENTS_AFTER_HF_1),
        }
    }
    pub(crate) fn max_num_public_announcements(&self) -> Option<usize> {
        match self {
            ConsensusRuleSet::Genesis => None,
            _ => Some(MAX_NUM_INPUTS_OUTPUTS_PUB_ANNOUNCEMENTS_AFTER_HF_1),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    impl ConsensusRuleSet {
        pub(crate) fn iter_merge_versions() -> std::vec::IntoIter<Self> {
            vec![Self::Genesis, Self::HardFork2].into_iter()
        }
    }
}
