use std::fmt;

use tasm_lib::prelude::Digest;

use crate::api::export::BlockHeight;
use crate::protocol::consensus::block::Block;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::state::wallet::expected_utxo::ExpectedUtxo;

/// A proposed block to extend the block chain with.
///
/// Block proposals have valid correctness proofs, but do not have proof-of-work
/// (yet). Guessers can contribute proof-of-work to a block proposal and, if
/// successful, the block proposal becomes a block.
#[derive(Debug, Clone, Default)]
pub enum BlockProposal {
    OwnComposition((Block, Vec<ExpectedUtxo>)),
    ForeignComposition(Block),
    #[default]
    None,
}

impl BlockProposal {
    pub(crate) fn own_proposal(block: Block, expected_utxos: Vec<ExpectedUtxo>) -> Self {
        Self::OwnComposition((block, expected_utxos))
    }

    pub(crate) fn foreign_proposal(block: Block) -> Self {
        Self::ForeignComposition(block)
    }

    pub(crate) fn none() -> Self {
        Self::None
    }

    pub(crate) fn has_own(&self) -> bool {
        matches!(self, Self::OwnComposition(_))
    }

    pub fn expect(&self, msg: &str) -> &Block {
        match self {
            BlockProposal::OwnComposition((block, _)) => block,
            BlockProposal::ForeignComposition(block) => block,
            BlockProposal::None => panic!("{msg}"),
        }
    }

    /// Map the inner block (if any) to some result
    pub(crate) fn map<T, F: FnOnce(&Block) -> T>(&self, function: F) -> Option<T> {
        match self {
            BlockProposal::OwnComposition((block, _)) => Some(function(block)),
            BlockProposal::ForeignComposition(block) => Some(function(block)),
            BlockProposal::None => None,
        }
    }

    /// Map the inner block (if any) to None if the predicate does not hold
    pub(crate) fn filter<F: FnOnce(&Block) -> bool>(&self, predicate: F) -> Option<&Block> {
        match self {
            BlockProposal::OwnComposition((block, _)) => {
                if predicate(block) {
                    Some(block)
                } else {
                    None
                }
            }
            BlockProposal::ForeignComposition(block) => {
                if predicate(block) {
                    Some(block)
                } else {
                    None
                }
            }
            BlockProposal::None => None,
        }
    }
}

/// Enumerates the reason that a specific block proposal was rejected. The
/// block proposal is most likely from another peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BlockProposalRejectError {
    /// Incoming block proposal does not have prev_block_digest matching current tip
    WrongParent { received: Digest, expected: Digest },

    /// Incoming block proposal wrong height
    WrongHeight {
        received: BlockHeight,
        expected: BlockHeight,
    },

    /// Incoming block proposal does not have sufficient fee
    InsufficientFee {
        current: Option<NativeCurrencyAmount>,
        received: NativeCurrencyAmount,
    },

    /// All foreign block proposals are ignored
    IgnoreAllForeign,

    /// Block proposal comes from a peer that's not whitelisted
    NotWhiteListed,

    /// Block proposal is rejected because we already built one locally.
    HasOwnBlockProposal,
}

impl fmt::Display for BlockProposalRejectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockProposalRejectError::WrongHeight { received, expected } => write!(
                f,
                "Expected block height: {}\nProposal block height: {}",
                expected, received
            ),
            BlockProposalRejectError::WrongParent { received, expected } => write!(
                f,
                "Expected block prev_block_digest: {}\nProposal prev_block_digest: {}",
                expected, received
            ),
            BlockProposalRejectError::InsufficientFee { current, received } => write!(
                f,
                "Insufficient fee. Proposal was {};\ncurrent fee is: {}",
                received,
                current
                    .map(|c| format!("{}", c))
                    .unwrap_or("None".to_string())
            ),
            BlockProposalRejectError::IgnoreAllForeign => {
                write!(f, "Ignoring all foreign proposals")
            }
            BlockProposalRejectError::NotWhiteListed => {
                write!(f, "Proposal received from non-whitelisted peer")
            }
            BlockProposalRejectError::HasOwnBlockProposal => {
                write!(f, "Proposal received but we already built one locally")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::state::mining::block_proposal::BlockProposal;

    impl BlockProposal {
        pub(crate) fn is_none(&self) -> bool {
            matches!(self, BlockProposal::None)
        }
    }
}
