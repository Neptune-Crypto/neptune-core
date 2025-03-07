use std::fmt;
use std::sync::Arc;

use crate::models::blockchain::block::Block;
use crate::models::blockchain::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::models::state::wallet::expected_utxo::ExpectedUtxo;
use crate::models::state::BlockHeight;

/// A proposed block to extend the block chain with.
///
/// Block proposals have valid correctness proofs, but do not have proof-of-work
/// (yet). Guessers can contribute proof-of-work to a block proposal and, if
/// successful, the block proposal becomes a block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BlockProposal {
    OwnComposition((Arc<Block>, Vec<ExpectedUtxo>)),
    ForeignComposition(Arc<Block>),
}

impl BlockProposal {
    pub(crate) fn own_proposal(block: Arc<Block>, expected_utxos: Vec<ExpectedUtxo>) -> Self {
        Self::OwnComposition((block, expected_utxos))
    }

    pub(crate) fn foreign_proposal(block: Arc<Block>) -> Self {
        Self::ForeignComposition(block)
    }

    pub(crate) fn block(&self) -> Arc<Block> {
        match self {
            BlockProposal::OwnComposition((block, _)) => block.clone(),
            BlockProposal::ForeignComposition(block) => block.clone(),
        }
    }

    /// Map the inner block (if any) to None if the predicate does not hold
    pub(crate) fn filter<F: FnOnce(&Block) -> bool>(&self, predicate: F) -> Option<Arc<Block>> {
        match self {
            BlockProposal::OwnComposition((block, _)) => {
                if predicate(block) {
                    Some(block.clone())
                } else {
                    None
                }
            }
            BlockProposal::ForeignComposition(block) => {
                if predicate(block) {
                    Some(block.clone())
                } else {
                    None
                }
            }
        }
    }
}

/// Enumerates the reason that a specific block proposal was rejected. The
/// block proposal is most likely from another peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BlockProposalRejectError {
    /// Denotes that this instance is itself composing blocks
    Composing,

    /// Incoming block proposal does not have height matching current tip
    WrongHeight {
        received: BlockHeight,
        expected: BlockHeight,
    },

    /// Incoming block proposal does not have sufficient fee
    InsufficientFee {
        current: Option<NativeCurrencyAmount>,
        received: NativeCurrencyAmount,
    },
}

impl fmt::Display for BlockProposalRejectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockProposalRejectError::Composing => write!(f, "Making own composition"),
            BlockProposalRejectError::WrongHeight { received, expected } => write!(
                f,
                "Expected block height: {}\nProposal block height: {}",
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
        }
    }
}
