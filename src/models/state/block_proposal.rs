use std::fmt;

use crate::models::blockchain::block::Block;
use crate::models::blockchain::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::models::state::wallet::expected_utxo::ExpectedUtxo;
use crate::models::state::BlockHeight;

/// A proposed block to extend the block chain with.
///
/// Block proposals have valid correctness proofs, but do not have proof-of-work
/// (yet). Guessers can contribute proof-of-work to a block proposal and, if
/// successful, the block proposal becomes a block.
#[derive(Debug, Clone, Default)]
pub(crate) enum BlockProposal {
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

    pub(crate) fn is_some(&self) -> bool {
        !self.is_none()
    }

    pub(crate) fn is_none(&self) -> bool {
        matches!(self, BlockProposal::None)
    }

    pub(crate) fn unwrap(&self) -> &Block {
        match self {
            BlockProposal::OwnComposition((block, _)) => block,
            BlockProposal::ForeignComposition(block) => block,
            BlockProposal::None => panic!("Called unwrap on a BlockProposal value which was None"),
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
        let error_message = match self {
            BlockProposalRejectError::Composing => "Making own composition".to_string(),
            BlockProposalRejectError::WrongHeight { received, expected } => {
                format!("Expected block height: {expected}\nProposal block height: {received}")
            }
            BlockProposalRejectError::InsufficientFee { current, received } => {
                let current = current.map(|c| c.to_string()).unwrap_or("None".to_string());
                format!("Insufficient fee. Proposal was {received};\ncurrent fee is: {current}")
            }
        };

        write!(f, "{error_message}")
    }
}
