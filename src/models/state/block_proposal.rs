use crate::models::blockchain::block::Block;
use crate::models::state::wallet::expected_utxo::ExpectedUtxo;

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
    pub(crate) fn composer_utxos(&self) -> Vec<ExpectedUtxo> {
        match self {
            BlockProposal::OwnComposition((_, utxo_info)) => utxo_info.clone(),
            _ => vec![],
        }
    }

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
        !matches!(self, BlockProposal::None)
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
