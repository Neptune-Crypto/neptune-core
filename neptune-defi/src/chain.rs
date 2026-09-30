//! What an overlay protocol needs to know about the chain.
//!
//! A protocol reads only the parts of a block that can open or close its
//! state: the announcements, the outputs with the AOCL leafs they became, and
//! the inputs' absolute index sets. [`ObservedBlock`] holds exactly those.

use neptune_consensus::block::Block;
use neptune_consensus::transaction::announcement::Announcement;
use neptune_consensus::transaction::transaction_kernel::TransactionKernel;
use neptune_mutator_set::addition_record::AdditionRecord;
use neptune_mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
use neptune_primitives::block_height::BlockHeight;
use tasm_lib::prelude::Digest;
use tasm_lib::twenty_first::util_types::mmr::mmr_trait::Mmr;

/// A block identifier: its height and its hash.
///
/// The height orders blocks, which rollback and pruning need. The hash
/// distinguishes blocks at the same height on different branches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(any(test, feature = "arbitrary-impls"), derive(arbitrary::Arbitrary))]
pub struct BlockId {
    pub height: BlockHeight,
    pub hash: Digest,
}

/// What an overlay protocol needs to know about one block.
#[derive(Debug, Clone)]
pub struct ObservedBlock {
    pub id: BlockId,
    pub parent: Digest,

    /// The number of AOCL leafs before this block, so that output `i` of the
    /// block's transaction became leaf `first_leaf_index + i`.
    pub first_leaf_index: u64,

    pub announcements: Vec<Announcement>,

    /// The transaction's outputs, in order.
    pub outputs: Vec<AdditionRecord>,

    /// The absolute index sets of the transaction's inputs.
    pub spent: Vec<AbsoluteIndexSet>,
}

impl ObservedBlock {
    /// What an overlay protocol needs from a block with this identity, parent, first
    /// AOCL leaf index and transaction kernel.
    pub fn new(
        id: BlockId,
        parent: Digest,
        first_leaf_index: u64,
        kernel: &TransactionKernel,
    ) -> Self {
        Self {
            id,
            parent,
            first_leaf_index,
            announcements: kernel.announcements.clone(),
            outputs: kernel.outputs.clone(),
            spent: kernel
                .inputs
                .iter()
                .map(|input| input.absolute_indices)
                .collect(),
        }
    }
}

impl From<&Block> for ObservedBlock {
    fn from(block: &Block) -> Self {
        let kernel = &block.body().transaction_kernel;

        // The body's accumulator counts the transaction's outputs but not the
        // guesser's, which come after them.
        let first_leaf_index = block
            .body()
            .mutator_set_accumulator_without_guesser_fees()
            .aocl
            .num_leafs()
            - kernel.outputs.len() as u64;
        let id = BlockId {
            height: block.header().height,
            hash: block.hash(),
        };

        Self::new(
            id,
            block.header().prev_block_digest,
            first_leaf_index,
            kernel,
        )
    }
}
