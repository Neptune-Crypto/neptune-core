use get_size::GetSize;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::twenty_first::prelude::Mmr;

use crate::models::blockchain::block::block_body::BlockBody;
use crate::models::blockchain::block::mutator_set_update::MutatorSetUpdate;
use crate::models::blockchain::block::Block;
use crate::models::blockchain::transaction::Transaction;

/// Wraps all information necessary to produce a block.
///
/// Represents the first stage in the block production pipeline, which looks
/// like this:
///
/// ```notest
/// predecessor : Block --------.
///                             |-- new --> BlockPrimitiveWitness
/// transaction : Transaction --'                               |
///                                                             |
///                                                             |---> BlockBody --.
///                                                             |                 |
/// TransactionIsValid : BlockConsensusProgram <-- conversion --+-> }             |
///  |               ? : BlockConsensusProgram <-- conversion --+-> } Appendix ---|
///  | ......        ? : BlockConsensusProgram <-- conversion --'-> }             |
/// prove                                                                         |
///  | prove                                                                      |
///  |  | prove                                                                   |
///  |  |  |       ...           ...                  ...                         |  
///  v  v  v                                                                      |
/// SoftClaimsWitness --------------- produce ----------------------> BlockProof -|
///                                                                               |
///                                                 Block <---------- mining -----'
/// ```
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize)]
pub(crate) struct BlockPrimitiveWitness {
    pub(crate) predecessor_block: Block,
    pub(crate) transaction: Transaction,
    maybe_body: Option<BlockBody>,
}

impl BlockPrimitiveWitness {
    pub(crate) fn new(predecessor_block: Block, transaction: Transaction) -> Self {
        Self {
            predecessor_block,
            transaction,
            maybe_body: None,
        }
    }

    pub(crate) fn body(&mut self) -> BlockBody {
        if let Some(body) = &self.maybe_body {
            return body.to_owned();
        }

        let predecessor_body = self.predecessor_block.body();

        let mut mutator_set = predecessor_body.mutator_set_accumulator.clone();
        let mutator_set_update = MutatorSetUpdate::new(
            self.transaction.kernel.inputs.clone(),
            self.transaction.kernel.outputs.clone(),
        );
        mutator_set_update.apply_to_accumulator(&mut mutator_set).unwrap_or_else(|e| {panic!("attempting to produce a block body from a transaction whose mutator set update is incompatible");});

        let lock_free_mmr = predecessor_body.lock_free_mmr_accumulator.clone();

        let mut block_mmr = predecessor_body.block_mmr_accumulator.clone();
        block_mmr.append(self.predecessor_block.hash());

        let body = BlockBody::new(
            self.transaction.kernel.clone(),
            mutator_set,
            lock_free_mmr,
            block_mmr,
        );
        self.maybe_body = Some(body.clone());
        body
    }
}
