use tasm_lib::triton_vm::proof::Claim;
use tasm_lib::twenty_first::prelude::Mmr;
use tasm_lib::Digest;
use tracing::error;

use crate::models::blockchain::block::block_body::BlockBody;
use crate::models::blockchain::block::mutator_set_update::MutatorSetUpdate;
use crate::models::blockchain::block::Block;
use crate::models::blockchain::transaction::validity::single_proof::SingleProof;
use crate::models::blockchain::transaction::Transaction;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::proof_abstractions::tasm::program::ConsensusProgram;

/// All information necessary to efficiently produce a proof for a block.
#[derive(Clone, Debug)]
pub(crate) struct BlockWitness {
    pub(crate) predecessor: Block,

    pub(crate) transaction: Transaction,
    // to be expanded with witnesses for additional undetermined claims
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum BlockWitnessToBodyConversionError {
    MutatorSetUpdateFailure,
}

impl TryFrom<&BlockWitness> for BlockBody {
    fn try_from(witness: &BlockWitness) -> Result<Self, Self::Error> {
        // update mutator set
        let mut mutator_set_accumulator =
            witness.predecessor.body().mutator_set_accumulator.clone();

        let addition_records = witness.transaction.kernel.outputs.clone();
        let removal_records = witness.transaction.kernel.inputs.clone();
        let mutator_set_update = MutatorSetUpdate::new(removal_records, addition_records);
        if let Err(err) = mutator_set_update.apply_to_accumulator(&mut mutator_set_accumulator) {
            error!("Could not produce block body from block witness because of failed mutator set update: {}", err);
            return Err(Self::Error::MutatorSetUpdateFailure);
        }

        // update lock-free MMR (at present, no leafs are defined yet)
        let lock_free_mmr_accumulator =
            witness.predecessor.body().lock_free_mmr_accumulator.clone();

        // update block mmr
        let mut block_mmr_accumulator = witness.predecessor.body().block_mmr_accumulator.clone();
        block_mmr_accumulator.append(witness.predecessor.hash());

        Ok(BlockBody {
            transaction_kernel: witness.transaction.kernel.clone(),
            mutator_set_accumulator,
            lock_free_mmr_accumulator,
            block_mmr_accumulator,
        })
    }

    type Error = BlockWitnessToBodyConversionError;
}

impl BlockWitness {
    pub(crate) fn claims(&self) -> Result<Vec<Claim>, BlockWitnessToBodyConversionError> {
        let block_body_hash = BlockBody::try_from(self)?.mast_hash();
        Ok(self.claims_for_block_body(block_body_hash))
    }

    pub(crate) fn claims_for_block_body(&self, block_body_hash: Digest) -> Vec<Claim> {
        let transaction_is_valid =
            Claim::new(SingleProof.hash()).with_input(block_body_hash.reversed().values().into());
        vec![transaction_is_valid]
    }
}
