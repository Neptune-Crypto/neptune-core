use get_size::GetSize;
use serde::Deserialize;
use serde::Serialize;
use strum::EnumCount;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
use twenty_first::math::bfield_codec::BFieldCodec;

use crate::models::blockchain::transaction::transaction_kernel::TransactionKernel;
use crate::models::proof_abstractions::mast_hash::HasDiscriminant;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::prelude::twenty_first;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;

#[derive(Debug, Clone, EnumCount)]
pub enum BlockBodyField {
    Transaction,
    MutatorSetAccumulator,
    LockFreeMmrAccumulator,
    BlockMmrAccumulator,
}

impl HasDiscriminant for BlockBodyField {
    fn discriminant(&self) -> usize {
        self.clone() as usize
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BFieldCodec, GetSize)]
pub struct BlockBody {
    /// Every block contains exactly one transaction, which represents the merger of all
    /// broadcasted transactions that the miner decided to confirm.
    pub(crate) transaction_kernel: TransactionKernel,

    /// The mutator set accumulator represents the UTXO set. It is simultaneously an
    /// accumulator (=> compact representation and membership proofs) and an anonymity
    /// construction (=> outputs from one transaction do not look like inputs to another).
    pub(crate) mutator_set_accumulator: MutatorSetAccumulator,

    /// Lock-free UTXOs do not come with lock scripts and do not live in the mutator set.
    pub(crate) lock_free_mmr_accumulator: MmrAccumulator,

    /// All blocks live in an MMR, so that we can efficiently prove that a given block
    /// lives on the line between the tip and genesis. This MMRA does not contain the
    /// current block.
    pub(crate) block_mmr_accumulator: MmrAccumulator,
}

impl BlockBody {
    pub(crate) fn new(
        transaction_kernel: TransactionKernel,
        mutator_set_accumulator: MutatorSetAccumulator,
        lock_free_mmr_accumulator: MmrAccumulator,
        block_mmr_accumulator: MmrAccumulator,
    ) -> Self {
        Self {
            transaction_kernel,
            mutator_set_accumulator,
            lock_free_mmr_accumulator,
            block_mmr_accumulator,
        }
    }
}

impl MastHash for BlockBody {
    type FieldEnum = BlockBodyField;

    fn mast_sequences(&self) -> Vec<Vec<BFieldElement>> {
        vec![
            self.transaction_kernel.encode(),
            self.mutator_set_accumulator.encode(),
            self.lock_free_mmr_accumulator.encode(),
            self.block_mmr_accumulator.encode(),
        ]
    }
}
