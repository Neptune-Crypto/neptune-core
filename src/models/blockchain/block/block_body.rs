use crate::models::consensus::mast_hash::{HasDiscriminant, MastHash};
use crate::prelude::twenty_first;

use get_size::GetSize;
use serde::{Deserialize, Serialize};
use tasm_lib::twenty_first::shared_math::b_field_element::BFieldElement;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
use twenty_first::shared_math::bfield_codec::BFieldCodec;

use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::transaction::Transaction;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;

enum BlockBodyField {
    Transaction,
    MutatorSetAccumulator,
    LockFreeMmrAccumulator,
    BlockMmrAccumulator,
}

impl HasDiscriminant for BlockBodyField {
    fn discriminant(&self) -> usize {
        match self {
            Transaction => 0,
            MutatorSetAccumulator => 1,
            LockFreeMmrAccumulator => 2,
            BlockMmrAccumulator => 3,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BFieldCodec, GetSize)]
pub struct BlockBody {
    /// Every block contains exactly one transaction, which represents the merger of all
    /// broadcasted transactions that the miner decided to confirm.
    pub transaction: Transaction,

    /// The mutator set accumulator represents the UTXO set. It is simultaneously an
    /// accumulator (=> compact representation and membership proofs) and an anonymity
    /// construction (=> outputs from one transaction do not look like inputs to another).
    pub mutator_set_accumulator: MutatorSetAccumulator<Hash>,

    /// Lock-free UTXOs do not come with lock scripts and do not live in the mutator set.
    pub lock_free_mmr_accumulator: MmrAccumulator<Hash>,

    /// All blocks live in an MMR, so that we can efficiently prove that a given block
    /// lives on the line between the tip and genesis.
    pub block_mmr_accumulator: MmrAccumulator<Hash>,
}

impl MastHash for BlockBody {
    type FieldEnum = BlockBodyField;

    fn mast_sequences(&self) -> Vec<Vec<BFieldElement>> {
        vec![
            self.transaction.encode(),
            self.mutator_set_accumulator.encode(),
            self.lock_free_mmr_accumulator.encode(),
            self.block_mmr_accumulator.encode(),
        ]
    }
}
