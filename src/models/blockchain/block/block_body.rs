use crate::prelude::twenty_first;

use get_size::GetSize;
use serde::{Deserialize, Serialize};
use twenty_first::shared_math::bfield_codec::BFieldCodec;

use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::transaction::Transaction;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BFieldCodec, GetSize)]
pub struct BlockBody {
    pub transaction: Transaction,
    pub next_mutator_set_accumulator: MutatorSetAccumulator<Hash>,
    pub previous_mutator_set_accumulator: MutatorSetAccumulator<Hash>,
}
