use crate::prelude::twenty_first;

use serde::{Deserialize, Serialize};
use twenty_first::shared_math::b_field_element::BFieldElement;
use twenty_first::shared_math::bfield_codec::BFieldCodec;

use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::transaction::Transaction;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BFieldCodec)]
pub struct BlockBody {
    pub transaction: Transaction,
    pub next_mutator_set_accumulator: MutatorSetAccumulator<Hash>,
    pub previous_mutator_set_accumulator: MutatorSetAccumulator<Hash>,
    pub stark_proof: Vec<BFieldElement>,
}
