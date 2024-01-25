use get_size::GetSize;
use serde::{Deserialize, Serialize};
use tasm_lib::twenty_first;
use twenty_first::shared_math::bfield_codec::BFieldCodec;

use self::{
    coinbase_is_valid::CoinbaseIsValid,
    correct_control_parameter_update::CorrectControlParameterUpdate,
    correct_mmr_update::CorrectMmrUpdate, correct_mutator_set_update::CorrectMutatorSetUpdate,
    predecessor_is_valid::PredecessorIsValid, transaction_is_valid::TransactionIsValid,
};

pub mod coinbase_is_valid;
pub mod correct_control_parameter_update;
pub mod correct_mmr_update;
pub mod correct_mutator_set_update;
pub mod predecessor_is_valid;
pub mod transaction_is_valid;

/// The validity of a block, when it is not the genesis block and when it does not
/// come with proofs, decomposes into these subclaims.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub struct BlockValidationLogic {
    // program: recursive-verify-or-is-genesis, input: block kernel, output: []
    pub predecessor_is_valid: PredecessorIsValid,

    // program: verify-transaction, input: block kernel, output: []
    pub transaction_is_valid: TransactionIsValid,

    // program: verify-coinbase, input: block kernel, output: []
    pub coinbase_is_valid: CoinbaseIsValid,

    // program: update-mutator-set, input: block kernel, output: []
    pub correct_mutator_set_update: CorrectMutatorSetUpdate,

    // program: update-mmr, input: block kernel, output: []
    pub correct_mmr_update: CorrectMmrUpdate,

    // program: update-control-parameters, input: block kernel, output: []
    pub correct_control_parameter_update: CorrectControlParameterUpdate,
}
