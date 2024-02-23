use get_size::GetSize;
use serde::{Deserialize, Serialize};
use tasm_lib::{
    triton_vm::program::{NonDeterminism, Program, PublicInput},
    twenty_first::{self, shared_math::b_field_element::BFieldElement},
};
use twenty_first::shared_math::bfield_codec::BFieldCodec;

use crate::models::consensus::SecretWitness;

use self::{
    coinbase_is_valid::CoinbaseIsValid,
    correct_control_parameter_update::CorrectControlParameterUpdate,
    correct_mmr_update::CorrectMmrUpdate, correct_mutator_set_update::CorrectMutatorSetUpdate,
    mmr_membership::MmrMembership, predecessor_is_valid::PredecessorIsValid,
    transaction_is_valid::TransactionIsValid,
};

use super::Block;

pub mod coinbase_is_valid;
pub mod correct_control_parameter_update;
pub mod correct_mmr_update;
pub mod correct_mutator_set_update;
pub mod mmr_membership;
pub mod predecessor_is_valid;
pub mod transaction_is_valid;

/// The validity of a block, in the principal case, decomposes into these subclaims.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub struct PrincipalBlockValidationLogic {
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

/// Alternatively, the validity of a block follows from that of a successor. This pathway
/// two subclaims, both of which are relative to the successor block.
///  1. the current block lives in the block mmr of the successor block
///  2. the successor block is valid
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub struct AlternativeBlockValidationLogic {
    pub mmr_membership: MmrMembership,
    pub successor_is_valid: PrincipalBlockValidationLogic,
}

#[derive(Debug, Clone, BFieldCodec, GetSize, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrincipalBlockValidationWitness {
    pub successor: Block, // includes proof
}

impl SecretWitness for PrincipalBlockValidationWitness {
    fn nondeterminism(&self) -> NonDeterminism<BFieldElement> {
        todo!()
    }

    fn subprogram(&self) -> Program {
        todo!()
    }

    fn standard_input(&self) -> PublicInput {
        todo!()
    }

}
