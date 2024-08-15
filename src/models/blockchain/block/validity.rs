pub mod coinbase_is_valid;
pub mod correct_control_parameter_update;
pub mod correct_mmr_update;
pub mod correct_mutator_set_update;
pub mod mmr_membership;
pub mod predecessor_is_valid;
pub mod transaction_is_valid;

use coinbase_is_valid::CoinbaseIsValid;
use correct_control_parameter_update::CorrectControlParameterUpdate;
use correct_mmr_update::CorrectMmrUpdate;
use correct_mutator_set_update::CorrectMutatorSetUpdate;
use get_size::GetSize;
use mmr_membership::MmrMembership;
use predecessor_is_valid::PredecessorIsValid;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::triton_vm::instruction::LabelledInstruction;
use tasm_lib::triton_vm::program::NonDeterminism;
use tasm_lib::triton_vm::program::PublicInput;
use tasm_lib::twenty_first;
use transaction_is_valid::TransactionIsValid;
use twenty_first::math::bfield_codec::BFieldCodec;

use crate::models::consensus::tasm::program::ConsensusProgram;
use crate::models::consensus::SecretWitness;

use super::Block;

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
    fn nondeterminism(&self) -> NonDeterminism {
        todo!()
    }

    fn standard_input(&self) -> PublicInput {
        todo!()
    }

    fn program(&self) -> tasm_lib::prelude::triton_vm::program::Program {
        todo!()
    }
}

impl ConsensusProgram for PrincipalBlockValidationLogic {
    fn source(&self) {
        todo!()
    }

    fn code(&self) -> Vec<LabelledInstruction> {
        todo!()
    }
}
