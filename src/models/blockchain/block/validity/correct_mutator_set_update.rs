use get_size::GetSize;
use serde::{Deserialize, Serialize};
use tasm_lib::{
    triton_vm::program::{NonDeterminism, Program, PublicInput},
    twenty_first::{bfieldcodec_derive::BFieldCodec, shared_math::b_field_element::BFieldElement},
};

use crate::{
    models::consensus::{SecretWitness, SupportedClaim},
    util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator,
};

#[derive(Debug, Clone, BFieldCodec, GetSize, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorrectMutatorSetUpdateWitness {
    previous_mutator_set_accumulator: MutatorSetAccumulator,
}

impl SecretWitness for CorrectMutatorSetUpdateWitness {
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

#[derive(Debug, Clone, BFieldCodec, GetSize, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorrectMutatorSetUpdate {
    pub supported_claim: SupportedClaim<CorrectMutatorSetUpdateWitness>,
}
