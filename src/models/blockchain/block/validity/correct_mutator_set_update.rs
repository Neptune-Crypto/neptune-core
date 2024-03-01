use get_size::GetSize;
use serde::{Deserialize, Serialize};
use tasm_lib::{
    triton_vm::program::{NonDeterminism, PublicInput},
    twenty_first::{bfieldcodec_derive::BFieldCodec, shared_math::b_field_element::BFieldElement},
};

use crate::{
    models::consensus::{tasm::program::ConsensusProgram, SecretWitness},
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

    fn standard_input(&self) -> PublicInput {
        todo!()
    }

    fn program(&self) -> tasm_lib::prelude::triton_vm::program::Program {
        todo!()
    }
}

#[derive(Debug, Clone, BFieldCodec, GetSize, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorrectMutatorSetUpdate {
    pub witness: CorrectMutatorSetUpdateWitness,
}

impl ConsensusProgram for CorrectMutatorSetUpdate {
    fn source(&self) {
        todo!()
    }

    fn code(&self) -> Vec<tasm_lib::prelude::triton_vm::prelude::LabelledInstruction> {
        todo!()
    }
}
