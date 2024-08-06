use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
use get_size::GetSize;
use serde::{Deserialize, Serialize};
use tasm_lib::{
    triton_vm::program::{NonDeterminism, PublicInput},
    twenty_first::{
        math::bfield_codec::BFieldCodec, util_types::mmr::mmr_accumulator::MmrAccumulator,
    },
};

use crate::models::proof_abstractions::SecretWitness;

#[derive(Debug, Clone, BFieldCodec, GetSize, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorrectMmrUpdateWitness {
    pub previous_mmr_accumulator: MmrAccumulator,
}

impl SecretWitness for CorrectMmrUpdateWitness {
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

#[derive(Debug, Clone, BFieldCodec, GetSize, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorrectMmrUpdate {
    pub witness: CorrectMmrUpdateWitness,
}

impl ConsensusProgram for CorrectMmrUpdate {
    fn source(&self) {
        todo!()
    }

    fn code(&self) -> Vec<tasm_lib::prelude::triton_vm::prelude::LabelledInstruction> {
        todo!()
    }
}
