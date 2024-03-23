use crate::models::consensus::SecretWitness;
use crate::util_types::mmr::MmrAccumulator;
use crate::{models::consensus::tasm::program::ConsensusProgram, Hash};

use get_size::GetSize;
use serde::{Deserialize, Serialize};
use tasm_lib::{
    triton_vm::program::{NonDeterminism, PublicInput},
    twenty_first::shared_math::{b_field_element::BFieldElement, bfield_codec::BFieldCodec},
};

#[derive(Debug, Clone, BFieldCodec, GetSize, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorrectMmrUpdateWitness {
    pub previous_mmr_accumulator: MmrAccumulator<Hash>,
}

impl SecretWitness for CorrectMmrUpdateWitness {
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
