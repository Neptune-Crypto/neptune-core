use get_size::GetSize;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::triton_vm::program::NonDeterminism;
use tasm_lib::triton_vm::program::PublicInput;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;

use crate::models::blockchain::block::Block;
use crate::models::consensus::tasm::program::ConsensusProgram;
use crate::models::consensus::SecretWitness;

#[derive(Debug, Clone, BFieldCodec, GetSize, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorrectControlParameterUpdateWitness {
    pub previous_block: Block,
}

impl SecretWitness for CorrectControlParameterUpdateWitness {
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
pub struct CorrectControlParameterUpdate {
    pub witness: CorrectControlParameterUpdateWitness,
}

impl ConsensusProgram for CorrectControlParameterUpdate {
    fn source(&self) {
        todo!()
    }

    fn code(&self) -> Vec<tasm_lib::prelude::triton_vm::prelude::LabelledInstruction> {
        todo!()
    }
}
