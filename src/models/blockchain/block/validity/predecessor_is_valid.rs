use get_size::GetSize;
use serde::{Deserialize, Serialize};
use tasm_lib::{
    triton_vm::{
        instruction::LabelledInstruction,
        program::{NonDeterminism, PublicInput},
    },
    twenty_first::math::bfield_codec::BFieldCodec,
};

use crate::models::{
    blockchain::block::Block,
    proof_abstractions::{tasm::program::ConsensusProgram, SecretWitness},
};

#[derive(Debug, Clone, BFieldCodec, GetSize, PartialEq, Eq, Serialize, Deserialize)]
pub struct PredecessorIsValidWitness {
    pub predecessor_block: Block,
}

impl SecretWitness for PredecessorIsValidWitness {
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
pub struct PredecessorIsValid {
    pub witness: PredecessorIsValidWitness,
}

impl ConsensusProgram for PredecessorIsValid {
    fn source(&self) {
        todo!()
    }

    fn code(&self) -> Vec<LabelledInstruction> {
        todo!()
    }
}
