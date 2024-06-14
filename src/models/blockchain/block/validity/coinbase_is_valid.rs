use get_size::GetSize;
use serde::{Deserialize, Serialize};
use tasm_lib::{
    triton_vm::{
        instruction::LabelledInstruction,
        program::{NonDeterminism, PublicInput},
    },
    twenty_first,
};
use twenty_first::math::bfield_codec::BFieldCodec;

use crate::models::{
    blockchain::block::Block,
    proof_abstractions::{tasm::program::ConsensusProgram, SecretWitness},
};

#[derive(Debug, Clone, BFieldCodec, GetSize, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoinbaseIsValidWitness {
    pub block: Block,
}

impl SecretWitness for CoinbaseIsValidWitness {
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
pub struct CoinbaseIsValid {
    witness: CoinbaseIsValidWitness,
}

impl ConsensusProgram for CoinbaseIsValid {
    fn source(&self) {
        todo!()
    }

    fn code(&self) -> Vec<LabelledInstruction> {
        todo!()
    }
}
