use get_size::GetSize;
use serde::{Deserialize, Serialize};
use tasm_lib::{
    triton_vm::program::{NonDeterminism, Program},
    twenty_first::shared_math::{b_field_element::BFieldElement, bfield_codec::BFieldCodec},
};

use crate::models::{
    blockchain::block::Block,
    consensus::{SecretWitness, SupportedClaim},
};

#[derive(Debug, Clone, BFieldCodec, GetSize, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorrectControlParameterUpdateWitness {
    pub previous_block: Block,
}

impl SecretWitness for CorrectControlParameterUpdateWitness {
    fn nondeterminism(&self) -> NonDeterminism<BFieldElement> {
        todo!()
    }

    fn subprogram(&self) -> Program {
        todo!()
    }
}

#[derive(Debug, Clone, BFieldCodec, GetSize, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorrectControlParameterUpdate {
    pub supported_claim: SupportedClaim<CorrectControlParameterUpdateWitness>,
}
