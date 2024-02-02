use get_size::GetSize;
use serde::{Deserialize, Serialize};
use tasm_lib::{
    triton_vm::program::{NonDeterminism, Program},
    twenty_first::{self, shared_math::b_field_element::BFieldElement},
};
use twenty_first::shared_math::bfield_codec::BFieldCodec;

use crate::models::{
    blockchain::block::Block,
    consensus::{SecretWitness, SupportedClaim},
};

#[derive(Debug, Clone, BFieldCodec, GetSize, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoinbaseIsValidWitness {
    pub block: Block,
}

impl SecretWitness for CoinbaseIsValidWitness {
    fn nondeterminism(&self) -> NonDeterminism<BFieldElement> {
        todo!()
    }

    fn subprogram(&self) -> Program {
        todo!()
    }
}

#[derive(Debug, Clone, BFieldCodec, GetSize, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoinbaseIsValid {
    supported_claim: SupportedClaim<CoinbaseIsValidWitness>,
}
