use crate::Hash;
use get_size::GetSize;
use serde::{Deserialize, Serialize};
use tasm_lib::{
    triton_vm::program::{NonDeterminism, Program},
    twenty_first::{
        shared_math::{b_field_element::BFieldElement, bfield_codec::BFieldCodec},
        util_types::mmr::mmr_accumulator::MmrAccumulator,
    },
};

use crate::models::consensus::{SecretWitness, SupportedClaim};

#[derive(Debug, Clone, BFieldCodec, GetSize, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorrectMmrUpdateWitness {
    pub previous_mmr_accumulator: MmrAccumulator<Hash>,
}

impl SecretWitness for CorrectMmrUpdateWitness {
    fn nondeterminism(&self) -> NonDeterminism<BFieldElement> {
        todo!()
    }

    fn subprogram(&self) -> Program {
        todo!()
    }
}

#[derive(Debug, Clone, BFieldCodec, GetSize, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorrectMmrUpdate {
    pub supported_claim: SupportedClaim<CorrectMmrUpdateWitness>,
}
