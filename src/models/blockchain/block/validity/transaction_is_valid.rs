use get_size::GetSize;
use serde::{Deserialize, Serialize};
use tasm_lib::{
    triton_vm::{
        instruction::LabelledInstruction,
        program::{NonDeterminism, PublicInput},
    },
    twenty_first::shared_math::{b_field_element::BFieldElement, bfield_codec::BFieldCodec},
};

use crate::models::{
    blockchain::transaction::Transaction,
    consensus::{tasm::program::ConsensusProgram, SecretWitness},
};

#[derive(Debug, Clone, BFieldCodec, GetSize, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionIsValidWitness {
    transaction: Transaction,
}

impl SecretWitness for TransactionIsValidWitness {
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
pub struct TransactionIsValid {
    witness: TransactionIsValidWitness,
}

impl ConsensusProgram for TransactionIsValid {
    fn source(&self) {
        todo!()
    }

    fn code(&self) -> Vec<LabelledInstruction> {
        todo!()
    }
}
