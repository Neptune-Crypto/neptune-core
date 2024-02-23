use get_size::GetSize;
use serde::{Deserialize, Serialize};
use tasm_lib::{
    triton_vm::program::{NonDeterminism, Program, PublicInput},
    twenty_first::shared_math::{b_field_element::BFieldElement, bfield_codec::BFieldCodec},
};

use crate::models::{
    blockchain::transaction::Transaction,
    consensus::{SecretWitness, SupportedClaim},
};

#[derive(Debug, Clone, BFieldCodec, GetSize, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionIsValidWitness {
    transaction: Transaction,
}

impl SecretWitness for TransactionIsValidWitness {
    fn nondeterminism(&self) -> NonDeterminism<BFieldElement> {
        todo!()
    }

    fn subprogram(&self) -> Program {
        todo!()
    }

    fn standard_input(&self) -> PublicInput {
        todo!()
    }

}

#[derive(Debug, Clone, BFieldCodec, GetSize, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionIsValid {
    supported_claim: SupportedClaim<TransactionIsValidWitness>,
}
