use chrono::Duration;
use get_size::GetSize;
use serde::{Deserialize, Serialize};
use tasm_lib::twenty_first::shared_math::bfield_codec::BFieldCodec;

use crate::models::{
    blockchain::transaction::{transaction_kernel::TransactionKernel, TransactionPrimitiveWitness},
    consensus::{SecretWitness, ValidationLogic},
};

pub struct TimeLock {
    /// Duration since the unix epoch (00:00 am on Jan 1 1970).
    release_date: Duration,
}

impl TimeLock {
    pub fn until(date: Duration) -> TimeLock {
        Self { release_date: date }
    }
}

#[derive(BFieldCodec, GetSize, PartialEq, Eq, Serialize, Deserialize, Clone)]
struct NoExternalWitness;

impl SecretWitness for (TransactionPrimitiveWitness, NoExternalWitness) {
    fn nondeterminism(
        &self,
    ) -> tasm_lib::prelude::triton_vm::program::NonDeterminism<
        tasm_lib::prelude::twenty_first::prelude::BFieldElement,
    > {
        todo!()
    }

    fn subprogram(&self) -> tasm_lib::prelude::triton_vm::program::Program {
        todo!()
    }
}

// impl TypeScriptValidationLogic<NoExternalWitness> for TimeLock
// Not yet; type aliases are still experimental ;-)
impl ValidationLogic<(TransactionPrimitiveWitness, NoExternalWitness)> for TimeLock {
    type PrimitiveWitness = (TransactionPrimitiveWitness, NoExternalWitness);

    type Kernel = TransactionKernel;

    fn subprogram(&self) -> tasm_lib::prelude::triton_vm::program::Program {
        todo!()
    }

    fn support(
        &self,
    ) -> crate::models::consensus::ClaimSupport<(TransactionPrimitiveWitness, NoExternalWitness)>
    {
        todo!()
    }

    fn claim(&self) -> tasm_lib::prelude::triton_vm::proof::Claim {
        todo!()
    }

    fn new_from_primitive_witness(
        primitive_witness: &Self::PrimitiveWitness,
        tx_kernel: &Self::Kernel,
    ) -> Self {
        todo!()
    }
}
