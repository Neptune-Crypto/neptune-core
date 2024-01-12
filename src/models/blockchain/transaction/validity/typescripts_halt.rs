use get_size::GetSize;
use serde::{Deserialize, Serialize};
use triton_vm::{BFieldElement, NonDeterminism};
use twenty_first::shared_math::bfield_codec::BFieldCodec;

use crate::models::blockchain::transaction::utxo::TypeScript;

use super::{SecretWitness, SupportedClaim, ValidationLogic};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
struct TypeScriptHaltsWitness {
    type_script: TypeScript,
}

impl SecretWitness for TypeScriptHaltsWitness {
    fn nondeterminism(&self) -> triton_vm::NonDeterminism<BFieldElement> {
        NonDeterminism::default()
    }

    fn program(&self) -> triton_vm::Program {
        self.type_script.program.clone()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub struct TypeScriptsHalt {
    pub supported_claims: Vec<SupportedClaim<TypeScriptHaltsWitness>>,
}

impl TypeScriptsHalt {
    // TODO: Remove after implementing this struct
    pub fn dummy() -> Self {
        Self {
            supported_claims: vec![SupportedClaim::dummy()],
        }
    }
}

impl ValidationLogic for TypeScriptsHalt {
    fn new_from_witness(
        _primitive_witness: &crate::models::blockchain::transaction::PrimitiveWitness,
        _tx_kernel: &crate::models::blockchain::transaction::transaction_kernel::TransactionKernel,
    ) -> Self {
        todo!()
    }

    fn prove(&mut self) -> anyhow::Result<()> {
        todo!()
    }

    fn verify(&self) -> bool {
        todo!()
    }
}
