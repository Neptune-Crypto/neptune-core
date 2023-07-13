use super::{SupportedClaim, ValidationLogic};
use get_size::GetSize;
use serde::{Deserialize, Serialize};
use tasm_lib::compiled_program::CompiledProgram;
use tasm_lib::library::Library;
use triton_vm::instruction::LabelledInstruction;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize)]
pub struct KernelToTypeScripts {
    pub supported_claim: SupportedClaim,
}

impl KernelToTypeScripts {
    // TODO: Remove after implementing this struct
    pub fn dummy() -> Self {
        Self {
            supported_claim: SupportedClaim::dummy(),
        }
    }
}

impl ValidationLogic for KernelToTypeScripts {
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

impl CompiledProgram for KernelToTypeScripts {
    fn rust_shadow(
        _public_input: &[triton_vm::BFieldElement],
        _secret_input: &[triton_vm::BFieldElement],
    ) -> anyhow::Result<Vec<triton_vm::BFieldElement>> {
        todo!()
    }

    fn code() -> (Vec<LabelledInstruction>, Library) {
        todo!()
    }

    fn crash_conditions() -> Vec<String> {
        todo!()
    }
}
