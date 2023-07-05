use get_size::GetSize;
use serde::{Deserialize, Serialize};
use triton_opcodes::program::Program;

use super::{compiled_program::CompiledProgram, SupportedClaim, ValidationLogic};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize)]
pub struct KernelToLockScripts {
    pub supported_claim: SupportedClaim,
}

impl KernelToLockScripts {
    // TODO: Remove after implementing this struct
    pub fn dummy() -> Self {
        Self {
            supported_claim: SupportedClaim::dummy(),
        }
    }
}

impl ValidationLogic for KernelToLockScripts {
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

impl CompiledProgram for KernelToLockScripts {
    fn rust_shadow(
        _public_input: std::collections::VecDeque<triton_vm::BFieldElement>,
        _secret_input: std::collections::VecDeque<triton_vm::BFieldElement>,
    ) -> Vec<triton_vm::BFieldElement> {
        todo!()
    }

    fn program() -> triton_opcodes::program::Program {
        Program::default()
    }

    fn crash_conditions() -> Vec<String> {
        todo!()
    }
}
