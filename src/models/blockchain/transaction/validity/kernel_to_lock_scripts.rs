use super::{SecretWitness, SupportedClaim, ValidationLogic};
use get_size::GetSize;
use serde::{Deserialize, Serialize};
use tasm_lib::library::Library;
use tasm_lib::traits::compiled_program::CompiledProgram;
use triton_vm::{BFieldElement, Digest, NonDeterminism, Program, PublicInput};
use twenty_first::shared_math::bfield_codec::BFieldCodec;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
struct KernelToLockScriptsWitness {
    lock_scripts: Vec<Program>,
    mast_path: Vec<Digest>,
}

impl SecretWitness for KernelToLockScriptsWitness {
    fn nondeterminism(&self) -> NonDeterminism<BFieldElement> {
        todo!()
    }

    fn program(&self) -> Program {
        todo!()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub struct KernelToLockScripts {
    pub supported_claim: SupportedClaim<KernelToLockScriptsWitness>,
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
        _public_input: &PublicInput,
        _secret_input: &NonDeterminism<BFieldElement>,
    ) -> anyhow::Result<Vec<BFieldElement>> {
        todo!()
    }

    fn crash_conditions() -> Vec<String> {
        todo!()
    }

    fn code() -> (Vec<triton_vm::instruction::LabelledInstruction>, Library) {
        todo!()
    }
}
