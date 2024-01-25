use crate::prelude::{triton_vm, twenty_first};

use crate::models::blockchain::transaction::{
    transaction_kernel::{TransactionKernel, TransactionKernelField},
    utxo::Utxo,
    PrimitiveWitness,
};

use super::{ClaimSupport, SecretWitness, SupportedClaim, ValidationLogic};
use get_size::GetSize;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use tasm_lib::library::Library;
use tasm_lib::traits::compiled_program::CompiledProgram;
use triton_vm::prelude::{BFieldElement, Claim, Digest, NonDeterminism, Program, PublicInput};
use twenty_first::shared_math::bfield_codec::BFieldCodec;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub struct KernelToLockScriptsWitness {
    input_utxos: Vec<Utxo>,
    mast_path: Vec<Digest>,
}

impl SecretWitness for KernelToLockScriptsWitness {
    fn nondeterminism(&self) -> NonDeterminism<BFieldElement> {
        todo!()
    }

    fn subprogram(&self) -> Program {
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

impl ValidationLogic<KernelToLockScriptsWitness> for KernelToLockScripts {
    fn new_from_primitive_witness(
        primitive_witness: &PrimitiveWitness,
        tx_kernel: &TransactionKernel,
    ) -> Self {
        let claim = Claim {
            input: tx_kernel.mast_hash().into(),
            output: primitive_witness
                .input_lock_scripts
                .iter()
                .flat_map(|ls| ls.hash().values().to_vec())
                .collect_vec(),
            // program_digest: Self::program().hash::<Hash>(),
            program_digest: Digest::default(),
        };
        let _kernel_to_lock_scripts_witness = KernelToLockScriptsWitness {
            input_utxos: primitive_witness.input_utxos.clone(),
            mast_path: tx_kernel.mast_path(TransactionKernelField::InputUtxos),
        };
        let supported_claim = SupportedClaim {
            claim,
            // support: ClaimSupport::SecretWitness(kernel_to_lock_scripts_witness),
            support: ClaimSupport::DummySupport,
        };
        Self { supported_claim }
    }

    fn subprogram(&self) -> Program {
        todo!()
    }

    fn support(&self) -> ClaimSupport<KernelToLockScriptsWitness> {
        self.supported_claim.support.clone()
    }

    fn claim(&self) -> Claim {
        self.supported_claim.claim.clone()
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
