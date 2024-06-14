use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
use crate::prelude::{triton_vm, twenty_first};

use crate::models::blockchain::transaction::{self};
use crate::models::blockchain::transaction::{
    transaction_kernel::TransactionKernelField, utxo::Utxo,
};

use crate::models::proof_abstractions::SecretWitness;
use get_size::GetSize;
use serde::{Deserialize, Serialize};
use tasm_lib::library::Library;
use tasm_lib::traits::compiled_program::CompiledProgram;
use tasm_lib::triton_vm::instruction::LabelledInstruction;
use triton_vm::prelude::{BFieldElement, Digest, NonDeterminism, PublicInput};
use twenty_first::math::bfield_codec::BFieldCodec;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub struct KernelToLockScriptsWitness {
    input_utxos: Vec<Utxo>,
    mast_path: Vec<Digest>,
}

impl SecretWitness for KernelToLockScriptsWitness {
    fn nondeterminism(&self) -> NonDeterminism {
        todo!()
    }

    fn standard_input(&self) -> PublicInput {
        todo!()
    }

    fn program(&self) -> triton_vm::prelude::Program {
        todo!()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub struct KernelToLockScripts {
    pub witness: KernelToLockScriptsWitness,
}

impl ConsensusProgram for KernelToLockScripts {
    fn source(&self) {
        todo!()
    }

    fn code(&self) -> Vec<LabelledInstruction> {
        todo!()
    }
}

impl From<transaction::PrimitiveWitness> for KernelToLockScripts {
    fn from(primitive_witness: transaction::PrimitiveWitness) -> Self {
        let kernel_to_lock_scripts_witness = KernelToLockScriptsWitness {
            input_utxos: primitive_witness.input_utxos.utxos.clone(),
            mast_path: primitive_witness
                .kernel
                .mast_path(TransactionKernelField::InputUtxos),
        };
        Self {
            witness: kernel_to_lock_scripts_witness,
        }
    }
}

impl CompiledProgram for KernelToLockScripts {
    fn rust_shadow(
        _public_input: &PublicInput,
        _secret_input: &NonDeterminism,
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
