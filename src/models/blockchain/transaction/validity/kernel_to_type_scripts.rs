use crate::models::blockchain::type_scripts::TypeScript;
use crate::models::consensus::tasm::program::ConsensusProgram;
use crate::prelude::{triton_vm, twenty_first};

use crate::models::blockchain::transaction::{self};
use crate::models::consensus::SecretWitness;

use get_size::GetSize;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use tasm_lib::library::Library;
use tasm_lib::traits::compiled_program::CompiledProgram;
use triton_vm::instruction::LabelledInstruction;
use triton_vm::prelude::{BFieldElement, Digest, NonDeterminism, PublicInput};
use twenty_first::math::bfield_codec::BFieldCodec;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub struct KernelToTypeScriptsWitness {
    type_scripts: Vec<TypeScript>,
    mast_path: Vec<Digest>,
}

impl SecretWitness for KernelToTypeScriptsWitness {
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
pub struct KernelToTypeScripts {
    pub witness: KernelToTypeScriptsWitness,
}

impl KernelToTypeScripts {}

impl ConsensusProgram for KernelToTypeScripts {
    fn source(&self) {
        todo!()
    }

    fn code(&self) -> Vec<LabelledInstruction> {
        todo!()
    }
}

impl From<transaction::PrimitiveWitness> for KernelToTypeScripts {
    fn from(primitive_witness: transaction::PrimitiveWitness) -> Self {
        let mut type_script_digests = primitive_witness
            .input_utxos
            .utxos
            .iter()
            .chain(primitive_witness.output_utxos.utxos.iter())
            .flat_map(|utxo| {
                utxo.coins
                    .iter()
                    .map(|coin| coin.type_script_hash)
                    .collect_vec()
            })
            .collect_vec();
        type_script_digests.sort();
        type_script_digests.dedup();
        Self {
            witness: KernelToTypeScriptsWitness {
                type_scripts: vec![],
                mast_path: vec![],
            },
        }
    }
}

impl CompiledProgram for KernelToTypeScripts {
    fn rust_shadow(
        _public_input: &PublicInput,
        _secret_input: &NonDeterminism,
    ) -> anyhow::Result<Vec<BFieldElement>> {
        todo!()
    }

    fn code() -> (Vec<LabelledInstruction>, Library) {
        todo!()
    }

    fn crash_conditions() -> Vec<String> {
        todo!()
    }
}
