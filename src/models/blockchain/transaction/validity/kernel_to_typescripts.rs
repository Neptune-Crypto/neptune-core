use crate::prelude::{triton_vm, twenty_first};

use crate::models::blockchain::transaction::utxo::TypeScript;

use super::{ClaimSupport, SecretWitness, SupportedClaim, ValidationLogic};
use get_size::GetSize;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use tasm_lib::library::Library;
use tasm_lib::traits::compiled_program::CompiledProgram;
use triton_vm::instruction::LabelledInstruction;
use triton_vm::prelude::{BFieldElement, Claim, Digest, NonDeterminism, Program, PublicInput};
use twenty_first::shared_math::bfield_codec::BFieldCodec;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub struct KernelToTypeScriptsWitness {
    type_scripts: Vec<TypeScript>,
    mast_path: Vec<Digest>,
}

impl SecretWitness for KernelToTypeScriptsWitness {
    fn nondeterminism(&self) -> NonDeterminism<BFieldElement> {
        todo!()
    }

    fn subprogram(&self) -> Program {
        todo!()
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub struct KernelToTypeScripts {
    pub supported_claim: SupportedClaim<KernelToTypeScriptsWitness>,
}

impl KernelToTypeScripts {
    // TODO: Remove after implementing this struct
    pub fn dummy() -> Self {
        Self {
            supported_claim: SupportedClaim::dummy(),
        }
    }
}

impl ValidationLogic<KernelToTypeScriptsWitness> for KernelToTypeScripts {
    fn new_from_primitive_witness(
        primitive_witness: &crate::models::blockchain::transaction::PrimitiveWitness,
        tx_kernel: &crate::models::blockchain::transaction::transaction_kernel::TransactionKernel,
    ) -> Self {
        let mut type_script_digests = primitive_witness
            .input_utxos
            .iter()
            .chain(primitive_witness.output_utxos.iter())
            .flat_map(|utxo| {
                utxo.coins
                    .iter()
                    .map(|coin| coin.type_script_hash)
                    .collect_vec()
            })
            .collect_vec();
        type_script_digests.sort();
        type_script_digests.dedup();
        let claim = Claim {
            input: tx_kernel.mast_hash().values().to_vec(),
            output: type_script_digests
                .into_iter()
                .flat_map(|d| d.values().to_vec())
                .collect_vec(),
            // program_hash: Self::program(),
            program_digest: Digest::default(),
        };
        let supported_claim = SupportedClaim {
            claim,
            support: ClaimSupport::DummySupport,
        };
        Self { supported_claim }
    }

    fn prove(&mut self) -> anyhow::Result<()> {
        todo!()
    }

    fn verify(&self) -> bool {
        todo!()
    }

    fn subprogram(&self) -> Program {
        todo!()
    }

    fn support(&self) -> ClaimSupport<KernelToTypeScriptsWitness> {
        self.supported_claim.support.clone()
    }

    fn claim(&self) -> Claim {
        self.supported_claim.claim.clone()
    }
}

impl CompiledProgram for KernelToTypeScripts {
    fn rust_shadow(
        _public_input: &PublicInput,
        _secret_input: &NonDeterminism<BFieldElement>,
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
