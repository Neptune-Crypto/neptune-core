use crate::{
    models::{
        blockchain::{
            transaction::{primitive_witness::SaltedUtxos, transaction_kernel::TransactionKernel},
            type_scripts::{TypeScript, TypeScriptWitness},
        },
        consensus::mast_hash::MastHash,
    },
    prelude::{triton_vm, twenty_first},
};

use get_size::GetSize;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use tasm_lib::triton_vm::program::PublicInput;
use triton_vm::prelude::{BFieldElement, Claim, NonDeterminism, Program};
use twenty_first::shared_math::bfield_codec::BFieldCodec;

use crate::models::{
    blockchain::transaction::PrimitiveWitness,
    consensus::{ClaimSupport, SecretWitness, SupportedClaim, ValidationLogic},
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub struct BasicTypeScriptWitness {
    type_script: TypeScript,
    input_utxos: SaltedUtxos,
    output_utxos: SaltedUtxos,
    transaction_kernel: TransactionKernel,
}

impl SecretWitness for BasicTypeScriptWitness {
    fn nondeterminism(&self) -> NonDeterminism<BFieldElement> {
        NonDeterminism::default()
    }

    fn subprogram(&self) -> Program {
        self.type_script.program.clone()
    }

    fn standard_input(&self) -> PublicInput {
        self.type_script_standard_input()
    }
}

impl TypeScriptWitness for BasicTypeScriptWitness {
    fn transaction_kernel(&self) -> TransactionKernel {
        self.transaction_kernel.clone()
    }

    fn salted_input_utxos(&self) -> SaltedUtxos {
        self.input_utxos.clone()
    }

    fn salted_output_utxos(&self) -> SaltedUtxos {
        self.output_utxos.clone()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub struct TypeScriptsHalt {
    pub supported_claims: Vec<SupportedClaim<BasicTypeScriptWitness>>,
}

impl TypeScriptsHalt {
    // TODO: Remove after implementing this struct
    pub fn dummy() -> Self {
        Self {
            supported_claims: vec![SupportedClaim::dummy()],
        }
    }
}

impl ValidationLogic<BasicTypeScriptWitness> for TypeScriptsHalt {
    type PrimitiveWitness = PrimitiveWitness;

    fn new_from_primitive_witness(primitive_witness: &PrimitiveWitness) -> Self {
        let claim = Claim {
            input: primitive_witness.kernel.mast_hash().values().to_vec(),
            output: vec![],
            program_digest: TypeScript::native_currency().hash(),
        };
        let witness = BasicTypeScriptWitness {
            type_script: TypeScript::native_currency(),
            input_utxos: primitive_witness.input_utxos.clone(),
            output_utxos: primitive_witness.output_utxos.clone(),
            transaction_kernel: primitive_witness.kernel.clone(),
        };
        let amount_logic: SupportedClaim<BasicTypeScriptWitness> = SupportedClaim {
            claim,
            support: ClaimSupport::SecretWitness(witness),
        };
        Self {
            supported_claims: vec![amount_logic],
        }
    }

    fn validation_program(&self) -> Program {
        todo!()
    }

    fn support(&self) -> ClaimSupport<BasicTypeScriptWitness> {
        ClaimSupport::MultipleSupports(
            self.supported_claims
                .clone()
                .into_iter()
                .map(|sc| match sc.support {
                    ClaimSupport::Proof(_) => todo!(),
                    ClaimSupport::MultipleSupports(_) => todo!(),
                    ClaimSupport::SecretWitness(sw) => sw.to_owned(),
                    ClaimSupport::DummySupport => todo!(),
                })
                .collect(),
        )
    }

    fn claim(&self) -> Claim {
        let input = self
            .supported_claims
            .iter()
            .flat_map(|sc| sc.claim.program_digest.values().to_vec())
            .collect_vec();
        let output = vec![];
        // let program_hash = AllTypeScriptsHalt::program().hash();
        let program_digest = Default::default();
        Claim {
            program_digest,
            input,
            output,
        }
    }
}
