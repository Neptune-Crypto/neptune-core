use crate::prelude::{triton_vm, twenty_first};

use get_size::GetSize;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use triton_vm::prelude::{BFieldElement, Claim, NonDeterminism, Program};
use twenty_first::shared_math::bfield_codec::BFieldCodec;

use crate::models::blockchain::transaction::{
    transaction_kernel::TransactionKernel,
    utxo::{TypeScript, Utxo},
    PrimitiveWitness,
};

use super::{ClaimSupport, SecretWitness, SupportedClaim, ValidationLogic};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub struct TypeScriptHaltsWitness {
    type_script: TypeScript,
    input_utxos: Vec<Utxo>,
    output_utxos: Vec<Utxo>,
}

impl SecretWitness for TypeScriptHaltsWitness {
    fn nondeterminism(&self) -> NonDeterminism<BFieldElement> {
        NonDeterminism::default()
    }

    fn subprogram(&self) -> Program {
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

impl ValidationLogic<TypeScriptHaltsWitness> for TypeScriptsHalt {
    fn new_from_primitive_witness(
        primitive_witness: &PrimitiveWitness,
        tx_kernel: &TransactionKernel,
    ) -> Self {
        let claim = Claim {
            input: tx_kernel.mast_hash().values().to_vec(),
            output: vec![],
            program_digest: TypeScript::native_coin().hash(),
        };
        let witness = TypeScriptHaltsWitness {
            type_script: TypeScript::native_coin(),
            input_utxos: primitive_witness.input_utxos.clone(),
            output_utxos: primitive_witness.output_utxos.clone(),
        };
        let amount_logic: SupportedClaim<TypeScriptHaltsWitness> = SupportedClaim {
            claim,
            support: ClaimSupport::SecretWitness(witness),
        };
        Self {
            supported_claims: vec![amount_logic],
        }
    }

    fn subprogram(&self) -> Program {
        todo!()
    }

    fn support(&self) -> ClaimSupport<TypeScriptHaltsWitness> {
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
        // let program_hash = AllLockScriptsHalt::program().hash();
        let program_digest = Default::default();
        Claim {
            program_digest,
            input,
            output,
        }
    }
}
