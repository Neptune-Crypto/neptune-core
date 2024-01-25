use crate::prelude::{triton_vm, twenty_first};

use get_size::GetSize;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use triton_vm::prelude::{BFieldElement, Claim, NonDeterminism, Program};
use twenty_first::shared_math::bfield_codec::BFieldCodec;

use super::{ClaimSupport, SecretWitness, SupportedClaim, ValidationLogic};
use crate::models::blockchain::transaction::{
    transaction_kernel::TransactionKernel, utxo::LockScript, PrimitiveWitness,
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub struct LockScriptHaltsWitness {
    lock_script: LockScript,
    preimage: Vec<BFieldElement>,
}

impl SecretWitness for LockScriptHaltsWitness {
    fn nondeterminism(&self) -> NonDeterminism<BFieldElement> {
        NonDeterminism::new(self.preimage.clone().into_iter().collect_vec())
    }

    fn subprogram(&self) -> Program {
        self.lock_script.program.clone()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, Default, BFieldCodec)]
pub struct LockScriptsHalt {
    pub supported_claims: Vec<SupportedClaim<LockScriptHaltsWitness>>,
}

impl ValidationLogic<LockScriptHaltsWitness> for LockScriptsHalt {
    fn new_from_primitive_witness(
        primitive_witness: &PrimitiveWitness,
        tx_kernel: &TransactionKernel,
    ) -> LockScriptsHalt {
        let program_and_program_digests_and_spending_keys = primitive_witness
            .input_lock_scripts
            .iter()
            .zip_eq(primitive_witness.lock_script_witnesses.iter())
            .map(|(lockscr, spendkey)| (lockscr, lockscr.hash(), spendkey));
        let tx_kernel_mast_hash = tx_kernel.mast_hash();
        let empty_string = vec![];

        Self {
            supported_claims: program_and_program_digests_and_spending_keys
                .into_iter()
                .map(|(lockscript, lockscript_digest, spendkey)| SupportedClaim {
                    claim: triton_vm::prelude::Claim {
                        program_digest: lockscript_digest,
                        input: tx_kernel_mast_hash.values().to_vec(),
                        output: empty_string.clone(),
                    },
                    support: ClaimSupport::SecretWitness(LockScriptHaltsWitness {
                        lock_script: lockscript.to_owned(),
                        preimage: spendkey.to_owned(),
                    }),
                })
                .collect(),
        }
    }

    fn subprogram(&self) -> Program {
        todo!()
    }

    fn support(&self) -> ClaimSupport<LockScriptHaltsWitness> {
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

    // fn support(&self) -> ClaimSupport<LockScriptHaltsWitness> {
    // let supports = self
    //     .supported_claims
    //     .iter()
    //     .map(|sc| sc.support.clone())
    //     .collect_vec();
    // ClaimSupport::MultipleSupports(supports)
    // }

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
