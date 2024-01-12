use get_size::GetSize;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use triton_vm::{Digest, NonDeterminism};
use twenty_first::shared_math::bfield_codec::BFieldCodec;

use super::{ClaimSupport, SecretWitness, SupportedClaim, ValidationLogic};
use crate::models::blockchain::transaction::{
    transaction_kernel::TransactionKernel, utxo::LockScript, PrimitiveWitness,
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, Default, BFieldCodec)]
struct LockScriptHaltsWitness {
    lock_script: LockScript,
    preimage: Digest,
}

impl SecretWitness for LockScriptHaltsWitness {
    fn nondeterminism(&self) -> triton_vm::NonDeterminism<triton_vm::BFieldElement> {
        NonDeterminism::new(self.preimage.reversed().values())
    }

    fn program(&self) -> triton_vm::Program {
        self.lock_script.clone()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, Default, BFieldCodec)]
pub struct LockScriptsHalt {
    pub supported_claims: Vec<SupportedClaim<LockScriptHaltsWitness>>,
}

impl ValidationLogic for LockScriptsHalt {
    fn new_from_witness(
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
                    claim: triton_vm::Claim {
                        program_digest: lockscript_digest,
                        input: tx_kernel_mast_hash.values().to_vec(),
                        output: empty_string.clone(),
                    },
                    support: ClaimSupport::SecretWitness(SecretWitness::new(
                        spendkey.to_owned(),
                        Some(lockscript.program.clone()),
                    )),
                })
                .collect(),
        }
    }
}
