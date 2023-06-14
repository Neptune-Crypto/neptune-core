use std::time::SystemTime;

use anyhow::{bail, Result};
use get_size::GetSize;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};
use triton_vm::StarkParameters;
use twenty_first::{
    shared_math::{b_field_element::BFieldElement, bfield_codec::BFieldCodec},
    util_types::algebraic_hasher::AlgebraicHasher,
};

use super::{ClaimSupport, SupportedClaim, TxValidationLogic};
use crate::models::blockchain::{
    shared::Hash,
    transaction::{transaction_kernel::TransactionKernel, PrimitiveWitness},
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, Default)]
pub struct LockScriptHalts {
    supported_claims: Vec<SupportedClaim>,
}

impl TxValidationLogic for LockScriptHalts {
    fn unproven_from_primitive_witness(
        primitive_witness: &PrimitiveWitness,
        tx_kernel: &TransactionKernel,
    ) -> LockScriptHalts {
        let program_and_program_digests_and_spending_keys = primitive_witness
            .input_lock_scripts
            .iter()
            .zip_eq(primitive_witness.lock_script_witnesses.iter())
            .map(|(lockscr, spendkey)| (lockscr, Hash::hash_varlen(&lockscr.encode()), spendkey));
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
                    support: ClaimSupport::SecretWitness(
                        spendkey.to_owned(),
                        lockscript.program.clone(),
                    ),
                })
                .collect(),
        }
    }

    fn prove(&mut self) -> Result<()> {
        for supported_claim in self.supported_claims.iter_mut() {
            if let ClaimSupport::SecretWitness(secret_witness, program) = &supported_claim.support {
                let input_bfes: Vec<BFieldElement> = supported_claim.claim.input.to_vec();
                debug!(
                "Running lockscript program:\n{program}\n program digest: {}\n Secret input\n{}\n, Public input\n{}\n",
                supported_claim.claim.program_digest,
                secret_witness.iter().map(|x| x.to_string()).join(","),
                input_bfes.iter().map(|x| x.to_string()).join(","),
            );

                // sanity check
                assert_eq!(
                    supported_claim.claim.program_digest,
                    Hash::hash_varlen(&program.encode())
                );
                if triton_vm::vm::run(program, input_bfes, secret_witness.to_owned()).is_err() {
                    bail!("Lockscript execution failed for program:\n{program}")
                }

                info!("Lockscript run suceeded. Now proving...");
                let tick = SystemTime::now();
                let proof = triton_vm::prove(
                    &StarkParameters::default(),
                    &supported_claim.claim,
                    program,
                    secret_witness,
                );

                let proof = match proof {
                    Ok(proof) => proof,
                    Err(e) => {
                        bail!("Proof generation failed: {}", e);
                    }
                };

                info!(
                    "Done proving. Elapsed time: {:?}",
                    tick.elapsed().expect("Don't mess with time")
                );
                supported_claim.support = ClaimSupport::Proof(proof);
            }

            // The claim already has a proof. Should we return an error here?
        }

        Ok(())
    }

    fn verify(&self, tx_kernel: &TransactionKernel) -> bool {
        for elem in self.supported_claims.iter() {
            let claim = triton_vm::Claim {
                program_digest: elem.claim.program_digest,
                input: tx_kernel.mast_hash().encode(),
                output: vec![],
            };
            match &elem.support {
                ClaimSupport::Proof(proof) => {
                    debug!(
                        "Running verify on lockscript with digest {}",
                        claim.program_digest,
                    );
                    debug!("claim is:\n {:?}", claim);
                    let tick = SystemTime::now();

                    // TODO: Don't we need to verify that the claim is also contained in the proof here?
                    if !triton_vm::verify(&StarkParameters::default(), proof) {
                        warn!("Verification of lockscript failed.");
                        return false;
                    }
                    debug!(
                        "Verify of lockscript succeeded. Elapsed time: {:?}",
                        tick.elapsed().expect("Don't mess with time")
                    );
                }
                ClaimSupport::SecretWitness(secretw, program) => {
                    if triton_vm::vm::run(program, claim.input.to_vec(), secretw.to_owned())
                        .is_err()
                    {
                        warn!("Execution of program failed:\n{}", program);
                        return false;
                    }
                }
                // TODO: Remove when all claims are implemented
                ClaimSupport::DummySupport => (),
            }
        }

        true
    }
}
