use std::time::SystemTime;

use anyhow::{bail, Result};
use get_size::GetSize;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};
use triton_vm::StarkParameters;
use twenty_first::shared_math::b_field_element::BFieldElement;

use super::{ClaimSupport, SupportedClaim, ValidationLogic};
use crate::models::blockchain::{
    shared::Hash,
    transaction::{transaction_kernel::TransactionKernel, PrimitiveWitness},
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, Default)]
pub struct LockScriptsHalt {
    pub supported_claims: Vec<SupportedClaim>,
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
                    support: ClaimSupport::SecretWitness(
                        spendkey.to_owned(),
                        Some(lockscript.program.clone()),
                    ),
                })
                .collect(),
        }
    }

    fn prove(&mut self) -> Result<()> {
        for supported_claim in self.supported_claims.iter_mut() {
            if let ClaimSupport::SecretWitness(secret_witness, maybe_program) =
                &supported_claim.support
            {
                if let Some(program) = maybe_program {
                    let input_bfes: Vec<BFieldElement> = supported_claim.claim.input.to_vec();
                    debug!(
                        "Running lockscript program:\n{}\n program digest: {}\n Secret input\n{}\n, Public input\n{}\n",
                        program,
                        supported_claim.claim.program_digest,
                        secret_witness.iter().map(|x| x.to_string()).join(","),
                        input_bfes.iter().map(|x| x.to_string()).join(","),
                    );

                    // sanity check
                    assert_eq!(supported_claim.claim.program_digest, program.hash::<Hash>());
                    if program.run(input_bfes, secret_witness.to_owned()).is_err() {
                        bail!("Lockscript execution failed for program:\n{program}")
                    }

                    info!("Lockscript run suceeded. Now proving...");
                    debug!("Proving program ({})", program.hash::<Hash>());
                    debug!("Claimed program ({})", supported_claim.claim.program_digest);
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
                        "Done proving lock script. Elapsed time: {:?}",
                        tick.elapsed().expect("Don't mess with time")
                    );
                    supported_claim.support = ClaimSupport::Proof(proof);
                } else {
                    bail!("No program supplied; which lock script do I prove?");
                }
            }

            // The claim already has a proof. Should we return an error here?
        }

        Ok(())
    }

    fn verify(&self) -> bool {
        for elem in self.supported_claims.iter() {
            let claim = elem.claim.clone();
            match &elem.support {
                ClaimSupport::Proof(proof) => {
                    debug!(
                        "Running verify on lockscript with digest {}",
                        claim.program_digest,
                    );
                    debug!("claim is:\n {:?}", claim);
                    let tick = SystemTime::now();

                    if !triton_vm::verify(&StarkParameters::default(), &claim, proof) {
                        warn!("Verification of lockscript failed.");
                        return false;
                    }
                    debug!(
                        "Verify of lockscript succeeded. Elapsed time: {:?}",
                        tick.elapsed().expect("Don't mess with time.")
                    );
                }
                ClaimSupport::SecretWitness(secretw, maybe_program) => {
                    if let Some(program) = maybe_program {
                        if program
                            .run(claim.input.to_vec(), secretw.to_owned())
                            .is_err()
                        {
                            warn!("Execution of program failed:\n{}", program);
                            return false;
                        }
                    } else {
                        warn!("Cannot verify secret witness; program not supplied.");
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
