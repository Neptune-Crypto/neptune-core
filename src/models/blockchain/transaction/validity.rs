pub mod kernel_to_lock_scripts;
pub mod kernel_to_typescripts;
pub mod lockscripts_halt;
pub mod tasm;
pub mod typescripts_halt;

use std::collections::HashMap;

use crate::models::blockchain::shared::Hash;
use anyhow::{bail, Ok, Result};
use get_size::GetSize;
use itertools::Itertools;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tasm_lib::traits::compiled_program::CompiledProgram;
use tracing::{debug, info, warn};
use triton_vm::program::Program;
use triton_vm::{proof::Proof, Claim};
use triton_vm::{NonDeterminism, PublicInput, StarkParameters};
use twenty_first::shared_math::b_field_element::BFieldElement;
use twenty_first::shared_math::bfield_codec::BFieldCodec;

use self::{
    kernel_to_lock_scripts::KernelToLockScripts,
    kernel_to_typescripts::KernelToTypeScripts,
    lockscripts_halt::LockScriptsHalt,
    tasm::removal_records_integrity::{RemovalRecordsIntegrity, RemovalRecordsIntegrityWitness},
    typescripts_halt::TypeScriptsHalt,
};
use super::{transaction_kernel::TransactionKernel, PrimitiveWitness};

pub trait SecretWitness:
    Clone + Serialize + DeserializeOwned + PartialEq + Eq + GetSize + BFieldCodec
{
    /// The non-determinism for the VM that this witness corresponds to
    fn nondeterminism(&self) -> NonDeterminism<BFieldElement>;

    /// Returns the subprogram
    fn program(&self) -> Program;
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub enum ClaimSupport {
    Proof(Proof),
    SecretWitness(dyn SecretWitness),
    DummySupport, // TODO: Remove this when all claims are implemented
}

/// SupportedClaim is a helper struct for ValiditySequence. It
/// encodes a Claim with an optional witness.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub struct SupportedClaim {
    pub claim: triton_vm::Claim,
    pub support: ClaimSupport,
}

impl SupportedClaim {
    // TODO: REMOVE when all validity logic is implemented
    pub fn dummy() -> SupportedClaim {
        let dummy_claim = triton_vm::Claim {
            input: Default::default(),
            output: Default::default(),
            program_digest: Default::default(),
        };

        Self {
            claim: dummy_claim,
            support: ClaimSupport::DummySupport,
        }
    }
}

/// ValidityConditions is a helper struct. It contains a sequence of
/// claims with optional witnesses. If all claims a true, then the
/// transaction is valid.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub struct TransactionValidityLogic {
    // programs: [lock_script], input: hash of tx kernel (MAST hash), witness: secret spending key, output: []
    pub lock_scripts_halt: LockScriptsHalt,

    // program: todo, input: hash of tx kernel (MAST hash), witness: input utxos, utxo mast auth path, output: hashes of lock scripts
    pub kernel_to_lock_scripts: KernelToLockScripts,

    // program: recompute swbf indices, input: hash of kernel, witness: inputs + mutator set accumulator, output: []
    pub removal_records_integrity: RemovalRecordsIntegrity,

    // program: todo, input: hash of tx kernel (MAST hash), witness: outputs + kernel mast auth path + coins, output: type scripts
    pub kernel_to_typescripts: KernelToTypeScripts,

    // program: type script, input: hash of inputs + hash of outputs + coinbase + fee, witness: inputs + outputs + any, output: []
    pub type_scripts_halt: TypeScriptsHalt,
}

pub trait ValidationLogic {
    fn new_from_witness(
        primitive_witness: &PrimitiveWitness,
        tx_kernel: &TransactionKernel,
    ) -> Self;

    /// Prove the claim.
    fn prove(&mut self) -> Result<()> {
        match &self.supported_claim.support {
            ClaimSupport::Proof(_) => {
                // nothing to do; proof already exists
                Ok(())
            }
            ClaimSupport::SecretWitness(rriw) => {
                if rriw.program().is_some() {
                    bail!("Protocol defines program of removal record integrity check. Must be None here.")
                }

                // Run program before proving
                Self::program()
                    .run(
                        self.supported_claim.claim.public_input().into(),
                        rriw.nondeterminism().clone(),
                    )
                    .expect("Program execution prior to proving must succeed");

                let proof = triton_vm::prove(
                    StarkParameters::default(),
                    &self.supported_claim.claim,
                    &Self::program(),
                    rriw.nondeterminism().clone(),
                )
                .expect("Proving integrity of removal records must succeed.");
                self.supported_claim.support = ClaimSupport::Proof(proof);
                Ok(())
            }
            ClaimSupport::DummySupport => {
                // nothing to do
                warn!(
                    "Trying to prove removal record integrity for claim supported by dummy support"
                );
                Ok(())
            }
        }
    }

    /// Verify the claim.
    fn verify(&self) -> bool {
        use std::result::Result::Ok;
        match &self.supported_claim.support {
            ClaimSupport::Proof(proof) => triton_vm::verify(
                StarkParameters::default(),
                &self.supported_claim.claim,
                proof,
            ),
            ClaimSupport::SecretWitness(w) => {
                let nondeterminism = w.nondeterminism();
                let input = &self.supported_claim.claim.input;
                let vm_result = w.program().run(PublicInput::new(input), nondeterminism);
                match vm_result {
                    Ok(observed_output) => {
                        let found_expected_output =
                            observed_output == self.supported_claim.claim.output;
                        if !found_expected_output {
                            warn!("Observed output does not match claimed output for RRI");
                            debug!("Got output: {found_expected_output}");
                        }

                        found_expected_output
                    }
                    Err(err) => {
                        warn!("VM execution for removal records integrity did not halt gracefully");
                        debug!("Last state was: {err}");
                        false
                    }
                }
            }
            ClaimSupport::DummySupport => {
                warn!("removal record integrity support must be supplied");
                false
            }
        }
    }
}

impl ValidationLogic for TransactionValidityLogic {
    fn new_from_witness(
        primitive_witness: &PrimitiveWitness,
        tx_kernel: &TransactionKernel,
    ) -> Self {
        let kernel_hash = tx_kernel.mast_hash().reversed().values().to_vec();
        let lock_scripts_halt = LockScriptsHalt {
            supported_claims: primitive_witness
                .input_utxos
                .iter()
                .zip(primitive_witness.input_lock_scripts.iter())
                .zip(primitive_witness.lock_script_witnesses.iter())
                .map(
                    |((_utxo, lock_script), lock_script_witness)| SupportedClaim {
                        claim: Claim {
                            program_digest: lock_script.hash(),
                            input: kernel_hash.clone(),
                            output: vec![],
                        },
                        support: ClaimSupport::SecretWitness(SecretWitness::new(
                            lock_script_witness.clone(),
                            Some(lock_script.program.clone()),
                        )),
                    },
                )
                .collect_vec(),
        };
        let kernel_to_lock_scripts = KernelToLockScripts {
            supported_claim: SupportedClaim::dummy(),
        };
        debug!(
            "Removal Records Integrity program digest: ({})",
            RemovalRecordsIntegrity::program().hash::<Hash>()
        );
        let removal_records_integrity = RemovalRecordsIntegrity {
            supported_claim: SupportedClaim {
                claim: Claim {
                    program_digest: RemovalRecordsIntegrity::program().hash::<Hash>(),
                    input: kernel_hash,
                    output: vec![],
                },
                support: ClaimSupport::SecretWitness(SecretWitness::new(
                    RemovalRecordsIntegrityWitness::new(primitive_witness, tx_kernel).encode(),
                    None,
                )),
            },
        };
        let kernel_to_typescripts = KernelToTypeScripts {
            supported_claim: SupportedClaim::dummy(),
        };
        let type_scripts_halt = TypeScriptsHalt {
            supported_claims: vec![SupportedClaim::dummy()],
        };
        Self {
            lock_scripts_halt,
            kernel_to_lock_scripts,
            removal_records_integrity,
            kernel_to_typescripts,
            type_scripts_halt,
        }
    }

    fn prove(&mut self) -> Result<()> {
        self.lock_scripts_halt.prove()?;

        self.removal_records_integrity.prove()?;

        // not supported yet:
        // self.kernel_to_lock_scripts.prove()?;
        // self.kernel_to_typescripts.prove()?;
        // self.type_scripts_halt.prove()?;
        Ok(())
    }

    fn verify(&self) -> bool {
        info!("validity logic for 'kernel_to_lock_scripts', 'kernel_to_type_scripts', 'type_scripts_halt' not implemented yet.");
        self.lock_scripts_halt.verify()
            // && self.kernel_to_lock_scripts.verify()
            && self.removal_records_integrity.verify()
        // && self.kernel_to_typescripts.verify()
        // && self.type_scripts_halt.verify()
    }
}
