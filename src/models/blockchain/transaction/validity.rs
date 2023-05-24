use std::time::SystemTime;

use anyhow::{bail, Result};
use get_size::GetSize;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};
use triton_vm::{proof::Proof, StarkParameters};
use twenty_first::{
    shared_math::{
        b_field_element::BFieldElement,
        bfield_codec::{encode_vec, BFieldCodec},
    },
    util_types::algebraic_hasher::AlgebraicHasher,
};

use crate::models::blockchain::shared::Hash;

use super::{transaction_kernel::TransactionKernel, PrimitiveWitness};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize)]
pub enum ClaimSupport {
    Proof(Proof),
    SecretWitness(Vec<BFieldElement>, triton_opcodes::program::Program),
    DummySupport, // TODO: Remove this when all claims are implemented
}

/// WitnessableClaim is a helper struct for ValiditySequence. It
/// encodes a Claim with an optional witness.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize)]
pub struct SupportedClaim {
    pub claim: triton_vm::Claim,
    pub support: ClaimSupport,
}

impl SupportedClaim {
    // TODO: REMOVE when all validity logic is implemented
    pub fn dummy_supported_claim() -> SupportedClaim {
        fn dummy_claim() -> triton_vm::Claim {
            triton_vm::Claim {
                input: Default::default(),
                output: Default::default(),
                padded_height: Default::default(),
                program_digest: Default::default(),
            }
        }

        Self {
            claim: dummy_claim(),
            support: ClaimSupport::DummySupport,
        }
    }
}

/// ValidityConditions is a helper struct. It contains a sequence of
/// claims with optional witnesses. If all claims a true, then the
/// transaction is valid.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize)]
pub struct ValidityLogic {
    // program: lock_script, input: hash of tx kernel (MAST hash), witness: secret spending key, output: []
    pub lock_script_halts: Vec<SupportedClaim>,

    // program: todo, input: encoding of all TX inputs (UTXOs), witness: input utxos, utxo mast auth path, output: lock scripts
    pub inputs_to_lock_scripts: SupportedClaim,

    // program: todo, input: hash of tx kernel (MAST hash), witness: kernel mast auth path, output: encoding of all TX inputs (UTXOs)
    pub kernel_to_inputs: SupportedClaim,

    // program: verify+drop, input: hash of inputs + mutator set hash, witness: inputs + mutator set accumulator, output: removal records
    pub removal_records_integrity: SupportedClaim,

    // program: todo, input: hash of tx kernel (MAST hash), witness: outputs + kernel mast auth path + coins, output: type scripts
    pub kernel_to_typescripts: SupportedClaim,

    // program: type script, input: inputs hash + outputs hash + coinbase + fee, witness: inputs + outputs + any, output: []
    pub type_script_halts: Vec<SupportedClaim>,
}

// Logic for generating ValidityLogic
impl ValidityLogic {
    // TODO: REMOVE when all validity logic is implemented
    pub fn dummy() -> Self {
        Self {
            lock_script_halts: Default::default(),
            inputs_to_lock_scripts: SupportedClaim::dummy_supported_claim(),
            kernel_to_inputs: SupportedClaim::dummy_supported_claim(),
            removal_records_integrity: SupportedClaim::dummy_supported_claim(),
            kernel_to_typescripts: SupportedClaim::dummy_supported_claim(),
            type_script_halts: Default::default(),
        }
    }

    pub fn from_primitive_witness(
        primitive_witness: &PrimitiveWitness,
        tx_kernel: &TransactionKernel,
    ) -> Self {
        let lock_script_halts = Self::generate_lock_script_halts(primitive_witness, tx_kernel);
        Self {
            lock_script_halts,
            inputs_to_lock_scripts: SupportedClaim::dummy_supported_claim(),
            kernel_to_inputs: SupportedClaim::dummy_supported_claim(),
            removal_records_integrity: SupportedClaim::dummy_supported_claim(),
            kernel_to_typescripts: SupportedClaim::dummy_supported_claim(),
            type_script_halts: Default::default(),
        }
    }

    pub fn generate_lock_script_halts(
        primitive_witness: &PrimitiveWitness,
        tx_kernel: &TransactionKernel,
    ) -> Vec<SupportedClaim> {
        let program_and_program_digests_and_spending_keys = primitive_witness
            .input_lock_scripts
            .iter()
            .zip_eq(primitive_witness.lock_script_witnesses.iter())
            .map(|(lockscr, spendkey)| (lockscr, Hash::hash_varlen(&lockscr.encode()), spendkey));
        let tx_kernel_mast_hash = tx_kernel.mast_hash();
        let empty_string = vec![];
        let padded_height = Default::default(); // TODO: Should be removed upstream

        program_and_program_digests_and_spending_keys
            .into_iter()
            .map(|(lockscript, lockscript_digest, spendkey)| SupportedClaim {
                claim: triton_vm::Claim {
                    program_digest: lockscript_digest,
                    input: tx_kernel_mast_hash.values().map(|x| x.value()).to_vec(),
                    output: empty_string.clone(),
                    padded_height,
                },
                support: ClaimSupport::SecretWitness(
                    spendkey.to_owned(),
                    lockscript.program.clone(),
                ),
            })
            .collect()
    }

    // Public input: Kernel MAST
    // guesses input UTXOs, verifies MAST auth path relative to kernel MAST digest, outputs them
    pub fn generate_kernel_to_inputs(
        primitive_witness: &PrimitiveWitness,
        tx_kernel: &TransactionKernel,
    ) -> SupportedClaim {
        let program = triton_opcodes::program::Program::default(); // TODO: implement!
        let program_digest = Hash::hash_varlen(&program.encode());
        let padded_height = Default::default(); // TODO: Should be removed upstream
        let empty_string = vec![];
        let input = tx_kernel.mast_hash();
        let output = encode_vec(&primitive_witness.input_utxos);
        SupportedClaim {
            claim: triton_vm::Claim {
                program_digest,
                input: input.values().map(|x| x.value()).to_vec(),
                output: output.iter().map(|x| x.value()).collect(),
                padded_height,
            },
            support: ClaimSupport::SecretWitness(empty_string, program),
        }
    }
}

// Logic for verifying ValidityLogic
impl ValidityLogic {
    pub fn verify(&self, tx_kernel: &TransactionKernel) -> bool {
        self.verify_lock_script_halts(tx_kernel)

        // TODO: Add all other checks here
    }

    pub fn verify_lock_script_halts(&self, tx_kernel: &TransactionKernel) -> bool {
        let lock_script_halts = &self.lock_script_halts;
        for elem in lock_script_halts.iter() {
            let claim = triton_vm::Claim {
                program_digest: elem.claim.program_digest,
                input: tx_kernel.mast_hash().values().map(|x| x.value()).to_vec(),
                output: vec![],
                // padded_height: Default::default(), // Remove upstream
                padded_height: elem.claim.padded_height,
            };
            match &elem.support {
                ClaimSupport::Proof(proof) => {
                    debug!(
                        "Running verify on lockscript with digest {}",
                        claim.program_digest,
                    );
                    debug!("claim is:\n {:?}", claim);
                    let tick = SystemTime::now();
                    if !triton_vm::verify(&triton_vm::StarkParameters::default(), &claim, proof) {
                        warn!("Verification of lockscript failed.");
                        return false;
                    }
                    debug!(
                        "Verify of lockscript succeeded. Elapsed time: {:?}",
                        tick.elapsed().expect("Don't mess with time")
                    );
                }
                ClaimSupport::SecretWitness(secretw, program) => {
                    if triton_vm::vm::run(
                        program,
                        claim.input.iter().map(|x| (*x).into()).collect(),
                        secretw.to_owned(),
                    )
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

    pub fn prove_lock_script_halts(lock_script_halts_claim: &mut SupportedClaim) -> Result<()> {
        if let ClaimSupport::SecretWitness(secret_witness, program) =
            &lock_script_halts_claim.support
        {
            let input_bfes: Vec<BFieldElement> = lock_script_halts_claim
                .claim
                .input
                .iter()
                .map(|x| (*x).into())
                .collect();
            debug!(
                "Running lockscript program:\n{program}\n program digest: {}\n Secret input\n{}\n, Public input\n{}\n",
                lock_script_halts_claim.claim.program_digest,
                secret_witness.iter().map(|x| x.to_string()).join(","),
                input_bfes.iter().map(|x| x.to_string()).join(","),
            );

            // sanity check
            assert_eq!(
                lock_script_halts_claim.claim.program_digest,
                Hash::hash_varlen(&program.encode())
            );
            if triton_vm::vm::run(program, input_bfes, secret_witness.to_owned()).is_err() {
                bail!("Lockscript execution failed for program:\n{program}")
            }

            info!("Lockscript run suceeded. Now proving...");
            let tick = SystemTime::now();
            let (used_stark_parameters, claim, proof) = triton_vm::prove(
                &program.to_string(),
                &lock_script_halts_claim.claim.input,
                &secret_witness.iter().map(|b| b.value()).collect_vec(),
            );

            // Set from proof. Can be removed once `padded_height` is removed from claim
            // in upstream triton-vm.
            lock_script_halts_claim.claim = claim;

            // Sanity check
            assert_eq!(
                StarkParameters::default(),
                used_stark_parameters,
                "Used STARK parameters must be default"
            );

            info!(
                "Done proving. Elapsed time: {:?}",
                tick.elapsed().expect("Don't mess with time")
            );
            lock_script_halts_claim.support = ClaimSupport::Proof(proof);

            return Ok(());
        }

        // The claim already has a proof. Should we return an error here?
        Ok(())
    }
}
