use crate::prelude::{triton_vm, twenty_first};

pub mod kernel_to_lock_scripts;
pub mod kernel_to_typescripts;
pub mod lockscripts_halt;
pub mod removal_records_integrity;
pub mod tasm;
pub mod typescripts_halt;

use anyhow::{Ok, Result};
use get_size::GetSize;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};
use triton_vm::prelude::{Claim, NonDeterminism, PublicInput, StarkParameters};
use triton_vm::program::Program;
use triton_vm::proof::Proof;
use twenty_first::shared_math::b_field_element::BFieldElement;
use twenty_first::shared_math::bfield_codec::BFieldCodec;

use self::lockscripts_halt::LockScriptsHalt;
use self::removal_records_integrity::RemovalRecordsIntegrity;
use self::{
    kernel_to_lock_scripts::KernelToLockScripts, kernel_to_typescripts::KernelToTypeScripts,
    typescripts_halt::TypeScriptsHalt,
};
use super::{transaction_kernel::TransactionKernel, PrimitiveWitness};

pub trait SecretWitness:
    Clone + Serialize + PartialEq + Eq + GetSize + BFieldCodec + Sized
{
    /// The non-determinism for the VM that this witness corresponds to
    fn nondeterminism(&self) -> NonDeterminism<BFieldElement>;

    /// Returns the subprogram
    fn subprogram(&self) -> Program;
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub enum ClaimSupport<SubprogramWitness: SecretWitness> {
    Proof(Proof),
    MultipleSupports(Vec<SubprogramWitness>),
    SecretWitness(SubprogramWitness),
    DummySupport, // TODO: Remove this when all claims are implemented
}

/// SupportedClaim is a helper struct for ValiditySequence. It
/// encodes a Claim with an optional witness.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub struct SupportedClaim<SubprogramWitness: SecretWitness> {
    pub claim: Claim,
    pub support: ClaimSupport<SubprogramWitness>,
}

impl<SubprogramWitness: SecretWitness> SupportedClaim<SubprogramWitness> {
    // TODO: REMOVE when all validity logic is implemented
    pub fn dummy() -> Self {
        let dummy_claim = Claim {
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
pub struct TransactionValidationLogic {
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

pub trait ValidationLogic<T: SecretWitness> {
    fn subprogram(&self) -> Program;
    fn support(&self) -> ClaimSupport<T>;
    fn claim(&self) -> Claim;

    /// Update witness secret witness to proof
    fn upgrade(&mut self, _proof: Proof) {
        todo!()
    }

    fn new_from_primitive_witness(
        primitive_witness: &PrimitiveWitness,
        tx_kernel: &TransactionKernel,
    ) -> Self;

    /// Prove the claim.
    fn prove(&mut self) -> Result<()> {
        match &self.support() {
            ClaimSupport::Proof(_) => {
                // nothing to do; proof already exists
                Ok(())
            }
            ClaimSupport::SecretWitness(witness) => {
                // Run program before proving
                self.subprogram()
                    .run(
                        self.claim().public_input().into(),
                        witness.nondeterminism().clone(),
                    )
                    .expect("Program execution prior to proving must succeed");

                let proof = triton_vm::prove(
                    StarkParameters::default(),
                    &self.claim(),
                    &self.subprogram(),
                    witness.nondeterminism().clone(),
                )
                .expect("Proving integrity of removal records must succeed.");
                self.upgrade(proof);
                Ok(())
            }
            ClaimSupport::DummySupport => {
                // nothing to do
                warn!("Trying to prove claim supported by dummy support");
                Ok(())
            }
            ClaimSupport::MultipleSupports(_supports) => {
                warn!("Trying to prove claim with multiple supports; not supported yet");
                Ok(())
            }
        }
    }

    /// Verify the claim.
    fn verify(&self) -> bool {
        use std::result::Result::Ok;
        match &self.support() {
            ClaimSupport::Proof(proof) => {
                triton_vm::verify(StarkParameters::default(), &self.claim(), proof)
            }
            ClaimSupport::SecretWitness(w) => {
                let nondeterminism = w.nondeterminism();
                let input = &self.claim().input;
                let vm_result = w
                    .subprogram()
                    .run(PublicInput::new(input.to_vec()), nondeterminism);
                match vm_result {
                    Ok(observed_output) => {
                        let found_expected_output = observed_output == self.claim().output;
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
                warn!("dummy support encountered");
                false
            }
            ClaimSupport::MultipleSupports(secret_witnesses) => {
                let claim = self.claim();
                for witness in secret_witnesses.iter() {
                    let vm_result = witness.subprogram().run(
                        PublicInput::new(claim.input.to_vec()),
                        witness.nondeterminism(),
                    );
                    match vm_result {
                        Ok(_) => (),
                        Err(err) => {
                            warn!("Multiple-support witness failed to validate: {err}");
                            return false;
                        }
                    }
                }

                true
            }
        }
    }
}

impl TransactionValidationLogic {
    pub fn new_from_primitive_witness(
        primitive_witness: &PrimitiveWitness,
        tx_kernel: &TransactionKernel,
    ) -> Self {
        let lock_scripts_halt =
            LockScriptsHalt::new_from_primitive_witness(primitive_witness, tx_kernel);
        let kernel_to_lock_scripts =
            KernelToLockScripts::new_from_primitive_witness(primitive_witness, tx_kernel);
        let removal_records_integrity =
            RemovalRecordsIntegrity::new_from_primitive_witness(primitive_witness, tx_kernel);
        let kernel_to_typescripts =
            KernelToTypeScripts::new_from_primitive_witness(primitive_witness, tx_kernel);
        let type_scripts_halt =
            TypeScriptsHalt::new_from_primitive_witness(primitive_witness, tx_kernel);
        Self {
            lock_scripts_halt,
            kernel_to_lock_scripts,
            removal_records_integrity,
            kernel_to_typescripts,
            type_scripts_halt,
        }
    }

    pub fn prove(&mut self) -> Result<()> {
        self.lock_scripts_halt.prove()?;

        self.removal_records_integrity.prove()?;

        // not supported yet:
        // self.kernel_to_lock_scripts.prove()?;
        // self.kernel_to_typescripts.prove()?;
        // self.type_scripts_halt.prove()?;
        Ok(())
    }

    pub fn verify(&self) -> bool {
        info!("validity logic for 'kernel_to_lock_scripts', 'kernel_to_type_scripts', 'type_scripts_halt' not implemented yet.");
        self.lock_scripts_halt.verify()
            // && self.kernel_to_lock_scripts.verify()
            && self.removal_records_integrity.verify()
        // && self.kernel_to_typescripts.verify()
        // && self.type_scripts_halt.verify()
    }
}
