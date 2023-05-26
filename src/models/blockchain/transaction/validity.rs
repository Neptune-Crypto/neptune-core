pub mod inputs_to_lock_scripts;
pub mod kernel_to_inputs;
pub mod kernel_to_typescripts;
pub mod lockscript_halts;
pub mod removal_records_integrity;
pub mod typescript_halts;

use anyhow::Result;
use get_size::GetSize;
use serde::{Deserialize, Serialize};
use triton_vm::proof::Proof;
use twenty_first::shared_math::b_field_element::BFieldElement;

use self::{
    inputs_to_lock_scripts::InputsToLockScripts, kernel_to_inputs::KernelToInputs,
    kernel_to_typescripts::KernelToTypeScripts, lockscript_halts::LockScriptHalts,
    removal_records_integrity::RemovalRecordsIntegrity, typescript_halts::TypescriptHalts,
};
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
    pub lock_script_halts: LockScriptHalts,

    // program: todo, input: encoding of all TX inputs (UTXOs), witness: input utxos, utxo mast auth path, output: lock scripts
    pub inputs_to_lock_scripts: InputsToLockScripts,

    // program: todo, input: hash of tx kernel (MAST hash), witness: kernel mast auth path, output: encoding of all TX inputs (UTXOs)
    pub kernel_to_inputs: KernelToInputs,

    // program: verify+drop, input: hash of inputs + mutator set hash, witness: inputs + mutator set accumulator, output: removal records
    pub removal_records_integrity: RemovalRecordsIntegrity,

    // program: todo, input: hash of tx kernel (MAST hash), witness: outputs + kernel mast auth path + coins, output: type scripts
    pub kernel_to_typescripts: KernelToTypeScripts,

    // program: type script, input: inputs hash + outputs hash + coinbase + fee, witness: inputs + outputs + any, output: []
    pub type_script_halts: TypescriptHalts,
}

pub trait TxValidationLogic {
    fn unproven_from_primitive_witness(
        primitive_witness: &PrimitiveWitness,
        tx_kernel: &TransactionKernel,
    ) -> Self;
    fn prove(&mut self) -> Result<()>;
    fn verify(&self, tx_kernel: &TransactionKernel) -> bool;
}

// Logic for generating ValidityLogic
impl ValidityLogic {
    // TODO: Consider implementing the `TxValidationLogic` trait here
    /// Generate validity logic for a transaction containing secret data as stand-in for proofs
    pub fn unproven_from_primitive_witness(
        primitive_witness: &PrimitiveWitness,
        tx_kernel: &TransactionKernel,
    ) -> Self {
        let lock_script_halts =
            LockScriptHalts::unproven_from_primitive_witness(primitive_witness, tx_kernel);

        // TODO: Generate all other fields correctly
        Self {
            lock_script_halts,
            inputs_to_lock_scripts: InputsToLockScripts::dummy(),
            kernel_to_inputs: KernelToInputs::dummy(),
            removal_records_integrity: RemovalRecordsIntegrity::dummy(),
            kernel_to_typescripts: KernelToTypeScripts::dummy(),
            type_script_halts: TypescriptHalts::dummy(),
        }
    }

    pub fn verify(&self, tx_kernel: &TransactionKernel) -> bool {
        self.lock_script_halts.verify(tx_kernel) // && ...

        // TODO: Add all other checks here
    }

    pub fn prove(&mut self) -> Result<()> {
        self.lock_script_halts.prove()?;

        // TODO: Prove all other fields here

        Ok(())
    }
}
