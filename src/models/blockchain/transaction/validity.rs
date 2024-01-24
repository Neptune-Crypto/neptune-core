use crate::prelude::{triton_vm, twenty_first};

pub mod kernel_to_lock_scripts;
pub mod kernel_to_type_scripts;
pub mod lockscripts_halt;
pub mod removal_records_integrity;
pub mod tasm;
pub mod typescripts_halt;

use anyhow::{Ok, Result};
use get_size::GetSize;
use serde::{Deserialize, Serialize};
use tracing::info;
use triton_vm::prelude::{Claim, NonDeterminism};
use triton_vm::program::Program;
use triton_vm::proof::Proof;
use twenty_first::shared_math::b_field_element::BFieldElement;
use twenty_first::shared_math::bfield_codec::BFieldCodec;

use crate::models::consensus::ValidationLogic;

use self::lockscripts_halt::LockScriptsHalt;
use self::removal_records_integrity::RemovalRecordsIntegrity;
use self::{
    kernel_to_lock_scripts::KernelToLockScripts, kernel_to_type_scripts::KernelToTypeScripts,
    typescripts_halt::TypeScriptsHalt,
};
use super::transaction_kernel::TransactionKernel;
use super::TransactionPrimitiveWitness;

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

impl TransactionValidationLogic {
    pub fn new_from_primitive_witness(
        primitive_witness: &TransactionPrimitiveWitness,
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
