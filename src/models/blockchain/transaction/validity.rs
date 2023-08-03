pub mod kernel_to_lock_scripts;
pub mod kernel_to_typescripts;
pub mod lockscripts_halt;
pub mod tasm;
pub mod typescripts_halt;

use crate::models::blockchain::shared::Hash;
use anyhow::{Ok, Result};
use get_size::GetSize;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use tasm_lib::compiled_program::CompiledProgram;
use tracing::{debug, info};
use triton_vm::program::Program;
use triton_vm::{proof::Proof, Claim};
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub enum ClaimSupport {
    Proof(Proof),
    SecretWitness(Vec<BFieldElement>, Option<Program>),
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
    fn prove(&mut self) -> Result<()>;
    fn verify(&self) -> bool;
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
                        support: ClaimSupport::SecretWitness(
                            lock_script_witness.clone(),
                            Some(lock_script.program.clone()),
                        ),
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
                support: ClaimSupport::SecretWitness(
                    RemovalRecordsIntegrityWitness::new(primitive_witness, tx_kernel).encode(),
                    None,
                ),
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
