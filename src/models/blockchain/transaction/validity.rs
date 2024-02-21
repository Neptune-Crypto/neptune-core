use crate::prelude::twenty_first;

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
use twenty_first::shared_math::bfield_codec::BFieldCodec;

use crate::models::consensus::ValidationLogic;

use self::lockscripts_halt::LockScriptsHalt;
use self::removal_records_integrity::RemovalRecordsIntegrity;
use self::{
    kernel_to_lock_scripts::KernelToLockScripts, kernel_to_type_scripts::KernelToTypeScripts,
    typescripts_halt::TypeScriptsHalt,
};
use super::PrimitiveWitness;

/// The validity of a transaction, in the base case, decomposes into
/// these subclaims.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub struct TransactionValidationLogic {
    // programs: [lock_script], input: transaction kernel mast hash, witness: secret spending key, output: []
    pub lock_scripts_halt: LockScriptsHalt,

    // program: todo, input: transaction kernel mast hash, witness: input utxos, utxo mast auth path, output: hashes of lock scripts
    pub kernel_to_lock_scripts: KernelToLockScripts,

    // program: recompute swbf indices, input: transaction kernel mast hash, witness: inputs + mutator set accumulator, output: []
    pub removal_records_integrity: RemovalRecordsIntegrity,

    // program: todo, input: transaction kernel mast hash, witness: outputs + kernel mast auth path + coins, output: hashes of type scripts
    pub kernel_to_typescripts: KernelToTypeScripts,

    // programs: [type script], input: transaction kernel mast hash, witness: inputs + outputs + any, output: []
    pub type_scripts_halt: TypeScriptsHalt,
}

impl TransactionValidationLogic {
    pub fn new_from_primitive_witness(primitive_witness: &PrimitiveWitness) -> Self {
        let lock_scripts_halt = LockScriptsHalt::new_from_primitive_witness(primitive_witness);
        let kernel_to_lock_scripts =
            KernelToLockScripts::new_from_primitive_witness(primitive_witness);
        let removal_records_integrity =
            RemovalRecordsIntegrity::new_from_primitive_witness(primitive_witness);
        let kernel_to_typescripts =
            KernelToTypeScripts::new_from_primitive_witness(primitive_witness);
        let type_scripts_halt = TypeScriptsHalt::new_from_primitive_witness(primitive_witness);
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
        let lock_scripts_halt = self.lock_scripts_halt.verify();
        let removal_records_integral = self.removal_records_integrity.verify();
        if !lock_scripts_halt {
            eprintln!("Lock scripts don't halt.");
        }
        if !removal_records_integral {
            eprintln!("Removal records are not integral.");
        }
        // && self.kernel_to_lock_scripts.verify()

        // && self.kernel_to_typescripts.verify()
        // && self.type_scripts_halt.verify()
        lock_scripts_halt && removal_records_integral
    }
}
