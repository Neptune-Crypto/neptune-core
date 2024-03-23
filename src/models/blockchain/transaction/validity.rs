use crate::models::blockchain::block::mutator_set_update::MutatorSetUpdate;
use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
use crate::models::consensus::mast_hash::MastHash;
use crate::models::consensus::{
    ValidationLogic, ValidityAstType, ValidityTree, WhichProgram, WitnessType,
};
use crate::prelude::twenty_first;

pub mod kernel_to_lock_scripts;
pub mod kernel_to_type_scripts;
pub mod lockscripts_halt;
pub mod removal_records_integrity;
pub mod tasm;
pub mod typescripts_halt;
use crate::models::blockchain::transaction;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use crate::util_types::mutator_set::mutator_set_trait::*;

use get_size::GetSize;
use serde::{Deserialize, Serialize};
use tasm_lib::triton_vm::proof::Claim;
use tasm_lib::Digest;
use twenty_first::shared_math::bfield_codec::BFieldCodec;

use self::lockscripts_halt::LockScriptsHalt;
use self::removal_records_integrity::RemovalRecordsIntegrity;
use self::{
    kernel_to_lock_scripts::KernelToLockScripts, kernel_to_type_scripts::KernelToTypeScripts,
    typescripts_halt::TypeScriptsHalt,
};

use super::primitive_witness::PrimitiveWitness;
use super::transaction_kernel::TransactionKernel;
use super::Transaction;

/// This boolean expression determines whether a transaction is valid. Until we start
/// proving away subexpressions, we drag around the original primitive witness that
/// generated the tree.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec, Default)]
pub struct TransactionValidationLogic {
    pub vast: ValidityTree,
    pub maybe_primitive_witness: Option<PrimitiveWitness>,
}

pub enum TransactionValidityTreeUpdateError {
    ProofIsPresent,
}

impl TransactionValidationLogic {
    pub fn new(tree: ValidityTree, maybe_primitive_witness: Option<PrimitiveWitness>) -> Self {
        Self {
            vast: tree,
            maybe_primitive_witness,
        }
    }

    fn new_validity_tree(
        kernel_hash: Digest,
        primitive: ValidityTree,
        mutator_set_update: ValidityTree,
        merger: ValidityTree,
    ) -> ValidityTree {
        ValidityTree::root(
            kernel_hash,
            ValidityTree::any(vec![primitive, mutator_set_update, merger]),
        )
    }

    pub fn validation_tree_from_merger(
        own_kernel: &TransactionKernel,
        own_proof: &ValidityTree,
        other_kernel: &TransactionKernel,
        other_proof: &ValidityTree,
        new_kernel: &TransactionKernel,
    ) -> ValidityTree {
        if !own_proof.verify(own_kernel.mast_hash())
            || !other_proof.verify(other_kernel.mast_hash())
            || [own_kernel.inputs.clone(), other_kernel.inputs.clone()].concat()
                != new_kernel.inputs
            || [own_kernel.outputs.clone(), other_kernel.outputs.clone()].concat()
                != new_kernel.outputs
            || [
                own_kernel.public_announcements.clone(),
                other_kernel.public_announcements.clone(),
            ]
            .concat()
                != new_kernel.public_announcements
            || own_kernel.fee + other_kernel.fee != new_kernel.fee
            || own_kernel.coinbase.unwrap_or(NeptuneCoins::new(0))
                + other_kernel.coinbase.unwrap_or(NeptuneCoins::new(0))
                != new_kernel.coinbase.unwrap_or(NeptuneCoins::new(0))
            || u64::max(own_kernel.timestamp.value(), other_kernel.timestamp.value())
                != new_kernel.timestamp.value()
            || own_kernel.mutator_set_hash != other_kernel.mutator_set_hash
            || other_kernel.mutator_set_hash != new_kernel.mutator_set_hash
        {
            return ValidityTree::none();
        }

        Self::new_validity_tree(
            new_kernel.mast_hash(),
            ValidityTree::none(),
            ValidityTree::none(),
            ValidityTree::new(
                ValidityAstType::Atomic(None, Claim::new(Digest::default()), WhichProgram::Merger),
                WitnessType::Faith,
            ),
        )
    }

    pub fn validation_tree_from_primitive_witness(
        primitive_witness: PrimitiveWitness,
    ) -> ValidityTree {
        let primitive = ValidityTree::all(vec![
            LockScriptsHalt::from(primitive_witness.clone()).vast(),
            TypeScriptsHalt::from(primitive_witness.clone()).vast(),
            RemovalRecordsIntegrity::from(primitive_witness.clone()).vast(),
        ]);
        Self::new_validity_tree(
            primitive_witness.kernel.mast_hash(),
            primitive,
            ValidityTree::none(),
            ValidityTree::none(),
        )
    }

    pub async fn validation_tree_from_mutator_set_update(
        old_tree: &ValidityTree,
        old_kernel: &TransactionKernel,
        old_mutator_set_accumulator: &MutatorSetAccumulator,
        new_kernel: &TransactionKernel,
        mutator_set_update: &MutatorSetUpdate,
    ) -> ValidityTree {
        if !old_tree.verify(old_kernel.mast_hash())
            || old_kernel.mutator_set_hash != old_mutator_set_accumulator.hash().await
        {
            return ValidityTree::none();
        }

        let mut mutator_set_accumulator = old_mutator_set_accumulator.clone();
        if mutator_set_update
            .apply_to_accumulator(&mut mutator_set_accumulator)
            .await
            .is_err()
        {
            return ValidityTree::none();
        }

        if new_kernel.mutator_set_hash != mutator_set_accumulator.hash().await {
            return ValidityTree::none();
        }

        Self::new_validity_tree(
            new_kernel.mast_hash(),
            ValidityTree::none(),
            ValidityTree::new(
                ValidityAstType::Atomic(
                    None,
                    Claim::new(Digest::default()),
                    WhichProgram::MutatorSetUpdate,
                ),
                WitnessType::Faith,
            ),
            ValidityTree::none(),
        )
    }
}

// impl TransactionValidationLogic {
//     pub fn prove(&mut self) -> Result<()> {
//         self.lock_scripts_halt.prove()?;

//         self.removal_records_integrity.prove()?;

//         // not supported yet:
//         // self.kernel_to_lock_scripts.prove()?;
//         // self.kernel_to_typescripts.prove()?;
//         // self.type_scripts_halt.prove()?;
//         Ok(())
//     }

//     pub fn verify(&self) -> bool {
//         info!("validity logic for 'kernel_to_lock_scripts', 'kernel_to_type_scripts', 'type_scripts_halt' not implemented yet.");
//         let lock_scripts_halt = self.lock_scripts_halt.verify();
//         let removal_records_integral = self.removal_records_integrity.verify();
//         // let type_scripts_halt = self.type_scripts_halt.verify();
//         if !lock_scripts_halt {
//             eprintln!("Lock scripts don't halt (gracefully).");
//         }
//         // if !type_scripts_halt {
//         //     eprintln!("Type scripts don't halt (gracefully).");
//         // }
//         if !removal_records_integral {
//             eprintln!("Removal records are not integral.");
//         }
//         // && self.kernel_to_lock_scripts.verify()
//         // && self.kernel_to_typescripts.verify()
//         lock_scripts_halt && removal_records_integral
//     }
// }

impl From<transaction::PrimitiveWitness> for TransactionValidationLogic {
    fn from(primitive_witness: transaction::PrimitiveWitness) -> Self {
        let lock_scripts_halt = LockScriptsHalt::from(primitive_witness.clone());
        let _kernel_to_lock_scripts = KernelToLockScripts::from(primitive_witness.clone());
        let _removal_records_integrity = RemovalRecordsIntegrity::from(primitive_witness.clone());
        let _kernel_to_typescripts = KernelToTypeScripts::from(primitive_witness.clone());
        let type_scripts_halt = TypeScriptsHalt::from(primitive_witness.clone());
        Self {
            vast: ValidityTree {
                vast_type: ValidityAstType::All(vec![
                    lock_scripts_halt.vast(),
                    // kernel_to_lock_scripts,
                    // removal_records_integrity,
                    // kernel_to_typescripts,
                    type_scripts_halt.vast(),
                ]),
                witness_type: WitnessType::Decomposition,
            },
            maybe_primitive_witness: Some(primitive_witness),
        }
    }
}

impl From<Transaction> for TransactionValidationLogic {
    fn from(transaction: Transaction) -> Self {
        transaction.witness
    }
}
