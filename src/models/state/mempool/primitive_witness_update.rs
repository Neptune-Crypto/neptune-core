use crate::api::export::Transaction;
use crate::api::export::TransactionKernelId;
use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;

/// A primitive-witness backed transaction that must be upgraded to be valid
/// under a new mutator set.
pub(crate) struct PrimitiveWitnessUpdate {
    /// The deprecated primitive witness, before applying a mutator set update.
    pub(crate) old_primitive_witness: PrimitiveWitness,

    /// Indicates if the transaction was already backed by a proof-collection
    /// when it got deprecated.
    pub(crate) was_proof_collection: bool,
}

impl PrimitiveWitnessUpdate {
    pub(crate) fn new(old_primitive_witness: PrimitiveWitness, was_proof_collection: bool) -> Self {
        Self {
            old_primitive_witness,
            was_proof_collection,
        }
    }
}

pub(crate) enum PrimitiveWitnessUpdateResult {
    Failure(TransactionKernelId),
    Success {
        new_primitive_witness: PrimitiveWitness,
        new_transaction: Transaction,
    },
}
