use neptune_consensus::transaction::primitive_witness::PrimitiveWitness;

use crate::api::export::Transaction;
use crate::api::export::TransactionKernelId;

pub(crate) enum MempoolUpdateJobResult {
    Failure(TransactionKernelId),
    Success {
        /// The primitive witness, with updated mutator set data
        new_primitive_witness: Option<Box<PrimitiveWitness>>,

        /// The transaction, with updated mutator set data.
        new_transaction: Box<Transaction>,
    },
}
