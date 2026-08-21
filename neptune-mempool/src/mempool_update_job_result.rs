use neptune_consensus::chaintx::link_tx::LinkTx;
use neptune_consensus::transaction::Transaction;
use neptune_consensus::transaction::primitive_witness::PrimitiveWitness;

use crate::transaction_kernel_id::TransactionKernelId;

#[derive(Debug)]
pub enum MempoolUpdateJobResult {
    Failure(TransactionKernelId),
    Success {
        /// The primitive witness, with updated mutator set data
        new_primitive_witness: Option<Box<PrimitiveWitness>>,

        /// The transaction, with updated mutator set data.
        new_transaction: Box<Transaction>,
    },
    SuccessLink {
        /// The link transaction, with updated mutator set data.
        new_link_tx: Box<LinkTx>,
    },
}
