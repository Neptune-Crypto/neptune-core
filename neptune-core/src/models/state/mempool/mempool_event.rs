use crate::api::export::{Transaction, TransactionKernelId};

/// Represents a mempool state change.
///
/// For purpose of notifying interested parties
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MempoolEvent {
    /// a transaction was added to the mempool
    AddTx(Transaction),

    /// a transaction was removed from the mempool
    RemoveTx(Transaction),

    /// the mutator-set of a transaction was updated in the mempool.
    ///
    /// (kernel-ID, Tx after mutator-set updated)
    UpdateTxMutatorSet(TransactionKernelId, Transaction),
}
