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

#[cfg(test)]
mod tests {
    use super::*;

    impl MempoolEvent {
        pub(crate) fn is_add(&self) -> bool {
            matches!(self, Self::AddTx(_))
        }

        pub(crate) fn is_remove(&self) -> bool {
            matches!(self, Self::RemoveTx(_))
        }

        pub(crate) fn num_removes(events: &[Self]) -> usize {
            events.iter().filter(|x| x.is_remove()).count()
        }

        pub(crate) fn num_adds(events: &[Self]) -> usize {
            events.iter().filter(|x| x.is_add()).count()
        }
    }
}
