use std::collections::HashMap;

use neptune_consensus::transaction::transaction_kernel::TransactionKernel;
use neptune_primitives::mast_hash::MastHash;
use tasm_lib::prelude::Digest;

/// Represents a mempool state change.
///
/// For purpose of notifying interested parties
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MempoolEvent {
    /// a transaction was added to the mempool
    // TODO: Consider adding proof type here in case any subscriber could use
    // that.
    AddTx(TransactionKernel),

    /// a transaction was removed from the mempool
    RemoveTx(TransactionKernel),
}

impl MempoolEvent {
    fn kernel_mast_hash(&self) -> Digest {
        match self {
            MempoolEvent::AddTx(transaction_kernel) => transaction_kernel.mast_hash(),
            MempoolEvent::RemoveTx(transaction_kernel) => transaction_kernel.mast_hash(),
        }
    }

    /// Remove pairs of the form (add, remove) referring to the same
    /// transaction.
    ///
    /// Shortens the list of [`MempoolEvent`]s such that pairs of events
    /// referring to the same transaction first being added, and then removed
    /// are eliminated from the list.
    pub(super) fn normalize(events: Vec<Self>) -> Vec<Self> {
        let mut added = HashMap::new();
        let mut removed = HashMap::new();
        for event in events {
            // We use kernel MAST hash as hash map key because we want two
            // events if an insertion is used for updating a mutator set.
            let tx_key = event.kernel_mast_hash();
            match event {
                MempoolEvent::AddTx(transaction_kernel) => {
                    if removed.contains_key(&tx_key) {
                        removed.remove(&tx_key);
                    } else {
                        added.insert(tx_key, transaction_kernel);
                    }
                }
                MempoolEvent::RemoveTx(transaction_kernel) => {
                    if added.contains_key(&tx_key) {
                        added.remove(&tx_key);
                    } else {
                        removed.insert(tx_key, transaction_kernel);
                    }
                }
            }
        }

        removed
            .into_values()
            .map(Self::RemoveTx)
            .chain(added.into_values().map(Self::AddTx))
            .collect()
    }
}

/// Test-support tallies over mempool events. Gated behind `test-helpers` so
/// downstream crates' tests (e.g. `neptune-core`) can use them.
#[cfg(any(test, feature = "test-helpers"))]
impl MempoolEvent {
    pub fn is_add(&self) -> bool {
        matches!(self, Self::AddTx(_))
    }

    pub fn is_remove(&self) -> bool {
        matches!(self, Self::RemoveTx(_))
    }

    pub fn num_removes(events: &[Self]) -> usize {
        events.iter().filter(|x| x.is_remove()).count()
    }

    pub fn num_adds(events: &[Self]) -> usize {
        events.iter().filter(|x| x.is_add()).count()
    }
}
