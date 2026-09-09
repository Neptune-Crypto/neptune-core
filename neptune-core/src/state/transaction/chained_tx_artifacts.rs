//! The results of creating a chained transaction: the chain-pipeline analog
//! of [`TxCreationArtifacts`](super::tx_creation_artifacts::TxCreationArtifacts).

use std::sync::Arc;

use neptune_consensus::transaction::Transaction;
use neptune_wallet::chained_transaction_details::ChainedTransactionDetails;

/// The results of creating a chained transaction.
///
/// Unlike [`TxCreationArtifacts`](super::tx_creation_artifacts::TxCreationArtifacts),
/// the details cannot reproduce the transaction's kernel: the transaction is
/// the fixed result of chaining onto predecessor transactions, while the
/// details describe only the initiator's own link. Validity rests on the
/// link-primitive-witness validation performed at construction.
#[derive(Debug, Clone)]
pub struct ChainedTxArtifacts {
    pub(crate) transaction: Arc<Transaction>,
    pub(crate) details: Arc<ChainedTransactionDetails>,
}

impl ChainedTxArtifacts {
    pub fn transaction(&self) -> &Transaction {
        &self.transaction
    }

    pub fn details(&self) -> &ChainedTransactionDetails {
        &self.details
    }
}
