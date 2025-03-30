//! a builder for [TxCreationArtifacts] and [Transaction].
//!
//! note that `TxCreationArtifacts` contains a `Transaction` as well
//! as [TransactionDetails].
//!
//! It is expected that usually callers will prefer to build
//! [TxCreationArtifacts] as it can be used as input for the
//! record_and_broadcast() API.  For this reason the build() method produces a
//! `TxCreationArtifacts`.  However the build_transaction() method is also
//! provided in case caller wants a standalone `Transaction`.
//!
//! see [builder](super) for examples of using the builders together.

use std::sync::Arc;

use crate::api::export::TxCreationArtifacts;
use crate::api::tx_initiation::error::CreateTxError;
use crate::config_models::network::Network;
use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;
use crate::models::blockchain::transaction::Transaction;
use crate::models::blockchain::transaction::TransactionProof;
use crate::models::state::transaction_details::TransactionDetails;

/// a builder for [Transaction] and [TxCreationArtifacts]
///
/// see module docs for details and example usage.
#[derive(Debug, Default)]
pub struct TransactionBuilder {
    transaction_details: Option<Arc<TransactionDetails>>,
    transaction_proof: Option<TransactionProof>,
}

impl TransactionBuilder {
    /// instantiate
    pub fn new() -> Self {
        Default::default()
    }

    /// add transaction details (required)
    pub fn transaction_details(mut self, transaction_details: Arc<TransactionDetails>) -> Self {
        self.transaction_details = Some(transaction_details);
        self
    }

    /// add transaction proof (required)
    pub fn transaction_proof(mut self, transaction_proof: TransactionProof) -> Self {
        self.transaction_proof = Some(transaction_proof);
        self
    }

    /// build a [TxCreationArtifacts]
    ///
    /// note: the builder does not validate the resulting artifacts.
    /// caller can do so with [TxCreationArtifacts::verify()]
    pub fn build(self, network: Network) -> Result<TxCreationArtifacts, CreateTxError> {
        let (Some(details), Some(proof)) = (self.transaction_details, self.transaction_proof)
        else {
            return Err(CreateTxError::MissingRequirement);
        };

        let witness = PrimitiveWitness::from_transaction_details(&details);

        let transaction = Transaction {
            kernel: witness.kernel,
            proof,
        };

        Ok(TxCreationArtifacts {
            network,
            transaction: Arc::new(transaction),
            details,
        })
    }

    /// build a [Transaction]
    ///
    /// note: the builder does not validate the resulting transaction.
    /// caller can do so with [Transaction::verify_proof()]
    pub fn build_transaction(self) -> Result<Transaction, CreateTxError> {
        let (Some(tx_details), Some(proof)) = (self.transaction_details, self.transaction_proof)
        else {
            return Err(CreateTxError::MissingRequirement);
        };

        let witness = PrimitiveWitness::from_transaction_details(&tx_details);

        Ok(Transaction {
            kernel: witness.kernel,
            proof,
        })
    }
}
