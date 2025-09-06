//! a builder for [TxCreationArtifacts].
//!
//! see [builder](super) for examples of using the builders together.

use std::sync::Arc;

use crate::api::export::Transaction;
use crate::api::export::TxCreationArtifacts;
use crate::api::tx_initiation::error::CreateTxError;
use crate::state::transaction::transaction_details::TransactionDetails;

/// a builder for [TxCreationArtifacts]
///
/// see parent module docs for details and example usage.
#[derive(Debug, Default)]
pub struct TxCreationArtifactsBuilder {
    transaction_details: Option<Arc<TransactionDetails>>,
    transaction: Option<Arc<Transaction>>,
}

impl TxCreationArtifactsBuilder {
    /// instantiate
    pub fn new() -> Self {
        Default::default()
    }

    /// add transaction details (required)
    pub fn transaction_details(
        mut self,
        transaction_details: impl Into<Arc<TransactionDetails>>,
    ) -> Self {
        self.transaction_details = Some(transaction_details.into());
        self
    }

    /// add transaction proof (required)
    pub fn transaction(mut self, transaction: impl Into<Arc<Transaction>>) -> Self {
        self.transaction = Some(transaction.into());
        self
    }

    /// build a [TxCreationArtifacts]
    ///
    /// note: the builder does not validate the resulting artifacts.
    /// That can be done with [TxCreationArtifacts::verify()]
    pub fn build(self) -> Result<TxCreationArtifacts, CreateTxError> {
        let (Some(transaction), Some(details)) = (self.transaction, self.transaction_details)
        else {
            return Err(CreateTxError::MissingRequirement);
        };

        Ok(TxCreationArtifacts {
            transaction,
            details,
        })
    }
}
