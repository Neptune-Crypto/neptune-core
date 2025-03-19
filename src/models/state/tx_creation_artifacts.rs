use std::sync::Arc;

use crate::models::blockchain::transaction::Transaction;
use crate::models::state::transaction_details::TransactionDetails;

/// Objects created by `create_transaction`.
#[derive(Debug, Clone)]
pub struct TxCreationArtifacts {
    pub(crate) transaction: Arc<Transaction>,
    pub(crate) details: Arc<TransactionDetails>,
}
