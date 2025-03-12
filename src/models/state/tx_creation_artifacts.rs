use crate::models::blockchain::transaction::Transaction;
use crate::models::state::transaction_details::TransactionDetails;
use crate::models::state::wallet::transaction_output::TxOutput;

#[derive(Debug, Clone)]
pub(crate) struct TxCreationArtifacts {
    pub(crate) transaction: Transaction,
    pub(crate) details: Option<TransactionDetails>,
    pub(crate) change_output: Option<TxOutput>,
}

impl From<TxCreationArtifacts> for Transaction {
    fn from(value: TxCreationArtifacts) -> Self {
        value.transaction
    }
}
