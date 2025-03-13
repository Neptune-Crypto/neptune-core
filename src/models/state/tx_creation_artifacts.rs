use crate::models::blockchain::transaction::Transaction;
use crate::models::state::transaction_details::TransactionDetails;
use crate::models::state::wallet::transaction_output::TxOutput;

/// Objects created by `create_transaction`.
///
/// Most of the time we are only interested in the transaction. The change
/// output is only set if there is a change (which is not always the case).
/// The details is set when the [`TxCreationConfig`](super::TxCreationConfig)
/// is configured to set it. In the common case it is not set, saving time,
/// state, and hassle.
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
