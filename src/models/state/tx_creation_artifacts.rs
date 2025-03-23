use std::sync::Arc;

use serde::Deserialize;
use serde::Serialize;

use crate::config_models::network::Network;
use crate::models::blockchain::transaction::Transaction;
use crate::models::state::transaction_details::TransactionDetails;
use crate::models::state::wallet::transaction_output::TxOutput;
use crate::models::state::wallet::utxo_notification::PrivateNotificationData;

/// Objects created by `create_transaction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxCreationArtifacts {
    pub(crate) network: Network,
    pub(crate) transaction: Arc<Transaction>,
    pub(crate) details: Arc<TransactionDetails>,
}

impl TxCreationArtifacts {
    pub fn transaction(&self) -> &Transaction {
        &self.transaction
    }

    pub fn details(&self) -> &TransactionDetails {
        &self.details
    }

    pub fn offchain_notifications(&self) -> Vec<PrivateNotificationData> {
        self.details.tx_outputs.offchain_notifications(self.network)
    }

    pub fn change_output(&self) -> Option<&TxOutput> {
        self.details.change_output()
    }
}
