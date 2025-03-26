use std::sync::Arc;

use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;

use crate::config_models::network::Network;
use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;
use crate::models::blockchain::transaction::Transaction;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::state::transaction_details::TransactionDetails;
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

    pub fn all_offchain_notifications(&self) -> Vec<PrivateNotificationData> {
        self.details
            .tx_outputs
            .offchain_notifications(self.network)
            .collect()
    }

    pub fn owned_offchain_notifications(&self) -> Vec<PrivateNotificationData> {
        self.details
            .tx_outputs
            .owned_offchain_notifications(self.network)
            .collect()
    }

    pub fn unowned_offchain_notifications(&self) -> Vec<PrivateNotificationData> {
        self.details
            .tx_outputs
            .unowned_offchain_notifications(self.network)
            .collect()
    }

    /// verifies that artifacts are consistent and valid.
    ///
    /// in particular:
    ///  1. Self::network matches provided Network.
    ///  2. Transaction and TransactionDetails match.
    ///  3. Transaction proof is valid, and thus the Tx itself is valid.
    pub async fn verify(&self, network: Network) -> Result<(), TxCreationArtifactsError> {
        // todo: (how) can we also verify that self.network matches the Tx?

        // 1. Self::network matches provided Network.
        if network != self.network {
            return Err(TxCreationArtifactsError::NetworkMismatch);
        }

        // 2. verify that Transaction and TransactionDetails match.
        let tx_hash = self.transaction.kernel.mast_hash();
        let details_hash = PrimitiveWitness::from_transaction_details(&self.details)
            .kernel
            .mast_hash();

        if details_hash != tx_hash {
            return Err(TxCreationArtifactsError::TxDetailsMismatch {
                tx_hash,
                details_hash,
            });
        }

        // 3. validate that transaction (proof) is valid.
        if !self.transaction.verify_proof().await {
            return Err(TxCreationArtifactsError::InvalidProof);
        }

        Ok(())
    }
}

/// enumerates possible transaction send errors
#[derive(Debug, Clone, thiserror::Error, Serialize, Deserialize)]
#[non_exhaustive]
pub enum TxCreationArtifactsError {
    #[error("details hash does not match transaction hash")]
    TxDetailsMismatch {
        tx_hash: Digest,
        details_hash: Digest,
    },

    #[error("invalid proof")]
    InvalidProof,

    #[error("network mismatch")]
    NetworkMismatch,
}
