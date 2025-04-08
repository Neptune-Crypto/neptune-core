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

/// represents a [Transaction] and its corresponding [TransactionDetails]
///
/// an instance of this type is necessary to record and broadcast (send) a
/// transaction with
/// [record_and_broadcast_transaction()](crate::api::tx_initiation::initiator::TransactionInitiator::record_and_broadcast_transaction()).
///
/// A [Transaction] contains blinded data that can be sent over the network to
/// other neptune-core nodes.  The [TransactionDetails] contains the unblinded
/// data that the `Transaction` is generated from, minus the [TransactionProof](crate::models::blockchain::transaction::transaction_proof::TransactionProof).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxCreationArtifacts {
    pub(crate) transaction: Arc<Transaction>,
    pub(crate) details: Arc<TransactionDetails>,
}

impl std::fmt::Display for TxCreationArtifacts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.details.fmt(f)
    }
}

impl TxCreationArtifacts {
    /// get the transaction
    pub fn transaction(&self) -> &Transaction {
        &self.transaction
    }

    /// get the transaction details
    pub fn details(&self) -> &TransactionDetails {
        &self.details
    }

    /// get all offchain notification (owned and unowned)
    pub fn all_offchain_notifications(&self) -> Vec<PrivateNotificationData> {
        self.details
            .tx_outputs
            .offchain_notifications(self.details.network)
            .collect()
    }

    /// get owned offchain notifications
    pub fn owned_offchain_notifications(&self) -> Vec<PrivateNotificationData> {
        self.details
            .tx_outputs
            .owned_offchain_notifications(self.details.network)
            .collect()
    }

    /// get unowned offchain notifications
    pub fn unowned_offchain_notifications(&self) -> Vec<PrivateNotificationData> {
        self.details
            .tx_outputs
            .unowned_offchain_notifications(self.details.network)
            .collect()
    }

    /// verifies that artifacts are consistent and valid.
    ///
    /// this is a wrapper for `verify` that just returns bool
    pub async fn is_valid(&self, network: Network) -> bool {
        self.verify(network).await.is_ok()
    }

    /// verifies that artifacts are consistent and valid.
    ///
    /// in particular:
    ///  1. Self::details.network matches provided Network.
    ///  2. Transaction and TransactionDetails match.
    ///  3. Transaction proof is valid, and thus the Tx itself is valid.
    ///
    /// At present we do NOT validate the TransactionDetails themselves
    /// because if the details match the transaction and the transaction is
    /// valid, that is sufficient.
    pub async fn verify(&self, network: Network) -> Result<(), TxCreationArtifactsError> {
        // tbd: maybe we should get rid of the network arg.  it's present
        // out of abundance of caution.

        // todo: (how) can we also verify that self.details.network matches the Tx?
        // it could be spoofed.

        // note: we check the least expensive things first.

        // 1. Self::details.network matches provided Network.
        if network != self.details.network {
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

        // 4. skipped.  validate the transaction details is valid.

        Ok(())
    }
}

/// enumerates possible transaction artifacts errors
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
