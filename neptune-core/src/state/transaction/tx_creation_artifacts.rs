use std::sync::Arc;

use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;

use crate::application::config::network::Network;
use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
use crate::protocol::consensus::transaction::primitive_witness::PrimitiveWitness;
use crate::protocol::consensus::transaction::primitive_witness::WitnessValidationError;
use crate::protocol::consensus::transaction::Transaction;
use crate::protocol::proof_abstractions::mast_hash::MastHash;
use crate::state::transaction::transaction_details::TransactionDetails;
use crate::state::wallet::utxo_notification::PrivateNotificationData;

/// represents a [Transaction] and its corresponding [TransactionDetails]
///
/// an instance of this type is necessary to record and broadcast (send) a
/// transaction with
/// [record_and_broadcast_transaction()](crate::api::tx_initiation::initiator::TransactionInitiator::record_and_broadcast_transaction()).
///
/// A [Transaction] contains blinded data that can be sent over the network to
/// other neptune-core nodes.  The [TransactionDetails] contains the unblinded
/// data that the `Transaction` is generated from, minus the [TransactionProof](crate::protocol::consensus::transaction::transaction_proof::TransactionProof).
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
    pub async fn is_valid(&self, network: Network, consensus_rule_set: ConsensusRuleSet) -> bool {
        self.verify(network, consensus_rule_set).await.is_ok()
    }

    /// verifies that artifacts are consistent and valid.
    ///
    /// in particular:
    ///  1. Self::details.network matches provided Network.
    ///  2. Transaction and TransactionDetails match.
    ///  3. TransactionDetails are valid, indicating the PrimitiveWitness is valid.
    ///  4. Transaction proof is valid, and thus the Tx itself is valid.
    //
    // note: we could skip the TransactionDetails validation when the network
    // does not mock-proofs, eg for Mainnet. When a real proof is present
    // that validation alone is sufficient because if the Transaction
    // is valid and the TransactionDetails match then the TransactionDetails
    // logically must be valid as well.
    //
    // When mock proofs are used, the Transaction proof will typically be
    // considered "valid" but the TransactionDetails might not be valid, so
    // it should be checked.
    //
    // For now we elect to validate the TransactionDetails anyway because:
    // 1. TransactionDetails::validate() provides more granular error variants indicating
    //    where the problem lies compared to Transaction::verify_proof() which just
    //    returns a bool
    // 2. it keeps the implementation the same regardless whether the network
    //    uses mock proofs or not.
    pub async fn verify(
        &self,
        network: Network,
        consensus_rule_set: ConsensusRuleSet,
    ) -> Result<(), TxCreationArtifactsError> {
        // tbd: maybe we should get rid of the network arg.  it's present
        // out of abundance of caution.

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

        // 3. validate the TransactionDetails
        self.details.validate().await?;

        // 4. validate that transaction (proof) is valid.
        if !self.transaction.is_valid(network, consensus_rule_set).await {
            return Err(TxCreationArtifactsError::InvalidProof);
        }

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

    #[error(transparent)]
    InvalidWitness(#[from] WitnessValidationError),

    #[error("invalid proof")]
    InvalidProof,

    #[error("network mismatch")]
    NetworkMismatch,
}
