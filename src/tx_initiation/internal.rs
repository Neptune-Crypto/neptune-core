//! this module provides crate-internal tx-initiation APIs.
use std::sync::Arc;

use crate::models::blockchain::transaction::Transaction;
use crate::models::state::transaction_details::TransactionDetails;
use crate::models::state::tx_creation_config::TxCreationConfig;
use crate::models::state::StateLock;
use crate::tx_initiation::builder::transaction_builder::TransactionBuilder;
use crate::tx_initiation::builder::transaction_details_builder::TransactionDetailsBuilder;
use crate::tx_initiation::builder::transaction_proof_builder::TransactionProofBuilder;
use crate::tx_initiation::builder::tx_input_list_builder::InputSelectionPolicy;
use crate::tx_initiation::builder::tx_input_list_builder::SortOrder;
use crate::tx_initiation::builder::tx_input_list_builder::TxInputListBuilder;
use crate::tx_initiation::export::ChangePolicy;
use crate::tx_initiation::export::NativeCurrencyAmount;
use crate::tx_initiation::export::Timestamp;
use crate::tx_initiation::export::TxCreationArtifacts;
use crate::tx_initiation::export::TxOutputList;
use crate::GlobalStateLock;

// provides crate-internal API(s)
pub(crate) struct TransactionInitiatorInternal {
    global_state_lock: GlobalStateLock,
}

impl TransactionInitiatorInternal {
    // obtain/instantiate via GlobalStateLock::tx_initiator_internal()
    pub(crate) fn new(global_state_lock: GlobalStateLock) -> Self {
        Self { global_state_lock }
    }

    /// note: this is an internal (crate-private) API.
    ///
    /// it is now just a wrapper around TxInputListBuilder,
    /// TransactionDetailsBuilder, TransactionProofBuilder and
    /// TransactionBuilder
    pub(crate) async fn create_transaction(
        &mut self,
        tx_outputs: TxOutputList,
        fee: NativeCurrencyAmount,
        timestamp: Timestamp,
        tx_creation_config: TxCreationConfig,
    ) -> anyhow::Result<TxCreationArtifacts> {
        // acquire lock.  write-lock is only needed if we must generate a
        // new change receiving address.  However, that is also the most common
        // scenario.
        let mut state_lock = match tx_creation_config.change_policy() {
            ChangePolicy::RecoverToNextUnusedKey { .. } => {
                StateLock::WriteGuard(self.global_state_lock.lock_guard_mut().await)
            }
            _ => StateLock::ReadGuard(self.global_state_lock.lock_guard().await),
        };

        // select inputs
        let tx_inputs = TxInputListBuilder::new()
            .spendable_inputs(
                state_lock
                    .gs()
                    .wallet_spendable_inputs(timestamp)
                    .await
                    .into_iter()
                    .collect(),
            )
            .policy(InputSelectionPolicy::ByNativeCoinAmount(
                SortOrder::Descending,
            ))
            .spend_amount(tx_outputs.total_native_coins() + fee)
            .build();

        // generate tx details
        let tx_details = TransactionDetailsBuilder::new()
            .inputs(tx_inputs.into_iter().into())
            .outputs(tx_outputs)
            .fee(fee)
            .change_policy(tx_creation_config.change_policy())
            .build(&mut state_lock)
            .await?;
        drop(state_lock);

        let tx_details_rc = Arc::new(tx_details);

        // generate proof
        let proof = TransactionProofBuilder::new()
            .transaction_details(tx_details_rc.clone())
            .job_queue(tx_creation_config.job_queue())
            .proof_job_options(tx_creation_config.proof_job_options())
            .tx_proving_capability(tx_creation_config.prover_capability())
            .build()
            .await?;

        // assemble transaction
        let transaction = TransactionBuilder::new()
            .transaction_details(tx_details_rc.clone())
            .transaction_proof(proof)
            .build()?;

        // package tx with details
        let transaction_creation_artifacts = TxCreationArtifacts {
            transaction: Arc::new(transaction),
            details: tx_details_rc,
        };

        Ok(transaction_creation_artifacts)
    }
}

/// note: this is a internal internal (crate-private) API.
///
/// note: this is now just a wrapper around TransactionProofBuilder and
/// TransactionBuilder
pub(crate) async fn create_raw_transaction(
    tx_details_arc: Arc<TransactionDetails>,
    config: TxCreationConfig,
) -> anyhow::Result<Transaction> {
    let proof = TransactionProofBuilder::new()
        .transaction_details(tx_details_arc.clone())
        .job_queue(config.job_queue())
        .proof_job_options(config.proof_job_options())
        .tx_proving_capability(config.prover_capability())
        .build()
        .await?;

    Ok(TransactionBuilder::new()
        .transaction_details(tx_details_arc)
        .transaction_proof(proof)
        .build()?)
}
