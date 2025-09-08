//! this is a test-util module that provides the historic create_transaction()
//! API for usage by tests.
//!
//! Going forward test authors are encouraged to use the public APIs instead.

use crate::api::export::ChangePolicy;
use crate::api::export::NativeCurrencyAmount;
use crate::api::export::Timestamp;
use crate::api::export::TxCreationArtifacts;
use crate::api::export::TxOutputList;
use crate::api::tx_initiation::builder::transaction_builder::TransactionBuilder;
use crate::api::tx_initiation::builder::transaction_details_builder::TransactionDetailsBuilder;
use crate::api::tx_initiation::builder::transaction_proof_builder::TransactionProofBuilder;
use crate::api::tx_initiation::builder::tx_artifacts_builder::TxCreationArtifactsBuilder;
use crate::api::tx_initiation::builder::tx_input_list_builder::InputSelectionPolicy;
use crate::api::tx_initiation::builder::tx_input_list_builder::TxInputListBuilder;
use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
use crate::state::transaction::tx_creation_config::TxCreationConfig;
use crate::state::StateLock;
use crate::GlobalStateLock;

// provides crate-internal API(s)
pub(crate) struct TransactionInitiatorInternal {
    global_state_lock: GlobalStateLock,
}

impl From<GlobalStateLock> for TransactionInitiatorInternal {
    fn from(global_state_lock: GlobalStateLock) -> Self {
        Self { global_state_lock }
    }
}

impl TransactionInitiatorInternal {
    /// note: this api only exists for legacy unit tests.
    ///
    /// new tests should use TransactionSender::send() or
    /// `TransactionInitiator or a builder.
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
        consensus_rule_set: ConsensusRuleSet,
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
            .policy(InputSelectionPolicy::ByProvidedOrder)
            .spend_amount(tx_outputs.total_native_coins() + fee)
            .build();

        // generate tx details
        let tx_details = TransactionDetailsBuilder::new()
            .timestamp(timestamp)
            .inputs(tx_inputs.into_iter().into())
            .outputs(tx_outputs)
            .fee(fee)
            .change_policy(tx_creation_config.change_policy())
            .build(&mut state_lock)
            .await?;
        drop(state_lock);

        let witness = tx_details.primitive_witness();
        let kernel = witness.kernel.clone();

        // generate proof

        let proof = TransactionProofBuilder::new()
            .consensus_rule_set(consensus_rule_set)
            .transaction_details(&tx_details)
            .primitive_witness(witness)
            .job_queue(tx_creation_config.job_queue())
            .proof_job_options(tx_creation_config.proof_job_options())
            .build()
            .await?;

        // create transaction
        let transaction = TransactionBuilder::new()
            .transaction_kernel(kernel)
            .transaction_proof(proof)
            .build()?;

        // assemble artifacts
        let artifacts = TxCreationArtifactsBuilder::new()
            .transaction_details(tx_details)
            .transaction(transaction)
            .build()?;

        Ok(artifacts)
    }
}
