//! provides an easy-to-use `TransactionSender` with single send() method.
//!
//! This is highest-level and easiest to use API for sending a transaction.
//!
//! It should be preferred to lower-level APIs unless there is a need for
//! greater flexibility than this provides.
//!
//! see [tx_initiation](super) for other available API.
//!
//! Example:
//!
//! ```
//! use neptune_cash::{api, api::export, api::tx_initiation::{self, send}};
//! use export::ChangePolicy;
//! use export::GlobalStateLock;
//! use export::NativeCurrencyAmount;
//! use export::ReceivingAddress;
//! use export::Timestamp;
//! use export::TxCreationArtifacts;
//!
//! async fn my_send_transaction(gsl: GlobalStateLock, recipient: ReceivingAddress, amount: NativeCurrencyAmount, change_policy: ChangePolicy, fee: NativeCurrencyAmount) -> Result<TxCreationArtifacts, tx_initiation::error::SendError> {
//!     let outputs = vec![(recipient, amount)];
//!
//!     send::TransactionSender::from(gsl)
//!         .send(
//!             outputs,
//!             change_policy,
//!             fee,
//!             Timestamp::now()
//!         ).await
//! }
//! ```

use super::error;
use crate::api::export::TransactionProofType;
use crate::api::tx_initiation::builder::transaction_builder::TransactionBuilder;
use crate::api::tx_initiation::builder::transaction_details_builder::TransactionDetailsBuilder;
use crate::api::tx_initiation::builder::transaction_proof_builder::TransactionProofBuilder;
use crate::api::tx_initiation::builder::triton_vm_proof_job_options_builder::TritonVmProofJobOptionsBuilder;
use crate::api::tx_initiation::builder::tx_artifacts_builder::TxCreationArtifactsBuilder;
use crate::api::tx_initiation::builder::tx_input_list_builder::InputSelectionPolicy;
use crate::api::tx_initiation::builder::tx_input_list_builder::TxInputListBuilder;
use crate::api::tx_initiation::builder::tx_output_list_builder::OutputFormat;
use crate::api::tx_initiation::builder::tx_output_list_builder::TxOutputListBuilder;
use crate::models::blockchain::consensus_rule_set::ConsensusRuleSet;
use crate::models::blockchain::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::models::state::tx_creation_artifacts::TxCreationArtifacts;
use crate::models::state::wallet::change_policy::ChangePolicy;
use crate::models::state::StateLock;
use crate::triton_vm_job_queue::vm_job_queue;
use crate::GlobalStateLock;

/// provides a send() method to send a neptune transaction in one call.
#[derive(Debug)]
pub struct TransactionSender {
    global_state_lock: GlobalStateLock,
}

impl From<GlobalStateLock> for TransactionSender {
    fn from(global_state_lock: GlobalStateLock) -> Self {
        Self { global_state_lock }
    }
}

impl TransactionSender {
    // You should call offchain-notifications() on the returned value
    // to retrieve (and store) offchain notifications, if any.
    pub async fn send(
        &mut self,
        outputs: impl IntoIterator<Item = impl Into<OutputFormat>>,
        change_policy: ChangePolicy,
        fee: NativeCurrencyAmount,
        timestamp: Timestamp,
    ) -> Result<TxCreationArtifacts, error::SendError> {
        self.private().check_proceed_with_send(fee).await?;

        let gsl = &mut self.global_state_lock;

        tracing::debug!("tx send initiated.");

        // The target proof-type is set to the lowest possible value here,
        // since we don't want the client (CLI or dashboard) to hang while
        // producing proofs. Instead, we let (a task started by) main loop
        // handle the proving.
        let target_proof_type = TransactionProofType::PrimitiveWitness;

        // acquire lock.  write-lock is only needed if we must generate a
        // new change receiving address.  However, that is also the most common
        // scenario.
        let mut state_lock = match change_policy {
            ChangePolicy::RecoverToNextUnusedKey { .. } => StateLock::write_guard(gsl).await,
            _ => StateLock::read_guard(gsl).await,
        };

        // generate outputs
        let tx_outputs = TxOutputListBuilder::new()
            .outputs(outputs)
            .build(&state_lock)
            .await;

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
            .policy(InputSelectionPolicy::Random)
            .spend_amount(tx_outputs.total_native_coins() + fee)
            .build();

        // generate tx details (may add change output)
        let tx_details = TransactionDetailsBuilder::new()
            .inputs(tx_inputs.into_iter().into())
            .outputs(tx_outputs)
            .fee(fee)
            .change_policy(change_policy)
            .build(&mut state_lock)
            .await?;

        let block_height = state_lock.gs().chain.light_state().header().height;
        let network = state_lock.cli().network;
        let consensus_rule_set = ConsensusRuleSet::infer_from(network, block_height);
        drop(state_lock); // release lock asap.

        tracing::info!("send: proving tx:\n{}", tx_details);

        let witness = tx_details.primitive_witness();
        let kernel = witness.kernel.clone();

        // use cli options for building proof, but override proof-type
        let options = TritonVmProofJobOptionsBuilder::new()
            .template(&gsl.cli().as_proof_job_options())
            .proof_type(target_proof_type)
            .build();

        // generate proof
        let proof = TransactionProofBuilder::new()
            .consensus_rule_set(consensus_rule_set)
            .transaction_details(&tx_details)
            .primitive_witness(witness)
            .job_queue(vm_job_queue())
            .proof_job_options(options)
            .build()
            .await?;

        tracing::info!("send: assembling tx");

        // create transaction
        let transaction = TransactionBuilder::new()
            .transaction_kernel(kernel)
            .transaction_proof(proof)
            .build()?;

        // assemble transaction artifacts
        let tx_creation_artifacts = TxCreationArtifactsBuilder::new()
            .transaction_details(tx_details)
            .transaction(transaction)
            .build()?;

        tracing::info!("send: recording tx");

        gsl.api()
            .tx_initiator()
            .record_and_broadcast_transaction(&tx_creation_artifacts)
            .await?;

        tracing::info!("send: all done!");

        Ok(tx_creation_artifacts)
    }

    fn private(&self) -> super::private::TransactionInitiatorPrivate {
        super::private::TransactionInitiatorPrivate::new(self.global_state_lock.clone())
    }
}
