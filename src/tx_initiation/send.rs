//! provides an easy-to-use `TransactionSender` with single send() method.
//!
//! This is highest-level and easiest to use API for sending a transaction.
//! callers should prefer it to lower-level APIs unless there is a need for
//! greater flexibility than this provides.
//!
//! see [tx_initiation](super) for other available API.

use std::sync::Arc;

use super::error;
use crate::job_queue::triton_vm::vm_job_queue;
use crate::models::blockchain::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::models::state::tx_creation_artifacts::TxCreationArtifacts;
use crate::models::state::wallet::change_policy::ChangePolicy;
use crate::models::state::StateLock;
use crate::tx_initiation::builder::transaction_builder::TransactionBuilder;
use crate::tx_initiation::builder::transaction_details_builder::TransactionDetailsBuilder;
use crate::tx_initiation::builder::transaction_proof_builder::TransactionProofBuilder;
use crate::tx_initiation::builder::tx_input_list_builder::InputSelectionPolicy;
use crate::tx_initiation::builder::tx_input_list_builder::TxInputListBuilder;
use crate::tx_initiation::builder::tx_output_list_builder::OutputFormat;
use crate::tx_initiation::builder::tx_output_list_builder::TxOutputListBuilder;
use crate::tx_initiation::export::TransactionProofType;
use crate::GlobalStateLock;

#[derive(Debug)]
pub struct TransactionSender {
    global_state_lock: GlobalStateLock,
}

impl TransactionSender {
    // this type should not be instantiated directly, but instead retrieved via
    // GlobalStateLock::tx_initiator()
    pub(crate) fn new(global_state_lock: GlobalStateLock) -> Self {
        Self { global_state_lock }
    }

    // caller should call offchain-notifications() on the returned value
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
        drop(state_lock); // release lock asap.

        tracing::info!("send: proving tx:\n{}", tx_details);

        let tx_details_rc = Arc::new(tx_details);

        // generate proof
        let proof = TransactionProofBuilder::new()
            .transaction_details(tx_details_rc.clone())
            .job_queue(vm_job_queue())
            .tx_proving_capability(gsl.cli().proving_capability())
            .proof_type(target_proof_type)
            .build()
            .await?;

        // assemble transaction
        let tx_creation_artifacts = TransactionBuilder::new()
            .transaction_details(tx_details_rc.clone())
            .transaction_proof(proof)
            .build(gsl.cli().network)?;

        tracing::info!("send: record and broadcast tx:\n{}", tx_details_rc);

        gsl.tx_initiator()
            .record_and_broadcast_transaction(&tx_creation_artifacts)
            .await?;

        Ok(tx_creation_artifacts)
    }

    fn private(&self) -> super::private::TransactionInitiatorPrivate {
        super::private::TransactionInitiatorPrivate::new(self.global_state_lock.clone())
    }
}
