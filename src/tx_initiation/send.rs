//! This is the start of an API layer for creating and sending transactions.  It
//! is callable by rust users of this crate as well as the RPC server.
//!
//! The intent is to present the same API for both rust callers and RPC callers.

use super::error;
use crate::job_queue::triton_vm::vm_job_queue;
use crate::models::blockchain::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::models::state::tx_creation_artifacts::TxCreationArtifacts;
use crate::models::state::tx_creation_config::ChangePolicy;
use crate::models::state::tx_creation_config::TxCreationConfig;
use crate::models::state::tx_proving_capability::TxProvingCapability;
use crate::tx_initiation::builder::tx_output_list_builder::OutputFormat;
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
        outputs: impl IntoIterator<Item = OutputFormat>,
        change_policy: ChangePolicy,
        fee: NativeCurrencyAmount,
        now: Timestamp,
    ) -> Result<TxCreationArtifacts, error::SendError> {
        let mut initiator = self.global_state_lock.tx_initiator();
        let mut initiator_internal = self.global_state_lock.tx_initiator_internal();
        let initiator_private = self.private();

        initiator_private.check_proceed_with_send(fee).await?;

        tracing::debug!("tx send initiated.");

        // The proving capability is set to the lowest possible value here,
        // since we don't want the client (CLI or dashboard) to hang while
        // producing proofs. Instead, we let (a task started by) main loop
        // handle the proving.
        let tx_proving_capability = TxProvingCapability::PrimitiveWitness;

        let tx_outputs = initiator.generate_tx_outputs(outputs).await;

        tracing::debug!(
            "send: generated outputs.  spend amount = {}",
            tx_outputs.total_native_coins()
        );

        // Create the transaction
        //
        // note: A change output will be added to tx_outputs if needed.
        //
        // create_transaction() modifies state only if a new-receiving address
        // is required for a change output.  It also calls prove() which is a
        // very lengthy operation.
        let config = TxCreationConfig::default()
            .use_change_policy(change_policy)
            .with_prover_capability(tx_proving_capability)
            .use_job_queue(vm_job_queue());

        let tx_artifacts = initiator_internal
            .create_transaction(tx_outputs, fee, now, config)
            .await
            .map_err(|e| {
                tracing::error!("Could not create transaction: {}", e);
                e
            })?;

        tracing::info!("send: record and broadcast tx:\n{}", tx_artifacts.details);

        initiator
            .record_and_broadcast_transaction(&tx_artifacts)
            .await?;

        Ok(tx_artifacts)
    }

    fn private(&self) -> super::private::TransactionInitiatorPrivate {
        super::private::TransactionInitiatorPrivate::new(self.global_state_lock.clone())
    }
}
