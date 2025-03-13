use std::fmt::Debug;
use std::sync::Arc;

use super::tx_proving_capability::TxProvingCapability;
use super::wallet::address::SpendingKey;
use super::wallet::utxo_notification::UtxoNotificationMedium;
use crate::job_queue::triton_vm::TritonVmJobQueue;
use crate::models::proof_abstractions::tasm::program::TritonVmProofJobOptions;

#[derive(Debug, Clone)]
pub(crate) struct ChangeKeyAndMedium {
    pub(crate) key: SpendingKey,
    pub(crate) medium: UtxoNotificationMedium,
}

/// When the selected inputs represent more coins than the outputs (with fee)
/// where does this change go?
#[derive(Debug, Clone, Default)]
pub(crate) enum ChangePolicy {
    /// If the change is nonzero, crash the transaction creator.
    #[default]
    None,

    /// If the change is nonzero, create a new UTXO spendable by this key and
    /// via this notification medium. Otherwise, do not create a change output.
    Recover(Box<ChangeKeyAndMedium>),

    /// If the change is nonzero, ignore it.
    #[cfg(test)]
    Burn,
}

/// Options and configuration settings for creating transactions
#[derive(Debug, Clone, Default)]
pub(crate) struct TxCreationConfig {
    change_policy: ChangePolicy,
    prover_capability: TxProvingCapability,
    triton_vm_job_queue: Option<Arc<TritonVmJobQueue>>,
    record_details: bool,
    proof_job_options: TritonVmProofJobOptions,
}

impl TxCreationConfig {
    /// Enable change-recovery and configure which key and notification medium
    /// to use for that purpose.
    pub(crate) fn recover_change(
        mut self,
        change_key: SpendingKey,
        notification_medium: UtxoNotificationMedium,
    ) -> Self {
        let change_key_and_medium = ChangeKeyAndMedium {
            key: change_key,
            medium: notification_medium,
        };
        self.change_policy = ChangePolicy::Recover(Box::new(change_key_and_medium));
        self
    }

    /// Enable change-recovery with the given key, and set the medium to
    /// `OnChain`.
    #[cfg(test)]
    pub(crate) fn recover_change_on_chain(self, change_key: SpendingKey) -> Self {
        self.recover_change(change_key, UtxoNotificationMedium::OnChain)
    }

    /// Enable change-recovery with the given key, and set the medium to
    /// `OffChain`.
    #[cfg(test)]
    pub(crate) fn recover_change_off_chain(self, change_key: SpendingKey) -> Self {
        self.recover_change(change_key, UtxoNotificationMedium::OffChain)
    }

    /// Burn the change.
    ///
    /// Only use this if you are certain you know what you are doing. Will
    /// result in loss-of-funds if the transaction is not balanced.
    #[cfg(test)]
    pub(crate) fn burn_change(mut self) -> Self {
        self.change_policy = ChangePolicy::Burn;
        self
    }

    /// Configure the proving capacity.
    pub(crate) fn with_prover_capability(mut self, prover_capability: TxProvingCapability) -> Self {
        self.prover_capability = prover_capability;
        self
    }

    /// Configure which job queue to use.
    pub(crate) fn use_job_queue(mut self, job_queue: Arc<TritonVmJobQueue>) -> Self {
        self.triton_vm_job_queue = Some(job_queue);
        self
    }

    /// Produce a [`TransactionDetails`] object along with the other artifacts.
    pub(crate) fn record_details(mut self) -> Self {
        self.record_details = true;
        self
    }

    /// Set the proof job options.
    ///
    /// By default, this field assumes the value determined by
    /// `TritonVmProofJobOptions::default()`.
    pub(crate) fn with_proof_job_options(
        mut self,
        proof_job_options: TritonVmProofJobOptions,
    ) -> Self {
        self.proof_job_options = proof_job_options;
        self
    }

    /// Determine whether a [`TransactionDetails`] object should be produced.
    pub(crate) fn details_are_recorded(&self) -> bool {
        self.record_details
    }

    /// Get the change key and notification medium, if any.
    pub(crate) fn change_policy(&self) -> ChangePolicy {
        self.change_policy.clone()
    }

    /// Get the transaction proving capability.
    pub(crate) fn prover_capability(&self) -> TxProvingCapability {
        self.prover_capability
    }

    /// Get the job queue, if set.
    pub(crate) fn job_queue(&self) -> Arc<TritonVmJobQueue> {
        self.triton_vm_job_queue
            .as_ref()
            .cloned()
            .unwrap_or_else(|| Arc::new(TritonVmJobQueue::start()))
    }

    pub(crate) fn proof_job_options(&self) -> TritonVmProofJobOptions {
        self.proof_job_options.clone()
    }
}
