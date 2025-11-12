//! note; this module is only used by tests.
//!
//! it can be removed once tests are fully updated to
//! use tx_initiator APIs directly.
use std::fmt::Debug;
use std::sync::Arc;

use super::super::wallet::address::SpendingKey;
use super::super::wallet::change_policy::ChangePolicy;
use super::super::wallet::utxo_notification::UtxoNotificationMedium;
use super::tx_proving_capability::TxProvingCapability;
use crate::application::triton_vm_job_queue::vm_job_queue;
use crate::application::triton_vm_job_queue::TritonVmJobQueue;
use crate::protocol::proof_abstractions::tasm::program::TritonVmProofJobOptions;

/// Options and configuration settings for creating transactions
#[derive(Debug, Clone)]
pub(crate) struct TxCreationConfig {
    triton_vm_job_queue: Arc<TritonVmJobQueue>,
    proof_job_options: TritonVmProofJobOptions,
    change_policy: ChangePolicy,
}

impl Default for TxCreationConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl TxCreationConfig {
    pub fn new() -> Self {
        Self {
            triton_vm_job_queue: vm_job_queue(),
            proof_job_options: Default::default(),
            change_policy: Default::default(),
        }
    }

    pub fn recover_to_provided_key(
        mut self,
        change_key: Arc<SpendingKey>,
        notification_medium: UtxoNotificationMedium,
    ) -> Self {
        self.change_policy = ChangePolicy::recover_to_provided_key(change_key, notification_medium);
        self
    }

    /// Configure the proving capacity.
    pub(crate) fn with_prover_capability(mut self, prover_capability: TxProvingCapability) -> Self {
        // note: legacy tests consider prover_capability and target proof_type to be the same thing
        self.proof_job_options.job_settings.tx_proving_capability = prover_capability;
        self.proof_job_options.job_settings.proof_type = prover_capability.into();
        self
    }

    /// Configure which job queue to use.
    pub(crate) fn use_job_queue(mut self, job_queue: Arc<TritonVmJobQueue>) -> Self {
        self.triton_vm_job_queue = job_queue;
        self
    }

    /// Get the change key and notification medium, if any.
    pub(crate) fn change_policy(&self) -> ChangePolicy {
        self.change_policy.clone()
    }

    /// Get (a smart pointer to) the job queue
    pub(crate) fn job_queue(&self) -> Arc<TritonVmJobQueue> {
        self.triton_vm_job_queue.clone()
    }

    pub(crate) fn proof_job_options(&self) -> TritonVmProofJobOptions {
        self.proof_job_options.clone()
    }

    /// Enable change-recovery with the given key, and set the medium to
    /// `OnChain`.
    pub(crate) fn recover_change_on_chain(self, change_key: SpendingKey) -> Self {
        self.recover_to_provided_key(Arc::new(change_key), UtxoNotificationMedium::OnChain)
    }

    /// Enable change-recovery with the given key, and set the medium to
    /// `OffChain`.
    pub(crate) fn recover_change_off_chain(self, change_key: SpendingKey) -> Self {
        self.recover_to_provided_key(Arc::new(change_key), UtxoNotificationMedium::OffChain)
    }
}
