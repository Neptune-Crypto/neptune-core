use std::fmt::Debug;
use std::sync::Arc;

use serde::Deserialize;
use serde::Serialize;

use super::tx_proving_capability::TxProvingCapability;
use super::wallet::address::SpendingKey;
use super::wallet::utxo_notification::UtxoNotificationMedium;
use crate::job_queue::triton_vm::vm_job_queue;
use crate::job_queue::triton_vm::TritonVmJobQueue;
use crate::models::proof_abstractions::tasm::program::TritonVmProofJobOptions;
use crate::models::state::wallet::address::KeyType;

/// When the selected inputs represent more coins than the outputs (with fee)
/// where does this change go?
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub enum ChangePolicy {
    /// Inputs must exactly equal spend amount, or else an error will result.
    #[default]
    ExactChange,

    RecoverToNextUnusedKey {
        key_type: KeyType,
        medium: UtxoNotificationMedium,
    },

    RecoverToProvidedKey {
        key: Arc<SpendingKey>,
        medium: UtxoNotificationMedium,
    },

    /// If the change is nonzero, the excess funds will be lost forever.
    Burn,
}
impl ChangePolicy {
    pub fn exact_change() -> Self {
        Self::ExactChange
    }

    /// Enable change-recovery and configure which key and notification medium
    /// to use for that purpose.
    pub fn recover_to_provided_key(
        change_key: Arc<SpendingKey>,
        notification_medium: UtxoNotificationMedium,
    ) -> Self {
        Self::RecoverToProvidedKey {
            key: change_key,
            medium: notification_medium,
        }
    }

    pub fn recover_to_next_unused_key(
        key_type: KeyType,
        notification_medium: UtxoNotificationMedium,
    ) -> Self {
        Self::RecoverToNextUnusedKey {
            key_type,
            medium: notification_medium,
        }
    }

    pub fn burn() -> Self {
        Self::Burn
    }
}

/// Options and configuration settings for creating transactions
#[derive(Debug, Clone)]
pub(crate) struct TxCreationConfig {
    prover_capability: TxProvingCapability,
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
            prover_capability: Default::default(),
            proof_job_options: Default::default(),
            change_policy: Default::default(),
        }
    }

    pub fn use_change_policy(mut self, change_policy: ChangePolicy) -> Self {
        self.change_policy = change_policy;
        self
    }

    pub fn exact_change(mut self) -> Self {
        self.change_policy = ChangePolicy::ExactChange;
        self
    }

    #[cfg(test)]
    pub fn recover_to_provided_key(
        mut self,
        change_key: Arc<SpendingKey>,
        notification_medium: UtxoNotificationMedium,
    ) -> Self {
        self.change_policy = ChangePolicy::recover_to_provided_key(change_key, notification_medium);
        self
    }

    // pub fn recover_to_next_unused_key(
    //     mut self,
    //     key_type: KeyType,
    //     notification_medium: UtxoNotificationMedium,
    // ) -> Self {
    //     self.change_policy =
    //         ChangePolicy::recover_to_next_unused_key(key_type, notification_medium);
    //     self
    // }

    // pub fn burn_change(mut self) -> Self {
    //     self.change_policy = ChangePolicy::Burn;
    //     self
    // }

    /// Configure the proving capacity.
    pub(crate) fn with_prover_capability(mut self, prover_capability: TxProvingCapability) -> Self {
        self.prover_capability = prover_capability;
        self
    }

    /// Configure which job queue to use.
    pub(crate) fn use_job_queue(mut self, job_queue: Arc<TritonVmJobQueue>) -> Self {
        self.triton_vm_job_queue = job_queue;
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

    /// Get the change key and notification medium, if any.
    pub(crate) fn change_policy(&self) -> ChangePolicy {
        self.change_policy.clone()
    }

    /// Get the transaction proving capability.
    pub(crate) fn prover_capability(&self) -> TxProvingCapability {
        self.prover_capability
    }

    /// Get (a smart pointer to) the job queue
    pub(crate) fn job_queue(&self) -> Arc<TritonVmJobQueue> {
        self.triton_vm_job_queue.clone()
    }

    pub(crate) fn proof_job_options(&self) -> TritonVmProofJobOptions {
        self.proof_job_options.clone()
    }
}

#[cfg(test)]
pub(crate) mod text {
    use super::*;

    impl TxCreationConfig {
        /// Enable change-recovery with the given key, and set the medium to
        /// `OnChain`.
        #[cfg(test)]
        pub(crate) fn recover_change_on_chain(self, change_key: SpendingKey) -> Self {
            self.recover_to_provided_key(Arc::new(change_key), UtxoNotificationMedium::OnChain)
        }

        /// Enable change-recovery with the given key, and set the medium to
        /// `OffChain`.
        #[cfg(test)]
        pub(crate) fn recover_change_off_chain(self, change_key: SpendingKey) -> Self {
            self.recover_to_provided_key(Arc::new(change_key), UtxoNotificationMedium::OffChain)
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
    }
}
