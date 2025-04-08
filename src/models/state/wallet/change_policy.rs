use std::fmt::Debug;
use std::sync::Arc;

use serde::Deserialize;
use serde::Serialize;

use super::address::KeyType;
use super::address::SpendingKey;
use super::utxo_notification::UtxoNotificationMedium;

/// specifies how to handle change for a transaction.
///
/// When the selected inputs represent more coins than the outputs (with fee)
/// where does this change go?
///
/// The default behavior is to recover to the next unused (symmetric) key with
/// onchain utxo notifications.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChangePolicy {
    /// Inputs must exactly equal spend amount, or else an error will result.
    ExactChange,

    /// recover change to the next unused key.
    ///
    /// (of specified key-type, via specified notification medium)
    RecoverToNextUnusedKey {
        key_type: KeyType,
        medium: UtxoNotificationMedium,
    },

    /// recover change to the provided key.
    ///
    /// (via specified notification medium)
    RecoverToProvidedKey {
        key: Arc<SpendingKey>,
        medium: UtxoNotificationMedium,
    },

    /// If the change is nonzero, the excess funds will be lost forever.
    Burn,
}

/// The default behavior is to recover to the next unused (symmetric) key with
/// onchain utxo notifications.
impl Default for ChangePolicy {
    fn default() -> Self {
        Self::recover_to_next_unused_symmetric_key_onchain()
    }
}

impl ChangePolicy {
    /// instantiate `ExactChange` variant
    pub fn exact_change() -> Self {
        Self::ExactChange
    }

    /// instantiate `RecoverToProvidedKey` variant
    ///
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

    /// instantiate `RecoverToNextUnusedKey` variant with symmetric key and onchain notification
    pub fn recover_to_next_unused_symmetric_key_onchain() -> Self {
        Self::recover_to_next_unused_key(KeyType::Symmetric, UtxoNotificationMedium::OnChain)
    }

    /// instantiate `RecoverToNextUnusedKey` variant with symmetric key and offchain notification
    pub fn recover_to_next_unused_symmetric_key_offchain() -> Self {
        Self::recover_to_next_unused_key(KeyType::Symmetric, UtxoNotificationMedium::OffChain)
    }

    /// instantiate `RecoverToNextUnusedKey` variant
    pub fn recover_to_next_unused_key(
        key_type: KeyType,
        notification_medium: UtxoNotificationMedium,
    ) -> Self {
        Self::RecoverToNextUnusedKey {
            key_type,
            medium: notification_medium,
        }
    }

    /// instantiate `Burn` variant
    pub fn burn() -> Self {
        Self::Burn
    }
}
