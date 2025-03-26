use std::fmt::Debug;
use std::sync::Arc;

use serde::Deserialize;
use serde::Serialize;

use super::address::KeyType;
use super::address::SpendingKey;
use super::utxo_notification::UtxoNotificationMedium;

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
