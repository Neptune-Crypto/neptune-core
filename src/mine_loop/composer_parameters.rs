use tasm_lib::prelude::Digest;

use crate::models::state::wallet::address::ReceivingAddress;
use crate::models::state::wallet::utxo_notification::UtxoNotificationMedium;

#[derive(Debug, Clone)]
pub(crate) struct ComposerParameters {
    reward_address: ReceivingAddress,
    sender_randomness: Digest,
    maybe_receiver_preimage: Option<Digest>,
    guesser_fee_fraction: f64,
    notification_medium: UtxoNotificationMedium,
}

impl ComposerParameters {
    pub(crate) fn new(
        reward_address: ReceivingAddress,
        sender_randomness: Digest,
        maybe_receiver_preimage: Option<Digest>,
        guesser_fee_fraction: f64,
        notification_medium: UtxoNotificationMedium,
    ) -> Self {
        let is_fraction = (0_f64..=1.0).contains(&guesser_fee_fraction);
        assert!(
            is_fraction,
            "Guesser fee fraction must be a fraction. Got: {guesser_fee_fraction}"
        );
        Self {
            reward_address,
            sender_randomness,
            maybe_receiver_preimage,
            guesser_fee_fraction,
            notification_medium,
        }
    }

    pub(crate) fn reward_address(&self) -> ReceivingAddress {
        self.reward_address.clone()
    }

    pub(crate) fn sender_randomness(&self) -> Digest {
        self.sender_randomness
    }

    pub(crate) fn maybe_receiver_preimage(&self) -> Option<Digest> {
        self.maybe_receiver_preimage
    }

    pub(crate) fn guesser_fee_fraction(&self) -> f64 {
        self.guesser_fee_fraction
    }

    pub(crate) fn notification_medium(&self) -> UtxoNotificationMedium {
        self.notification_medium
    }
}
