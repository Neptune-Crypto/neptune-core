use tasm_lib::prelude::Digest;

use crate::config_models::fee_notification_policy::FeeNotificationPolicy;
use crate::models::state::wallet::address::ReceivingAddress;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ComposerParameters {
    reward_address: ReceivingAddress,
    sender_randomness: Digest,
    maybe_receiver_preimage: Option<Digest>,
    guesser_fee_fraction: f64,
    notification_policy: FeeNotificationPolicy,
}

impl Eq for ComposerParameters {}

impl ComposerParameters {
    pub(crate) fn new(
        reward_address: ReceivingAddress,
        sender_randomness: Digest,
        maybe_receiver_preimage: Option<Digest>,
        guesser_fee_fraction: f64,
        notification_medium: FeeNotificationPolicy,
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
            notification_policy: notification_medium,
        }
    }

    pub(crate) fn reward_address(&self) -> ReceivingAddress {
        self.reward_address.clone()
    }

    pub(crate) fn sender_randomness(&self) -> Digest {
        self.sender_randomness
    }

    /// Get the receiver preimage, if it is stored; and `None` otherwise.
    ///
    /// Note that the receiver preimage is not known in a *cold composing*
    /// scenario, where the composer fee UTXOs are sent to a foreign
    /// [`ReceivingAddress`].
    pub(crate) fn maybe_receiver_preimage(&self) -> Option<Digest> {
        self.maybe_receiver_preimage
    }

    pub(crate) fn guesser_fee_fraction(&self) -> f64 {
        self.guesser_fee_fraction
    }

    pub(crate) fn notification_policy(&self) -> FeeNotificationPolicy {
        self.notification_policy
    }
}
