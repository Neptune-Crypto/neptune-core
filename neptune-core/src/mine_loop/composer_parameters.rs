use tasm_lib::prelude::Digest;

use crate::config_models::fee_notification_policy::FeeNotificationPolicy;
use crate::models::state::wallet::address::ReceivingAddress;
use crate::models::state::wallet::expected_utxo::ExpectedUtxo;
use crate::models::state::wallet::expected_utxo::UtxoNotifier;
use crate::models::state::wallet::transaction_output::TxOutputList;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ComposerParameters {
    reward_address: ReceivingAddress,
    sender_randomness: Digest,
    maybe_receiver_preimage: Option<Digest>,
    guesser_fee_fraction: f64,
    notification_policy: FeeNotificationPolicy,
}

impl ComposerParameters {
    /// # Panics
    ///
    ///  - If `guesser_fee_fraction` is not a fraction contained in \[0;1\].
    pub(crate) fn new(
        reward_address: ReceivingAddress,
        sender_randomness: Digest,
        maybe_receiver_preimage: Option<Digest>,
        guesser_fee_fraction: f64,
        notification_policy: FeeNotificationPolicy,
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
            notification_policy,
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

    /// Convert the [`TxOutputList`] to a list of [`ExpectedUtxo`]s consistent
    /// with the composer parameters.
    ///
    /// # Panics
    ///
    /// Panics if the composer parameter's receiver preimage is set to something
    /// that does not match with some output's receiver digest.
    pub(crate) fn extract_expected_utxos(&self, composer_txos: TxOutputList) -> Vec<ExpectedUtxo> {
        // If composer UTXO notifications are sent onchain, the wallet does not need
        // to expect them. If they are handled offchain, the wallet must be
        // notified, but only if the receiver preimage is known (otherwise you
        // cannot expect them, as you can't generate the addition record).
        if self.notification_policy() != FeeNotificationPolicy::OffChain {
            return vec![];
        }

        let Some(receiver_preimage) = self.maybe_receiver_preimage() else {
            return vec![];
        };

        composer_txos.expected_utxos(UtxoNotifier::OwnMinerComposeBlock, receiver_preimage)
    }
}
