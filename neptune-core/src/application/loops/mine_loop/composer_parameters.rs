use num_traits::CheckedSub;
use num_traits::Zero;
use tasm_lib::prelude::Digest;

use crate::api::export::NativeCurrencyAmount;
use crate::api::export::Timestamp;
use crate::application::config::fee_notification_policy::FeeNotificationPolicy;
use crate::application::loops::mine_loop::coinbase_distribution::CoinbaseDistribution;
use crate::protocol::consensus::block::MINING_REWARD_TIME_LOCK_PERIOD;
use crate::state::wallet::expected_utxo::ExpectedUtxo;
use crate::state::wallet::expected_utxo::UtxoNotifier;
use crate::state::wallet::transaction_output::TxOutput;
use crate::state::wallet::transaction_output::TxOutputList;
use crate::state::wallet::utxo_notification::UtxoNotificationMedium;

#[derive(Debug, Clone)]
pub(crate) struct ComposerParameters {
    coinbase_distribution: CoinbaseDistribution,
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
        coinbase_distribution: CoinbaseDistribution,
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
            coinbase_distribution,
            sender_randomness,
            maybe_receiver_preimage,
            guesser_fee_fraction,
            notification_policy,
        }
    }

    /// Produce outputs spending a given portion of the coinbase amount,
    /// according to the specified coinbase distribution.
    ///
    /// The coinbase amount is usually set to the block subsidy for this block
    /// height.
    ///
    /// Will always produce outputs where at least half the amount is timelocked
    /// for 3 years, since this is dictated by the consensus rules. The portion
    /// of the entire block subsidy that goes to the composer is determined by
    /// the `guesser_fee_fraction` field of the composer parameters.
    ///
    /// The sum of the value of the outputs is guaranteed to not exceed the
    /// coinbase amount, since the guesser fee fraction is guaranteed to be in the
    /// range \[0;1\].
    ///
    /// Returns: Either the empty list, or n outputs according to the specified
    /// coinbase distribution.
    ///
    /// # Panics
    ///
    /// If the provided guesser fee fraction is not between 0 and 1 (inclusive).
    pub(crate) fn tx_outputs(
        &self,
        coinbase_amount: NativeCurrencyAmount,
        timestamp: Timestamp,
    ) -> TxOutputList {
        let guesser_fee = coinbase_amount.lossy_f64_fraction_mul(self.guesser_fee_fraction);

        let total_composer_amount = coinbase_amount
            .checked_sub(&guesser_fee)
            .expect("total_composer_fee cannot exceed coinbase_amount");

        if total_composer_amount.is_zero() {
            return Vec::<TxOutput>::default().into();
        }

        let sender_randomness = self.sender_randomness;
        let notification_medium: UtxoNotificationMedium = self.notification_policy.into();
        let owned = true;
        let mut ret = vec![];
        let mut distributed = NativeCurrencyAmount::zero();
        for coinbase_output in self.coinbase_distribution.iter() {
            let amount = total_composer_amount
                .scalar_mul(coinbase_output.fraction_in_promille())
                .to_nau()
                / 1000i128;
            let amount = NativeCurrencyAmount::from_nau(amount);
            distributed += amount;
            let mut tx_output = TxOutput::native_currency(
                amount,
                sender_randomness,
                coinbase_output.recipient().to_owned(),
                notification_medium,
                owned,
            );

            if coinbase_output.is_timelocked() {
                let small_delta = Timestamp::minutes(30);
                let release_date = timestamp + MINING_REWARD_TIME_LOCK_PERIOD + small_delta;
                tx_output = tx_output.with_time_lock(release_date);
            }

            ret.push(tx_output);
        }

        // Correct any rounding errors that may have resulted from the use
        // of fractions. Do so in a consensus-compatible way guaranteeing that
        // the timelocked amount is greater than or equal to liquid amount.
        if distributed < total_composer_amount {
            // Add correction to timelocked output
            let correction = total_composer_amount.checked_sub(&distributed).unwrap();
            let first_timelocked = ret
                .iter_mut()
                .find(|x| x.is_timelocked())
                .expect("Must have at least one timelocked output");
            *first_timelocked = first_timelocked.clone().add_to_amount(correction);
        } else {
            // Subtract correction from liquid output
            let correction = distributed.checked_sub(&total_composer_amount).unwrap();
            let first_liquid = ret
                .iter_mut()
                .find(|x| !x.is_timelocked())
                .expect("Must have at least one liquid output");
            *first_liquid = first_liquid.clone().add_to_amount(-correction);
        };

        ret.into()
    }

    /// Get the receiver preimage, if it is stored; and `None` otherwise.
    ///
    /// Note that the receiver preimage is not known in a *cold composing*
    /// scenario, where the composer fee UTXOs are sent to a foreign
    /// [`crate::state::wallet::address::ReceivingAddress`].
    pub(crate) fn maybe_receiver_preimage(&self) -> Option<Digest> {
        self.maybe_receiver_preimage
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
