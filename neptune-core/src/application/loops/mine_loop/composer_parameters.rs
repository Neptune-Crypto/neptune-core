use neptune_consensus::block::MINING_REWARD_TIME_LOCK_PERIOD;
use neptune_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use neptune_primitives::timestamp::Timestamp;
use neptune_wallet::expected_utxo::ExpectedUtxo;
use neptune_wallet::expected_utxo::UtxoNotifier;
use neptune_wallet::transaction_output::TxOutput;
use neptune_wallet::transaction_output::TxOutputList;
use neptune_wallet::utxo_notification::UtxoNotificationMedium;
use num_traits::CheckedSub;
use num_traits::Zero;
use tasm_lib::prelude::Digest;

use crate::application::config::fee_notification_policy::FeeNotificationPolicy;
use crate::application::loops::mine_loop::coinbase_distribution::CoinbaseDistribution;

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
        let owned = self.maybe_receiver_preimage.is_some();
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
    /// [`neptune_wallet::address::ReceivingAddress`].
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

#[cfg(test)]
mod tests {
    use neptune_consensus::block::INITIAL_BLOCK_SUBSIDY;
    use neptune_primitives::block_height::BlockHeight;
    use neptune_primitives::network::Network;
    use neptune_wallet::address::ReceivingAddress;
    use neptune_wallet::wallet_entropy::WalletEntropy;

    use super::*;
    use crate::application::config::cli_args;
    use crate::tests::shared::globalstate::mock_genesis_global_state;
    use crate::tests::shared::mock_genesis_wallet_state;

    #[tokio::test]
    async fn dynamic_overriding_trumps_cli_override() {
        let network = Network::Main;
        let devnet_wallet = WalletEntropy::devnet_wallet();
        let another_wallet = WalletEntropy::new_random();
        let third_wallet = WalletEntropy::new_random();

        let cli_override = cli_args::Args {
            network,
            guesser_fraction: 0.4,
            mining_address: Some(
                third_wallet
                    .composer_fee_key()
                    .to_address()
                    .to_bech32m(network)
                    .unwrap(),
            ),
            ..Default::default()
        };
        let mut dynamic_override =
            mock_genesis_global_state(0, devnet_wallet.clone(), cli_override).await;
        let mut dynamic_override = dynamic_override.lock_guard_mut().await;

        let composition_receiver: ReceivingAddress = another_wallet
            .nth_generation_spending_key(0)
            .to_address()
            .into();
        let overridden_cb_distribution = CoinbaseDistribution::solo(composition_receiver.clone());

        let now = Timestamp::now();
        let coinbase_amount = INITIAL_BLOCK_SUBSIDY;
        let next_height = BlockHeight::genesis().next();
        dynamic_override
            .mining_state
            .set_coinbase_distribution(overridden_cb_distribution);
        let dynamic_overriden_composer_outputs = dynamic_override
            .composer_parameters(next_height)
            .tx_outputs(coinbase_amount, now);

        let another_wallet = mock_genesis_wallet_state(
            another_wallet,
            &cli_args::Args::default_with_network(network),
        )
        .await;
        let third_wallet =
            mock_genesis_wallet_state(third_wallet, &cli_args::Args::default_with_network(network))
                .await;
        for output in dynamic_overriden_composer_outputs.iter() {
            assert!(
                another_wallet.can_unlock(&output.utxo()),
                "Dynamic mining recipient must be able to spend composer reward."
            );
            assert!(
                !third_wallet.can_unlock(&output.utxo()),
                "Mining address set in CLI argument must be overridden by dynamic override."
            );
            assert!(
                !dynamic_override.wallet_state.can_unlock(&output.utxo()),
                "Wallet may not be able to spend composition rewards when composer distribution is overridden."
            );
            assert_eq!(
                composition_receiver.privacy_digest(),
                output.receiver_digest(),
                "Receiver digest of composer output must match that from overridden mining address"
            );
        }
    }

    #[tokio::test]
    async fn composer_parameters_respect_cli_flag_overriding() {
        let network = Network::Main;
        let devnet_wallet = WalletEntropy::devnet_wallet();

        // No override
        let no_override = cli_args::Args {
            network,
            guesser_fraction: 0.4,
            ..Default::default()
        };
        let no_override = mock_genesis_global_state(0, devnet_wallet.clone(), no_override).await;
        let no_override = no_override.lock_guard().await;

        let now = Timestamp::now();
        let coinbase_amount = INITIAL_BLOCK_SUBSIDY;
        let next_height = BlockHeight::genesis().next();

        let no_override_composer_outputs = no_override
            .composer_parameters(next_height)
            .tx_outputs(coinbase_amount, now);
        assert_eq!(
            2,
            no_override_composer_outputs.len(),
            "Default parameters must produce exactly two coinbase outputs"
        );

        for output in no_override_composer_outputs.iter() {
            assert!(
                no_override.wallet_state.can_unlock(&output.utxo()),
                "Wallet must be able to spend composition rewards when explicit mining address is not set."
            );
        }

        // CLI flag override
        let another_wallet = WalletEntropy::new_random();
        let mining_address: ReceivingAddress = another_wallet
            .nth_generation_spending_key(0)
            .to_address()
            .into();
        let another_wallet = mock_genesis_wallet_state(
            another_wallet,
            &cli_args::Args::default_with_network(network),
        )
        .await;
        let cli_override = cli_args::Args {
            network,
            guesser_fraction: 0.4,
            mining_address: Some(mining_address.to_display_bech32m(network).unwrap()),
            ..Default::default()
        };

        let cli_override = mock_genesis_global_state(0, devnet_wallet.clone(), cli_override).await;
        let cli_override = cli_override.lock_guard().await;
        let cli_override_composer_outputs = cli_override
            .composer_parameters(next_height)
            .tx_outputs(coinbase_amount, now);

        for output in cli_override_composer_outputs.iter() {
            assert!(
                another_wallet.can_unlock(&output.utxo()),
                "Mining recipient must be able to unlock composer reward."
            );
            assert!(
                !cli_override.wallet_state.can_unlock(&output.utxo()),
                "Wallet may not be able to spend composition rewards when mining reward address is overridden through a CLI flag."
            );
            assert_eq!(
                mining_address.privacy_digest(),
                output.receiver_digest(),
                "Receiver digest of composer output must match that from overridden mining address"
            );
        }
    }
}
