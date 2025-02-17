//! provides an interface to transaction outputs and associated types

use std::ops::Deref;
use std::ops::DerefMut;

use itertools::Itertools;
use serde::Deserialize;
use serde::Serialize;

use super::utxo_notification::UtxoNotifyMethod;
use crate::config_models::network::Network;
use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::blockchain::transaction::PublicAnnouncement;
use crate::models::blockchain::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::models::state::wallet::address::ReceivingAddress;
use crate::models::state::wallet::utxo_notification::PrivateNotificationData;
use crate::models::state::wallet::utxo_notification::UtxoNotificationMedium;
use crate::models::state::wallet::utxo_notification::UtxoNotificationPayload;
use crate::models::state::wallet::wallet_state::WalletState;
use crate::prelude::twenty_first::math::digest::Digest;
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::commit;

/// represents a transaction output, as accepted by
/// [GlobalState::create_transaction()](crate::models::state::GlobalState::create_transaction())
///
/// Contains data that a UTXO recipient requires in order to be notified about
/// and claim a given UTXO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxOutput {
    utxo: Utxo,
    sender_randomness: Digest,
    receiver_digest: Digest,
    notification_method: UtxoNotifyMethod,

    /// Indicates if this client can unlock the UTXO
    owned: bool,
}

impl From<&TxOutput> for AdditionRecord {
    /// retrieves public announcements from possible sub-set of the list
    fn from(txo: &TxOutput) -> Self {
        commit(
            Hash::hash(&txo.utxo),
            txo.sender_randomness,
            txo.receiver_digest,
        )
    }
}

impl TxOutput {
    fn notification_payload(&self) -> UtxoNotificationPayload {
        UtxoNotificationPayload {
            utxo: self.utxo(),
            sender_randomness: self.sender_randomness(),
        }
    }

    /// automatically generates [TxOutput] using some heuristics
    ///
    /// If the [Utxo] cannot be claimed by our wallet then the specified
    /// notification for owned UTXOs is used, otherwise the specified
    /// notification medium for unowned UTXOs is used.
    pub fn auto(
        wallet_state: &WalletState,
        address: ReceivingAddress,
        amount: NativeCurrencyAmount,
        sender_randomness: Digest,
        owned_utxo_notify_medium: UtxoNotificationMedium,
        unowned_utxo_notify_medium: UtxoNotificationMedium,
    ) -> Self {
        let utxo = Utxo::new_native_currency(address.lock_script(), amount);

        let has_matching_spending_key = wallet_state.can_unlock(&utxo);

        let receiver_digest = address.privacy_digest();
        let notification_method = if has_matching_spending_key {
            match owned_utxo_notify_medium {
                UtxoNotificationMedium::OnChain => UtxoNotifyMethod::OnChain(address),
                UtxoNotificationMedium::OffChain => UtxoNotifyMethod::OffChain(address),
            }
        } else {
            match unowned_utxo_notify_medium {
                UtxoNotificationMedium::OnChain => UtxoNotifyMethod::OnChain(address),
                UtxoNotificationMedium::OffChain => UtxoNotifyMethod::OffChain(address),
            }
        };

        Self {
            utxo,
            sender_randomness,
            receiver_digest,
            notification_method,
            owned: has_matching_spending_key,
        }
    }

    /// Instantiaties [TxOutput] without any associated notification-info.
    ///
    /// Warning: If care is not taken, this is an easy way to lose funds.
    /// Don't use this constructor unless you have a good reason to.
    #[cfg(test)]
    pub(crate) fn no_notification(
        utxo: Utxo,
        sender_randomness: Digest,
        privacy_digest: Digest,
        owned: bool,
    ) -> Self {
        Self {
            utxo,
            sender_randomness,
            receiver_digest: privacy_digest,
            notification_method: UtxoNotifyMethod::None,
            owned,
        }
    }

    /// Instantiate a [TxOutput] for native currency intended fro on-chain UTXO
    /// notification.
    pub(crate) fn onchain_native_currency(
        amount: NativeCurrencyAmount,
        sender_randomness: Digest,
        receiving_address: ReceivingAddress,
        owned: bool,
    ) -> Self {
        let utxo = Utxo::new_native_currency(receiving_address.lock_script(), amount);
        Self {
            utxo,
            sender_randomness,
            receiver_digest: receiving_address.privacy_digest(),
            notification_method: UtxoNotifyMethod::OnChain(receiving_address),
            owned,
        }
    }

    /// Instantiate a [TxOutput] for native currency intended for off-chain UTXO
    /// notification.
    pub(crate) fn offchain_native_currency(
        amount: NativeCurrencyAmount,
        sender_randomness: Digest,
        receiving_address: ReceivingAddress,
        owned: bool,
    ) -> Self {
        let utxo = Utxo::new_native_currency(receiving_address.lock_script(), amount);
        Self {
            utxo,
            sender_randomness,
            receiver_digest: receiving_address.privacy_digest(),
            notification_method: UtxoNotifyMethod::OffChain(receiving_address),
            owned,
        }
    }

    pub(crate) fn is_offchain(&self) -> bool {
        matches!(self.notification_method, UtxoNotifyMethod::OffChain(_))
    }

    pub(crate) fn utxo(&self) -> Utxo {
        self.utxo.clone()
    }

    pub(crate) fn sender_randomness(&self) -> Digest {
        self.sender_randomness
    }

    pub(crate) fn receiver_digest(&self) -> Digest {
        self.receiver_digest
    }

    pub(crate) fn public_announcement(&self) -> Option<PublicAnnouncement> {
        match &self.notification_method {
            UtxoNotifyMethod::None => None,
            UtxoNotifyMethod::OffChain(_) => None,
            UtxoNotifyMethod::OnChain(receiving_address) => {
                let notification_payload = self.notification_payload();
                Some(receiving_address.generate_public_announcement(notification_payload))
            }
        }
    }

    pub(crate) fn private_notification(
        &self,
        network: Network,
    ) -> Option<(String, ReceivingAddress)> {
        match &self.notification_method {
            UtxoNotifyMethod::OnChain(_) => None,
            UtxoNotifyMethod::OffChain(receiving_address) => {
                let notification_payload = self.notification_payload();

                Some((
                    receiving_address.private_notification(notification_payload, network),
                    receiving_address.to_owned(),
                ))
            }
            UtxoNotifyMethod::None => None,
        }
    }

    /// Adds a time lock coin, if necessary.
    ///
    /// Does nothing if there already is a time lock coin whose release date is
    /// later than the argument.
    pub(crate) fn with_time_lock(self, release_date: Timestamp) -> Self {
        Self {
            utxo: self.utxo.with_time_lock(release_date),
            sender_randomness: self.sender_randomness,
            receiver_digest: self.receiver_digest,
            notification_method: self.notification_method,
            owned: self.owned,
        }
    }
}

/// Represents a list of [TxOutput]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TxOutputList(Vec<TxOutput>);

impl Deref for TxOutputList {
    type Target = Vec<TxOutput>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl IntoIterator for TxOutputList {
    type Item = TxOutput;

    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl DerefMut for TxOutputList {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<Vec<TxOutput>> for TxOutputList {
    fn from(v: Vec<TxOutput>) -> Self {
        Self(v)
    }
}

impl From<&TxOutputList> for Vec<AdditionRecord> {
    fn from(list: &TxOutputList) -> Self {
        list.addition_records_iter().into_iter().collect()
    }
}

impl From<&TxOutputList> for Vec<Utxo> {
    fn from(list: &TxOutputList) -> Self {
        list.utxos_iter().into_iter().collect()
    }
}

impl From<Option<TxOutput>> for TxOutputList {
    fn from(value: Option<TxOutput>) -> Self {
        value.into_iter().collect_vec().into()
    }
}

// Killed because: this mapping requires wallet info!
// impl From<&TxOutputList> for Vec<ExpectedUtxo> {
//     fn from(list: &TxOutputList) -> Self {
//         list.expected_utxos_iter().collect()
//     }
// }

// Killed because: this mapping requires recipient info!
// impl From<&TxOutputList> for Vec<PublicAnnouncement> {
//     fn from(list: &TxOutputList) -> Self {
//         list.public_announcements_iter().into_iter().collect()
//     }
// }

impl TxOutputList {
    /// calculates total amount in native currency
    pub fn total_native_coins(&self) -> NativeCurrencyAmount {
        self.0
            .iter()
            .map(|u| u.utxo.get_native_currency_amount())
            .sum()
    }

    /// retrieves utxos
    pub fn utxos_iter(&self) -> impl IntoIterator<Item = Utxo> + '_ {
        self.0.iter().map(|u| u.utxo.clone())
    }

    /// retrieves utxos
    pub fn utxos(&self) -> Vec<Utxo> {
        self.utxos_iter().into_iter().collect()
    }

    pub(crate) fn sender_randomnesses(&self) -> Vec<Digest> {
        self.iter().map(|x| x.sender_randomness()).collect()
    }

    pub(crate) fn receiver_digests(&self) -> Vec<Digest> {
        self.iter().map(|x| x.receiver_digest()).collect()
    }

    /// retrieves addition_records
    pub fn addition_records_iter(&self) -> impl IntoIterator<Item = AdditionRecord> + '_ {
        self.0.iter().map(|u| u.into())
    }

    /// retrieves addition_records
    pub fn addition_records(&self) -> Vec<AdditionRecord> {
        self.addition_records_iter().into_iter().collect()
    }

    /// Returns all public announcement for this TxOutputList
    pub(crate) fn public_announcements(&self) -> Vec<PublicAnnouncement> {
        let mut public_announcements = vec![];
        for tx_output in self.0.iter() {
            if let Some(pa) = tx_output.public_announcement() {
                public_announcements.push(pa);
            }
        }

        public_announcements
    }

    pub(crate) fn private_notifications(&self, network: Network) -> Vec<PrivateNotificationData> {
        let mut private_utxo_notifications = vec![];
        for tx_output in self.0.iter() {
            if let Some((ciphertext, receiver_address)) = tx_output.private_notification(network) {
                let notification_data = PrivateNotificationData {
                    cleartext: tx_output.notification_payload(),
                    ciphertext,
                    recipient_address: receiver_address,
                    owned: tx_output.owned,
                };
                private_utxo_notifications.push(notification_data)
            }
        }

        private_utxo_notifications
    }

    /// indicates if any offchain notifications exist
    pub fn has_offchain(&self) -> bool {
        self.0.iter().any(|u| u.is_offchain())
    }

    pub(crate) fn push(&mut self, tx_output: TxOutput) {
        self.0.push(tx_output);
    }

    pub(crate) fn concat_with<T>(mut self, maybe_tx_output: T) -> Self
    where
        T: IntoIterator<Item = TxOutput>,
    {
        self.0.extend(maybe_tx_output);
        self
    }
}

#[cfg(test)]
mod tests {
    use rand::Rng;

    use super::*;
    use crate::config_models::cli_args;
    use crate::config_models::network::Network;
    use crate::models::blockchain::transaction::utxo::Coin;
    use crate::models::blockchain::type_scripts::native_currency_amount::NativeCurrencyAmount;
    use crate::models::state::wallet::address::generation_address::GenerationReceivingAddress;
    use crate::models::state::wallet::address::KeyType;
    use crate::models::state::wallet::WalletSecret;
    use crate::tests::shared::mock_genesis_global_state;

    impl TxOutput {
        pub(crate) fn with_coin(self, coin: Coin) -> Self {
            Self {
                utxo: self.utxo.with_coin(coin),
                sender_randomness: self.sender_randomness,
                receiver_digest: self.receiver_digest,
                notification_method: self.notification_method,
                owned: self.owned,
            }
        }

        pub(crate) fn replace_utxo(self, utxo: Utxo) -> Self {
            Self {
                utxo,
                sender_randomness: self.sender_randomness,
                receiver_digest: self.receiver_digest,
                notification_method: self.notification_method,
                owned: self.owned,
            }
        }
    }

    #[tokio::test]
    async fn test_utxoreceiver_auto_not_owned_output() {
        let global_state_lock = mock_genesis_global_state(
            Network::RegTest,
            2,
            WalletSecret::devnet_wallet(),
            cli_args::Args::default(),
        )
        .await;

        let state = global_state_lock.lock_guard().await;
        let block_height = state.chain.light_state().header().height;

        // generate a new receiving address that is not from our wallet.
        let mut rng = rand::rng();
        let seed: Digest = rng.random();
        let address = GenerationReceivingAddress::derive_from_seed(seed);

        let amount = NativeCurrencyAmount::one();
        let utxo = Utxo::new_native_currency(address.lock_script(), amount);

        let sender_randomness = state
            .wallet_state
            .wallet_secret
            .generate_sender_randomness(block_height, address.privacy_digest());

        for owned_utxo_notification_medium in [
            UtxoNotificationMedium::OffChain,
            UtxoNotificationMedium::OnChain,
        ] {
            let tx_output = TxOutput::auto(
                &state.wallet_state,
                address.into(),
                amount,
                sender_randomness,
                owned_utxo_notification_medium, // how to notify utxos sent to myself.
                UtxoNotificationMedium::OnChain,
            );

            assert!(
                matches!(tx_output.notification_method, UtxoNotifyMethod::OnChain(_)),
                "Not owned UTXOs are, currently, always transmitted on-chain"
            );
            assert_eq!(tx_output.sender_randomness(), sender_randomness);
            assert_eq!(tx_output.receiver_digest(), address.privacy_digest());
            assert_eq!(tx_output.utxo(), utxo);
        }
    }

    #[tokio::test]
    async fn test_utxoreceiver_auto_owned_output() {
        let mut global_state_lock = mock_genesis_global_state(
            Network::RegTest,
            2,
            WalletSecret::devnet_wallet(),
            cli_args::Args::default(),
        )
        .await;

        // obtain next unused receiving address from our wallet.
        let spending_key_gen = global_state_lock
            .lock_guard_mut()
            .await
            .wallet_state
            .next_unused_spending_key(KeyType::Generation)
            .await
            .expect("wallet should be capable of generating a generation address spending key");
        let address_gen = spending_key_gen.to_address().unwrap();

        // obtain next unused symmetric address from our wallet.
        let spending_key_sym = global_state_lock
            .lock_guard_mut()
            .await
            .wallet_state
            .next_unused_spending_key(KeyType::Symmetric)
            .await
            .expect("wallet should be capable of generating a symmetric address spending key");
        let address_sym = spending_key_sym.to_address().unwrap();

        let state = global_state_lock.lock_guard().await;
        let block_height = state.chain.light_state().header().height;

        let amount = NativeCurrencyAmount::one();

        for (owned_utxo_notification_medium, address) in [
            (UtxoNotificationMedium::OffChain, address_gen.clone()),
            (UtxoNotificationMedium::OnChain, address_sym.clone()),
        ] {
            let utxo = Utxo::new_native_currency(address.lock_script(), amount);
            let sender_randomness = state
                .wallet_state
                .wallet_secret
                .generate_sender_randomness(block_height, address.privacy_digest());

            let tx_output = TxOutput::auto(
                &state.wallet_state,
                address.clone(),
                amount,
                sender_randomness,
                owned_utxo_notification_medium, // how to notify of utxos sent to myself
                UtxoNotificationMedium::OnChain,
            );

            match owned_utxo_notification_medium {
                UtxoNotificationMedium::OnChain => assert!(matches!(
                    tx_output.notification_method,
                    UtxoNotifyMethod::OnChain(_)
                )),
                UtxoNotificationMedium::OffChain => assert!(matches!(
                    tx_output.notification_method,
                    UtxoNotifyMethod::OffChain(_)
                )),
            };

            assert_eq!(sender_randomness, tx_output.sender_randomness());
            assert_eq!(
                address.lock_script().hash(),
                tx_output.utxo().lock_script_hash()
            );

            assert_eq!(tx_output.sender_randomness(), sender_randomness);
            assert_eq!(tx_output.receiver_digest(), address.privacy_digest());
            assert_eq!(tx_output.utxo(), utxo);
        }
    }
}
