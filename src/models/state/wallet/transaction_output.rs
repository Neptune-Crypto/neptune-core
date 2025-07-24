//! provides an interface to transaction outputs and associated types

use std::ops::Deref;
use std::ops::DerefMut;

use serde::Deserialize;
use serde::Serialize;

use super::utxo_notification::UtxoNotifyMethod;
use crate::config_models::network::Network;
use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::transaction::public_announcement::PublicAnnouncement;
use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::blockchain::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::models::state::wallet::address::ReceivingAddress;
use crate::models::state::wallet::expected_utxo::ExpectedUtxo;
use crate::models::state::wallet::expected_utxo::UtxoNotifier;
use crate::models::state::wallet::utxo_notification::PrivateNotificationData;
use crate::models::state::wallet::utxo_notification::UtxoNotificationMedium;
use crate::models::state::wallet::utxo_notification::UtxoNotificationPayload;
use crate::models::state::wallet::wallet_state::WalletState;
use crate::prelude::twenty_first::prelude::Digest;
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::commit;

/// represents a transaction output, as used by
/// [TransactionDetailsBuilder](crate::api::tx_initiation::builder::transaction_details_builder::TransactionDetailsBuilder)
///
/// Contains data that a UTXO recipient requires in order to be notified about
/// and claim a given UTXO.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxOutput {
    utxo: Utxo,
    sender_randomness: Digest,
    receiver_digest: Digest,
    notification_method: UtxoNotifyMethod,

    /// Indicates if this client can unlock the UTXO
    owned: bool,
    is_change: bool,
}

// fix for issue #552.
//
// The TxOutput struct gets stored in the wallet database. (via
// SpentTransaction)  As such, any field changes must be versioned somehow.
//
// Going from v1 to v2 (of the struct), we want the new is_changed field to
// use the value of the owned field from v1.
//
// We create a TxOutputVersioned struct to represent the structs fields in
// different logical versions and instruct serde how to convert between the
// two.
//
// This provides DB migration/compat for DBs created with commits prior to
// 69e2867106fe727665fd74e21a0b3e309d160d5d and/or version 0.2.2.
//
// See:
//   https://github.com/Neptune-Crypto/neptune-core/issues/552
/*
mod fix_552 {
    use super::*;

    #[derive(Debug, Serialize, Deserialize)]
    pub(super) struct TxOutputVersioned {
        // these fields were in "v1".
        utxo: Utxo,
        sender_randomness: Digest,
        receiver_digest: Digest,
        notification_method: UtxoNotifyMethod,
        owned: bool,

        // this field is new in "v2".
        // skip field if non-existing and default to None.
        #[serde(skip, default)]
        is_change: Option<bool>,
    }

    impl From<TxOutputVersioned> for TxOutput {
        fn from(v1: TxOutputVersioned) -> Self {
            Self {
                utxo: v1.utxo,
                sender_randomness: v1.sender_randomness,
                receiver_digest: v1.receiver_digest,
                notification_method: v1.notification_method,
                owned: v1.owned,
                is_change: v1.is_change.unwrap_or(v1.owned), // default is_changed to owned (v1)
            }
        }
    }
}
*/

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
    // note: normally use one of the other constructors.
    pub(crate) fn new(
        utxo: Utxo,
        sender_randomness: Digest,
        receiver_digest: Digest,
        notification_method: UtxoNotifyMethod,
        owned: bool,
        is_change: bool,
    ) -> Self {
        Self {
            utxo,
            sender_randomness,
            receiver_digest,
            notification_method,
            owned,
            is_change,
        }
    }

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
    pub(crate) fn auto(
        wallet_state: &WalletState,
        address: ReceivingAddress,
        amount: NativeCurrencyAmount,
        sender_randomness: Digest,
        owned_utxo_notify_medium: UtxoNotificationMedium,
        unowned_utxo_notify_medium: UtxoNotificationMedium,
    ) -> Self {
        let utxo = Utxo::new_native_currency(address.lock_script(), amount);
        Self::auto_utxo_maybe_change(
            wallet_state,
            utxo,
            address,
            sender_randomness,
            owned_utxo_notify_medium,
            unowned_utxo_notify_medium,
            false, // is_change
        )
    }

    pub(crate) fn auto_utxo(
        wallet_state: &WalletState,
        utxo: Utxo,
        address: ReceivingAddress,
        sender_randomness: Digest,
        owned_utxo_notify_medium: UtxoNotificationMedium,
        unowned_utxo_notify_medium: UtxoNotificationMedium,
    ) -> Self {
        Self::auto_utxo_maybe_change(
            wallet_state,
            utxo,
            address,
            sender_randomness,
            owned_utxo_notify_medium,
            unowned_utxo_notify_medium,
            false, // is_change
        )
    }

    // private!
    fn auto_utxo_maybe_change(
        wallet_state: &WalletState,
        utxo: Utxo,
        address: ReceivingAddress,
        sender_randomness: Digest,
        owned_utxo_notify_medium: UtxoNotificationMedium,
        unowned_utxo_notify_medium: UtxoNotificationMedium,
        is_change: bool,
    ) -> Self {
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
            is_change,
        }
    }

    /// retrieve native currency amount
    pub fn native_currency_amount(&self) -> NativeCurrencyAmount {
        self.utxo.get_native_currency_amount()
    }

    /// Instantiates [TxOutput] without any associated notification-info.
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
            is_change: false,
        }
    }

    /// Instantiates [TxOutput] without any associated notification-info.
    ///
    /// Warning: If care is not taken, this is an easy way to lose funds.
    /// Don't use this constructor unless you have a good reason to.
    pub(crate) fn no_notification_as_change(
        utxo: Utxo,
        sender_randomness: Digest,
        privacy_digest: Digest,
    ) -> Self {
        Self {
            utxo,
            sender_randomness,
            receiver_digest: privacy_digest,
            notification_method: UtxoNotifyMethod::None,
            owned: true,
            is_change: true,
        }
    }

    /// Instantiate a [TxOutput] for any utxo intended for on-chain UTXO
    /// notification.
    pub(crate) fn onchain_utxo(
        utxo: Utxo,
        sender_randomness: Digest,
        receiving_address: ReceivingAddress,
        owned: bool,
    ) -> Self {
        Self {
            utxo,
            sender_randomness,
            receiver_digest: receiving_address.privacy_digest(),
            notification_method: UtxoNotifyMethod::OnChain(receiving_address),
            owned,
            is_change: false,
        }
    }

    /// Instantiate a [TxOutput] for any utxo intended for off-chain UTXO
    /// notification.
    pub(crate) fn offchain_utxo(
        utxo: Utxo,
        sender_randomness: Digest,
        receiving_address: ReceivingAddress,
        owned: bool,
    ) -> Self {
        Self {
            utxo,
            sender_randomness,
            receiver_digest: receiving_address.privacy_digest(),
            notification_method: UtxoNotifyMethod::OffChain(receiving_address),
            owned,
            is_change: false,
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
            is_change: false,
        }
    }

    /// Instantiate a [TxOutput] for native currency intended fro on-chain UTXO
    /// notification.
    pub(crate) fn onchain_native_currency_as_change(
        amount: NativeCurrencyAmount,
        sender_randomness: Digest,
        receiving_address: ReceivingAddress,
    ) -> Self {
        let utxo = Utxo::new_native_currency(receiving_address.lock_script(), amount);
        Self {
            utxo,
            sender_randomness,
            receiver_digest: receiving_address.privacy_digest(),
            notification_method: UtxoNotifyMethod::OnChain(receiving_address),
            owned: true,
            is_change: true,
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
        Self::native_currency(
            amount,
            sender_randomness,
            receiving_address,
            UtxoNotificationMedium::OffChain,
            owned,
        )
    }

    /// Instantiate a [TxOutput] for native currency.
    pub(crate) fn native_currency(
        amount: NativeCurrencyAmount,
        sender_randomness: Digest,
        receiving_address: ReceivingAddress,
        notification_medium: UtxoNotificationMedium,
        owned: bool,
    ) -> Self {
        let receiver_digest = receiving_address.privacy_digest();
        let utxo = Utxo::new_native_currency(receiving_address.lock_script(), amount);
        let notify_method = UtxoNotifyMethod::new(notification_medium, receiving_address);
        Self {
            utxo,
            sender_randomness,
            receiver_digest,
            notification_method: notify_method,
            owned,
            is_change: false,
        }
    }

    /// Instantiate a [TxOutput] for native currency intended for off-chain UTXO
    /// notification.
    pub(crate) fn offchain_native_currency_as_change(
        amount: NativeCurrencyAmount,
        sender_randomness: Digest,
        receiving_address: ReceivingAddress,
    ) -> Self {
        let utxo = Utxo::new_native_currency(receiving_address.lock_script(), amount);
        Self {
            utxo,
            sender_randomness,
            receiver_digest: receiving_address.privacy_digest(),
            notification_method: UtxoNotifyMethod::OffChain(receiving_address),
            owned: true,
            is_change: true,
        }
    }

    pub fn is_change(&self) -> bool {
        self.is_change
    }

    pub fn is_owned(&self) -> bool {
        self.owned
    }

    pub fn is_offchain(&self) -> bool {
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

    /// retrieve public announcement, if any
    pub fn public_announcement(&self) -> Option<PublicAnnouncement> {
        match &self.notification_method {
            UtxoNotifyMethod::None => None,
            UtxoNotifyMethod::OffChain(_) => None,
            UtxoNotifyMethod::OnChain(receiving_address) => {
                let notification_payload = self.notification_payload();
                Some(receiving_address.generate_public_announcement(notification_payload))
            }
        }
    }

    pub(crate) fn offchain_notification(
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
            is_change: self.is_change,
        }
    }

    /// Convert the [`TxOutput`] into an [`ExpectedUtxo`].
    ///
    /// Requires cryptographic data from the wallet.
    ///
    /// # Panics
    ///
    /// Panics if the receiver preimage does not match the receiver digest from
    /// the transaction output.
    fn expected_utxo(&self, receiver_preimage: Digest, notifier: UtxoNotifier) -> ExpectedUtxo {
        assert_eq!(
            self.receiver_digest,
            receiver_preimage.hash(),
            "Claimed receiver preimage must match transaction output"
        );
        let utxo = self.utxo();
        let sender_randomness = self.sender_randomness();
        ExpectedUtxo::new(utxo, sender_randomness, receiver_preimage, notifier)
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

impl DerefMut for TxOutputList {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
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

impl From<TxOutputList> for Vec<TxOutput> {
    fn from(list: TxOutputList) -> Self {
        list.0
    }
}

impl<I: Into<TxOutput>, T: IntoIterator<Item = I>> From<T> for TxOutputList {
    fn from(v: T) -> Self {
        Self(v.into_iter().map(|i| i.into()).collect())
    }
}

impl TxOutputList {
    /// calculates total amount in native currency, regardless of which other
    /// coins are present (even if that makes the native currency unspendable).
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
        for tx_output in &self.0 {
            if let Some(pa) = tx_output.public_announcement() {
                public_announcements.push(pa);
            }
        }

        public_announcements
    }

    pub fn offchain_notifications(
        &self,
        network: Network,
    ) -> impl Iterator<Item = PrivateNotificationData> + use<'_> {
        self.0.iter().filter_map(move |tx_output| {
            if let Some((ciphertext, receiver_address)) = tx_output.offchain_notification(network) {
                Some(PrivateNotificationData {
                    cleartext: tx_output.notification_payload(),
                    ciphertext,
                    recipient_address: receiver_address,
                    owned: tx_output.owned,
                })
            } else {
                None
            }
        })
    }

    pub fn owned_offchain_notifications(
        &self,
        network: Network,
    ) -> impl Iterator<Item = PrivateNotificationData> + use<'_> {
        self.offchain_notifications(network).filter(|n| n.owned)
    }

    pub fn unowned_offchain_notifications(
        &self,
        network: Network,
    ) -> impl Iterator<Item = PrivateNotificationData> + use<'_> {
        self.offchain_notifications(network).filter(|n| !n.owned)
    }

    /// indicates if any offchain notifications exist
    pub fn has_offchain(&self) -> bool {
        self.0.iter().any(|u| u.is_offchain())
    }

    pub(crate) fn push(&mut self, tx_output: TxOutput) {
        self.0.push(tx_output);
    }

    #[cfg(test)]
    pub(crate) fn concat_with<T>(mut self, maybe_tx_output: T) -> Self
    where
        T: IntoIterator<Item = TxOutput>,
    {
        self.0.extend(maybe_tx_output);
        self
    }

    /// Convert the [`TxOutputList`] to a list of [`ExpectedUtxo`]s.
    ///
    /// Useful in the context where all outputs in the [`TxOutputList`] are
    /// owned by the client's wallet.
    ///
    /// # Panics
    ///
    /// Panics if the receiver preimage does not match the receiver digest from
    /// any transaction output.
    pub(crate) fn expected_utxos(
        &self,
        utxo_notifier: UtxoNotifier,
        receiver_preimage: Digest,
    ) -> Vec<ExpectedUtxo> {
        self.iter()
            .map(|txo| txo.expected_utxo(receiver_preimage, utxo_notifier))
            .collect()
    }

    pub fn owned_iter(&self) -> impl Iterator<Item = &TxOutput> + '_ {
        self.0.iter().filter(|o| o.owned)
    }

    pub fn owned_amount(&self) -> NativeCurrencyAmount {
        self.owned_iter().map(|o| o.native_currency_amount()).sum()
    }

    pub fn has_owned_output(&self) -> bool {
        self.0.iter().any(|o| o.owned)
    }

    pub fn change_iter(&self) -> impl Iterator<Item = &TxOutput> + '_ {
        self.0.iter().filter(|o| o.is_change)
    }

    pub fn change_amount(&self) -> NativeCurrencyAmount {
        self.change_iter().map(|o| o.native_currency_amount()).sum()
    }

    pub fn has_change_output(&self) -> bool {
        self.0.iter().any(|o| o.is_change)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use macro_rules_attr::apply;
    use rand::Rng;

    use super::*;
    use crate::config_models::cli_args;
    use crate::config_models::network::Network;
    use crate::models::blockchain::transaction::utxo::Coin;
    use crate::models::blockchain::type_scripts::native_currency_amount::NativeCurrencyAmount;
    use crate::models::state::wallet::address::generation_address::GenerationReceivingAddress;
    use crate::models::state::wallet::address::KeyType;
    use crate::models::state::wallet::wallet_entropy::WalletEntropy;
    use crate::tests::shared::globalstate::mock_genesis_global_state;
    use crate::tests::shared_tokio_runtime;

    impl TxOutput {
        pub(crate) fn with_coin(self, coin: Coin) -> Self {
            Self {
                utxo: self.utxo.with_coin(coin),
                sender_randomness: self.sender_randomness,
                receiver_digest: self.receiver_digest,
                notification_method: self.notification_method,
                owned: self.owned,
                is_change: false,
            }
        }

        pub(crate) fn replace_utxo(self, utxo: Utxo) -> Self {
            Self {
                utxo,
                sender_randomness: self.sender_randomness,
                receiver_digest: self.receiver_digest,
                notification_method: self.notification_method,
                owned: self.owned,
                is_change: self.is_change,
            }
        }
    }

    #[test]
    fn iter_over_empty_tx_output_list_works() {
        let tx_output_list: TxOutputList = Vec::<TxOutput>::default().into();
        let mut as_iter = tx_output_list.iter();
        assert!(as_iter.next().is_none());
    }

    #[apply(shared_tokio_runtime)]
    async fn test_utxoreceiver_auto_not_owned_output() {
        let network = Network::RegTest;
        let global_state_lock = mock_genesis_global_state(
            2,
            WalletEntropy::devnet_wallet(),
            cli_args::Args::default_with_network(network),
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
            .wallet_entropy
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

    #[apply(shared_tokio_runtime)]
    async fn test_utxoreceiver_auto_owned_output() {
        let network = Network::RegTest;
        let mut global_state_lock = mock_genesis_global_state(
            2,
            WalletEntropy::devnet_wallet(),
            cli_args::Args::default_with_network(network),
        )
        .await;

        // obtain next unused receiving address from our wallet.
        let spending_key_gen = global_state_lock
            .lock_guard_mut()
            .await
            .wallet_state
            .next_unused_spending_key(KeyType::Generation)
            .await;
        let address_gen = spending_key_gen.to_address();

        // obtain next unused symmetric address from our wallet.
        let spending_key_sym = global_state_lock
            .lock_guard_mut()
            .await
            .wallet_state
            .next_unused_spending_key(KeyType::Symmetric)
            .await;
        let address_sym = spending_key_sym.to_address();

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
                .wallet_entropy
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
    /*
        #[apply(shared_tokio_runtime)]
        async fn test_tx_output_upgrade_serialization() {
            #[serde(Serialize)]
            struct TxOutputV1 {
                utxo: Utxo,
                sender_randomness: Digest,
                receiver_digest: Digest,
                notification_method: UtxoNotifyMethod,
                owned: bool,
            }

            let v1 = TxOutputV1 {
                utxo: Utxo::random(),
                sender_randomness: Digest::default(),
                receiver_digest: Digest::default(),
                notification_method: Default::default(),
                owned: true,
            };

            let serialized_v1 = bincode_serialize(&v1).unwrap();

            let v2 = bincode_deserialize(&serialized_v1).unwrap();

            assert_eq!(v2.is_change, v1.owned);

            let serialized_v2 = bincode_serialize(&v2).unwrap();
            let v2_again = bincode_deserialize(&serialized_v2).unwrap();

            assert_eq!(v2, v2_again);
        }
    */
}
