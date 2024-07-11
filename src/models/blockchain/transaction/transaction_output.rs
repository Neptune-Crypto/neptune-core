use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::blockchain::transaction::PublicAnnouncement;
use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
use crate::models::state::wallet::address::ReceivingAddressType;
use crate::models::state::wallet::utxo_notification_pool::ExpectedUtxo;
use crate::models::state::wallet::utxo_notification_pool::UtxoNotifier;
use crate::models::state::wallet::wallet_state::WalletState;
use crate::prelude::twenty_first::math::digest::Digest;
use crate::prelude::twenty_first::util_types::algebraic_hasher::AlgebraicHasher;
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::commit;
use anyhow::Result;
use std::ops::Deref;
use std::ops::DerefMut;

/// enumerates how a transaction recipient should be notified
/// that a Utxo exists which they can claim/spend.
///
/// see also: [UtxoNotification]
#[derive(Debug, Clone)]
pub enum UtxoNotifyMethod {
    OnChainPubKey,
    OnChainSymmetricKey,
    OffChain,
}

/// enumerates transaction notifications.
///
/// This mirrors variants in [`UtxoNotifyMethod`] but also holds notification
/// data.
#[derive(Debug, Clone)]
pub enum UtxoNotification {
    OnChainPubKey(PublicAnnouncement),
    OnChainSymmetricKey(PublicAnnouncement),
    OffChain(Box<ExpectedUtxo>),
}

/// represents a transaction output, as accepted by
/// `GlobalState::create_transaction()`
///
/// Contains data that a UTXO recipient requires in order to be notified about
/// and claim a given UTXO
#[derive(Debug, Clone)]
pub struct TxOutput {
    pub utxo: Utxo,
    pub sender_randomness: Digest,
    pub receiver_privacy_digest: Digest,
    pub utxo_notification: UtxoNotification,
}

impl From<ExpectedUtxo> for TxOutput {
    fn from(expected_utxo: ExpectedUtxo) -> Self {
        Self {
            utxo: expected_utxo.utxo.clone(),
            sender_randomness: expected_utxo.sender_randomness,
            receiver_privacy_digest: expected_utxo.receiver_preimage.hash::<Hash>(),
            utxo_notification: UtxoNotification::OffChain(Box::new(expected_utxo)),
        }
    }
}

impl From<&TxOutput> for AdditionRecord {
    /// retrieves public announcements from possible sub-set of the list
    fn from(ur: &TxOutput) -> Self {
        commit(
            Hash::hash(&ur.utxo),
            ur.sender_randomness,
            ur.receiver_privacy_digest,
        )
    }
}

impl TxOutput {
    /// automatically generates `TxOutput` from address and amount.
    ///
    /// If the `Utxo` can be claimed by our wallet then private OffChain
    /// notification will be used.  Else `OnChain` notification.
    ///
    /// This method should normally be used when instantiating `TxOutput`
    ///
    /// note: in the future, OnChainSymmetric may be preferred instead of
    /// OffChain for `Utxo` that can be claimed by our wallet.
    pub fn auto(
        wallet_state: &WalletState,
        address: &ReceivingAddressType,
        amount: NeptuneCoins,
        sender_randomness: Digest,
    ) -> Result<Self> {
        let utxo = Utxo::new_native_coin(address.lock_script(), amount);

        Ok(match wallet_state.find_spending_key_for_utxo(&utxo) {
            Some(key) => Self::offchain(utxo, sender_randomness, key.privacy_preimage()),
            None => {
                let pub_ann = address.generate_public_announcement(&utxo, sender_randomness)?;
                Self::onchain_pubkey(utxo, sender_randomness, address.privacy_digest(), pub_ann)
            }
        })
    }

    /// instantiates `TxOutput` using OnChainPubKey notification method.
    ///
    /// For normal situations, auto() should be used instead.
    pub fn onchain_pubkey(
        utxo: Utxo,
        sender_randomness: Digest,
        receiver_privacy_digest: Digest,
        public_announcement: PublicAnnouncement,
    ) -> Self {
        Self {
            utxo,
            sender_randomness,
            receiver_privacy_digest,
            utxo_notification: UtxoNotification::OnChainPubKey(public_announcement),
        }
    }

    /// instantiates `TxOutput` using OnChainSymmetricKey notification method.
    ///
    /// For normal situations, auto() should be used instead.
    pub fn onchain_symkey(
        utxo: Utxo,
        sender_randomness: Digest,
        receiver_privacy_digest: Digest,
        public_announcement: PublicAnnouncement,
    ) -> Self {
        Self {
            utxo,
            sender_randomness,
            receiver_privacy_digest,
            utxo_notification: UtxoNotification::OnChainSymmetricKey(public_announcement),
        }
    }

    /// instantiates `TxOutput` using OffChain notification method.
    ///
    /// For normal situations, auto() should be used instead.
    pub fn offchain(
        utxo: Utxo,
        sender_randomness: Digest,
        receiver_privacy_preimage: Digest,
    ) -> Self {
        ExpectedUtxo::new(
            utxo,
            sender_randomness,
            receiver_privacy_preimage,
            UtxoNotifier::Myself,
        )
        .into()
    }

    // only for tests
    #[cfg(test)]
    pub fn fake_announcement(
        utxo: Utxo,
        sender_randomness: Digest,
        receiver_privacy_digest: Digest,
    ) -> Self {
        Self {
            utxo,
            sender_randomness,
            receiver_privacy_digest,
            utxo_notification: UtxoNotification::OnChainPubKey(Default::default()),
        }
    }

    // only for tests
    #[cfg(test)]
    pub fn random(utxo: Utxo) -> Self {
        Self::fake_announcement(utxo, rand::random(), rand::random())
    }
}

/// Represents a list of [TxOutput]
#[derive(Debug, Clone, Default)]
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

impl From<&TxOutputList> for Vec<ExpectedUtxo> {
    fn from(list: &TxOutputList) -> Self {
        list.expected_utxos_iter().into_iter().collect()
    }
}

impl From<&TxOutputList> for Vec<PublicAnnouncement> {
    fn from(list: &TxOutputList) -> Self {
        list.public_announcements_iter().into_iter().collect()
    }
}

impl TxOutputList {
    pub fn total_native_coins(&self) -> NeptuneCoins {
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

    /// retrieves addition_records
    pub fn addition_records_iter(&self) -> impl IntoIterator<Item = AdditionRecord> + '_ {
        self.0.iter().map(|u| u.into())
    }

    /// retrieves addition_records
    pub fn addition_records(&self) -> Vec<AdditionRecord> {
        self.addition_records_iter().into_iter().collect()
    }

    /// retrieves public announcements from possible sub-set of the list
    pub fn public_announcements_iter(&self) -> impl IntoIterator<Item = PublicAnnouncement> + '_ {
        self.0.iter().filter_map(|u| match &u.utxo_notification {
            UtxoNotification::OnChainPubKey(pa) => Some(pa.clone()),
            UtxoNotification::OnChainSymmetricKey(pa) => Some(pa.clone()),
            _ => None,
        })
    }

    /// retrieves public announcements from possible sub-set of the list
    pub fn public_announcements(&self) -> Vec<PublicAnnouncement> {
        self.public_announcements_iter().into_iter().collect()
    }

    /// retrieves expected_utxos from possible sub-set of the list
    pub fn expected_utxos_iter(&self) -> impl IntoIterator<Item = ExpectedUtxo> + '_ {
        self.0.iter().filter_map(|u| match &u.utxo_notification {
            UtxoNotification::OffChain(eu) => Some(*eu.clone()),
            _ => None,
        })
    }

    /// retrieves expected_utxos from possible sub-set of the list
    pub fn expected_utxos(&self) -> Vec<ExpectedUtxo> {
        self.expected_utxos_iter().into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_models::network::Network;
    use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
    use crate::models::state::wallet::address::generation_address::ReceivingAddress;
    use crate::models::state::wallet::WalletSecret;
    use crate::tests::shared::mock_genesis_global_state;
    use rand::Rng;

    #[tokio::test]
    async fn test_utxoreceiver_auto_on_chain_pubkey() -> Result<()> {
        let global_state_lock =
            mock_genesis_global_state(Network::RegTest, 2, WalletSecret::devnet_wallet()).await;

        let state = global_state_lock.lock_guard().await;
        let block_height = state.chain.light_state().header().height;

        // generate a new receiving address that is not from our wallet.
        let mut rng = rand::thread_rng();
        let seed: Digest = rng.gen();
        let address = ReceivingAddress::derive_from_seed(seed);

        let amount = NeptuneCoins::one();
        let utxo = Utxo::new_native_coin(address.lock_script(), amount);

        let sender_randomness = state
            .wallet_state
            .wallet_secret
            .generate_sender_randomness(block_height, address.privacy_digest);

        let utxo_receiver = TxOutput::auto(
            &state.wallet_state,
            &address.into(),
            amount,
            sender_randomness,
        )?;

        assert!(matches!(
            utxo_receiver.utxo_notification,
            UtxoNotification::OnChainPubKey(_)
        ));
        assert_eq!(utxo_receiver.sender_randomness, sender_randomness);
        assert_eq!(
            utxo_receiver.receiver_privacy_digest,
            address.privacy_digest
        );
        assert_eq!(utxo_receiver.utxo, utxo);
        Ok(())
    }

    #[tokio::test]
    async fn test_utxoreceiver_auto_off_chain() -> Result<()> {
        let global_state_lock =
            mock_genesis_global_state(Network::RegTest, 2, WalletSecret::devnet_wallet()).await;

        // obtain next unused receiving address from our wallet.
        let spending_key = global_state_lock
            .lock_guard_mut()
            .await
            .wallet_state
            .wallet_secret
            .next_unused_generation_spending_key();
        let address = spending_key.to_address();

        let state = global_state_lock.lock_guard().await;
        let block_height = state.chain.light_state().header().height;

        let amount = NeptuneCoins::one();
        let utxo = Utxo::new_native_coin(address.lock_script(), amount);

        let sender_randomness = state
            .wallet_state
            .wallet_secret
            .generate_sender_randomness(block_height, address.privacy_digest);

        let utxo_receiver = TxOutput::auto(
            &state.wallet_state,
            &address.into(),
            amount,
            sender_randomness,
        )?;

        assert!(matches!(
            utxo_receiver.utxo_notification,
            UtxoNotification::OffChain(_)
        ));
        assert_eq!(utxo_receiver.sender_randomness, sender_randomness);
        assert_eq!(
            utxo_receiver.receiver_privacy_digest,
            address.privacy_digest
        );
        assert_eq!(utxo_receiver.utxo, utxo);
        Ok(())
    }
}
