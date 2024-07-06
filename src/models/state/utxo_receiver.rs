use super::wallet::address::Address;
use super::wallet::utxo_notification_pool::UtxoNotifier;
use super::wallet::wallet_state::WalletState;
use super::PublicAnnouncement;
use super::Utxo;
use crate::models::blockchain::shared::Hash;
use crate::models::state::wallet::utxo_notification_pool::ExpectedUtxo;
use crate::models::state::NeptuneCoins;
use crate::prelude::twenty_first::math::digest::Digest;
use anyhow::Result;
use std::ops::Deref;
use std::ops::DerefMut;

/// enumerates how a transaction recipient should be notified
/// that a Utxo exists which they can claim/spend.
#[derive(Debug, Clone)]
pub enum UtxoNotifyMethod {
    OnChainPubKey,
    OnChainSymmetricKey,
    OffChain,
}

/// enumerates transaction notifications
/// like `UtxoNotifyMethod` but holds notification data.
#[derive(Debug, Clone)]
pub enum UtxoNotification {
    OnChainPubKey(PublicAnnouncement),
    OnChainSymmetricKey(PublicAnnouncement),
    OffChain(ExpectedUtxo),
}

/// Contains data that a UTXO recipient needs to be notified
/// about and claim a given UTXO
#[derive(Debug, Clone)]
pub struct UtxoReceiver {
    pub utxo: Utxo,
    pub sender_randomness: Digest,
    pub receiver_privacy_digest: Digest,
    pub utxo_notification: UtxoNotification,
}

impl From<ExpectedUtxo> for UtxoReceiver {
    fn from(expected_utxo: ExpectedUtxo) -> Self {
        Self {
            utxo: expected_utxo.utxo.clone(),
            sender_randomness: expected_utxo.sender_randomness,
            receiver_privacy_digest: expected_utxo.receiver_preimage.hash::<Hash>(),
            utxo_notification: UtxoNotification::OffChain(expected_utxo),
        }
    }
}

impl TryFrom<&UtxoReceiver> for ExpectedUtxo {
    type Error = anyhow::Error;

    fn try_from(d: &UtxoReceiver) -> Result<Self> {
        match &d.utxo_notification {
            UtxoNotification::OffChain(eu) => Ok(eu.clone()),
            _ => Err(anyhow::anyhow!("utxo_notification is not offchain.")),
        }
    }
}

impl UtxoReceiver {
    /// automatically generates `UtxoReceiver` from address and amount.
    ///
    /// If the `Utxo` can be claimed by our wallet then private OffChain
    /// notification will be used.  Else `OnChain` notification.
    ///
    /// This method should normally be used when instantiating `UtxoReceiver`
    ///
    /// note: in the future, OnChainSymmetric may be preferred instead of
    /// OffChain for `Utxo` that can be claimed by our wallet.
    pub fn auto(
        wallet_state: &WalletState,
        address: &Address,
        amount: NeptuneCoins,
        sender_randomness: Digest,
    ) -> Result<Self> {
        let utxo = Utxo::new_native_coin(address.lock_script(), amount);

        Ok(match wallet_state.find_spending_key_for_utxo(&utxo) {
            Some(key) => Self::offchain(utxo, sender_randomness, key.privacy_preimage),
            None => {
                let pub_ann = address.generate_public_announcement(&utxo, sender_randomness)?;
                Self::onchain_pubkey(utxo, sender_randomness, address.privacy_digest(), pub_ann)
            }
        })
    }

    /// instantiates `UtxoReceiver` using OnChainPubKey notification method.
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

    /// instantiates `UtxoReceiver` using OnChainSymmetricKey notification method.
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

    /// instantiates `UtxoReceiver` using OffChain notification method.
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

/// Represents a list of UtxoReceiver
#[derive(Debug, Clone, Default)]
pub struct UtxoReceiverList(Vec<UtxoReceiver>);

impl Deref for UtxoReceiverList {
    type Target = Vec<UtxoReceiver>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for UtxoReceiverList {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<Vec<UtxoReceiver>> for UtxoReceiverList {
    fn from(v: Vec<UtxoReceiver>) -> Self {
        Self(v)
    }
}

impl From<UtxoReceiverList> for Vec<ExpectedUtxo> {
    fn from(list: UtxoReceiverList) -> Self {
        list.expected_utxos().into_iter().collect()
    }
}

impl UtxoReceiverList {
    pub fn total_native_coins(&self) -> NeptuneCoins {
        self.0
            .iter()
            .map(|u| u.utxo.get_native_currency_amount())
            .sum()
    }

    /// retrieves public announcements from possible sub-set of the list
    pub fn utxos(&self) -> impl IntoIterator<Item = Utxo> + '_ {
        self.0.iter().map(|u| u.utxo.clone())
    }

    /// retrieves public announcements from possible sub-set of the list
    pub fn public_announcements(&self) -> impl IntoIterator<Item = PublicAnnouncement> + '_ {
        self.0.iter().filter_map(|u| match &u.utxo_notification {
            UtxoNotification::OnChainPubKey(pa) => Some(pa.clone()),
            UtxoNotification::OnChainSymmetricKey(pa) => Some(pa.clone()),
            _ => None,
        })
    }

    /// retrieves expected_utxos from possible sub-set of the list
    pub fn expected_utxos(&self) -> impl IntoIterator<Item = ExpectedUtxo> + '_ {
        self.0.iter().filter_map(|u| match &u.utxo_notification {
            UtxoNotification::OffChain(expected_utxo) => Some(expected_utxo.clone()),
            _ => None,
        })
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

        let utxo_receiver = UtxoReceiver::auto(
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

        let state = global_state_lock.lock_guard().await;
        let block_height = state.chain.light_state().header().height;

        // obtain a receiving address from our wallet.
        let spending_key = state
            .wallet_state
            .wallet_secret
            .nth_generation_spending_key(0);
        let address = spending_key.to_address();

        let amount = NeptuneCoins::one();
        let utxo = Utxo::new_native_coin(address.lock_script(), amount);

        let sender_randomness = state
            .wallet_state
            .wallet_secret
            .generate_sender_randomness(block_height, address.privacy_digest);

        let utxo_receiver = UtxoReceiver::auto(
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
