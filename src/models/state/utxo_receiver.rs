use super::wallet::address::generation_address::ReceivingAddress;
use super::wallet::utxo_notification_pool::UtxoNotifier;
use super::wallet::wallet_state::WalletState;
use super::PublicAnnouncement;
use super::Utxo;
use crate::models::state::wallet::utxo_notification_pool::ExpectedUtxo;
use crate::prelude::twenty_first::math::digest::Digest;
use anyhow::Result;

/// enumerates how a transaction recipient can be notified
/// that a Utxo exists which they can claim/spend.
#[derive(Debug, Clone)]
pub enum UtxoNotifyMethod {
    OnChain(PublicAnnouncement),
    OffChain,
}

/// enumerates how a transaction recipient can be notified
/// that a Change Utxo exists which they can claim/spend.
///
/// note: This is equivalent to [UtxoNotifyMethod] but does
/// not carry any data.  Also, it defaults to `OffChain`.
#[derive(Debug, Clone)]
pub enum ChangeNotifyMethod {
    OnChain,
    OffChain,
}

impl Default for ChangeNotifyMethod {
    fn default() -> Self {
        Self::OffChain
    }
}

/// Contains data that a UTXO recipient needs to be notified
/// about and claim a given UTXO
#[derive(Debug, Clone)]
pub struct UtxoReceiver {
    pub utxo: Utxo,
    pub sender_randomness: Digest,
    pub receiver_privacy_digest: Digest,
    pub utxo_notify_method: UtxoNotifyMethod,
}

impl From<&UtxoReceiver> for ExpectedUtxo {
    fn from(d: &UtxoReceiver) -> Self {
        ExpectedUtxo::new(
            d.utxo.clone(),
            d.sender_randomness,
            d.receiver_privacy_digest,
            UtxoNotifier::Myself,
        )
    }
}

impl UtxoReceiver {
    /// automatically generates `UtxoReceiver` from a `ReceivingAddress` and
    /// `Utxo` info.
    ///
    /// If the `Utxo` can be claimed by our wallet then private OffChain
    /// notification will be used.  Else `OnChain` notification.
    ///
    /// This method should normally be used when instantiating `UtxoReceiver`
    pub fn auto(
        wallet_state: &WalletState,
        address: &ReceivingAddress,
        utxo: Utxo,
        sender_randomness: Digest,
    ) -> Result<Self> {
        let utxo_notify_method = match wallet_state.is_wallet_utxo(&utxo) {
            true => UtxoNotifyMethod::OffChain,
            false => UtxoNotifyMethod::OnChain(
                address.generate_public_announcement(&utxo, sender_randomness)?,
            ),
        };
        Ok(Self {
            utxo,
            sender_randomness,
            receiver_privacy_digest: address.privacy_digest,
            utxo_notify_method,
        })
    }

    /// instantiates `UtxoReceiver` using OnChain notification method.
    ///
    /// For normal situations, auto() should be used instead.
    pub fn onchain(
        utxo: Utxo,
        sender_randomness: Digest,
        receiver_privacy_digest: Digest,
        public_announcement: PublicAnnouncement,
    ) -> Self {
        Self {
            utxo,
            sender_randomness,
            receiver_privacy_digest,
            utxo_notify_method: UtxoNotifyMethod::OnChain(public_announcement),
        }
    }

    /// instantiates `UtxoReceiver` using OffChain notification method.
    ///
    /// For normal situations, auto() should be used instead.
    pub fn offchain(
        utxo: Utxo,
        sender_randomness: Digest,
        receiver_privacy_digest: Digest,
    ) -> Self {
        Self {
            utxo,
            sender_randomness,
            receiver_privacy_digest,
            utxo_notify_method: UtxoNotifyMethod::OffChain,
        }
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
            utxo_notify_method: UtxoNotifyMethod::OnChain(PublicAnnouncement::default()),
        }
    }

    // only for tests
    #[cfg(test)]
    pub fn random(utxo: Utxo) -> Self {
        Self::fake_announcement(utxo, rand::random(), rand::random())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_models::network::Network;
    use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
    use crate::models::state::wallet::WalletSecret;
    use crate::tests::shared::mock_genesis_global_state;
    use rand::Rng;

    #[tokio::test]
    async fn test_utxoreceiver_auto_on_chain() -> Result<()> {
        let global_state_lock =
            mock_genesis_global_state(Network::RegTest, 2, WalletSecret::devnet_wallet()).await;

        let state = global_state_lock.lock_guard().await;
        let block_height = state.chain.light_state().header().height;

        // generate a new receiving address that is not from our wallet.
        let mut rng = rand::thread_rng();
        let seed: Digest = rng.gen();
        let address = ReceivingAddress::derive_from_seed(seed);

        let utxo = Utxo::new(address.lock_script(), NeptuneCoins::one().to_native_coins());

        let sender_randomness = state
            .wallet_state
            .wallet_secret
            .generate_sender_randomness(block_height, address.privacy_digest);

        let utxo_receiver = UtxoReceiver::auto(
            &state.wallet_state,
            &address,
            utxo.clone(),
            sender_randomness,
        )?;

        assert!(matches!(
            utxo_receiver.utxo_notify_method,
            UtxoNotifyMethod::OnChain(_)
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
        let spending_key = state.wallet_state.get_known_spending_keys()[0];
        let address = spending_key.to_address();

        let utxo = Utxo::new(address.lock_script(), NeptuneCoins::one().to_native_coins());

        let sender_randomness = state
            .wallet_state
            .wallet_secret
            .generate_sender_randomness(block_height, address.privacy_digest);

        let utxo_receiver = UtxoReceiver::auto(
            &state.wallet_state,
            &address,
            utxo.clone(),
            sender_randomness,
        )?;

        assert!(matches!(
            utxo_receiver.utxo_notify_method,
            UtxoNotifyMethod::OffChain
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
