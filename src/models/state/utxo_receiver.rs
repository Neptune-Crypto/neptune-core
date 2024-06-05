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
    pub receiver_preimage: Digest,
    pub utxo_notify_method: UtxoNotifyMethod,
}

impl From<&UtxoReceiver> for ExpectedUtxo {
    fn from(d: &UtxoReceiver) -> Self {
        ExpectedUtxo::new(
            d.utxo.clone(),
            d.sender_randomness,
            d.receiver_preimage,
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
        receiver_preimage: Digest,
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
            receiver_preimage,
            utxo_notify_method,
        })
    }

    /// instantiates `UtxoReceiver` using OnChain notification method.
    ///
    /// For normal situations, auto() should be used instead.
    pub fn onchain(
        utxo: Utxo,
        sender_randomness: Digest,
        receiver_preimage: Digest,
        public_announcement: PublicAnnouncement,
    ) -> Self {
        Self {
            utxo,
            sender_randomness,
            receiver_preimage,
            utxo_notify_method: UtxoNotifyMethod::OnChain(public_announcement),
        }
    }

    /// instantiates `UtxoReceiver` using OffChain notification method.
    ///
    /// For normal situations, auto() should be used instead.
    pub fn offchain(utxo: Utxo, sender_randomness: Digest, receiver_preimage: Digest) -> Self {
        Self {
            utxo,
            sender_randomness,
            receiver_preimage,
            utxo_notify_method: UtxoNotifyMethod::OffChain,
        }
    }

    // only for tests
    #[cfg(test)]
    pub fn fake_announcement(
        utxo: Utxo,
        sender_randomness: Digest,
        receiver_preimage: Digest,
    ) -> Self {
        Self {
            utxo,
            sender_randomness,
            receiver_preimage,
            utxo_notify_method: UtxoNotifyMethod::OnChain(PublicAnnouncement::default()),
        }
    }

    // only for tests
    #[cfg(test)]
    pub fn random(utxo: Utxo) -> Self {
        Self::fake_announcement(utxo, rand::random(), rand::random())
    }
}
