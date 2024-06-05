use super::wallet::address::generation_address::ReceivingAddress;
use super::wallet::utxo_notification_pool::UtxoNotifier;
use super::wallet::wallet_state::WalletState;
use super::PublicAnnouncement;
use super::Utxo;
use crate::models::state::wallet::utxo_notification_pool::ExpectedUtxo;
use crate::prelude::twenty_first::math::digest::Digest;
use anyhow::Result;

#[derive(Debug, Clone)]
pub enum UtxoNotifyMethod {
    Onchain(PublicAnnouncement),
    Offchain,
}

#[derive(Debug, Clone)]
pub struct UtxoReceiverData {
    pub utxo: Utxo,
    pub sender_randomness: Digest,
    pub receiver_preimage: Digest,
    pub utxo_notify_method: UtxoNotifyMethod,
}

impl From<&UtxoReceiverData> for ExpectedUtxo {
    fn from(d: &UtxoReceiverData) -> Self {
        ExpectedUtxo::new(
            d.utxo.clone(),
            d.sender_randomness,
            d.receiver_preimage,
            UtxoNotifier::Myself,
        )
    }
}

impl UtxoReceiverData {
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
            utxo_notify_method: UtxoNotifyMethod::Onchain(public_announcement),
        }
    }

    pub fn offchain(utxo: Utxo, sender_randomness: Digest, receiver_preimage: Digest) -> Self {
        Self {
            utxo,
            sender_randomness,
            receiver_preimage,
            utxo_notify_method: UtxoNotifyMethod::Offchain,
        }
    }

    pub fn auto(
        wallet_state: &WalletState,
        address: &ReceivingAddress,
        utxo: Utxo,
        sender_randomness: Digest,
        receiver_preimage: Digest,
    ) -> Result<Self> {
        let utxo_notify_method = match wallet_state.is_wallet_utxo(&utxo) {
            true => UtxoNotifyMethod::Onchain(
                address.generate_public_announcement(&utxo, sender_randomness)?,
            ),
            false => UtxoNotifyMethod::Offchain,
        };
        Ok(Self {
            utxo,
            sender_randomness,
            receiver_preimage,
            utxo_notify_method,
        })
    }

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
            utxo_notify_method: UtxoNotifyMethod::Onchain(PublicAnnouncement::default()),
        }
    }

    #[cfg(test)]
    pub fn random(utxo: Utxo) -> Self {
        Self::fake_announcement(utxo, rand::random(), rand::random())
    }
}
