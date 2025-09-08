use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;

use crate::protocol::consensus::transaction::utxo::Utxo;
use crate::state::wallet::address::ReceivingAddress;

/// Enumerates the medium of exchange for UTXO-notifications.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default, clap::ValueEnum)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub enum UtxoNotificationMedium {
    /// The UTXO notification should be sent on-chain
    #[default]
    OnChain,

    /// The UTXO notification should be sent off-chain
    OffChain,
}

/// enumerates how utxos and spending information is communicated, including how
/// to encrypt this information.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub(crate) enum UtxoNotificationMethod {
    /// the utxo notification should be transferred to recipient encrypted on the blockchain
    OnChain(ReceivingAddress),

    /// the utxo notification should be transferred to recipient off the blockchain
    OffChain(ReceivingAddress),

    /// No UTXO notification is intended
    None,
}

impl UtxoNotificationMethod {
    pub(crate) fn new(medium: UtxoNotificationMedium, address: ReceivingAddress) -> Self {
        match medium {
            UtxoNotificationMedium::OnChain => Self::OnChain(address),
            UtxoNotificationMedium::OffChain => Self::OffChain(address),
        }
    }
}

/// The payload of a UTXO notification, containing all information necessary
/// to claim it, provided that the decryptor already has access to the
/// associated spending key.
///
/// future work:
/// we should consider adding functionality that would facilitate passing
/// these payloads from sender to receiver off-chain for lower-fee transfers
/// between trusted parties or eg wallets owned by the same person/org.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UtxoNotificationPayload {
    pub(crate) utxo: Utxo,
    pub(crate) sender_randomness: Digest,
}

impl UtxoNotificationPayload {
    pub(crate) fn new(utxo: Utxo, sender_randomness: Digest) -> Self {
        Self {
            utxo,
            sender_randomness,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivateNotificationData {
    pub cleartext: UtxoNotificationPayload,
    pub ciphertext: String,
    pub recipient_address: ReceivingAddress,

    /// Indicates if this client can unlock the UTXO
    pub owned: bool,
}
