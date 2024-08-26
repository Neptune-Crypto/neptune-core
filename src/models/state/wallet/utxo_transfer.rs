//! This module contains types for transferring [Utxo] notifications between parties
//! outside of neptune-core.  (out-of-band)
//!
//! Such transfers look like:
//!
//! 1. sender creates tx params with `rpc.generate_tx_params()` and specifies
//!    UnownedUtxoNotifyMethod::OffchainSerialized for at least 1 output utxo.
//! 2. sender sends tx with `rpc.send(tx_params)`
//! 3. sender reads tx_params.tx_output_list().utxo_transfer_iter() to obtain
//!    list of `UtxoTransferEncrypted` that must be transferred out-of-band
//!    as well as a list of `TxOutputMeta` that has a `ReceivingAddress` for each
//!    `UtxoTransferEncrypted`
//! 4. sender serializes the `UtxoTransferEncrypted` into bech32m, possibly
//!    along with some metadata.  (see neptune-cli source-code for a standard
//!    file-format)
//! 5. sender transmits the bech32m encoded `UtxoTransferEncrypted` to the owner
//!    of the `ReceivingAddress`.
//! 6. recipient calls rpc.claim_utxo() passing it the received bech32m string.
//! 7. the recipients wallet is now notified of the utxo and applies it towards
//!    wallet balance, etc.

use crate::config_models::network::Network;
use crate::models::blockchain::transaction::utxo::Utxo;
use crate::prelude::twenty_first;
use anyhow::bail;
use anyhow::Result;
use bech32::FromBase32;
use bech32::ToBase32;
use get_size::GetSize;
use serde::{Deserialize, Serialize};
use tasm_lib::triton_vm::prelude::BFieldElement;
use twenty_first::math::tip5::Digest;

use super::address::{ReceivingAddress, SpendingKey};

/// intended for transferring utxo-notification secrets between parties
///
/// this type intentionally does not impl Serialize, Deserialize because it
/// should not be transferred directly, but rather encrypted inside
/// UtxoTransferEncrypted
#[derive(Clone, Debug, PartialEq, Eq, Hash, GetSize)]
pub struct UtxoTransfer {
    pub utxo: Utxo,
    pub sender_randomness: Digest,
}

impl UtxoTransfer {
    /// instantiate
    pub fn new(utxo: Utxo, sender_randomness: Digest) -> Self {
        Self {
            utxo,
            sender_randomness,
        }
    }

    /// encrypts the UtxoTransfer to a [ReceivingAddress] creating a [UtxoTransferEncrypted].
    pub fn encrypt_to_address(
        &self,
        address: &ReceivingAddress,
    ) -> anyhow::Result<UtxoTransferEncrypted> {
        Ok(UtxoTransferEncrypted {
            ciphertext: address.encrypt(&self.utxo, self.sender_randomness)?,
            receiver_identifier: address.receiver_identifier(),
        })
    }
}

/// an encrypted wrapper for UtxoTransfer.
///
/// This type is intended to be serialized and actually transferred between
/// parties.
///
/// note: bech32m encoding of this type is considered standard and is
/// recommended over serde serialization.
///
/// the receiver_identifier enables the receiver to find the matching
/// `SpendingKey` in their wallet.
#[derive(Clone, Debug, PartialEq, Eq, Hash, GetSize, Serialize, Deserialize)]
pub struct UtxoTransferEncrypted {
    /// contains encrypted UtxoTransfer
    pub ciphertext: Vec<BFieldElement>,

    /// enables the receiver to find the matching `SpendingKey` in their wallet.
    pub receiver_identifier: BFieldElement,
}

impl UtxoTransferEncrypted {
    /// decrypts into a [UtxoTransfer]
    pub fn decrypt_with_spending_key(
        &self,
        spending_key: &SpendingKey,
    ) -> anyhow::Result<UtxoTransfer> {
        let (utxo, sender_randomness) = spending_key.decrypt(&self.ciphertext)?;

        Ok(UtxoTransfer {
            utxo,
            sender_randomness,
        })
    }

    /// encodes into a bech32m string for the given network
    pub fn to_bech32m(&self, network: Network) -> Result<String> {
        let hrp = Self::get_hrp(network);
        let payload = bincode::serialize(self)?;
        let variant = bech32::Variant::Bech32m;
        match bech32::encode(&hrp, payload.to_base32(), variant) {
            Ok(enc) => Ok(enc),
            Err(e) => bail!("Could not encode UtxoTransferEncrypted as bech32m because error: {e}"),
        }
    }

    /// decodes from a bech32m string and verifies it matches `network`
    pub fn from_bech32m(encoded: &str, network: Network) -> Result<Self> {
        let (hrp, data, variant) = bech32::decode(encoded)?;

        if variant != bech32::Variant::Bech32m {
            bail!("Can only decode bech32m addresses.");
        }

        if hrp != *Self::get_hrp(network) {
            bail!("Could not decode bech32m address because of invalid prefix");
        }

        let payload = Vec::<u8>::from_base32(&data)?;

        match bincode::deserialize(&payload) {
            Ok(ra) => Ok(ra),
            Err(e) => bail!("Could not decode bech32m because of error: {e}"),
        }
    }

    /// returns human readable prefix (hrp) of a utxo-transfer-encrypted, specific to `network`
    pub fn get_hrp(network: Network) -> String {
        format!("utxo{}", super::address::common::network_hrp_char(network))
    }
}
