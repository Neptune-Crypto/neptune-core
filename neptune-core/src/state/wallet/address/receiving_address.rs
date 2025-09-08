//! provides an abstraction over key and address types.

use anyhow::bail;
use anyhow::Result;
#[cfg(any(test, feature = "arbitrary-impls"))]
use arbitrary::Arbitrary;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::triton_vm::prelude::Digest;

use super::generation_address;
use super::symmetric_key;
use crate::api::export::KeyType;
use crate::application::config::network::Network;
use crate::protocol::consensus::transaction::announcement::Announcement;
use crate::state::wallet::utxo_notification::UtxoNotificationPayload;
use crate::BFieldElement;

// note: assigning the flags to `KeyType` variants as discriminants has bonus
// that we get a compiler verification that values do not conflict.  which is
// nice since they are (presently) defined in separate files.
//
// anyway it is a desirable property that KeyType variants match the values
// actually stored in Announcement.

/// Represents any type of Neptune receiving Address.
///
/// This enum provides an abstraction API for Address types, so that
/// a method or struct may simply accept a `ReceivingAddress` and be
/// forward-compatible with new types of Address as they are implemented.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(any(test, feature = "arbitrary-impls"), derive(Arbitrary))]
pub enum ReceivingAddress {
    /// a [generation_address]
    Generation(Box<generation_address::GenerationReceivingAddress>),

    /// a [symmetric_key] acting as an address.
    Symmetric(symmetric_key::SymmetricKey),
}

impl From<generation_address::GenerationReceivingAddress> for ReceivingAddress {
    fn from(a: generation_address::GenerationReceivingAddress) -> Self {
        Self::Generation(Box::new(a))
    }
}

impl From<&generation_address::GenerationReceivingAddress> for ReceivingAddress {
    fn from(a: &generation_address::GenerationReceivingAddress) -> Self {
        Self::Generation(Box::new(*a))
    }
}

impl From<symmetric_key::SymmetricKey> for ReceivingAddress {
    fn from(k: symmetric_key::SymmetricKey) -> Self {
        Self::Symmetric(k)
    }
}

impl From<&symmetric_key::SymmetricKey> for ReceivingAddress {
    fn from(k: &symmetric_key::SymmetricKey) -> Self {
        Self::Symmetric(*k)
    }
}

impl TryFrom<ReceivingAddress> for generation_address::GenerationReceivingAddress {
    type Error = anyhow::Error;

    fn try_from(a: ReceivingAddress) -> Result<Self> {
        let ReceivingAddress::Generation(a) = a else {
            bail!("not a generation address");
        };

        Ok(*a)
    }
}

impl ReceivingAddress {
    /// returns `receiver_identifier`
    pub fn receiver_identifier(&self) -> BFieldElement {
        match self {
            Self::Generation(a) => a.receiver_identifier(),
            Self::Symmetric(a) => a.receiver_identifier(),
        }
    }

    /// generates a [Announcement] for an output Utxo
    ///
    /// The announcement contains a [`Vec<BFieldElement>`] with fields:
    ///   0    --> type flag.  (flag of key type)
    ///   1    --> receiver_identifier  (fingerprint derived from seed)
    ///   2..n --> ciphertext (encrypted utxo + sender_randomness)
    ///
    /// Fields |0,1| enable the receiver to determine the ciphertext
    /// is intended for them and decryption should be attempted.
    pub(crate) fn generate_announcement(
        &self,
        utxo_notification_payload: UtxoNotificationPayload,
    ) -> Announcement {
        match self {
            ReceivingAddress::Generation(generation_receiving_address) => {
                generation_receiving_address.generate_announcement(&utxo_notification_payload)
            }
            ReceivingAddress::Symmetric(symmetric_key) => {
                symmetric_key.generate_announcement(&utxo_notification_payload)
            }
        }
    }

    pub(crate) fn private_notification(
        &self,
        utxo_notification_payload: UtxoNotificationPayload,
        network: Network,
    ) -> String {
        match self {
            ReceivingAddress::Generation(generation_receiving_address) => {
                generation_receiving_address
                    .private_utxo_notification(&utxo_notification_payload, network)
            }
            ReceivingAddress::Symmetric(symmetric_key) => {
                symmetric_key.private_utxo_notification(&utxo_notification_payload, network)
            }
        }
    }

    /// returns the `spending_lock`
    pub fn spending_lock(&self) -> Digest {
        match self {
            Self::Generation(a) => a.spending_lock(),
            Self::Symmetric(k) => k.lock_after_image(),
        }
    }

    /// returns a privacy digest which is the post-image of privacy preimage of
    /// the matching [SpendingKey](super::SpendingKey)
    pub fn privacy_digest(&self) -> Digest {
        match self {
            Self::Generation(a) => a.receiver_postimage(),
            Self::Symmetric(k) => k.receiver_postimage(),
        }
    }

    /// encrypts a [Utxo] and `sender_randomness` secret for purpose of transferring to payment recipient
    #[cfg(test)]
    pub(crate) fn encrypt(
        &self,
        utxo_notification_payload: &UtxoNotificationPayload,
    ) -> Vec<BFieldElement> {
        match self {
            Self::Generation(a) => a.encrypt(utxo_notification_payload),
            Self::Symmetric(a) => a.encrypt(utxo_notification_payload),
        }
    }

    /// encodes this address as bech32m
    ///
    /// For any key-type, the resulting bech32m can be provided as input to
    /// Self::from_bech32m() and will generate the original ReceivingAddress.
    ///
    /// Security: for key-type==Symmetric the resulting string exposes
    /// the secret-key.  As such, great care must be taken and it should
    /// never be used for display purposes.
    ///
    /// For most uses, prefer [Self::to_display_bech32m()] instead.
    pub fn to_bech32m(&self, network: Network) -> Result<String> {
        match self {
            Self::Generation(k) => k.to_bech32m(network),
            Self::Symmetric(k) => k.to_bech32m(network),
        }
    }

    /// returns an abbreviated bech32m encoded address.
    ///
    /// This method *may* reveal secret-key information for some key-types.  For
    /// general display purposes, prefer
    /// [Self::to_display_bech32m_abbreviated()].
    ///
    /// The idea is that this suitable for human recognition purposes
    ///
    /// ```text
    /// format:  <hrp><start>...<end>
    ///
    ///   [4 or 6] human readable prefix. 4 for symmetric-key, 6 for generation.
    ///   12 start of address.
    ///   12 end of address.
    /// ```
    pub fn to_bech32m_abbreviated(&self, network: Network) -> Result<String> {
        Ok(self.bech32m_abbreviate(self.to_bech32m(network)?, network))
    }

    /// returns a bech32m string suitable for display purposes.
    ///
    /// This method does not reveal secret-key information for any key-type.
    ///
    /// The resulting bech32m string is not guaranteed to result in the same
    /// [ReceivingAddress] if provided as input to [Self::from_bech32m()].  For
    /// that, [Self::to_bech32m()] should be used instead.
    ///
    /// For [Self::Generation] keys, this is equivalent to calling [Self::to_bech32m()].
    /// For [Self::Symmetric] keys, this returns the privacy_preimage hash bech32m encoded
    /// instead of the key itself.
    pub fn to_display_bech32m(&self, network: Network) -> anyhow::Result<String> {
        match self {
            Self::Generation(k) => k.to_bech32m(network),
            Self::Symmetric(k) => k.to_display_bech32m(network),
        }
    }

    /// returns an abbreviated address suitable for display purposes.
    ///
    /// This method does not reveal secret-key information for any key-type.
    ///
    /// The idea is that this suitable for human recognition purposes
    ///
    /// ```text
    /// format:  <hrp><start>...<end>
    ///
    ///   [4 or 6] human readable prefix. 4 for symmetric-key, 6 for generation.
    ///   12 start of address.
    ///   12 end of address.
    /// ```
    pub fn to_display_bech32m_abbreviated(&self, network: Network) -> Result<String> {
        Ok(self.bech32m_abbreviate(self.to_display_bech32m(network)?, network))
    }

    fn bech32m_abbreviate(&self, bech32m: String, network: Network) -> String {
        let first_len = self.get_hrp(network).len() + 12usize;
        let last_len = 12usize;

        assert!(bech32m.len() > first_len + last_len);

        let (first, _) = bech32m.split_at(first_len);
        let (_, last) = bech32m.split_at(bech32m.len() - last_len);

        format!("{first}...{last}")
    }

    /// parses an address from its bech32m encoding
    pub fn from_bech32m(encoded: &str, network: Network) -> Result<Self> {
        if let Ok(addr) =
            generation_address::GenerationReceivingAddress::from_bech32m(encoded, network)
        {
            return Ok(addr.into());
        }

        let key = symmetric_key::SymmetricKey::from_bech32m(encoded, network)?;
        Ok(key.into())

        // when future addr types are supported, we would attempt each type in
        // turn.
    }

    /// returns human-readable-prefix (hrp) for a given network
    pub fn get_hrp(&self, network: Network) -> String {
        match self {
            Self::Generation(_) => generation_address::GenerationReceivingAddress::get_hrp(network),
            Self::Symmetric(_) => symmetric_key::SymmetricKey::get_hrp(network).to_string(),
        }
    }

    /// Returns the address's lock script hash.
    ///
    /// In the general case, only the receiver knows the lock script.
    pub fn lock_script_hash(&self) -> Digest {
        match self {
            Self::Generation(x) => x.lock_script().hash(),
            Self::Symmetric(x) => x.lock_script().hash(),
        }
    }

    /// returns true if the [Announcement] has a type-flag that matches the type of this address.
    pub fn matches_announcement_key_type(&self, pa: &Announcement) -> bool {
        matches!(KeyType::try_from(pa), Ok(kt) if kt == KeyType::from(self))
    }
}
