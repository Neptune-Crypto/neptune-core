use super::generation_address;
use crate::{
    config_models::network::Network,
    models::blockchain::transaction::{
        utxo::{LockScript, Utxo},
        PublicAnnouncement,
    },
};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use tasm_lib::triton_vm::prelude::Digest;

/// Represents any type of Neptune receiving Address.
///
/// This enum provides an abstraction API for Address types, so that
/// a method or struct may simply accept a `ReceivingAddressType` and be
/// forward-compatible with new types of Address as they are implemented.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReceivingAddressType {
    Generation(generation_address::ReceivingAddress),
}

impl From<generation_address::ReceivingAddress> for ReceivingAddressType {
    fn from(a: generation_address::ReceivingAddress) -> Self {
        Self::Generation(a)
    }
}

impl ReceivingAddressType {
    /// generates a [PublicAnnouncement] for an output Utxo
    pub fn generate_public_announcement(
        &self,
        utxo: &Utxo,
        sender_randomness: Digest,
    ) -> Result<PublicAnnouncement> {
        match self {
            Self::Generation(a) => a.generate_public_announcement(utxo, sender_randomness),
        }
    }

    /// Generate a [LockScript] from the spending lock. Satisfaction
    /// of this lock script establishes the UTXO owner's assent to
    /// the transaction.
    pub fn lock_script(&self) -> LockScript {
        match self {
            Self::Generation(a) => a.lock_script(),
        }
    }

    /// returns a privacy digest which corresponds to the privacy_preimage
    /// of the matching [SpendingKeyType]
    pub fn privacy_digest(&self) -> Digest {
        match self {
            Self::Generation(a) => a.privacy_digest,
        }
    }

    /// encodes this address as bech32m
    pub fn to_bech32m(&self, network: Network) -> Result<String> {
        match self {
            Self::Generation(k) => k.to_bech32m(network),
        }
    }

    /// parses an address from its bech32m encoding
    pub fn from_bech32m(encoded: String, network: Network) -> Result<Self> {
        let addr = generation_address::ReceivingAddress::from_bech32m(encoded, network)?;
        Ok(Self::Generation(addr))

        // when future addr types are supported, we would attempt each type in
        // turn.
    }
}

/// Represents any type of Neptune spending key.
///
/// This enum provides an abstraction API for spending key types, so that a
/// method or struct may simply accept a `SpendingKeyType` and be
/// forward-compatible with new types of spending key as they are implemented.
#[derive(Debug, Clone, Copy)]
pub enum SpendingKeyType {
    Generation(generation_address::SpendingKey),
}

impl From<generation_address::SpendingKey> for SpendingKeyType {
    fn from(key: generation_address::SpendingKey) -> Self {
        Self::Generation(key)
    }
}

impl SpendingKeyType {
    /// returns the address that corresponds to this spending key.
    pub fn to_address(&self) -> ReceivingAddressType {
        match self {
            Self::Generation(k) => k.to_address().into(),
        }
    }

    /// returns the privacy preimage.
    ///
    /// note: The hash of the preimage is available in the receiving address
    /// as the privacy_digest
    pub fn privacy_preimage(&self) -> Digest {
        match self {
            Self::Generation(k) => k.privacy_preimage,
        }
    }

    /// returns unlock_key needed for transaction witnesses
    ///
    /// doc todo: better description
    pub fn unlock_key(&self) -> Digest {
        match self {
            Self::Generation(k) => k.unlock_key,
        }
    }
}
