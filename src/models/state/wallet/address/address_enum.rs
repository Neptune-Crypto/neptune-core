use super::generation_address;
use crate::models::blockchain::transaction::{
    utxo::{LockScript, Utxo},
    PublicAnnouncement,
};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use tasm_lib::triton_vm::prelude::Digest;

/// Represents any type of Neptune receiving Address.
///
/// This enum provides an abstraction API for Address types, so that
/// a method or struct may simply accept an AbstractAddress and be
/// forward-compatible with new types of Address as they are implemented.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AbstractAddress {
    Generation(generation_address::ReceivingAddress),
}

impl From<generation_address::ReceivingAddress> for AbstractAddress {
    fn from(a: generation_address::ReceivingAddress) -> Self {
        Self::Generation(a)
    }
}

impl AbstractAddress {
    pub fn generate_public_announcement(
        &self,
        utxo: &Utxo,
        sender_randomness: Digest,
    ) -> Result<PublicAnnouncement> {
        match self {
            Self::Generation(a) => a.generate_public_announcement(utxo, sender_randomness),
        }
    }

    /// Generate a lock script from the spending lock. Satisfaction
    /// of this lock script establishes the UTXO owner's assent to
    /// the transaction.
    pub fn lock_script(&self) -> LockScript {
        match self {
            Self::Generation(a) => a.lock_script(),
        }
    }

    pub fn privacy_digest(&self) -> Digest {
        match self {
            Self::Generation(a) => a.privacy_digest,
        }
    }
}

/// Represents any type of Neptune spending key.
///
/// This enum provides an abstraction API for spending key types, so that a
/// method or struct may simply accept an AbstractSpendingKey and be
/// forward-compatible with new types of spending key as they are implemented.
#[derive(Debug, Clone, Copy)]
pub enum AbstractSpendingKey {
    Generation(generation_address::SpendingKey),
}

impl From<generation_address::SpendingKey> for AbstractSpendingKey {
    fn from(key: generation_address::SpendingKey) -> Self {
        Self::Generation(key)
    }
}

impl AbstractSpendingKey {
    pub fn to_address(&self) -> AbstractAddress {
        match self {
            Self::Generation(k) => k.to_address().into(),
        }
    }

    pub fn privacy_preimage(&self) -> Digest {
        match self {
            Self::Generation(k) => k.privacy_preimage,
        }
    }

    pub fn unlock_key(&self) -> Digest {
        match self {
            Self::Generation(k) => k.unlock_key,
        }
    }
}
