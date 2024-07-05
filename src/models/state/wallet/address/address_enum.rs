use serde::{Deserialize, Serialize};
use tasm_lib::triton_vm::prelude::Digest;
use crate::models::blockchain::transaction::{utxo::{LockScript, Utxo}, PublicAnnouncement};
use super::generation_address;
use anyhow::Result;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Address {
    Generation(generation_address::ReceivingAddress),
}

impl From<generation_address::ReceivingAddress> for Address {
    fn from(a: generation_address::ReceivingAddress) -> Self {
        Self::Generation(a)
    }
}

impl Address {
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
