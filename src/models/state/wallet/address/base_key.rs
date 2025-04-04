//! provides an abstraction over all spending key types.

use anyhow::bail;
use anyhow::Result;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::triton_vm::prelude::Digest;
use tracing::warn;

use super::common;
use super::generation_address;
use super::hash_lock_key;
use super::symmetric_key;
use super::ReceivingAddress;
use crate::models::blockchain::transaction::lock_script::LockScript;
use crate::models::blockchain::transaction::lock_script::LockScriptAndWitness;
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernel;
use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::blockchain::transaction::PublicAnnouncement;
use crate::models::state::wallet::incoming_utxo::IncomingUtxo;
use crate::BFieldElement;

// note: assigning the flags to `BaseKeyType` variants as discriminants has bonus
// that we get a compiler verification that values do not conflict.  which is
// nice since they are (presently) defined in separate files.
//
// anyway it is a desirable property that BaseKeyType variants match the values
// actually stored in PublicAnnouncement.

/// Enumerates available cryptographic key implementations for sending funds.
///
/// In most (but not all) cases there is a matching address.
///
/// There is also [KeyType](super::KeyType) that enumerates only
/// addressable key types.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BaseKeyType {
    /// To unlock, prove knowledge of the preimage.
    RawHashLock = hash_lock_key::RAW_HASH_LOCK_KEY_FLAG_U8,

    /// [generation_address] built on [crate::prelude::twenty_first::math::lattice::kem]
    ///
    /// wraps a symmetric key built on aes-256-gcm
    Generation = generation_address::GENERATION_FLAG_U8,

    /// [symmetric_key] built on aes-256-gcm
    Symmetric = symmetric_key::SYMMETRIC_KEY_FLAG_U8,
}

impl std::fmt::Display for BaseKeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RawHashLock => write!(f, "Raw Hash Lock"),
            Self::Generation => write!(f, "Generation"),
            Self::Symmetric => write!(f, "Symmetric"),
        }
    }
}

impl From<&ReceivingAddress> for BaseKeyType {
    fn from(addr: &ReceivingAddress) -> Self {
        match addr {
            ReceivingAddress::Generation(_) => Self::Generation,
            ReceivingAddress::Symmetric(_) => Self::Symmetric,
        }
    }
}

impl From<&BaseSpendingKey> for BaseKeyType {
    fn from(addr: &BaseSpendingKey) -> Self {
        match addr {
            BaseSpendingKey::Generation(_) => Self::Generation,
            BaseSpendingKey::Symmetric(_) => Self::Symmetric,
            BaseSpendingKey::RawHashLock { .. } => Self::RawHashLock,
        }
    }
}

impl From<BaseKeyType> for BFieldElement {
    fn from(key_type: BaseKeyType) -> Self {
        (key_type as u8).into()
    }
}

impl TryFrom<&PublicAnnouncement> for BaseKeyType {
    type Error = anyhow::Error;

    fn try_from(pa: &PublicAnnouncement) -> Result<Self> {
        match common::key_type_from_public_announcement(pa) {
            Ok(kt) if kt == Self::Generation.into() => Ok(Self::Generation),
            Ok(kt) if kt == Self::Symmetric.into() => Ok(Self::Symmetric),
            _ => bail!("encountered PublicAnnouncement of unknown type"),
        }
    }
}

impl BaseKeyType {
    /// returns all available `BaseKeyType`
    pub fn all_types() -> Vec<BaseKeyType> {
        vec![Self::RawHashLock, Self::Generation, Self::Symmetric]
    }
}

/// Represents cryptographic data necessary for spending funds (or, more
/// specifically, for unlocking UTXOs).
///
/// This enum provides an abstraction API for spending key types, so that a
/// method or struct may simply accept a `BaseSpendingKey` and be
/// forward-compatible with new types of spending key as they are implemented.
///
/// Note that not all spending keys have associated receiving addresses. In
/// particular, the `HashLock` variant has no associated address.
///
/// There is also [SpendingKey](super::SpendingKey) that enumerates only
/// addressable spending keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BaseSpendingKey {
    RawHashLock(hash_lock_key::HashLockKey),

    /// a key from [generation_address]
    Generation(generation_address::GenerationSpendingKey),

    /// a [symmetric_key]
    Symmetric(symmetric_key::SymmetricKey),
}

impl std::hash::Hash for BaseSpendingKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::hash::Hash::hash(&self.privacy_preimage(), state)
    }
}

impl From<generation_address::GenerationSpendingKey> for BaseSpendingKey {
    fn from(key: generation_address::GenerationSpendingKey) -> Self {
        Self::Generation(key)
    }
}

impl From<symmetric_key::SymmetricKey> for BaseSpendingKey {
    fn from(key: symmetric_key::SymmetricKey) -> Self {
        Self::Symmetric(key)
    }
}

// future improvements: a strong argument can be made that this type
// (and the key types it wraps) should not have any methods with
// outside types as parameters.  for example:
//
// pub(crate) fn scan_for_announced_utxos(
//     &self,
//     tx_kernel: &TransactionKernel,
// ) -> Vec<IncomingUtxo> {
//
// this method is dealing with types far outside the concern of
// a key, which means this method belongs elsewhere.
impl BaseSpendingKey {
    /// returns the address that corresponds to this spending key.
    pub fn to_address(&self) -> Option<ReceivingAddress> {
        match self {
            Self::Generation(k) => Some(k.to_address().into()),
            Self::Symmetric(k) => Some((*k).into()),
            Self::RawHashLock(_) => None,
        }
    }

    /// Return the lock script and its witness
    pub(crate) fn lock_script_and_witness(&self) -> LockScriptAndWitness {
        match self {
            BaseSpendingKey::Generation(generation_spending_key) => {
                generation_spending_key.lock_script_and_witness()
            }
            BaseSpendingKey::Symmetric(symmetric_key) => symmetric_key.lock_script_and_witness(),
            BaseSpendingKey::RawHashLock(raw_hash_lock) => raw_hash_lock.lock_script_and_witness(),
        }
    }

    pub(crate) fn lock_script(&self) -> LockScript {
        LockScript {
            program: self.lock_script_and_witness().program,
        }
    }

    pub(crate) fn lock_script_hash(&self) -> Digest {
        self.lock_script().hash()
    }

    /// Return the privacy preimage if this spending key has a corresponding
    /// receiving address.
    ///
    /// note: The hash of the preimage is available in the receiving address
    /// as the privacy_digest
    pub fn privacy_preimage(&self) -> Option<Digest> {
        match self {
            Self::Generation(k) => Some(k.privacy_preimage()),
            Self::Symmetric(k) => Some(k.privacy_preimage()),
            Self::RawHashLock { .. } => None,
        }
    }

    /// Return the receiver_identifier if this spending key has a corresponding
    /// receiving address.
    ///
    /// The receiver identifier is a public (=readably by anyone) fingerprint of
    /// the beneficiary's receiving address. It is used to efficiently scan
    /// incoming blocks for new UTXOs that are destined for this key.
    ///
    /// However, the fingerprint can *also* be used to link different payments
    /// to the same address as payments to the same person. Users who want to
    /// avoid this linkability must generate a new address. Down the line we
    /// expect to support address formats that do not come with fingerprints,
    /// and users can enable them for better privacy in exchange for the
    /// increased workload associated with detecting incoming UTXOs.
    pub fn receiver_identifier(&self) -> Option<BFieldElement> {
        match self {
            Self::Generation(k) => Some(k.receiver_identifier()),
            Self::Symmetric(k) => Some(k.receiver_identifier()),
            Self::RawHashLock { .. } => None,
        }
    }

    /// Decrypt a slice of BFieldElement into a [Utxo] and [Digest] representing
    /// `sender_randomness`, if this spending key has a corresponding receiving
    /// address.
    ///
    /// # Return Value
    ///
    ///  - `None` if this spending key has no associated receiving address.
    ///  - `Some(Err(..))` if decryption failed.
    ///  - `Some(Ok(..))` if decryption succeeds.
    pub fn decrypt(&self, ciphertext_bfes: &[BFieldElement]) -> Option<Result<(Utxo, Digest)>> {
        let result = match self {
            Self::Generation(k) => k.decrypt(ciphertext_bfes),
            Self::Symmetric(k) => k.decrypt(ciphertext_bfes).map_err(anyhow::Error::new),
            Self::RawHashLock { .. } => {
                return None;
            }
        };
        Some(result)
    }

    /// Scans all public announcements in a `Transaction` and return all
    /// UTXOs that are recognized by this spending key.
    ///
    /// Note that a single `Transaction` may represent an entire block.
    ///
    /// # Side Effects
    ///
    ///  - Logs a warning for any announcement targeted at this key that cannot
    ///    be decrypted.
    pub(crate) fn scan_for_announced_utxos(
        &self,
        tx_kernel: &TransactionKernel,
    ) -> Vec<IncomingUtxo> {
        // pre-compute some fields, and early-abort if key cannot receive.
        let Some(receiver_identifier) = self.receiver_identifier() else {
            return vec![];
        };
        let Some(receiver_preimage) = self.privacy_preimage() else {
            return vec![];
        };

        // for all public announcements
        tx_kernel
            .public_announcements
            .iter()

            // ... that are marked as encrypted to our key type
            .filter(|pa| self.matches_public_announcement_key_type(pa))

            // ... that match the receiver_id of this key
            .filter(move |pa| {
                matches!(common::receiver_identifier_from_public_announcement(pa), Ok(r) if r == receiver_identifier)
            })

            // ... that have a ciphertext field
            .filter_map(|pa| self.ok_warn(common::ciphertext_from_public_announcement(pa)))

            // ... which can be decrypted with this key
            .filter_map(|c| self.ok_warn(self.decrypt(&c).expect("non-hash-lock key should have decryption option")))

            // ... map to IncomingUtxo
            .map(move |(utxo, sender_randomness)| {
                // and join those with the receiver digest to get a commitment
                // Note: the commitment is computed in the same way as in the mutator set.
                IncomingUtxo {
                    utxo,
                    sender_randomness,
                    receiver_preimage,
                }
            }).collect()
    }

    /// converts a result into an Option and logs a warning on any error
    fn ok_warn<T>(&self, result: Result<T>) -> Option<T> {
        let Some(receiver_identifier) = self.receiver_identifier() else {
            panic!("Cannot call `ok_warn` unless the spending key has an associated address.");
        };
        match result {
            Ok(v) => Some(v),
            Err(e) => {
                warn!("possible loss of funds! skipping public announcement for {:?} key with receiver_identifier: {}.  error: {}", BaseKeyType::from(self), receiver_identifier, e.to_string());
                None
            }
        }
    }

    /// returns true if the [PublicAnnouncement] has a type-flag that matches the type of this key
    fn matches_public_announcement_key_type(&self, pa: &PublicAnnouncement) -> bool {
        matches!(BaseKeyType::try_from(pa), Ok(kt) if kt == BaseKeyType::from(self))
    }
}
