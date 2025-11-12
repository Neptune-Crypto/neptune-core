use anyhow::bail;
use anyhow::Result;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::triton_vm::prelude::Digest;
use tracing::warn;

use super::common;
use super::generation_address;
use super::receiving_address::ReceivingAddress;
use super::symmetric_key;
use crate::protocol::consensus::transaction::announcement::Announcement;
use crate::protocol::consensus::transaction::lock_script::LockScript;
use crate::protocol::consensus::transaction::lock_script::LockScriptAndWitness;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel;
use crate::protocol::consensus::transaction::utxo::Utxo;
use crate::state::wallet::incoming_utxo::IncomingUtxo;
use crate::BFieldElement;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[cfg_attr(test, derive(strum::EnumIter))]
#[repr(u8)]
pub enum KeyType {
    /// [generation_address] built on [crate::prelude::twenty_first::math::lattice::kem]
    ///
    /// wraps a symmetric key built on aes-256-gcm
    Generation = generation_address::GENERATION_FLAG_U8,

    /// [symmetric_key] built on aes-256-gcm
    Symmetric = symmetric_key::SYMMETRIC_KEY_FLAG_U8,
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Generation => write!(f, "Generation"),
            Self::Symmetric => write!(f, "Symmetric"),
        }
    }
}

impl From<&ReceivingAddress> for KeyType {
    fn from(addr: &ReceivingAddress) -> Self {
        match addr {
            ReceivingAddress::Generation(_) => Self::Generation,
            ReceivingAddress::Symmetric(_) => Self::Symmetric,
        }
    }
}

impl From<&SpendingKey> for KeyType {
    fn from(addr: &SpendingKey) -> Self {
        match addr {
            SpendingKey::Generation(_) => Self::Generation,
            SpendingKey::Symmetric(_) => Self::Symmetric,
        }
    }
}

impl From<KeyType> for BFieldElement {
    fn from(key_type: KeyType) -> Self {
        (key_type as u8).into()
    }
}

impl TryFrom<&Announcement> for KeyType {
    type Error = anyhow::Error;

    fn try_from(pa: &Announcement) -> Result<Self> {
        match common::key_type_from_announcement(pa) {
            Ok(kt) if kt == Self::Generation.into() => Ok(Self::Generation),
            Ok(kt) if kt == Self::Symmetric.into() => Ok(Self::Symmetric),
            _ => bail!("encountered Announcement of unknown type"),
        }
    }
}

impl KeyType {
    /// returns all available `AddressableKeyType`
    pub fn all_types() -> Vec<KeyType> {
        vec![Self::Generation, Self::Symmetric]
    }
}

/// Represents cryptographic data necessary for spending funds (or, more
/// specifically, for unlocking UTXOs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpendingKey {
    /// a key from [generation_address]
    Generation(generation_address::GenerationSpendingKey),

    /// a [symmetric_key]
    Symmetric(symmetric_key::SymmetricKey),
}

impl std::hash::Hash for SpendingKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::hash::Hash::hash(&self.privacy_preimage(), state)
    }
}

impl From<generation_address::GenerationSpendingKey> for SpendingKey {
    fn from(key: generation_address::GenerationSpendingKey) -> Self {
        Self::Generation(key)
    }
}

impl From<symmetric_key::SymmetricKey> for SpendingKey {
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
impl SpendingKey {
    /// returns the address that corresponds to this spending key.
    pub fn to_address(self) -> ReceivingAddress {
        match self {
            Self::Generation(k) => k.to_address().into(),
            Self::Symmetric(k) => k.into(),
        }
    }

    /// Return the lock script and its witness
    pub(crate) fn lock_script_and_witness(&self) -> LockScriptAndWitness {
        match self {
            SpendingKey::Generation(generation_spending_key) => {
                generation_spending_key.lock_script_and_witness()
            }
            SpendingKey::Symmetric(symmetric_key) => symmetric_key.lock_script_and_witness(),
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
    pub fn privacy_preimage(&self) -> Digest {
        match self {
            Self::Generation(k) => k.receiver_preimage(),
            Self::Symmetric(k) => k.receiver_preimage(),
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
    pub fn receiver_identifier(&self) -> BFieldElement {
        match self {
            Self::Generation(k) => k.receiver_identifier(),
            Self::Symmetric(k) => k.receiver_identifier(),
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
    pub fn decrypt(&self, ciphertext_bfes: &[BFieldElement]) -> Result<(Utxo, Digest)> {
        match self {
            Self::Generation(k) => k.decrypt(ciphertext_bfes),
            Self::Symmetric(k) => k.decrypt(ciphertext_bfes).map_err(anyhow::Error::new),
        }
    }

    /// Scans all announcements in a `Transaction` and return all
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
        let receiver_identifier = self.receiver_identifier();
        let receiver_preimage = self.privacy_preimage();

        // for all announcements
        tx_kernel
            .announcements
            .iter()

            // ... that are marked as encrypted to our key type
            .filter(|pa| self.matches_announcement_key_type(pa))

            // ... that match the receiver_id of this key
            .filter(move |pa| {
                matches!(common::receiver_identifier_from_announcement(pa), Ok(r) if r == receiver_identifier)
            })

            // ... that have a ciphertext field
            .filter_map(|pa| self.ok_warn(common::ciphertext_from_announcement(pa)))

            // ... which can be decrypted with this key
            .filter_map(|c| self.ok_warn(self.decrypt(&c)))

            // ... map to IncomingUtxo
            .map(move |(utxo, sender_randomness)| {
                // and join those with the receiver digest to get a commitment
                // Note: the commitment is computed in the same way as in the mutator set.
                IncomingUtxo {
                    utxo,
                    sender_randomness,
                    receiver_preimage,
                    is_guesser_fee: false,
                }
            }).collect()
    }

    /// converts a result into an Option and logs a warning on any error
    fn ok_warn<T>(&self, result: Result<T>) -> Option<T> {
        match result {
            Ok(v) => Some(v),
            Err(e) => {
                warn!("possible loss of funds! skipping announcement for {:?} key with receiver_identifier: {}.  error: {}", KeyType::from(self), self.receiver_identifier(), e.to_string());
                None
            }
        }
    }

    /// returns true if the [Announcement] has a type-flag that matches the type of this key
    pub(super) fn matches_announcement_key_type(&self, pa: &Announcement) -> bool {
        matches!(KeyType::try_from(pa), Ok(kt) if kt == KeyType::from(self))
    }
}
