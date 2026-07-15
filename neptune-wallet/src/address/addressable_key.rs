use std::collections::HashMap;

use anyhow::bail;
use anyhow::Result;
use neptune_consensus::block::guesser_receiver_data::GuesserReceiverData;
use neptune_consensus::transaction::announcement::Announcement;
use neptune_consensus::transaction::lock_script::LockScript;
use neptune_consensus::transaction::lock_script::LockScriptAndWitness;
use neptune_consensus::transaction::transaction_kernel::TransactionKernel;
use neptune_consensus::transaction::utxo::Utxo;
use neptune_primitives::network::Network;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::triton_vm::prelude::BFieldElement;
use tasm_lib::triton_vm::prelude::Digest;
use tracing::warn;

use super::common;
use super::generation_address;
use super::receiving_address::ReceivingAddress;
use super::symmetric_key;
use crate::address::elliptic_curve_hybrid;
use crate::address::viewing_address;
use crate::incoming_utxo::IncomingUtxo;

#[derive(
    Debug,
    Clone,
    Copy,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Hash,
    strum::EnumString,
    strum::EnumIter,
)]
#[strum(serialize_all = "snake_case", ascii_case_insensitive)]
#[repr(u8)]
#[non_exhaustive]
pub enum KeyType {
    /// [generation_address] built on [tasm_lib::twenty_first::math::lattice::kem]
    ///
    /// wraps a symmetric key built on aes-256-gcm
    Generation = generation_address::GENERATION_FLAG_U8,

    /// [symmetric_key] built on aes-256-gcm
    Symmetric = symmetric_key::SYMMETRIC_KEY_FLAG_U8,

    /// Elliptic curve hybrid address.
    ///
    /// This address format should not be reused to request payments from
    /// multiple parties.
    ///
    /// If an attacker has a quantum computer *and* knows the address, they can
    /// see the entire transaction history of that address.
    EcHybrid = elliptic_curve_hybrid::ELLIPTIC_CURVE_HYBRID_ADDRESS_FLAG_U8,

    /// An address format that leaks transaction information to anyone who
    /// knows the address, if on-chain announcements are used.
    ///
    /// The notification encryption key is derived from the address through
    /// symmetric crypto only.
    ///
    /// This address format should not be reused to request payments from
    /// multiple parties.
    ///
    /// Attacker only needs to know the address in order to see the entire
    /// onchain transaction history of that address.
    ViewingAddress = viewing_address::VIEWING_ADDRESS_FLAG_U8,
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Generation => write!(f, "generation"),
            Self::Symmetric => write!(f, "symmetric"),
            Self::EcHybrid => write!(f, "ec_hybrid"),
            Self::ViewingAddress => write!(f, "viewing_address"),
        }
    }
}

impl From<&ReceivingAddress> for KeyType {
    fn from(addr: &ReceivingAddress) -> Self {
        match addr {
            ReceivingAddress::Generation(_) => Self::Generation,
            ReceivingAddress::Symmetric(_) => Self::Symmetric,
            ReceivingAddress::EcHybrid(_) => Self::EcHybrid,
            ReceivingAddress::ViewingAddress(_) => Self::ViewingAddress,
        }
    }
}

impl From<&SpendingKey> for KeyType {
    fn from(addr: &SpendingKey) -> Self {
        match addr {
            SpendingKey::Generation(_) => Self::Generation,
            SpendingKey::Symmetric(_) => Self::Symmetric,
            SpendingKey::EcHybrid(_) => Self::EcHybrid,
            SpendingKey::ViewingAddressKey(_) => Self::ViewingAddress,
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
            Ok(kt) if kt == Self::EcHybrid.into() => Ok(Self::EcHybrid),
            Ok(kt) if kt == Self::ViewingAddress.into() => Ok(Self::ViewingAddress),
            _ => bail!("encountered Announcement of unknown type"),
        }
    }
}

impl KeyType {
    /// returns human-readable-prefix (hrp) for a given network
    pub fn get_hrp(&self, network: Network) -> String {
        match self {
            Self::Generation => generation_address::GenerationReceivingAddress::get_hrp(network),
            Self::Symmetric => symmetric_key::SymmetricKey::get_hrp(network),
            Self::EcHybrid => elliptic_curve_hybrid::EcHybridAddress::get_hrp(network),
            Self::ViewingAddress => viewing_address::ViewingAddress::get_hrp(network),
        }
    }
}

/// Represents cryptographic data necessary for spending funds (or, more
/// specifically, for unlocking UTXOs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SpendingKey {
    /// A key from [generation_address]
    Generation(generation_address::GenerationSpendingKey),

    /// A [symmetric_key]
    Symmetric(symmetric_key::SymmetricKey),

    /// An elliptic curve hybrid key
    EcHybrid(elliptic_curve_hybrid::EcHybridKey),

    /// A key for a "viewing address"
    ViewingAddressKey(viewing_address::ViewingAddressKey),
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

impl From<elliptic_curve_hybrid::EcHybridKey> for SpendingKey {
    fn from(key: elliptic_curve_hybrid::EcHybridKey) -> Self {
        Self::EcHybrid(key)
    }
}

impl From<viewing_address::ViewingAddressKey> for SpendingKey {
    fn from(key: viewing_address::ViewingAddressKey) -> Self {
        Self::ViewingAddressKey(key)
    }
}

// future improvements: a strong argument can be made that this type
// (and the key types it wraps) should not have any methods with
// outside types as parameters.  for example:
//
// pub fn scan_for_announced_utxos(
//     &self,
//     tx_kernel: &TransactionKernel,
// ) -> Vec<IncomingUtxo> {
//
// this method is dealing with types far outside the concern of
// a key, which means this method belongs elsewhere.
impl SpendingKey {
    /// returns the address that corresponds to this spending key.
    pub fn to_address(&self) -> ReceivingAddress {
        match self {
            Self::Generation(k) => k.to_address().into(),
            Self::Symmetric(k) => k.into(),
            Self::EcHybrid(k) => k.to_address().into(),
            Self::ViewingAddressKey(k) => k.to_address().into(),
        }
    }

    /// Export the viewing key that corresponds to this spending key, encoded as
    /// bech32m.
    ///
    /// A viewing key grants the ability to recognize incoming UTXOs without the
    /// ability to spend them. Only some key types support viewing keys; for the
    /// rest this returns an error. Currently only the EC hybrid and viewing
    /// address key types are supported.
    pub fn to_viewing_key_bech32m(&self, network: Network) -> Result<String> {
        match self {
            Self::EcHybrid(k) => Ok(k.viewing_key().to_bech32m(network)),
            // For a viewing address, the address *is* the viewing key.
            Self::ViewingAddressKey(k) => Ok(k.to_address().to_bech32m(network)),
            Self::Generation(_) | Self::Symmetric(_) => bail!(
                "Key type {} does not support viewing keys.",
                KeyType::from(self)
            ),
        }
    }

    /// Return the lock script and its witness
    pub fn lock_script_and_witness(&self) -> LockScriptAndWitness {
        match self {
            SpendingKey::Generation(generation_spending_key) => {
                generation_spending_key.lock_script_and_witness()
            }
            SpendingKey::Symmetric(symmetric_key) => symmetric_key.lock_script_and_witness(),
            SpendingKey::EcHybrid(key) => key.lock_script_and_witness(),
            SpendingKey::ViewingAddressKey(key) => key.lock_script_and_witness(),
        }
    }

    pub fn lock_script(&self) -> LockScript {
        LockScript {
            program: self.lock_script_and_witness().program,
        }
    }

    pub fn lock_script_hash(&self) -> Digest {
        self.lock_script().hash()
    }

    /// The [`GuesserReceiverData`] that locks a block's guesser-fee reward to
    /// this key.
    ///
    /// Equivalent to `GuesserReceiverData::from(self.to_address())`, but derived
    /// straight from the key's hash-based lock and receiver preimage — avoiding
    /// the expensive lattice-KEM key derivation performed by
    /// [`Self::to_address`], for generation keys.
    pub fn guesser_receiver_data(&self) -> GuesserReceiverData {
        GuesserReceiverData {
            receiver_digest: self.privacy_preimage().hash(),
            lock_script_hash: self.lock_script_hash(),
        }
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
            Self::EcHybrid(k) => k.receiver_preimage(),
            Self::ViewingAddressKey(k) => k.receiver_preimage(),
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
            Self::EcHybrid(k) => k.receiver_identifier(),
            Self::ViewingAddressKey(k) => k.receiver_identifier(),
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
            Self::EcHybrid(k) => k.viewing_key().decrypt(ciphertext_bfes),
            Self::ViewingAddressKey(k) => k.to_address().decrypt(ciphertext_bfes),
        }
    }

    /// Scans all announcements in a `Transaction` and return all
    /// UTXOs that are announced and recognized by this spending key. Does not
    /// verify that the announced UTXOs are actually present. This is the
    /// caller's responsibility..
    ///
    /// Note that a single `Transaction` may represent an entire block.
    ///
    /// # Side Effects
    ///
    ///  - Logs a warning for any announcement targeted at this key that cannot
    ///    be decrypted.
    ///
    /// # Warning
    ///
    /// Only scans the matching announcements. Does not verify that the
    /// announced UTXO is actually an output in the transaction.
    pub fn scan_for_announced_utxos(&self, tx_kernel: &TransactionKernel) -> Vec<IncomingUtxo> {
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

    /// Scan a transaction's announcements for UTXOs decryptable by any of the
    /// given keys.
    ///
    /// Equivalent to calling [`Self::scan_for_announced_utxos`] for each key and
    /// concatenating the results, but runs in `O(keys + announcements)` rather
    /// than `O(keys × announcements)`: an announcement names exactly one key via
    /// its receiver identifier, so the keys are indexed by that identifier and
    /// each announcement is matched with a single lookup.
    ///
    /// Does not verify that the announced UTXOs are actually outputs of the
    /// transaction; that is the caller's responsibility.
    pub fn scan_announcements_for_keys(
        announcements: &[Announcement],
        keys: impl IntoIterator<Item = SpendingKey>,
    ) -> Vec<IncomingUtxo> {
        // Index the keys by receiver identifier. A single identifier mapping to
        // more than one key is astronomically unlikely but handled for
        // correctness.
        let mut keys_by_receiver_id: HashMap<BFieldElement, Vec<SpendingKey>> = HashMap::new();
        for key in keys {
            keys_by_receiver_id
                .entry(key.receiver_identifier())
                .or_default()
                .push(key);
        }

        let mut incoming_utxos = vec![];
        for announcement in announcements {
            let Ok(receiver_identifier) =
                common::receiver_identifier_from_announcement(announcement)
            else {
                continue;
            };
            let Some(candidate_keys) = keys_by_receiver_id.get(&receiver_identifier) else {
                continue;
            };
            for key in candidate_keys {
                if let Some(incoming_utxo) = key.incoming_utxo_from_announcement(announcement) {
                    incoming_utxos.push(incoming_utxo);
                    // An announcement encrypts a UTXO to a single key.
                    break;
                }
            }
        }

        incoming_utxos
    }

    /// Decrypt a single announcement with this key, if it is of this key's type
    /// and decryptable.
    ///
    /// The caller is responsible for having matched the announcement's receiver
    /// identifier to this key (see [`Self::scan_announcements_for_keys`]); this
    /// method only checks the key-type flag and attempts decryption.
    fn incoming_utxo_from_announcement(&self, announcement: &Announcement) -> Option<IncomingUtxo> {
        if !self.matches_announcement_key_type(announcement) {
            return None;
        }
        let ciphertext = self.ok_warn(common::ciphertext_from_announcement(announcement))?;
        let (utxo, sender_randomness) = self.ok_warn(self.decrypt(&ciphertext))?;
        Some(IncomingUtxo {
            utxo,
            sender_randomness,
            receiver_preimage: self.privacy_preimage(),
            is_guesser_fee: false,
        })
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

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use strum::IntoEnumIterator;

    use super::*;

    impl SpendingKey {
        pub fn from_seed(seed: Digest, key_type: KeyType) -> Self {
            match key_type {
                KeyType::Generation => {
                    generation_address::GenerationSpendingKey::derive_from_seed(seed).into()
                }
                KeyType::Symmetric => symmetric_key::SymmetricKey::from_seed(seed).into(),
                KeyType::EcHybrid => elliptic_curve_hybrid::EcHybridKey::from_seed(seed).into(),
                KeyType::ViewingAddress => {
                    viewing_address::ViewingAddressKey::from_seed(seed).into()
                }
            }
        }
    }

    #[test]
    fn keytype_to_string_is_as_defined() {
        assert_eq!(KeyType::Generation.to_string(), "generation");
        assert_eq!(KeyType::Symmetric.to_string(), "symmetric");
    }

    #[test]
    fn keytype_from_str_works_when_all_lowercase() {
        assert_eq!(
            KeyType::Generation,
            KeyType::from_str("generation").unwrap()
        );
        assert_eq!(KeyType::Symmetric, KeyType::from_str("symmetric").unwrap());
        assert_eq!(KeyType::EcHybrid, KeyType::from_str("ec_hybrid").unwrap());
        assert_eq!(
            KeyType::ViewingAddress,
            KeyType::from_str("viewing_address").unwrap()
        );
    }

    #[test]
    fn keytype_string_roundtrip() {
        for v in KeyType::iter() {
            let as_str = v.to_string();
            println!("as_str: {as_str}");
            assert_eq!(v, KeyType::from_str(&as_str).unwrap());
        }
    }

    #[test]
    fn guesser_receiver_data_matches_address_derivation() {
        for seed in [Digest::default(), Digest::default().hash()] {
            for key_type in KeyType::iter() {
                let key = SpendingKey::from_seed(seed, key_type);
                assert_eq!(
                    GuesserReceiverData::from(key.to_address()),
                    key.guesser_receiver_data(),
                    "guesser_receiver_data mismatch for {key_type:?}",
                );
            }
        }
    }

    #[test]
    fn viewing_key_export_supported_only_for_ec_hybrid_and_viewing_address() {
        let network = Network::Main;
        let seed = Digest::default();

        // EC hybrid and viewing address support viewing keys and export as
        // bech32m with the expected human-readable prefixes.
        let ec_hybrid_vk = SpendingKey::from_seed(seed, KeyType::EcHybrid)
            .to_viewing_key_bech32m(network)
            .unwrap();
        assert!(ec_hybrid_vk.starts_with(elliptic_curve_hybrid::ECH_VIEWING_KEY_HRP_PREFIX));

        let viewing_address_vk = SpendingKey::from_seed(seed, KeyType::ViewingAddress)
            .to_viewing_key_bech32m(network)
            .unwrap();
        assert!(viewing_address_vk.starts_with(viewing_address::VIEWING_ADDRESS_HRP_PREFIX));

        // Generation and symmetric do not support viewing keys.
        assert!(SpendingKey::from_seed(seed, KeyType::Generation)
            .to_viewing_key_bech32m(network)
            .is_err());
        assert!(SpendingKey::from_seed(seed, KeyType::Symmetric)
            .to_viewing_key_bech32m(network)
            .is_err());
    }
}
