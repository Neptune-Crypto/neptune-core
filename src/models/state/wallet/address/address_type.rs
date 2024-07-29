//! provides an abstraction over key and address types.

use super::common;
use super::{generation_address, symmetric_key};
use crate::config_models::network::Network;
use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::transaction::utxo::LockScript;
use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::blockchain::transaction::AnnouncedUtxo;
use crate::models::blockchain::transaction::PublicAnnouncement;
use crate::models::blockchain::transaction::Transaction;
use crate::prelude::twenty_first;
use crate::util_types::mutator_set::commit;
use crate::BFieldElement;
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use tasm_lib::triton_vm::prelude::Digest;
use tracing::warn;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;

// note: assigning the flags to `KeyType` variants as discriminants has bonus
// that we get a compiler verification that values do not conflict.  which is
// nice since they are (presently) defined in separate files.
//
// anyway it is a desirable property that KeyType variants match the values
// actually stored in PublicAnnouncement.

/// enumerates available cryptographic key implementations for sending and receiving funds.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[repr(u8)]
pub enum KeyType {
    /// [generation_address] built on [twenty_first::math::lattice::kem]
    ///
    /// wraps a symmetric key built on aes-256-gcm
    Generation = generation_address::GENERATION_FLAG_U8,

    /// [symmetric_key] built on aes-256-gcm
    Symmetric = symmetric_key::SYMMETRIC_KEY_FLAG_U8,
}

impl From<&ReceivingAddressType> for KeyType {
    fn from(addr: &ReceivingAddressType) -> Self {
        match addr {
            ReceivingAddressType::Generation(_) => Self::Generation,
            ReceivingAddressType::Symmetric(_) => Self::Symmetric,
        }
    }
}

impl From<&SpendingKeyType> for KeyType {
    fn from(addr: &SpendingKeyType) -> Self {
        match addr {
            SpendingKeyType::Generation(_) => Self::Generation,
            SpendingKeyType::Symmetric(_) => Self::Symmetric,
        }
    }
}

impl From<KeyType> for BFieldElement {
    fn from(key_type: KeyType) -> Self {
        (key_type as u8).into()
    }
}

impl TryFrom<&PublicAnnouncement> for KeyType {
    type Error = anyhow::Error;

    fn try_from(pa: &PublicAnnouncement) -> Result<Self> {
        match common::key_type_from_public_announcement(pa) {
            Ok(kt) if kt == Self::Generation.into() => Ok(Self::Generation),
            Ok(kt) if kt == Self::Symmetric.into() => Ok(Self::Symmetric),
            _ => bail!("encountered PublicAnnouncement of unknown type"),
        }
    }
}

impl KeyType {
    /// returns all available `KeyType`
    pub fn all_types() -> Vec<KeyType> {
        vec![Self::Generation, Self::Symmetric]
    }
}

/// Represents any type of Neptune receiving Address.
///
/// This enum provides an abstraction API for Address types, so that
/// a method or struct may simply accept a `ReceivingAddressType` and be
/// forward-compatible with new types of Address as they are implemented.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReceivingAddressType {
    /// a [generation_address]
    Generation(Box<generation_address::ReceivingAddress>),

    /// a [symmetric_key] acting as an address.
    Symmetric(symmetric_key::SymmetricKey),
}

impl From<generation_address::ReceivingAddress> for ReceivingAddressType {
    fn from(a: generation_address::ReceivingAddress) -> Self {
        Self::Generation(Box::new(a))
    }
}

impl From<&generation_address::ReceivingAddress> for ReceivingAddressType {
    fn from(a: &generation_address::ReceivingAddress) -> Self {
        Self::Generation(Box::new(*a))
    }
}

impl From<symmetric_key::SymmetricKey> for ReceivingAddressType {
    fn from(k: symmetric_key::SymmetricKey) -> Self {
        Self::Symmetric(k)
    }
}

impl From<&symmetric_key::SymmetricKey> for ReceivingAddressType {
    fn from(k: &symmetric_key::SymmetricKey) -> Self {
        Self::Symmetric(*k)
    }
}

impl TryFrom<ReceivingAddressType> for generation_address::ReceivingAddress {
    type Error = anyhow::Error;

    fn try_from(a: ReceivingAddressType) -> Result<Self> {
        match a {
            ReceivingAddressType::Generation(a) => Ok(*a),
            _ => bail!("not a generation address"),
        }
    }
}

impl ReceivingAddressType {
    /// returns `receiver_identifer`
    pub fn receiver_identifier(&self) -> BFieldElement {
        match self {
            Self::Generation(a) => a.receiver_identifier,
            Self::Symmetric(a) => a.receiver_identifier(),
        }
    }

    /// generates a [PublicAnnouncement] for an output Utxo
    ///
    /// The public announcement contains a Vec<BFieldElement] with fields:
    ///   0    --> type flag.  (SYMMETRIC_KEY_FLAG)
    ///   1    --> receiver_identifier  (fingerprint derived from seed)
    ///   2..n --> ciphertext (encrypted utxo + sender_randomness)
    ///
    /// Fields |0,1| enable the receiver to determine the ciphertext
    /// is intended for them and decryption should be attempted.
    pub fn generate_public_announcement(
        &self,
        utxo: &Utxo,
        sender_randomness: Digest,
    ) -> Result<PublicAnnouncement> {
        let ciphertext = [
            &[KeyType::from(self).into(), self.receiver_identifier()],
            self.encrypt(utxo, sender_randomness)?.as_slice(),
        ]
        .concat();
        Ok(PublicAnnouncement::new(ciphertext))
    }

    /// returns the `spending_lock`
    pub fn spending_lock(&self) -> Digest {
        match self {
            Self::Generation(a) => a.spending_lock,
            Self::Symmetric(k) => k.spending_lock(),
        }
    }

    /// returns a privacy digest which corresponds to the privacy_preimage
    /// of the matching [SpendingKeyType]
    pub fn privacy_digest(&self) -> Digest {
        match self {
            Self::Generation(a) => a.privacy_digest,
            Self::Symmetric(k) => k.privacy_digest(),
        }
    }

    /// encrypts a [Utxo] and `sender_randomness` secret for purpose of transferring to payment recipient
    pub fn encrypt(&self, utxo: &Utxo, sender_randomness: Digest) -> Result<Vec<BFieldElement>> {
        match self {
            Self::Generation(a) => a.encrypt(utxo, sender_randomness),
            Self::Symmetric(a) => Ok(a.encrypt(utxo, sender_randomness)?),
        }
    }

    /// encodes this address as bech32m
    ///
    /// note: this will return an error for symmetric keys as they do not impl
    ///       bech32m at present.  There is no need to give them out to 3rd
    ///       parties in a serialized form.
    pub fn to_bech32m(&self, network: Network) -> Result<String> {
        match self {
            Self::Generation(k) => k.to_bech32m(network),
            Self::Symmetric(_k) => bail!("bech32m not implemented for symmetric keys"),
        }
    }

    /// parses an address from its bech32m encoding
    ///
    /// note: this will fail for Symmetric keys which do not impl bech32m
    ///       at present.  There is no need to give them out to 3rd parties
    ///       in a serialized form.
    pub fn from_bech32m(encoded: &str, network: Network) -> Result<Self> {
        let addr = generation_address::ReceivingAddress::from_bech32m(encoded, network)?;
        Ok(addr.into())

        // when future addr types are supported, we would attempt each type in
        // turn.

        // note: not implemented for SymmetricKey (yet?)
    }

    /// generates a lock script from the spending lock.
    ///
    /// Satisfaction of this lock script establishes the UTXO owner's assent to
    /// the transaction.
    pub fn lock_script(&self) -> LockScript {
        match self {
            Self::Generation(k) => k.lock_script(),
            Self::Symmetric(k) => k.lock_script(),
        }
    }

    /// returns true if the [PublicAnnouncement] has a type-flag that matches the type of this address.
    pub fn matches_public_announcement_key_type(&self, pa: &PublicAnnouncement) -> bool {
        matches!(KeyType::try_from(pa), Ok(kt) if kt == KeyType::from(self))
    }
}

/// Represents any type of Neptune spending key.
///
/// This enum provides an abstraction API for spending key types, so that a
/// method or struct may simply accept a `SpendingKeyType` and be
/// forward-compatible with new types of spending key as they are implemented.
#[derive(Debug, Clone, Copy)]
pub enum SpendingKeyType {
    /// a key from [generation_address]
    Generation(generation_address::SpendingKey),

    /// a [symmetric_key]
    Symmetric(symmetric_key::SymmetricKey),
}

impl From<generation_address::SpendingKey> for SpendingKeyType {
    fn from(key: generation_address::SpendingKey) -> Self {
        Self::Generation(key)
    }
}

impl From<symmetric_key::SymmetricKey> for SpendingKeyType {
    fn from(key: symmetric_key::SymmetricKey) -> Self {
        Self::Symmetric(key)
    }
}

impl SpendingKeyType {
    /// returns the address that corresponds to this spending key.
    pub fn to_address(&self) -> ReceivingAddressType {
        match self {
            Self::Generation(k) => k.to_address().into(),
            Self::Symmetric(k) => (*k).into(),
        }
    }

    /// returns the privacy preimage.
    ///
    /// note: The hash of the preimage is available in the receiving address
    /// as the privacy_digest
    pub fn privacy_preimage(&self) -> Digest {
        match self {
            Self::Generation(k) => k.privacy_preimage,
            Self::Symmetric(k) => k.privacy_preimage(),
        }
    }

    /// returns the receiver_identifier, a public fingerprint
    pub fn receiver_identifier(&self) -> BFieldElement {
        match self {
            Self::Generation(k) => k.receiver_identifier,
            Self::Symmetric(k) => k.receiver_identifier(),
        }
    }

    /// returns unlock_key needed for transaction witnesses
    pub fn unlock_key(&self) -> Digest {
        match self {
            Self::Generation(k) => k.unlock_key,
            Self::Symmetric(k) => k.unlock_key(),
        }
    }

    /// decrypts an array of BFieldElement into a [Utxo] and [Digest] representing `sender_randomness`.
    pub fn decrypt(&self, ciphertext_bfes: &[BFieldElement]) -> Result<(Utxo, Digest)> {
        match self {
            Self::Generation(k) => k.decrypt(ciphertext_bfes),
            Self::Symmetric(k) => Ok(k.decrypt(ciphertext_bfes)?),
        }
    }

    /// scans public announcements in a [Transaction] and finds any that match this key
    ///
    /// note that a single [Transaction] may represent an entire block
    ///
    /// returns an iterator over [AnnouncedUtxo]
    ///
    /// side-effect: logs a warning for any announcement targeted at this key
    /// that cannot be decypted.
    pub fn scan_for_announced_utxos<'a>(
        &'a self,
        transaction: &'a Transaction,
    ) -> impl Iterator<Item = AnnouncedUtxo> + 'a {
        // pre-compute some fields.
        let receiver_identifier = self.receiver_identifier();
        let receiver_preimage = self.privacy_preimage();
        let receiver_digest = receiver_preimage.hash::<Hash>();

        // for all public announcements
        transaction
            .kernel
            .public_announcements
            .iter()

            // ... that are marked as encrypted to our key type
            .filter(|pa| self.matches_public_announcement_key_type(pa))

            // ... that match the receiver_id of this key
            .filter(move |pa| {
                matches!(common::receiver_identifier_from_public_announcement(pa), Ok(r) if r == receiver_identifier)
            })

            // ... that have a ciphertext field
            .filter_map(|pa| self.ok_warn(common::ciphertext_from_public_announcement(pa)) )

            // ... which can be decrypted with this key
            .filter_map(|c| self.ok_warn(self.decrypt(&c)))

            // ... map to AnnouncedUtxo
            .map(move |(utxo, sender_randomness)| {
                // and join those with the receiver digest to get a commitment
                // Note: the commitment is computed in the same way as in the mutator set.
                AnnouncedUtxo {
                    addition_record: commit(Hash::hash(&utxo), sender_randomness, receiver_digest),
                    utxo,
                    sender_randomness,
                    receiver_preimage,
                }
            })
    }

    /// converts a result into an Option and logs a warning on any error
    fn ok_warn<T>(&self, result: Result<T>) -> Option<T> {
        match result {
            Ok(v) => Some(v),
            Err(e) => {
                warn!("possible loss of funds! skipping public announcement for symmetric key with receiver_identifier: {}.  error: {}", self.receiver_identifier(), e.to_string());
                None
            }
        }
    }

    /// returns true if the [PublicAnnouncement] has a type-flag that matches the type of this key
    fn matches_public_announcement_key_type(&self, pa: &PublicAnnouncement) -> bool {
        matches!(KeyType::try_from(pa), Ok(kt) if kt == KeyType::from(self))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
    use crate::tests::shared::make_mock_transaction;
    use generation_address::ReceivingAddress;
    use generation_address::SpendingKey;
    use itertools::Itertools;
    use proptest_arbitrary_interop::arb;
    use rand::random;
    use rand::thread_rng;
    use rand::Rng;
    use symmetric_key::SymmetricKey;
    use test_strategy::proptest;

    /// tests scanning for announced utxos with a symmetric key
    #[proptest]
    fn scan_for_announced_utxos_symmetric(#[strategy(arb())] seed: Digest) {
        worker::scan_for_announced_utxos(SymmetricKey::from_seed(seed).into())
    }

    /// tests scanning for announced utxos with an asymmetric (generation) key
    #[proptest]
    fn scan_for_announced_utxos_generation(#[strategy(arb())] seed: Digest) {
        worker::scan_for_announced_utxos(SpendingKey::derive_from_seed(seed).into())
    }

    /// tests encrypting and decrypting with a symmetric key
    #[proptest]
    fn test_encrypt_decrypt_symmetric(#[strategy(arb())] seed: Digest) {
        worker::test_encrypt_decrypt(SymmetricKey::from_seed(seed).into())
    }

    /// tests encrypting and decrypting with an asymmetric (generation) key
    #[proptest]
    fn test_encrypt_decrypt_generation(#[strategy(arb())] seed: Digest) {
        worker::test_encrypt_decrypt(SpendingKey::derive_from_seed(seed).into())
    }

    /// tests keygen, sign, and verify with a symmetric key
    #[proptest]
    fn test_keygen_sign_verify_symmetric(#[strategy(arb())] seed: Digest) {
        worker::test_keygen_sign_verify(
            SymmetricKey::from_seed(seed).into(),
            SymmetricKey::from_seed(seed).into(),
        );
    }

    /// tests keygen, sign, and verify with an asymmetric (generation) key
    #[proptest]
    fn test_keygen_sign_verify_generation(#[strategy(arb())] seed: Digest) {
        worker::test_keygen_sign_verify(
            SpendingKey::derive_from_seed(seed).into(),
            ReceivingAddress::derive_from_seed(seed).into(),
        );
    }

    /// tests bech32m serialize, deserialize with a symmetric key
    #[should_panic(expected = "bech32m not implemented for symmetric keys")]
    #[proptest]
    fn test_bech32m_conversion_symmetric(#[strategy(arb())] seed: Digest) {
        worker::test_bech32m_conversion(SymmetricKey::from_seed(seed).into());
    }

    /// tests bech32m serialize, deserialize with an asymmetric (generation) key
    #[proptest]
    fn test_bech32m_conversion_generation(#[strategy(arb())] seed: Digest) {
        worker::test_bech32m_conversion(ReceivingAddress::derive_from_seed(seed).into());
    }

    mod worker {
        use super::*;

        /// this tests the generate_public_announcement() and
        /// scan_for_announced_utxos() methods with a [SpendingKeyType]
        ///
        /// a PublicAnnouncement is created with generate_public_announcement() and
        /// added to a Tx.  It is then found by scanning for announced_utoxs.  Then
        /// we verify that the data matches the original/expected values.
        pub fn scan_for_announced_utxos(key: SpendingKeyType) {
            // 1. generate a utxo with amount = 10
            let utxo = Utxo::new_native_coin(key.to_address().lock_script(), NeptuneCoins::new(10));

            // 2. generate sender randomness
            let sender_randomness: Digest = random();

            // 3. create an addition record to verify against later.
            let expected_addition_record = commit(
                Hash::hash(&utxo),
                sender_randomness,
                key.to_address().privacy_digest(),
            );

            // 4. create a mock tx with no inputs or outputs
            let mut mock_tx = make_mock_transaction(vec![], vec![]);

            // 5. verify that no announced utxos exist for this key
            assert!(key
                .scan_for_announced_utxos(&mock_tx)
                .collect_vec()
                .is_empty());

            // 6. generate a public announcement for this address
            let public_announcement = key
                .to_address()
                .generate_public_announcement(&utxo, sender_randomness)
                .unwrap();

            // 7. verify that the public_announcement is marked as our key type.
            assert!(key.matches_public_announcement_key_type(&public_announcement));

            // 8. add the public announcement to the mock tx.
            mock_tx
                .kernel
                .public_announcements
                .push(public_announcement);

            // 9. scan tx public announcements for announced utxos
            let announced_utxos = key.scan_for_announced_utxos(&mock_tx).collect_vec();

            // 10. verify there is exactly 1 announced_utxo and obtain it.
            assert_eq!(1, announced_utxos.len());
            let announced_utxo = announced_utxos.into_iter().next().unwrap();

            // 11. verify each field of the announced_utxo matches original values.
            assert_eq!(utxo, announced_utxo.utxo);
            assert_eq!(expected_addition_record, announced_utxo.addition_record);
            assert_eq!(sender_randomness, announced_utxo.sender_randomness);
            assert_eq!(key.privacy_preimage(), announced_utxo.receiver_preimage);
        }

        /// This tests encrypting and decrypting with a [SpendingKeyType]
        pub fn test_encrypt_decrypt(key: SpendingKeyType) {
            let mut rng = thread_rng();

            // 1. create utxo with random amount
            let amount = NeptuneCoins::new(rng.gen_range(0..42000000));
            let utxo = Utxo::new_native_coin(key.to_address().lock_script(), amount);

            // 2. generate sender randomness
            let sender_randomness: Digest = random();

            // 3. encrypt secrets (utxo, sender_randomness)
            let ciphertext = key.to_address().encrypt(&utxo, sender_randomness).unwrap();
            println!("ciphertext.get_size() = {}", ciphertext.len() * 8);

            // 4. decrypt secrets
            let (utxo_again, sender_randomness_again) = key.decrypt(&ciphertext).unwrap();

            // 5. verify that decrypted secrets match original secrets
            assert_eq!(utxo, utxo_again);
            assert_eq!(sender_randomness, sender_randomness_again);
        }

        /// tests key generation, signing, and decrypting with a [SpendingKeyType]
        ///
        /// note: key generation is performed by the caller. Both the
        /// spending_key and receiving_address must be independently derived from
        /// the same seed.
        pub fn test_keygen_sign_verify(
            spending_key: SpendingKeyType,
            receiving_address: ReceivingAddressType,
        ) {
            // 1. prepare a (random) message and witness data.
            let msg: Digest = random();
            let witness_data = common::test::binding_unlock(spending_key.unlock_key(), msg);

            // 2. perform mock proof verification
            assert!(common::test::std_lockscript_reference_verify_unlock(
                receiving_address.spending_lock(),
                msg,
                witness_data
            ));

            // 3. convert spending key to an address.
            let receiving_address_again = spending_key.to_address();

            // 4. verify that both address match.
            assert_eq!(receiving_address, receiving_address_again);
        }

        /// tests bech32m serialize, deserialize for [ReceivingAddressType]
        pub fn test_bech32m_conversion(receiving_address: ReceivingAddressType) {
            // 1. serialize address to bech32m
            let encoded = receiving_address.to_bech32m(Network::Testnet).unwrap();

            // 2. deserialize bech32m back into an address
            let receiving_address_again =
                ReceivingAddressType::from_bech32m(&encoded, Network::Testnet).unwrap();

            // 3. verify both addresses match
            assert_eq!(receiving_address, receiving_address_again);
        }
    }
}
