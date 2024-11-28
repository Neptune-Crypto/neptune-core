//! provides an abstraction over key and address types.

use anyhow::bail;
use anyhow::Result;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::triton_vm::prelude::Digest;
use tracing::warn;

use super::common;
use super::generation_address;
use super::symmetric_key;
use crate::config_models::network::Network;
use crate::models::blockchain::transaction::lock_script::LockScript;
use crate::models::blockchain::transaction::lock_script::LockScriptAndWitness;
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernel;
use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::blockchain::transaction::AnnouncedUtxo;
use crate::models::blockchain::transaction::PublicAnnouncement;
use crate::models::state::wallet::transaction_output::UtxoNotificationPayload;
use crate::BFieldElement;

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
/// a method or struct may simply accept a `ReceivingAddress` and be
/// forward-compatible with new types of Address as they are implemented.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
        match a {
            ReceivingAddress::Generation(a) => Ok(*a),
            _ => bail!("not a generation address"),
        }
    }
}

impl ReceivingAddress {
    /// returns `receiver_identifer`
    pub fn receiver_identifier(&self) -> BFieldElement {
        match self {
            Self::Generation(a) => a.receiver_identifier,
            Self::Symmetric(a) => a.receiver_identifier(),
        }
    }

    /// generates a [PublicAnnouncement] for an output Utxo
    ///
    /// The public announcement contains a Vec<BFieldElement> with fields:
    ///   0    --> type flag.  (flag of key type)
    ///   1    --> receiver_identifier  (fingerprint derived from seed)
    ///   2..n --> ciphertext (encrypted utxo + sender_randomness)
    ///
    /// Fields |0,1| enable the receiver to determine the ciphertext
    /// is intended for them and decryption should be attempted.
    pub(crate) fn generate_public_announcement(
        &self,
        utxo_notification_payload: UtxoNotificationPayload,
    ) -> PublicAnnouncement {
        match self {
            ReceivingAddress::Generation(generation_receiving_address) => {
                generation_receiving_address
                    .generate_public_announcement(&utxo_notification_payload)
            }
            ReceivingAddress::Symmetric(symmetric_key) => {
                symmetric_key.generate_public_announcement(&utxo_notification_payload)
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
            Self::Generation(a) => a.spending_lock,
            Self::Symmetric(k) => k.spending_lock(),
        }
    }

    /// returns a privacy digest which corresponds to the privacy_preimage
    /// of the matching [SpendingKey]
    pub fn privacy_digest(&self) -> Digest {
        match self {
            Self::Generation(a) => a.privacy_digest,
            Self::Symmetric(k) => k.privacy_digest(),
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
    /// note: this will return an error for symmetric keys as they do not impl
    ///       bech32m at present.  There is no need to give them out to 3rd
    ///       parties in a serialized form.
    pub fn to_bech32m(&self, network: Network) -> Result<String> {
        match self {
            Self::Generation(k) => k.to_bech32m(network),
            Self::Symmetric(k) => k.to_bech32m(network),
        }
    }

    /// returns an abbreviated address.
    ///
    /// The idea is that this suitable for human recognition purposes
    ///
    /// ```text
    /// format:  <hrp><start>...<end>
    ///
    ///   [4 or 6] human readable prefix. 4 for symmetric-key, 6 for generation.
    ///   8 start of address.
    ///   8 end of address.
    /// ```
    ///
    /// security: note that if this is used on a symmetric key it will display 16 chars
    /// of the bech32m encoded key.  This seriously reduces the key's strength and it
    /// may be possible to brute-force it.  In general it is best practice to avoid
    /// display of any part of a symmetric key.
    ///
    /// todo:
    ///
    /// it would be nice to standardize on a single prefix-len.  6 chars seems a
    /// bit much.  maybe we could shorten generation prefix to 4 somehow, eg:
    /// ngkm --> neptune-generation-key-mainnet
    pub fn to_bech32m_abbreviated(&self, network: Network) -> Result<String> {
        let bech32 = self.to_bech32m(network)?;
        let first_len = self.get_hrp(network).len() + 8usize;
        let last_len = 8usize;

        assert!(bech32.len() > first_len + last_len);

        let (first, _) = bech32.split_at(first_len);
        let (_, last) = bech32.split_at(bech32.len() - last_len);

        Ok(format!("{}...{}", first, last))
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
/// method or struct may simply accept a `SpendingKey` and be
/// forward-compatible with new types of spending key as they are implemented.
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

impl SpendingKey {
    /// returns the address that corresponds to this spending key.
    pub fn to_address(&self) -> ReceivingAddress {
        match self {
            Self::Generation(k) => k.to_address().into(),
            Self::Symmetric(k) => (*k).into(),
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
        tx_kernel: &'a TransactionKernel,
    ) -> impl Iterator<Item = AnnouncedUtxo> + 'a {
        // pre-compute some fields.
        let receiver_identifier = self.receiver_identifier();
        let receiver_preimage = self.privacy_preimage();

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
            .filter_map(|c| self.ok_warn(self.decrypt(&c)))

            // ... map to AnnouncedUtxo
            .map(move |(utxo, sender_randomness)| {
                // and join those with the receiver digest to get a commitment
                // Note: the commitment is computed in the same way as in the mutator set.
                AnnouncedUtxo {
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
                warn!("possible loss of funds! skipping public announcement for {:?} key with receiver_identifier: {}.  error: {}", KeyType::from(self), self.receiver_identifier(), e.to_string());
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
    use generation_address::GenerationReceivingAddress;
    use generation_address::GenerationSpendingKey;
    use itertools::Itertools;
    use proptest_arbitrary_interop::arb;
    use rand::random;
    use rand::thread_rng;
    use rand::Rng;
    use symmetric_key::SymmetricKey;
    use test_strategy::proptest;

    use super::*;
    use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
    use crate::tests::shared::make_mock_transaction;

    /// tests scanning for announced utxos with a symmetric key
    #[proptest]
    fn scan_for_announced_utxos_symmetric(#[strategy(arb())] seed: Digest) {
        worker::scan_for_announced_utxos(SymmetricKey::from_seed(seed).into())
    }

    /// tests scanning for announced utxos with an asymmetric (generation) key
    #[proptest]
    fn scan_for_announced_utxos_generation(#[strategy(arb())] seed: Digest) {
        worker::scan_for_announced_utxos(GenerationSpendingKey::derive_from_seed(seed).into())
    }

    /// tests encrypting and decrypting with a symmetric key
    #[proptest]
    fn test_encrypt_decrypt_symmetric(#[strategy(arb())] seed: Digest) {
        worker::test_encrypt_decrypt(SymmetricKey::from_seed(seed).into())
    }

    /// tests encrypting and decrypting with an asymmetric (generation) key
    #[proptest]
    fn test_encrypt_decrypt_generation(#[strategy(arb())] seed: Digest) {
        worker::test_encrypt_decrypt(GenerationSpendingKey::derive_from_seed(seed).into())
    }

    /// tests keygen, sign, and verify with a symmetric key
    #[proptest]
    fn test_keygen_sign_verify_symmetric(#[strategy(arb())] seed: Digest) {
        worker::test_keypair_validity(
            SymmetricKey::from_seed(seed).into(),
            SymmetricKey::from_seed(seed).into(),
        );
    }

    /// tests keygen, sign, and verify with an asymmetric (generation) key
    #[proptest]
    fn test_keygen_sign_verify_generation(#[strategy(arb())] seed: Digest) {
        worker::test_keypair_validity(
            GenerationSpendingKey::derive_from_seed(seed).into(),
            GenerationReceivingAddress::derive_from_seed(seed).into(),
        );
    }

    /// tests bech32m serialize, deserialize with a symmetric key
    #[proptest]
    fn test_bech32m_conversion_symmetric(#[strategy(arb())] seed: Digest) {
        worker::test_bech32m_conversion(SymmetricKey::from_seed(seed).into());
    }

    /// tests bech32m serialize, deserialize with an asymmetric (generation) key
    #[proptest]
    fn test_bech32m_conversion_generation(#[strategy(arb())] seed: Digest) {
        worker::test_bech32m_conversion(GenerationReceivingAddress::derive_from_seed(seed).into());
    }

    mod worker {
        use super::*;
        use crate::models::blockchain::transaction::transaction_kernel::TransactionKernelModifier;
        use crate::prelude::twenty_first::prelude::Tip5;
        use crate::prelude::twenty_first::util_types::algebraic_hasher::AlgebraicHasher;
        use crate::util_types::mutator_set::commit;

        /// this tests the generate_public_announcement() and
        /// scan_for_announced_utxos() methods with a [SpendingKey]
        ///
        /// a PublicAnnouncement is created with generate_public_announcement() and
        /// added to a Tx.  It is then found by scanning for announced_utoxs.  Then
        /// we verify that the data matches the original/expected values.
        pub fn scan_for_announced_utxos(key: SpendingKey) {
            // 1. generate a utxo with amount = 10
            let utxo =
                Utxo::new_native_currency(key.to_address().lock_script(), NeptuneCoins::new(10));

            // 2. generate sender randomness
            let sender_randomness: Digest = random();

            // 3. create an addition record to verify against later.
            let expected_addition_record = commit(
                Tip5::hash(&utxo),
                sender_randomness,
                key.to_address().privacy_digest(),
            );

            // 4. create a mock tx with no inputs or outputs
            let mut mock_tx = make_mock_transaction(vec![], vec![]);

            // 5. verify that no announced utxos exist for this key
            assert!(key
                .scan_for_announced_utxos(&mock_tx.kernel)
                .collect_vec()
                .is_empty());

            // 6. generate a public announcement for this address
            let utxo_notification_payload =
                UtxoNotificationPayload::new(utxo.clone(), sender_randomness);
            let public_announcement = key
                .to_address()
                .generate_public_announcement(utxo_notification_payload);

            // 7. verify that the public_announcement is marked as our key type.
            assert!(key.matches_public_announcement_key_type(&public_announcement));

            // 8. add the public announcement to the mock tx.
            let mut new_public_announcements = mock_tx.kernel.public_announcements.clone();
            new_public_announcements.push(public_announcement);

            mock_tx.kernel = TransactionKernelModifier::default()
                .public_announcements(new_public_announcements)
                .modify(mock_tx.kernel);

            // 9. scan tx public announcements for announced utxos
            let announced_utxos = key.scan_for_announced_utxos(&mock_tx.kernel).collect_vec();

            // 10. verify there is exactly 1 announced_utxo and obtain it.
            assert_eq!(1, announced_utxos.len());
            let announced_utxo = announced_utxos.into_iter().next().unwrap();

            // 11. verify each field of the announced_utxo matches original values.
            assert_eq!(utxo, announced_utxo.utxo);
            assert_eq!(expected_addition_record, announced_utxo.addition_record());
            assert_eq!(sender_randomness, announced_utxo.sender_randomness);
            assert_eq!(key.privacy_preimage(), announced_utxo.receiver_preimage);
        }

        /// This tests encrypting and decrypting with a [SpendingKey]
        pub fn test_encrypt_decrypt(key: SpendingKey) {
            let mut rng = thread_rng();

            // 1. create utxo with random amount
            let amount = NeptuneCoins::new(rng.gen_range(0..42000000));
            let utxo = Utxo::new_native_currency(key.to_address().lock_script(), amount);

            // 2. generate sender randomness
            let sender_randomness: Digest = random();

            // 3. encrypt secrets (utxo, sender_randomness)
            let notification_payload =
                UtxoNotificationPayload::new(utxo.clone(), sender_randomness);
            let ciphertext = key.to_address().encrypt(&notification_payload);
            println!("ciphertext.get_size() = {}", ciphertext.len() * 8);

            // 4. decrypt secrets
            let (utxo_again, sender_randomness_again) = key.decrypt(&ciphertext).unwrap();

            // 5. verify that decrypted secrets match original secrets
            assert_eq!(utxo, utxo_again);
            assert_eq!(sender_randomness, sender_randomness_again);
        }

        /// tests key generation, signing, and decrypting with a [SpendingKey]
        ///
        /// note: key generation is performed by the caller. Both the
        /// spending_key and receiving_address must be independently derived from
        /// the same seed.
        pub fn test_keypair_validity(
            spending_key: SpendingKey,
            receiving_address: ReceivingAddress,
        ) {
            // 1. prepare a (random) message and witness data.
            let msg: Digest = random();
            let l_and_s = spending_key.lock_script_and_witness();

            // 2. perform proof verification
            assert!(l_and_s.halts_gracefully(msg.values().to_vec().into()));

            // 3. convert spending key to an address.
            let receiving_address_again = spending_key.to_address();

            // 4. verify that both address match.
            assert_eq!(receiving_address, receiving_address_again);
        }

        /// tests bech32m serialize, deserialize for [ReceivingAddress]
        pub fn test_bech32m_conversion(receiving_address: ReceivingAddress) {
            // 1. serialize address to bech32m
            let encoded = receiving_address.to_bech32m(Network::Testnet).unwrap();

            // 2. deserialize bech32m back into an address
            let receiving_address_again =
                ReceivingAddress::from_bech32m(&encoded, Network::Testnet).unwrap();

            // 3. verify both addresses match
            assert_eq!(receiving_address, receiving_address_again);
        }
    }
}
