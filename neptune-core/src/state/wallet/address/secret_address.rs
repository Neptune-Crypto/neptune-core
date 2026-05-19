use aead::Aead;
use aead::KeyInit;
use aes_gcm::Aes256Gcm;
use aes_gcm::Nonce;
use anyhow::anyhow;
use anyhow::ensure;
use anyhow::Result;
use bech32::FromBase32;
use bech32::ToBase32;
use bech32::Variant;
use itertools::Itertools;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::triton_vm::vm::NonDeterminism;
use tasm_lib::twenty_first::bfe;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;
use tasm_lib::twenty_first::tip5::Digest;
use tasm_lib::twenty_first::tip5::Tip5;

use crate::api::export::Announcement;
use crate::api::export::Utxo;
use crate::application::config::network::Network;
use crate::protocol::consensus::transaction::lock_script::LockScript;
use crate::protocol::consensus::transaction::lock_script::LockScriptAndWitness;
use crate::state::wallet::address::common;
use crate::state::wallet::address::common::deterministically_derive_seed_and_nonce;
use crate::state::wallet::address::common::network_hrp_char;
use crate::state::wallet::address::encrypted_utxo_notification::EncryptedUtxoNotification;
use crate::state::wallet::utxo_notification::UtxoNotificationPayload;

pub(super) const SECRET_ADDRESS_FLAG_U8: u8 = 82;
pub const SECRET_ADDRESS_FLAG: BFieldElement = BFieldElement::new(SECRET_ADDRESS_FLAG_U8 as u64);

pub(crate) const SECRET_ADDRESS_HRP_PREFIX: &str = "nsec";

fn receiver_id(aes_key: &[u8; 32]) -> BFieldElement {
    let [e0, _, _, _, _] = Tip5::hash(aes_key).values();

    e0
}

/// Lightweight struct containing what is sent over the wire in case of RPC
/// serialization of an address.
#[derive(Serialize, Deserialize)]
struct SecretAddressKeyDto {
    seed: Digest,
}

impl From<SecretAddressKeyDto> for SecretAddressKey {
    fn from(helper: SecretAddressKeyDto) -> Self {
        SecretAddressKey::from_seed(helper.seed)
    }
}

impl From<SecretAddressKey> for SecretAddressKeyDto {
    fn from(key: SecretAddressKey) -> Self {
        SecretAddressKeyDto { seed: key.seed }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "SecretAddressKeyDto", into = "SecretAddressKeyDto")]
pub struct SecretAddressKey {
    seed: Digest,

    // All fields are derivable from the seed. They are cached here to make
    // many wallet operations faster.
    receiver_identifier: BFieldElement,

    aes_key: [u8; 32],

    receiver_preimage: Digest,

    unlock_key_preimage: Digest,
}

impl SecretAddressKey {
    pub fn from_seed(seed: Digest) -> Self {
        let [e0, e1, e2, e3, e4] = seed.values();

        // The unlock preimage may not be linkable to any of the other fields,
        // except for the seed field.
        let unlock_key_preimage = Tip5::hash(&[SECRET_ADDRESS_FLAG, e0, e1, e2, e3, e4]);
        let aes_key = Tip5::hash(&[e0, e1, e2, e3, e4, SECRET_ADDRESS_FLAG]);

        // receiver preimage must not be derivable from the the AES key since
        // that would leak if UTXOs received on this address were spent or not.
        let receiver_preimage = Tip5::hash_pair(aes_key, seed);

        let aes_key: [u8; 40] = aes_key.into();
        let aes_key: [u8; 32] = aes_key
            .into_iter()
            .take(32)
            .collect_vec()
            .try_into()
            .unwrap();
        let receiver_identifier = receiver_id(&aes_key);

        Self {
            seed,
            receiver_identifier,
            aes_key,
            receiver_preimage,
            unlock_key_preimage,
        }
    }

    pub fn to_address(&self) -> SecretAddress {
        // let viewing_key = self.viewing_key();
        // viewing_key.to_address()
        let [_, _, e2, e3, e4] = self.unlock_key_preimage.hash().values();
        let lock_postimage = [e2, e3, e4];
        SecretAddress {
            aes_key: self.aes_key,
            receiver_digest: self.receiver_preimage.hash(),
            lock_postimage,
        }
    }

    pub(crate) fn lock_script_and_witness(&self) -> LockScriptAndWitness {
        let lock_script = self.to_address().lock_script();
        LockScriptAndWitness::new_with_nondeterminism(
            lock_script.program,
            NonDeterminism::new(self.unlock_key_preimage.reversed().values()),
        )
    }

    pub(crate) fn receiver_identifier(&self) -> BFieldElement {
        self.receiver_identifier
    }

    pub(crate) fn receiver_preimage(&self) -> Digest {
        self.receiver_preimage
    }
}

#[derive(Clone, Debug, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretAddress {
    /// The AES key used to encrypt the UTXO notification.
    aes_key: [u8; 32],

    /// Post-image of the receiver preimage
    receiver_digest: Digest,

    /// Post-image of the hashlock key
    lock_postimage: [BFieldElement; 3],
}

impl SecretAddress {
    const RAW_SERIALIZATION_LENGTH: usize = 96;

    /// Manually serialize to exactly 96 bytes to avoid bincode overhead.
    ///
    /// Used to make the address as short as possible.
    fn to_raw_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(Self::RAW_SERIALIZATION_LENGTH);

        bytes.extend_from_slice(&self.aes_key);

        // 2. Serialize Digest (40 bytes)
        let digest: [u8; Digest::BYTES] = self.receiver_digest.into();
        bytes.extend_from_slice(&digest);

        // 3. Serialize the 3 BFieldElements (24 bytes)
        for element in &self.lock_postimage {
            bytes.extend_from_slice(&element.value().to_le_bytes());
        }

        debug_assert_eq!(
            bytes.len(),
            Self::RAW_SERIALIZATION_LENGTH,
            "Address payload must be exactly 96 bytes"
        );

        bytes
    }

    /// Manually deserialize from exactly 96 bytes
    fn from_raw_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != Self::RAW_SERIALIZATION_LENGTH {
            return Err("Invalid byte length for SecretAddress: expected exactly 96 bytes");
        }

        let aes_key: [u8; 32] = bytes[0..32].to_vec().try_into().unwrap();

        // 2. Parse Digest (bytes 32..72)
        let mut digest_bytes = [0u8; Digest::BYTES];
        digest_bytes.copy_from_slice(&bytes[32..72]);
        let receiver_digest = Digest::try_from(digest_bytes).map_err(|_| "Invalid digest")?;

        // 3. Parse 3 BFieldElements (bytes 72..96)
        let mut lock_postimage_elements = Vec::with_capacity(3);
        for i in 0..3 {
            let start = 72 + (i * BFieldElement::BYTES);
            let mut le_bytes = [0u8; BFieldElement::BYTES];
            le_bytes.copy_from_slice(&bytes[start..start + BFieldElement::BYTES]);

            let elem = BFieldElement::try_from(le_bytes).map_err(|_| "Invalid B field element")?;
            lock_postimage_elements.push(elem);
        }

        // Convert the Vec back into a fixed-size array of 3 elements
        let lock_postimage: [BFieldElement; 3] = lock_postimage_elements
            .try_into()
            .expect("Guaranteed to be exactly 3 elements");

        Ok(Self {
            aes_key,
            receiver_digest,
            lock_postimage,
        })
    }

    pub fn from_bech32m(encoded: &str, network: Network) -> Result<Self> {
        let (hrp, data, variant) = bech32::decode(encoded)?;

        ensure!(
            variant == Variant::Bech32m,
            "Can only decode bech32m addresses.",
        );

        // human-readable part must be prefix plus one character for network
        ensure!(
            hrp.len() == SECRET_ADDRESS_HRP_PREFIX.len() + 1,
            "Wrong size for human-readable part",
        );
        ensure!(
            hrp == Self::get_hrp(network),
            "Could not decode bech32m address because of invalid prefix",
        );

        let payload = Vec::<u8>::from_base32(&data)?;
        Self::from_raw_bytes(&payload)
            .map_err(|e| anyhow!("Could not decode bech32m address because of error: {e}"))
    }

    pub fn lock_script(&self) -> LockScript {
        LockScript::hash_lock_from_after_image_192_bit_security(self.lock_postimage)
    }

    pub fn receiver_id(&self) -> BFieldElement {
        receiver_id(&self.aes_key)
    }

    pub fn receiver_postimage(&self) -> Digest {
        self.receiver_digest
    }

    pub(super) fn get_hrp(network: Network) -> String {
        let mut hrp = SECRET_ADDRESS_HRP_PREFIX.to_string();

        let network_byte = network_hrp_char(network);
        hrp.push(network_byte);
        hrp
    }

    pub fn to_bech32m(&self, network: Network) -> String {
        let hrp = Self::get_hrp(network);

        let payload = self.to_raw_bytes();

        let variant = Variant::Bech32m;
        bech32::encode(&hrp, payload.to_base32(), variant)
            .expect("Could not encode address as bech32m because")
    }

    pub(crate) fn generate_announcement(
        &self,
        utxo_notification_payload: &UtxoNotificationPayload,
    ) -> Announcement {
        let encrypted_utxo_notification = EncryptedUtxoNotification {
            flag: SECRET_ADDRESS_FLAG,
            receiver_identifier: self.receiver_id(),
            ciphertext: self.encrypt(utxo_notification_payload),
        };

        encrypted_utxo_notification.into_announcement()
    }

    pub(crate) fn private_utxo_notification(
        &self,
        utxo_notification_payload: &UtxoNotificationPayload,
        network: Network,
    ) -> String {
        let encrypted_utxo_notification = EncryptedUtxoNotification {
            flag: SECRET_ADDRESS_FLAG,
            receiver_identifier: self.receiver_id(),
            ciphertext: self.encrypt(utxo_notification_payload),
        };

        encrypted_utxo_notification.into_bech32m(network)
    }

    pub(crate) fn encrypt(&self, payload: &UtxoNotificationPayload) -> Vec<BFieldElement> {
        let (_, aes_nonce_bfe) = deterministically_derive_seed_and_nonce(payload);
        let aes_nonce = [aes_nonce_bfe.value().to_be_bytes().to_vec(), vec![0u8; 4]].concat();
        let aes_nonce = Nonce::from_slice(&aes_nonce); // almost 64 bits; unique per message

        let plaintext = bincode::serialize(payload).unwrap();

        let cipher = Aes256Gcm::new(&self.aes_key.into());
        let ciphertext = cipher.encrypt(aes_nonce, plaintext.as_ref()).unwrap();

        [vec![aes_nonce_bfe], common::bytes_to_bfes(&ciphertext)].concat()
    }

    pub fn decrypt(
        &self,
        encrypted_bfes: &[BFieldElement],
    ) -> Result<(Utxo, Digest), anyhow::Error> {
        if encrypted_bfes.len() < 2 {
            anyhow::bail!("Message too short to nonce and ciphertext");
        }

        let aes_nonce_bfe = encrypted_bfes[0];
        let aes_nonce = [aes_nonce_bfe.value().to_be_bytes().to_vec(), vec![0u8; 4]].concat();
        let aes_nonce = Nonce::from_slice(&aes_nonce);
        let cipher = Aes256Gcm::new(&self.aes_key.into());

        let ciphertext = &encrypted_bfes[1..];
        let ciphertext = common::bfes_to_bytes(ciphertext)?;
        let ciphertext = &ciphertext[..];
        let plaintext = cipher
            .decrypt(aes_nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("AES-GCM decryption failed: {:?}", e))?;

        let payload: UtxoNotificationPayload = bincode::deserialize(&plaintext)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize payload: {:?}", e))?;

        Ok((payload.utxo, payload.sender_randomness))
    }

    #[cfg(any(test, feature = "arbitrary-impls"))]
    pub(crate) fn from_seed(seed: Digest) -> Self {
        let key = SecretAddressKey::from_seed(seed);
        key.to_address()
    }
}

#[cfg(any(test, feature = "arbitrary-impls"))]
impl<'a> arbitrary::Arbitrary<'a> for SecretAddress {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let seed = Digest::arbitrary(u)?;
        Ok(Self::from_seed(seed))
    }
}

#[cfg(test)]
mod tests {
    use proptest::prop_assert_eq;
    use proptest_arbitrary_interop::arb;
    use test_strategy::proptest;

    use super::*;
    use crate::api::export::WalletEntropy;

    #[test]
    fn bech32_representation_is_unchanged() {
        assert_eq!(
            "nsecm1r6gvlcgls2r6remt6avufem6zc4rag6sff8r6ua7q44ayam42yh0fkdkq25nyfezy2jv6r3z6nvcjlmxjm904gmx0z3zauq9mksw93c972864p0rstgj5tnhdtnt7765un063tem4qq0w0jpka44e8wtpg6z2y3z",
            WalletEntropy::devnet_wallet()
                .nth_secret_address_key(0)
                .to_address()
                .to_bech32m(Network::Main)
        );
    }

    #[test]
    fn encryption_is_deterministic() {
        let expected = "c55a3ddcd94285586879b1fa035d588b8451c738084d8c7edd5525bb38b3862badda141849ccba1ae730ef2d5ba2c1f996e72fca5389976cc0247aaca4e0bdbf08d7d7686f29abba87efa68ddcaa764da874135fe7840dac462700ce3c44c1566ff6943d5827114a544115443323d1e4c6";
        let payload = UtxoNotificationPayload::new(Utxo::empty_dummy(), Digest::default());
        let result = WalletEntropy::devnet_wallet()
            .nth_secret_address_key(0)
            .to_address()
            .encrypt(&payload);

        assert_eq!(expected, result.iter().map(|x| format!("{x:x}")).join(""));
    }

    #[test]
    fn no_crash_in_bech32_decoding() {
        const SHORT_PREFIX: &str = "n";
        let network = Network::Main;

        // Encodings with valid checksum
        let short_prefix =
            bech32::encode(SHORT_PREFIX, vec![].to_base32(), Variant::Bech32m).unwrap();
        let long_prefix =
            bech32::encode("nolganolga", vec![].to_base32(), Variant::Bech32m).unwrap();

        for str in [short_prefix, long_prefix] {
            assert!(
                SecretAddress::from_bech32m(&str, network).is_err(),
                "Invalid bech32 encoding must lead to error: {str}"
            );
        }

        // Not valid checksums.
        for i in 0..10 {
            let as_ = "a".repeat(i);
            assert!(
                SecretAddress::from_bech32m(&as_, network).is_err(),
                "Invalid bech32 encoding must lead to error 1"
            );
            assert!(
                SecretAddress::from_bech32m(&format!("{SECRET_ADDRESS_HRP_PREFIX}1{as_}"), network)
                    .is_err(),
                "Invalid bech32 encoding must lead to error 2"
            );
            assert!(
                SecretAddress::from_bech32m(&format!("{SHORT_PREFIX}1{as_}"), network).is_err(),
                "Invalid bech32 encoding must lead to error 3"
            );
        }
    }

    #[proptest(cases = 10)]
    fn custom_serialization_consistency(#[strategy(arb())] address: SecretAddress) {
        prop_assert_eq!(
            address,
            SecretAddress::from_raw_bytes(&address.to_raw_bytes()).unwrap()
        );
    }

    #[proptest(cases = 10)]
    fn bech32_consistency(#[strategy(arb())] address: SecretAddress) {
        let network = Network::Main;
        prop_assert_eq!(
            address,
            SecretAddress::from_bech32m(&address.to_bech32m(network), network).unwrap()
        );
    }

    #[test]
    fn encryption_roundtrip_unit() {
        let address = SecretAddressKey::from_seed(Digest::default()).to_address();

        let payload = UtxoNotificationPayload::new(Utxo::empty_dummy(), Digest::default());
        let encrypted_bfes = address.encrypt(&payload);

        let (utxo, sender_randomness) = address
            .decrypt(&encrypted_bfes)
            .expect("Decryption should succeed for valid ciphertext and matching keys");

        assert_eq!(
            payload,
            UtxoNotificationPayload::new(utxo, sender_randomness)
        );
    }

    #[proptest(cases = 10)]
    fn encryption_roundtrip_prop(
        #[strategy(arb())] payload: UtxoNotificationPayload,
        #[strategy(arb())] address: SecretAddress,
    ) {
        let encrypted_bfes = address.encrypt(&payload);

        let (utxo, sender_randomness) = address
            .decrypt(&encrypted_bfes)
            .expect("Decryption should succeed for valid ciphertext and matching keys");

        // 4. Assert Identity
        prop_assert_eq!(
            payload,
            UtxoNotificationPayload::new(utxo, sender_randomness)
        );
    }

    #[test]
    fn decryption_fails_with_wrong_address() {
        let alice_address = SecretAddressKey::from_seed(Digest::default()).to_address();
        let bob_address = SecretAddressKey::from_seed(Digest::default().hash()).to_address();
        let payload = UtxoNotificationPayload::new(Utxo::empty_dummy(), Digest::default());

        // Bob's address is used to encrypt
        let encrypted_bfes = bob_address.encrypt(&payload);

        // Alice tries to decrypt a message sent to Bob
        let result = alice_address.decrypt(&encrypted_bfes);

        assert!(
            result.is_err(),
            "Decryption should fail when using the wrong key"
        );
    }
}
