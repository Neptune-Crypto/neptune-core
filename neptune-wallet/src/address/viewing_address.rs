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
use neptune_consensus::network::Network;
use neptune_consensus::transaction::announcement::Announcement;
use neptune_consensus::transaction::lock_script::LockScript;
use neptune_consensus::transaction::lock_script::LockScriptAndWitness;
use neptune_consensus::transaction::utxo::Utxo;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::triton_vm::vm::NonDeterminism;
use tasm_lib::twenty_first::bfe;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;
use tasm_lib::twenty_first::tip5::Digest;
use tasm_lib::twenty_first::tip5::Tip5;

use crate::address::common;
use crate::address::common::deterministically_derive_seed_and_nonce;
use crate::address::common::network_hrp_char;
use crate::address::encrypted_utxo_notification::EncryptedUtxoNotification;
use crate::utxo_notification::UtxoNotificationPayload;

pub(super) const VIEWING_ADDRESS_FLAG_U8: u8 = 82;
pub const VIEWING_ADDRESS_FLAG: BFieldElement = BFieldElement::new(VIEWING_ADDRESS_FLAG_U8 as u64);

pub const VIEWING_ADDRESS_HRP_PREFIX: &str = "nview";

fn receiver_id(lock_postimage: [BFieldElement; 3], receiever_digest: Digest) -> BFieldElement {
    let [e0, e1, e2] = lock_postimage;
    let left = Digest::new([e0, e1, e2, VIEWING_ADDRESS_FLAG, VIEWING_ADDRESS_FLAG]);
    let [f0, _, _, _, _] = Tip5::hash_pair(left, receiever_digest).values();

    f0
}

fn lock_postimage(unlock_key_preimage: Digest) -> [BFieldElement; 3] {
    let [_, _, e2, e3, e4] = unlock_key_preimage.hash().values();

    [e2, e3, e4]
}

/// Lightweight struct containing what is sent over the wire in case of RPC
/// serialization of a key.
#[derive(Serialize, Deserialize)]
struct ViewingAddressKeyDto {
    seed: Digest,
}

impl From<ViewingAddressKeyDto> for ViewingAddressKey {
    fn from(helper: ViewingAddressKeyDto) -> Self {
        ViewingAddressKey::from_seed(helper.seed)
    }
}

impl From<ViewingAddressKey> for ViewingAddressKeyDto {
    fn from(key: ViewingAddressKey) -> Self {
        ViewingAddressKeyDto { seed: key.seed }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "ViewingAddressKeyDto", into = "ViewingAddressKeyDto")]
pub struct ViewingAddressKey {
    seed: Digest,

    // All fields are derivable from the seed. They are cached here to make
    // many wallet operations faster.
    receiver_identifier: BFieldElement,

    receiver_preimage: Digest,

    unlock_key_preimage: Digest,
}

impl ViewingAddressKey {
    pub fn from_seed(seed: Digest) -> Self {
        let [e0, e1, e2, e3, e4] = seed.values();

        // The unlock preimage may not be linkable to any of the other fields,
        // except for the seed field.
        let unlock_key_preimage = Tip5::hash(&[VIEWING_ADDRESS_FLAG, e0, e1, e2, e3, e4]);

        // receiver preimage must not be derivable from the the AES key since
        // that would leak if UTXOs received on this address were spent or not.
        let receiver_preimage = Tip5::hash_pair(unlock_key_preimage, seed);

        let lockscript_postimage = lock_postimage(unlock_key_preimage);
        let receiver_identifier = receiver_id(lockscript_postimage, receiver_preimage.hash());

        Self {
            seed,
            receiver_identifier,
            receiver_preimage,
            unlock_key_preimage,
        }
    }

    pub fn to_address(&self) -> ViewingAddress {
        let lock_postimage = lock_postimage(self.unlock_key_preimage);
        ViewingAddress {
            receiver_digest: self.receiver_preimage.hash(),
            lock_postimage,
        }
    }

    pub fn lock_script_and_witness(&self) -> LockScriptAndWitness {
        let lock_script = self.to_address().lock_script();
        LockScriptAndWitness::new_with_nondeterminism(
            lock_script.program,
            NonDeterminism::new(self.unlock_key_preimage.reversed().values()),
        )
    }

    pub fn receiver_identifier(&self) -> BFieldElement {
        self.receiver_identifier
    }

    pub fn receiver_preimage(&self) -> Digest {
        self.receiver_preimage
    }
}

#[derive(Clone, Debug, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewingAddress {
    /// Post-image of the receiver preimage
    receiver_digest: Digest,

    /// Post-image of the hashlock key
    lock_postimage: [BFieldElement; 3],
}

impl ViewingAddress {
    const RAW_SERIALIZATION_LENGTH: usize = 64;

    fn aes_key(&self) -> [u8; 32] {
        let [e0, e1, e2] = self.lock_postimage;
        let digest = Tip5::hash_pair(
            self.receiver_digest,
            Digest([e0, e1, e2, VIEWING_ADDRESS_FLAG, bfe!(0)]),
        );
        let digest: [u8; 40] = digest.into();

        digest.into_iter().take(32).collect_array().unwrap()
    }

    /// Manually serialize to exactly 64 bytes to avoid bincode overhead.
    ///
    /// Used to make the address as short as possible.
    fn to_raw_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(Self::RAW_SERIALIZATION_LENGTH);

        // 1. Serialize Digest (40 bytes)
        let digest: [u8; Digest::BYTES] = self.receiver_digest.into();
        bytes.extend_from_slice(&digest);

        // 2. Serialize the 3 BFieldElements (24 bytes)
        for element in &self.lock_postimage {
            bytes.extend_from_slice(&element.value().to_le_bytes());
        }

        debug_assert_eq!(
            bytes.len(),
            Self::RAW_SERIALIZATION_LENGTH,
            "Address payload must be exactly 64 bytes"
        );

        bytes
    }

    /// Manually deserialize from exactly 64 bytes
    fn from_raw_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != Self::RAW_SERIALIZATION_LENGTH {
            return Err("Invalid byte length for ViewingAddress: expected exactly 96 bytes");
        }

        // 2. Parse Digest
        let mut digest_bytes = [0u8; Digest::BYTES];
        digest_bytes.copy_from_slice(&bytes[0..Digest::BYTES]);
        let receiver_digest = Digest::try_from(digest_bytes).map_err(|_| "Invalid digest")?;

        // 3. Parse 3 BFieldElements
        let mut lock_postimage_elements = Vec::with_capacity(3);
        for i in 0..3 {
            let start = Digest::BYTES + (i * BFieldElement::BYTES);
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
            hrp.len() == VIEWING_ADDRESS_HRP_PREFIX.len() + 1,
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
        receiver_id(self.lock_postimage, self.receiver_digest)
    }

    pub fn receiver_postimage(&self) -> Digest {
        self.receiver_digest
    }

    pub(super) fn get_hrp(network: Network) -> String {
        let mut hrp = VIEWING_ADDRESS_HRP_PREFIX.to_string();

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

    pub fn generate_announcement(
        &self,
        utxo_notification_payload: &UtxoNotificationPayload,
    ) -> Announcement {
        let encrypted_utxo_notification = EncryptedUtxoNotification {
            flag: VIEWING_ADDRESS_FLAG,
            receiver_identifier: self.receiver_id(),
            ciphertext: self.encrypt(utxo_notification_payload),
        };

        encrypted_utxo_notification.into_announcement()
    }

    pub fn private_utxo_notification(
        &self,
        utxo_notification_payload: &UtxoNotificationPayload,
        network: Network,
    ) -> String {
        let encrypted_utxo_notification = EncryptedUtxoNotification {
            flag: VIEWING_ADDRESS_FLAG,
            receiver_identifier: self.receiver_id(),
            ciphertext: self.encrypt(utxo_notification_payload),
        };

        encrypted_utxo_notification.into_bech32m(network)
    }

    pub fn encrypt(&self, payload: &UtxoNotificationPayload) -> Vec<BFieldElement> {
        let (_, aes_nonce_bfe) = deterministically_derive_seed_and_nonce(payload);
        let aes_nonce = [aes_nonce_bfe.value().to_be_bytes().to_vec(), vec![0u8; 4]].concat();
        let aes_nonce = Nonce::from_slice(&aes_nonce); // almost 64 bits; unique per message

        let plaintext = bincode::serialize(payload).unwrap();

        let cipher = Aes256Gcm::new(&self.aes_key().into());
        let ciphertext = cipher.encrypt(aes_nonce, plaintext.as_ref()).unwrap();

        [vec![aes_nonce_bfe], common::bytes_to_bfes(&ciphertext)].concat()
    }

    pub fn decrypt(
        &self,
        encrypted_bfes: &[BFieldElement],
    ) -> Result<(Utxo, Digest), anyhow::Error> {
        if encrypted_bfes.len() < 2 {
            anyhow::bail!("Message too short for nonce and ciphertext");
        }

        let aes_nonce_bfe = encrypted_bfes[0];
        let aes_nonce = [aes_nonce_bfe.value().to_be_bytes().to_vec(), vec![0u8; 4]].concat();
        let aes_nonce = Nonce::from_slice(&aes_nonce);

        let cipher = Aes256Gcm::new(&self.aes_key().into());

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
    pub fn from_seed(seed: Digest) -> Self {
        let key = ViewingAddressKey::from_seed(seed);
        key.to_address()
    }
}

#[cfg(any(test, feature = "arbitrary-impls"))]
impl<'a> arbitrary::Arbitrary<'a> for ViewingAddress {
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
    use crate::wallet_entropy::WalletEntropy;

    #[test]
    fn bech32_representation_is_unchanged() {
        assert_eq!(
            "nviewm10243hqsugd3nvmck0f3f49y75dku9lq4ym37lxx6vzl0p2l4kvthjcyzkkpy6f9v9gh8w6hxhaa4fexl4zhnh2qq7ulyrdmttjwukzsn87z88",
            WalletEntropy::devnet_wallet()
                .nth_viewing_address_key(0)
                .to_address()
                .to_bech32m(Network::Main)
        );
    }

    #[test]
    fn encryption_is_deterministic() {
        let expected = "a48b4c4777fc3e7600000000000000684b69e67664182b3828ed19dba3f6c55f54110284018e51e4808d037c9955668b282c60d8724be77f09a77201b8c4de1600e50068ff095748555fcb9c41e94815ae402977aefd6c4f40497b2e9b50b09fd945625d382a03c1a077adee2cc2f4b664f0f31d6380c975";
        let payload = UtxoNotificationPayload::new(Utxo::empty_dummy(), Digest::default());
        let result = WalletEntropy::devnet_wallet()
            .nth_viewing_address_key(0)
            .to_address()
            .encrypt(&payload);

        assert_eq!(
            expected,
            result.iter().map(|bfe| format!("{bfe:016x}")).join("")
        );
    }

    #[test]
    fn no_crash_in_decryption() {
        let address = ViewingAddress::from_seed(Digest::default());
        for i in 0..20 {
            let msg = vec![bfe!(0); i];
            assert!(address.decrypt(&msg).is_err());
        }
    }

    #[test]
    fn address_and_key_agree_on_receiver_id() {
        let key = ViewingAddressKey::from_seed(Digest::default());
        assert_eq!(key.receiver_identifier(), key.to_address().receiver_id());
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
                ViewingAddress::from_bech32m(&str, network).is_err(),
                "Invalid bech32 encoding must lead to error: {str}"
            );
        }

        // Not valid checksums.
        for i in 0..10 {
            let as_ = "a".repeat(i);
            assert!(
                ViewingAddress::from_bech32m(&as_, network).is_err(),
                "Invalid bech32 encoding must lead to error 1"
            );
            assert!(
                ViewingAddress::from_bech32m(
                    &format!("{VIEWING_ADDRESS_HRP_PREFIX}1{as_}"),
                    network
                )
                .is_err(),
                "Invalid bech32 encoding must lead to error 2"
            );
            assert!(
                ViewingAddress::from_bech32m(&format!("{SHORT_PREFIX}1{as_}"), network).is_err(),
                "Invalid bech32 encoding must lead to error 3"
            );
        }
    }

    #[proptest(cases = 10)]
    fn custom_serialization_consistency(#[strategy(arb())] address: ViewingAddress) {
        prop_assert_eq!(
            address,
            ViewingAddress::from_raw_bytes(&address.to_raw_bytes()).unwrap()
        );
    }

    #[proptest(cases = 10)]
    fn bech32_consistency(#[strategy(arb())] address: ViewingAddress) {
        let network = Network::Main;
        prop_assert_eq!(
            address,
            ViewingAddress::from_bech32m(&address.to_bech32m(network), network).unwrap()
        );
    }

    #[test]
    fn encryption_roundtrip_unit() {
        let address = ViewingAddressKey::from_seed(Digest::default()).to_address();

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
        #[strategy(arb())] address: ViewingAddress,
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
        let alice_address = ViewingAddressKey::from_seed(Digest::default()).to_address();
        let bob_address = ViewingAddressKey::from_seed(Digest::default().hash()).to_address();
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
