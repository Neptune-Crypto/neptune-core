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

pub(super) const ELLIPTIC_CURVE_HYBRID_ADDRESS_FLAG_U8: u8 = 81;
pub const ELLIPTIC_CURVE_HYBRID_ADDRESS_FLAG: BFieldElement =
    BFieldElement::new(ELLIPTIC_CURVE_HYBRID_ADDRESS_FLAG_U8 as u64);

const ELLIPTIC_CURVE_HYBRID_AES_NONCE: [u8; 12] = [0u8; 12];

pub const ECH_HRP_PREFIX: &str = "nech";

fn receiver_id(ec_pubkey: &k256::PublicKey) -> BFieldElement {
    let pubkey_encoded = ec_pubkey.to_sec1_bytes().to_vec();
    let [e0, _, _, _, _] = Tip5::hash(&pubkey_encoded).values();

    e0
}

/// The receiver-shard of the main AES key.
///
/// When a transaction is made, the notification payload is AES encrypted and
/// sent to the receiver. The AES key used for this encryption is the XOR of to
/// 256-bit values: the sender part and the receiver part. This function returns
/// the receiver part, which is the part that the receiver gets to define.
fn aes_key_receiver_part(lock_postimage: [BFieldElement; 3], receiever_digest: Digest) -> [u8; 32] {
    let [e0, e1, e2] = lock_postimage;
    let digest = Tip5::hash_pair(receiever_digest, Digest([e0, e1, e2, bfe!(0), bfe!(0)]));
    let digest: [u8; 40] = digest.into();

    digest.into_iter().take(32).collect_array().unwrap()
}

/// Lightweight struct containing what is sent over the wire in case of RPC
/// serialization of an address.
#[derive(Serialize, Deserialize)]
struct EcHybridKeyDto {
    seed: Digest,
}

impl From<EcHybridKeyDto> for EcHybridKey {
    fn from(helper: EcHybridKeyDto) -> Self {
        EcHybridKey::from_seed(helper.seed)
    }
}

impl From<EcHybridKey> for EcHybridKeyDto {
    fn from(key: EcHybridKey) -> Self {
        EcHybridKeyDto { seed: key.seed }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "EcHybridKeyDto", into = "EcHybridKeyDto")]
pub struct EcHybridKey {
    seed: Digest,

    // All fields are derivable from the seed. They are cached here to make
    // many wallet operations faster.
    receiver_identifier: BFieldElement,

    ec_secret_key: k256::SecretKey,

    ec_public_key: k256::PublicKey,

    receiver_preimage: Digest,

    unlock_key_preimage: Digest,
}

impl EcHybridKey {
    pub fn from_seed(seed: Digest) -> Self {
        let [e0, e1, e2, e3, e4] = seed.values();

        // The unlock preimage may not be linkable to any of the other fields,
        // except for the seed field.
        let unlock_key_preimage =
            Tip5::hash(&[ELLIPTIC_CURVE_HYBRID_ADDRESS_FLAG, e0, e1, e2, e3, e4]);
        let privacy_seed = Tip5::hash(&[e0, e1, e2, e3, e4, ELLIPTIC_CURVE_HYBRID_ADDRESS_FLAG]);

        // Teh receiver preimage must not be derivable from the elliptic curve
        // secret key. Otherwise the viewing key would leak the receiver
        // preimage -- meaning that the viewer key would leak information about
        // whether a received UTXO is spent or not. We only want the viewing key
        // to reveal what is received.
        let receiver_preimage = Tip5::hash_pair(privacy_seed, seed);

        let privacy_seed: [u8; 40] = privacy_seed.into();
        let privacy_seed: [u8; 32] = privacy_seed
            .into_iter()
            .take(32)
            .collect_vec()
            .try_into()
            .unwrap();
        let ec_secret_key = k256::SecretKey::from_slice(&privacy_seed)
            .expect("Derived randomness exceeded secp256k1 curve order");
        let ec_public_key = ec_secret_key.public_key();
        let receiver_identifier = receiver_id(&ec_public_key);

        Self {
            seed,
            receiver_identifier,
            ec_secret_key,
            ec_public_key,
            receiver_preimage,
            unlock_key_preimage,
        }
    }

    pub fn viewing_key(&self) -> EcHybridViewingKey {
        let [_, _, e2, e3, e4] = self.unlock_key_preimage.hash().values();
        let lock_postimage = [e2, e3, e4];
        EcHybridViewingKey {
            ec_secret_key: self.ec_secret_key.clone(),
            receiver_digest: self.receiver_preimage.hash(),
            lock_postimage,
        }
    }

    pub fn to_address(&self) -> EcHybridAddress {
        let viewing_key = self.viewing_key();
        viewing_key.to_address()
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

/// Cryptographic information to retrieve all information about incoming UTXOs
/// for an address without the ability to spend any of its UTXOs.
///
/// If you want to see if UTXOs received on an address has also been spent
/// (still without spending abilities), you will need the receiver preimage, in
/// addition to this data structure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EcHybridViewingKey {
    ec_secret_key: k256::SecretKey,

    receiver_digest: Digest,

    lock_postimage: [BFieldElement; 3],
}

impl EcHybridViewingKey {
    pub fn decrypt(
        &self,
        encrypted_bfes: &[BFieldElement],
    ) -> Result<(Utxo, Digest), anyhow::Error> {
        // 1. Convert the concatenated BFieldElements back to bytes.
        let all_bytes = common::bfes_to_bytes(encrypted_bfes)?;

        if all_bytes.len() < 33 {
            anyhow::bail!("Ciphertext too short to contain ephemeral public key");
        }

        // 2. Split the bytes into the 33-byte ephemeral public key and the AES
        //    ciphertext.
        let (ephemeral_pubkey_bytes, ciphertext) = all_bytes.split_at(33);

        // 3. Parse the sender's ephemeral public key.
        let ephemeral_pubkey = k256::PublicKey::from_sec1_bytes(ephemeral_pubkey_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid ephemeral public key: {:?}", e))?;

        // 4. Perform ECDH using the receiver's secret key and the sender's
        //    ephemeral public key.
        //    The math guarantees this matches the sender's `sender_key_share`.
        let shared_secret = k256::ecdh::diffie_hellman(
            self.ec_secret_key.to_nonzero_scalar(),
            ephemeral_pubkey.as_affine(),
        );

        // 5. Hash the shared secret to derive the sender's part of the AES key.
        let sender_key_share = shared_secret.raw_secret_bytes().to_vec();
        let sender_key_share: [u8; 40] = Tip5::hash(&sender_key_share).into();
        let sender_key_share: [u8; 32] = sender_key_share
            .into_iter()
            .take(32)
            .collect_vec()
            .try_into()
            .unwrap();

        // 6. XOR with the receiver's part to reconstruct the 256-bit symmetric
        //    AES key which encrypts the payload.
        let receiver_key_share = aes_key_receiver_part(self.lock_postimage, self.receiver_digest);
        let aes_key: [u8; 32] = receiver_key_share
            .into_iter()
            .zip_eq(sender_key_share)
            .map(|(receiver, sender)| receiver ^ sender)
            .collect_array()
            .unwrap();

        // 7. Decrypt the payload using the reconstructed AES key and the fixed
        //    nonce.
        let cipher = Aes256Gcm::new(&aes_key.into());
        let nonce = Nonce::from_slice(&ELLIPTIC_CURVE_HYBRID_AES_NONCE);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("AES-GCM decryption failed: {:?}", e))?;

        // 8. Deserialize the plaintext back into the payload struct.
        let payload: UtxoNotificationPayload = bincode::deserialize(&plaintext)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize payload: {:?}", e))?;

        Ok((payload.utxo, payload.sender_randomness))
    }

    pub fn to_address(&self) -> EcHybridAddress {
        EcHybridAddress {
            ec_public_key: self.ec_secret_key.public_key(),
            receiver_digest: self.receiver_digest,
            lock_postimage: self.lock_postimage,
        }
    }
}

#[derive(Clone, Debug, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcHybridAddress {
    /// The public key with which to communicate the sender-part of the
    /// AES key to the receiver.
    ec_public_key: k256::PublicKey,

    /// Post-image of the receiver preimage
    receiver_digest: Digest,

    /// Post-image of the hashlock key
    lock_postimage: [BFieldElement; 3],
}

impl EcHybridAddress {
    const RAW_SERIALIZATION_LENGTH: usize = 97;

    /// Manually serialize to exactly 97 bytes to avoid bincode overhead.
    ///
    /// Used to make the address as short as possible.
    fn to_raw_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(Self::RAW_SERIALIZATION_LENGTH);

        let pubkey_bytes = self.ec_public_key.to_sec1_bytes();
        bytes.extend_from_slice(&pubkey_bytes);

        // 2. Serialize Digest (40 bytes)
        let digest: [u8; Digest::BYTES] = self.receiver_digest.into();
        bytes.extend_from_slice(&digest);

        // 3. Serialize the 3 BFieldElements (24 bytes)
        for element in &self.lock_postimage {
            bytes.extend_from_slice(&element.value().to_le_bytes());
        }

        debug_assert_eq!(bytes.len(), 97, "Address payload must be exactly 97 bytes");
        bytes
    }

    /// Manually deserialize from exactly 97 bytes
    fn from_raw_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != Self::RAW_SERIALIZATION_LENGTH {
            return Err("Invalid byte length for EcHybridAddress: expected exactly 97 bytes");
        }

        let ec_public_key = k256::PublicKey::from_sec1_bytes(&bytes[0..33])
            .map_err(|_| "Failed to parse compressed sec1 public key")?;

        // 2. Parse Digest (bytes 33..73)
        let mut digest_bytes = [0u8; Digest::BYTES];
        digest_bytes.copy_from_slice(&bytes[33..73]);
        let receiver_digest = Digest::try_from(digest_bytes).map_err(|_| "Invalid digest")?;

        // 3. Parse 3 BFieldElements (bytes 73..97)
        let mut lock_postimage_elements = Vec::with_capacity(3);
        for i in 0..3 {
            let start = 73 + (i * BFieldElement::BYTES);
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
            ec_public_key,
            receiver_digest,
            lock_postimage,
        })
    }

    fn aes_key_receiver_part(&self) -> [u8; 32] {
        aes_key_receiver_part(self.lock_postimage, self.receiver_digest)
    }

    pub fn from_bech32m(encoded: &str, network: Network) -> Result<Self> {
        let (hrp, data, variant) = bech32::decode(encoded)?;

        ensure!(
            variant == Variant::Bech32m,
            "Can only decode bech32m addresses.",
        );

        // human-readable part must be prefix plus one character for network
        ensure!(
            hrp.len() == ECH_HRP_PREFIX.len() + 1,
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
        receiver_id(&self.ec_public_key)
    }

    pub fn receiver_postimage(&self) -> Digest {
        self.receiver_digest
    }

    pub(super) fn get_hrp(network: Network) -> String {
        let mut hrp = ECH_HRP_PREFIX.to_string();

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
            flag: ELLIPTIC_CURVE_HYBRID_ADDRESS_FLAG,
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
            flag: ELLIPTIC_CURVE_HYBRID_ADDRESS_FLAG,
            receiver_identifier: self.receiver_id(),
            ciphertext: self.encrypt(utxo_notification_payload),
        };

        encrypted_utxo_notification.into_bech32m(network)
    }

    pub fn encrypt(&self, payload: &UtxoNotificationPayload) -> Vec<BFieldElement> {
        // 1. Generate an Ephemeral Keypair for ECDH, deterministically.
        let (ephemeral_secret, _nonce_bfe) = deterministically_derive_seed_and_nonce(payload);
        let ephemeral_secret = k256::SecretKey::from_slice(&ephemeral_secret)
            .expect("Derived randomness exceeded secp256k1 curve order");

        let ephemeral_pubkey = ephemeral_secret.public_key();

        // Serialize the ephemeral pubkey to 33 compressed bytes to send
        // on-chain
        let ephemeral_pubkey_bytes = ephemeral_pubkey.to_sec1_bytes();

        // 2. Perform ECDH to get the asymmetric shared secret
        let sender_key_share = k256::ecdh::diffie_hellman(
            ephemeral_secret.to_nonzero_scalar(),
            self.ec_public_key.as_affine(),
        );

        // 3. Hash the shared secret to destroy curve structure and get uniform
        // randomness. This digest is used as the "sender part" of the main AES
        // key.
        let sender_key_share = sender_key_share.raw_secret_bytes().to_vec();
        let sender_key_share: [u8; 40] = Tip5::hash(&sender_key_share).into();
        let sender_key_share: [u8; 32] = sender_key_share
            .into_iter()
            .take(32)
            .collect_vec()
            .try_into()
            .unwrap();

        // 4. XOR with receiver_part to generate the main, 256-bit symmetric
        // key used for the payload encryption.
        let receiver_key_share = self.aes_key_receiver_part();
        let aes_key: [u8; 32] = receiver_key_share
            .into_iter()
            .zip_eq(sender_key_share)
            .map(|(receiver, sender)| receiver ^ sender)
            .collect_array()
            .unwrap();

        // 5. Generate symmetric ciphertext.
        // It's OK to used a fixed nonce here because its only purpose is to
        // protect against the same plaintext encrypting to the same ciphertext,
        // under the same key. But since AES keys under this scheme are never
        // reused, we don't need a real nonce.
        // If the above deterministially-derived sender key share is repeated,
        // the addition record will also be repeated. So there's no point in
        // trying to obfuscate in that scenario.
        let plaintext = bincode::serialize(payload).unwrap();
        let nonce = Nonce::from_slice(&ELLIPTIC_CURVE_HYBRID_AES_NONCE);

        let cipher = Aes256Gcm::new(&aes_key.into());
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();

        let all_bytes = [ephemeral_pubkey_bytes.to_vec(), ciphertext].concat();

        common::bytes_to_bfes(&all_bytes)
    }

    #[cfg(any(test, feature = "arbitrary-impls"))]
    pub fn from_seed(seed: Digest) -> Self {
        let key = EcHybridKey::from_seed(seed);
        key.to_address()
    }
}

#[cfg(any(test, feature = "arbitrary-impls"))]
impl<'a> arbitrary::Arbitrary<'a> for EcHybridAddress {
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
            "nechm1qtmcrts70kl4hzjej5te74pk67aja8wmz6aawx995c0cnzl2sxuxdv37p70sgxl7z4dqnmrvqcy2lgsy3xu8gc6xpgaps8x6ppxulpzqj8vqnm5p3n4cyjrzpr2pjr6zwn49x0ejs2p3vyausep5pcftn2dq200dz7",
            WalletEntropy::devnet_wallet()
                .nth_ec_hybrid_key(0)
                .to_address()
                .to_bech32m(Network::Main));
    }

    #[test]
    fn encryption_is_deterministic() {
        let expected = "000000000000008902b646ea6d2c444e1a98a9efaade0e599beda53d597fdeff5b7b6812633d2cfecadbf04479d1a50116040c62dc427ec6ffb9d508fba6fe8ae94eb429e09b32dd08b374ef6141e6595c09eb7af7f01d0aff96eac5645caeb41ed090ba74677fec37b45819b60f3428862ef77d77f42675f26d020d69648b65e6e85099f018257f39c80269d0ea7f7ef600000000000000";
        let payload = UtxoNotificationPayload::new(Utxo::empty_dummy(), Digest::default());
        let result = WalletEntropy::devnet_wallet()
            .nth_ec_hybrid_key(0)
            .to_address()
            .encrypt(&payload);

        assert_eq!(
            expected,
            result.iter().map(|bfe| format!("{bfe:016x}")).join("")
        );
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
                EcHybridAddress::from_bech32m(&str, network).is_err(),
                "Invalid bech32 encoding must lead to error: {str}"
            );
        }

        // Not valid checksums.
        for i in 0..10 {
            let as_ = "a".repeat(i);
            assert!(
                EcHybridAddress::from_bech32m(&as_, network).is_err(),
                "Invalid bech32 encoding must lead to error 1"
            );
            assert!(
                EcHybridAddress::from_bech32m(&format!("{ECH_HRP_PREFIX}1{as_}"), network).is_err(),
                "Invalid bech32 encoding must lead to error 2"
            );
            assert!(
                EcHybridAddress::from_bech32m(&format!("{SHORT_PREFIX}1{as_}"), network).is_err(),
                "Invalid bech32 encoding must lead to error 3"
            );
        }
    }

    #[proptest(cases = 10)]
    fn custom_serialization_consistency(#[strategy(arb())] key_seed: Digest) {
        let address = EcHybridKey::from_seed(key_seed).to_address();

        prop_assert_eq!(
            address,
            EcHybridAddress::from_raw_bytes(&address.to_raw_bytes()).unwrap()
        );
    }

    #[proptest(cases = 10)]
    fn bech32_consistency(#[strategy(arb())] key_seed: Digest) {
        let network = Network::Main;
        let address = EcHybridKey::from_seed(key_seed).to_address();

        prop_assert_eq!(
            address,
            EcHybridAddress::from_bech32m(&address.to_bech32m(network), network).unwrap()
        );
    }

    #[test]
    fn encryption_roundtrip_unit() {
        let key = EcHybridKey::from_seed(Digest::default());
        let address = key.to_address();

        let payload = UtxoNotificationPayload::new(Utxo::empty_dummy(), Digest::default());
        let encrypted_bfes = address.encrypt(&payload);

        let (utxo, sender_randomness) = key
            .viewing_key()
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
        #[strategy(arb())] key_seed: Digest,
    ) {
        let key = EcHybridKey::from_seed(key_seed);
        let address = key.to_address();

        let encrypted_bfes = address.encrypt(&payload);

        let (utxo, sender_randomness) = key
            .viewing_key()
            .decrypt(&encrypted_bfes)
            .expect("Decryption should succeed for valid ciphertext and matching keys");

        // 4. Assert Identity
        prop_assert_eq!(
            payload,
            UtxoNotificationPayload::new(utxo, sender_randomness)
        );
    }

    #[test]
    fn decryption_fails_with_wrong_key() {
        let alice_key = EcHybridKey::from_seed(Digest::default());
        let bob_key = EcHybridKey::from_seed(Digest::default().hash());
        let bob_address = bob_key.to_address();
        let payload = UtxoNotificationPayload::new(Utxo::empty_dummy(), Digest::default());

        // Bob's address is used to encrypt
        let encrypted_bfes = bob_address.encrypt(&payload);

        // Alice tries to decrypt a message sent to Bob
        let result = alice_key.viewing_key().decrypt(&encrypted_bfes);

        assert!(
            result.is_err(),
            "Decryption should fail when using the wrong key"
        );
    }
}
