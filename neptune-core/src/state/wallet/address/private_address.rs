use aead::Aead;
use aead::KeyInit;
use aes_gcm::Aes256Gcm;
use aes_gcm::Nonce;
use bech32::ToBase32;
use bech32::Variant;
use bincode::Options;
use itertools::Itertools;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::twenty_first::bfe;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;
use tasm_lib::twenty_first::tip5::Digest;
use tasm_lib::twenty_first::tip5::Tip5;

use crate::api::export::Announcement;
use crate::api::export::Utxo;
use crate::application::config::network::Network;
use crate::state::wallet::address::common;
use crate::state::wallet::address::common::deterministically_derive_seed_and_nonce;
use crate::state::wallet::address::common::network_hrp_char;
use crate::state::wallet::address::encrypted_utxo_notification::EncryptedUtxoNotification;
use crate::state::wallet::utxo_notification::UtxoNotificationPayload;

pub(super) const PRIVATE_ADDRESS_FLAG_U8: u8 = 81;
pub const PRIVATE_ADDRESS_FLAG: BFieldElement = BFieldElement::new(PRIVATE_ADDRESS_FLAG_U8 as u64);

const PRIVATE_ADDRESS_AES_NONCE: [u8; 12] = [0u8; 12];

fn receiver_id(ec_pubkey: &k256::PublicKey) -> BFieldElement {
    let pubkey_encoded = ec_pubkey.to_sec1_bytes().to_vec();
    let [e0, _, _, _, _] = Tip5::hash(&pubkey_encoded).values();

    e0
}

/// The receiver-shard of the main AES key.
fn aes_key_receiver_part(lock_postimage: [BFieldElement; 3], receiever_digest: Digest) -> [u8; 32] {
    let [e0, e1, e2] = lock_postimage;
    let digest = Tip5::hash_pair(receiever_digest, Digest([e0, e1, e2, bfe!(0), bfe!(0)]));
    let digest: [u8; 40] = digest.into();

    digest.into_iter().take(32).collect_array().unwrap()
}

// note: we serde(skip) fields that can be computed from the seed in order to
// keep the serialized (including bech32m) representation small.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PrivateAddressKey {
    seed: Digest,

    #[serde(skip)]
    receiver_identifier: BFieldElement,

    #[serde(skip)]
    ec_secret_key: k256::SecretKey,

    #[serde(skip)]
    receiver_preimage: Digest,

    #[serde(skip)]
    unlock_key_preimage: Digest,
}

impl PrivateAddressKey {
    pub fn from_seed(seed: Digest) -> Self {
        let [e0, e1, e2, e3, e4] = seed.values();

        // The unlock preimage may not be linkable to any of the other fields,
        // except for the seed field.
        let unlock_key_preimage = Tip5::hash(&[PRIVATE_ADDRESS_FLAG, e0, e1, e2, e3, e4]);
        let privacy_seed = Tip5::hash(&[e0, e1, e2, e3, e4, PRIVATE_ADDRESS_FLAG]);

        // May not be derivable from the elliptic curve secret key. Otherwise
        // the viewing key would leak the receiver preimage -- meaning that the
        // viewer key would leak information about whether a received UTXO is
        // spent or not.
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
        let ec_pubkey = ec_secret_key.public_key();
        let receiver_identifier = receiver_id(&ec_pubkey);

        Self {
            seed,
            receiver_identifier,
            ec_secret_key,
            receiver_preimage,
            unlock_key_preimage,
        }
    }

    pub fn viewing_key(&self) -> PrivateAddressViewingKey {
        let [e0, e1, e2, _, _] = self.unlock_key_preimage.hash().values();
        let lock_postimage = [e0, e1, e2];
        PrivateAddressViewingKey {
            ec_secret_key: self.ec_secret_key.clone(),
            receiver_digest: self.receiver_preimage.hash(),
            lock_postimage,
        }
    }
}

/// Cryptographic information to retrieve all information about incoming UTXOs
/// for an address without the ability to spend any of its UTXOs.
///
/// If you want to see if UTXOs received on an address has also been spent
/// (still without spending abilities), you will need the receiver preimage, in
/// addition to this data structure.
struct PrivateAddressViewingKey {
    ec_secret_key: k256::SecretKey,

    receiver_digest: Digest,

    lock_postimage: [BFieldElement; 3],
}

impl PrivateAddressViewingKey {
    pub fn decrypt(
        &self,
        encrypted_bfes: &[BFieldElement],
    ) -> Result<(Utxo, Digest), anyhow::Error> {
        // 1. Convert the concatenated BFieldElements back to bytes.
        let all_bytes = common::bfes_to_bytes(encrypted_bfes)?;

        if all_bytes.len() < 33 {
            anyhow::bail!("Ciphertext too short to contain ephemeral public key");
        }

        // 2. Split the bytes into the 33-byte ephemeral public key and the AES ciphertext.
        let (ephemeral_pubkey_bytes, ciphertext) = all_bytes.split_at(33);

        // 3. Parse the sender's ephemeral public key.
        let ephemeral_pubkey = k256::PublicKey::from_sec1_bytes(ephemeral_pubkey_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid ephemeral public key: {:?}", e))?;

        // 4. Perform ECDH using the receiver's private key and the sender's ephemeral public key.
        // The math guarantees this matches the sender's `sender_key_share`.
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

        // 6. XOR with the receiver's part to reconstruct the 256-bit symmetric AES key.
        let receiver_key_share = aes_key_receiver_part(self.lock_postimage, self.receiver_digest);
        let aes_key: [u8; 32] = receiver_key_share
            .into_iter()
            .zip_eq(sender_key_share)
            .map(|(receiver, sender)| receiver ^ sender)
            .collect_array()
            .unwrap();

        // 7. Decrypt the payload using the reconstructed AES key and the fixed nonce.
        let cipher = Aes256Gcm::new(&aes_key.into());
        let nonce = Nonce::from_slice(&PRIVATE_ADDRESS_AES_NONCE);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("AES-GCM decryption failed: {:?}", e))?;

        // 8. Deserialize the plaintext back into the payload struct.
        let payload: UtxoNotificationPayload = bincode::deserialize(&plaintext)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize payload: {:?}", e))?;

        Ok((payload.utxo, payload.sender_randomness))
    }
}

#[derive(Clone, Debug, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateAddress {
    ec_pubkey: k256::PublicKey,

    /// Post-image of the receiver preimage
    receiver_digest: Digest,

    /// Post-image of the hashlock key
    lock_postimage: [BFieldElement; 3],
}

impl PrivateAddress {
    fn serialize(&self) -> Vec<u8> {
        let bincode_opts = bincode::DefaultOptions::new().with_fixint_encoding();

        bincode_opts.serialize(self).expect("Serialization failed")
    }

    fn aes_key_receiver_part(&self) -> [u8; 32] {
        aes_key_receiver_part(self.lock_postimage, self.receiver_digest)
    }

    pub fn receiver_id(&self) -> BFieldElement {
        receiver_id(&self.ec_pubkey)
    }

    pub fn receiver_postimage(&self) -> Digest {
        self.receiver_digest
    }

    pub(super) fn get_hrp(network: Network) -> String {
        let mut hrp = "npriv".to_string();

        let network_byte = network_hrp_char(network);
        hrp.push(network_byte);
        hrp
    }

    pub fn to_bech32m(&self, network: Network) -> String {
        let hrp = Self::get_hrp(network);

        // Use default options but force it to fix variable length integers if possible,
        // or just rely on a custom serialization if you need absolute control over bytes.
        let bincode_opts = bincode::DefaultOptions::new().with_fixint_encoding();

        let payload = bincode_opts.serialize(self).expect("Serialization failed");

        let variant = Variant::Bech32m;
        bech32::encode(&hrp, payload.to_base32(), variant)
            .expect("Could not encode address as bech32m because")
    }

    pub(crate) fn generate_announcement(
        &self,
        utxo_notification_payload: &UtxoNotificationPayload,
    ) -> Announcement {
        let encrypted_utxo_notification = EncryptedUtxoNotification {
            flag: PRIVATE_ADDRESS_FLAG,
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
            flag: PRIVATE_ADDRESS_FLAG,
            receiver_identifier: self.receiver_id(),
            ciphertext: self.encrypt(utxo_notification_payload),
        };

        encrypted_utxo_notification.into_bech32m(network)
    }

    pub(crate) fn encrypt(&self, payload: &UtxoNotificationPayload) -> Vec<BFieldElement> {
        // 1. Generate an Ephemeral Keypair for ECDH, deterministically.
        let (ephemeral_secret, _nonce_bfe) = deterministically_derive_seed_and_nonce(payload);
        let ephemeral_secret = k256::SecretKey::from_slice(&ephemeral_secret)
            .expect("Derived randomness exceeded secp256k1 curve order");
        let ephemeral_pubkey = ephemeral_secret.public_key();

        // Serialize the ephemeral pubkey to 33 compressed bytes to send on-chain
        let ephemeral_pubkey_bytes = ephemeral_pubkey.to_sec1_bytes();

        // 2. Perform ECDH to get the asymmetric shared secret
        let sender_key_share = k256::ecdh::diffie_hellman(
            ephemeral_secret.to_nonzero_scalar(),
            self.ec_pubkey.as_affine(),
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
        let nonce = Nonce::from_slice(&PRIVATE_ADDRESS_AES_NONCE);

        let cipher = Aes256Gcm::new(&aes_key.into());
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();

        let all_bytes = [ephemeral_pubkey_bytes.to_vec(), ciphertext].concat();

        common::bytes_to_bfes(&all_bytes)
    }
}

#[cfg(any(test, feature = "arbitrary-impls"))]
impl<'a> arbitrary::Arbitrary<'a> for PrivateAddress {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let seed = Digest::arbitrary(u)?;
        Ok(Self::from_seed(seed))
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;
    use test_strategy::proptest;

    use super::*;

    // Helper function to mock generating a valid PrivateAddressKey and PrivateAddress pair
    // Note: Adjust the internals to match how you natively instantiate your keys/digests
    fn generate_test_address_pair() -> (PrivateAddressKey, PrivateAddress) {
        let ec_secret_key = k256::SecretKey::random(&mut OsRng);
        let ec_pubkey = ec_secret_key.public_key();

        // Mock deterministic digests for the test
        let mock_digest = Tip5::hash(&[BFieldElement::new(1)]);

        let priv_key = PrivateAddressKey {
            seed: mock_digest,
            receiver_identifier: BFieldElement::new(42),
            ec_secret_key,
            receiver_preimage: mock_digest,
            unlock_key_preimage: mock_digest,
        };

        let pub_address = PrivateAddress {
            ec_pubkey,
            receiver_digest: mock_digest,
            lock_postimage: [
                BFieldElement::new(1),
                BFieldElement::new(2),
                BFieldElement::new(3),
            ],
        };

        (priv_key, pub_address)
    }

    #[proptest]
    fn test_private_address_encryption_roundtrip(
        #[strategy(arb())] payload: UtxoNotificationPayload,
    ) {
        // 1. Setup Sender and Receiver
        let (receiver_priv_key, receiver_pub_address) = generate_test_address_pair();

        // 2. Sender Encrypts
        let encrypted_bfes = receiver_pub_address.encrypt(&payload);

        // 3. Receiver Decrypts
        let decrypted_payload = receiver_priv_key
            .decrypt(&encrypted_bfes, &receiver_pub_address)
            .expect("Decryption should succeed for valid ciphertext and matching keys");

        // 4. Assert Identity
        prop_assert_eq!(payload, decrypted_payload);
    }

    #[test]
    fn test_decryption_fails_with_wrong_key() {
        let (alice_priv_key, _alice_pub_address) = generate_test_address_pair();
        let (_bob_priv_key, bob_pub_address) = generate_test_address_pair();

        // Create a dummy payload
        let payload = UtxoNotificationPayload::default(); // Assumes Default is implemented

        // Bob's address is used to encrypt
        let encrypted_bfes = bob_pub_address.encrypt(&payload);

        // Alice tries to decrypt a message sent to Bob
        let result = alice_priv_key.decrypt(&encrypted_bfes, &bob_pub_address);

        assert!(
            result.is_err(),
            "Decryption should fail when using the wrong private key"
        );
    }
}
