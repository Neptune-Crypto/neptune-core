//! provides an asymmetric key interface for sending and claiming [Utxo].
//!
//! The asymmetric key is based on [lattice::kem] and encrypts a symmetric key
//! based on [aes_gcm::Aes256Gcm] which encrypts the actual payload.
//!
//! ### Naming
//!
//! These are called "Generation" keys because they are quantum-secure and it is
//! believed/hoped that the cryptography should be unbreakable for at least a
//! generation and hopefully many generations.  If correct, it would be safe to
//! put funds in a paper or metal wallet and ignore them for decades, perhaps
//! until they are transferred to the original owner's children or
//! grand-children.

use aead::Aead;
use aead::KeyInit;
use aes_gcm::Aes256Gcm;
use aes_gcm::Nonce;
use anyhow::bail;
use anyhow::Result;
use arbitrary::Arbitrary;
use bech32::FromBase32;
use bech32::ToBase32;
use bech32::Variant;
use serde_derive::Deserialize;
use serde_derive::Serialize;
use twenty_first::math::b_field_element::BFieldElement;
use twenty_first::math::lattice;
use twenty_first::math::lattice::kem::CIPHERTEXT_SIZE_IN_BFES;
use twenty_first::math::tip5::Digest;

use super::common;
use super::common::deterministically_derive_seed_and_nonce;
use super::common::network_hrp_char;
use super::encrypted_utxo_notification::EncryptedUtxoNotification;
use crate::config_models::network::Network;
use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::transaction::lock_script::LockScript;
use crate::models::blockchain::transaction::lock_script::LockScriptAndWitness;
use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::blockchain::transaction::PublicAnnouncement;
use crate::models::state::wallet::utxo_notification::UtxoNotificationPayload;
use crate::prelude::twenty_first;

pub(super) const GENERATION_FLAG_U8: u8 = 79;
pub const GENERATION_FLAG: BFieldElement = BFieldElement::new(GENERATION_FLAG_U8 as u64);

// note: we serde(skip) fields that can be computed from the seed in order to
// keep the serialized (including bech32m) representation small.
#[derive(Clone, Debug, Copy, PartialEq, Eq, Serialize)]
pub struct GenerationSpendingKey {
    seed: Digest,

    #[serde(skip)]
    receiver_identifier: BFieldElement,

    #[serde(skip)]
    decryption_key: lattice::kem::SecretKey,

    #[serde(skip)]
    privacy_preimage: Digest,

    #[serde(skip)]
    unlock_key: Digest,
}

// manually impl Deserialize so we can derive all other fields from the seed.
impl<'de> serde::de::Deserialize<'de> for GenerationSpendingKey {
    // todo: is there a more succinct way to impl this fn that works for
    // both sequential and map visitor access patterns?
    //
    // for seq access (bincode, postcard) we can simply do:
    //    let seed = Digest::deserialize(deserializer)?;
    //    Ok(Self::derive_from_seed(seed))
    //
    // but that fails for crates like serde_json that use map access.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Seed,
        }

        struct FieldVisitor;

        impl<'de> serde::de::Visitor<'de> for FieldVisitor {
            type Value = GenerationSpendingKey;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct GenerationSpendingKey")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
            where
                V: serde::de::SeqAccess<'de>,
            {
                let seed = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                Ok(GenerationSpendingKey::derive_from_seed(seed))
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut seed = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Seed => {
                            if seed.is_some() {
                                return Err(serde::de::Error::duplicate_field("seed"));
                            }
                            seed = Some(map.next_value()?);
                        }
                    }
                }
                let seed_digest = seed.ok_or_else(|| serde::de::Error::missing_field("seed"))?;
                Ok(GenerationSpendingKey::derive_from_seed(seed_digest))
            }
        }

        const FIELDS: &[&str] = &["seed"];
        deserializer.deserialize_struct("GenerationSpendingKey", FIELDS, FieldVisitor)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct GenerationReceivingAddress {
    receiver_identifier: BFieldElement,
    encryption_key: lattice::kem::PublicKey,

    privacy_digest: Digest,
    spending_lock: Digest,
}

impl<'a> Arbitrary<'a> for GenerationReceivingAddress {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let seed = Digest::arbitrary(u)?;
        Ok(Self::derive_from_seed(seed))
    }
}

impl GenerationSpendingKey {
    pub fn to_address(&self) -> GenerationReceivingAddress {
        let randomness: [u8; 32] = common::shake256::<32>(&bincode::serialize(&self.seed).unwrap());
        let (_sk, pk) = lattice::kem::keygen(randomness);
        let privacy_digest = self.privacy_preimage.hash();
        GenerationReceivingAddress {
            receiver_identifier: self.receiver_identifier(),
            encryption_key: pk,
            privacy_digest,
            spending_lock: self.generate_spending_lock(),
        }
    }

    pub(crate) fn lock_script_and_witness(&self) -> LockScriptAndWitness {
        LockScriptAndWitness::hash_lock(self.unlock_key)
    }

    pub fn derive_from_seed(seed: Digest) -> Self {
        let privacy_preimage =
            Hash::hash_varlen(&[seed.values().to_vec(), vec![BFieldElement::new(0)]].concat());
        let unlock_key =
            Hash::hash_varlen(&[seed.values().to_vec(), vec![BFieldElement::new(1)]].concat());
        let randomness: [u8; 32] = common::shake256::<32>(&bincode::serialize(&seed).unwrap());
        let (sk, _pk) = lattice::kem::keygen(randomness);
        let receiver_identifier = common::derive_receiver_id(seed);

        let spending_key = Self {
            receiver_identifier,
            decryption_key: sk,
            privacy_preimage,
            unlock_key,
            seed: seed.to_owned(),
        };

        // Sanity check that spending key's receiver address can be encoded to
        // bech32m without loss of information.
        let receiving_address = spending_key.to_address();
        let encoded_address = receiving_address.to_bech32m(Network::Alpha).unwrap();
        let decoded_address =
            GenerationReceivingAddress::from_bech32m(&encoded_address, Network::Alpha).unwrap();
        assert_eq!(
            receiving_address, decoded_address,
            "encoding/decoding from bech32m must succeed. Receiving address was: {receiving_address:#?}"
        );

        spending_key
    }

    /// Decrypt a Generation Address ciphertext
    pub(super) fn decrypt(&self, ciphertext: &[BFieldElement]) -> Result<(Utxo, Digest)> {
        // parse ciphertext
        if ciphertext.len() <= CIPHERTEXT_SIZE_IN_BFES {
            bail!("Ciphertext does not have nonce.");
        }
        let (kem_ctxt, remainder_ctxt) = ciphertext.split_at(CIPHERTEXT_SIZE_IN_BFES);
        if remainder_ctxt.len() <= 1 {
            bail!("Ciphertext does not have payload.")
        }
        let (nonce_ctxt, dem_ctxt) = remainder_ctxt.split_at(1);
        let kem_ctxt_array: [BFieldElement; CIPHERTEXT_SIZE_IN_BFES] = kem_ctxt.try_into().unwrap();

        // decrypt
        let shared_key = match lattice::kem::dec(self.decryption_key, kem_ctxt_array.into()) {
            Some(sk) => sk,
            None => bail!("Could not establish shared secret key."),
        };
        let cipher = Aes256Gcm::new(&shared_key.into());
        let nonce_as_bytes = [nonce_ctxt[0].value().to_be_bytes().to_vec(), vec![0u8; 4]].concat();
        let nonce = Nonce::from_slice(&nonce_as_bytes); // almost 64 bits; unique per message
        let ciphertext_bytes = common::bfes_to_bytes(dem_ctxt)?;
        let plaintext = match cipher.decrypt(nonce, ciphertext_bytes.as_ref()) {
            Ok(ptxt) => ptxt,
            Err(_) => bail!("Failed to decrypt symmetric payload."),
        };

        // convert plaintext to utxo and digest
        Ok(bincode::deserialize(&plaintext)?)
    }

    fn generate_spending_lock(&self) -> Digest {
        self.unlock_key.hash()
    }

    /// returns the privacy preimage.
    ///
    /// note: The hash of the preimage is available in the receiving address
    /// as the privacy_digest
    pub fn privacy_preimage(&self) -> Digest {
        self.privacy_preimage
    }

    /// returns the receiver_identifier, a public fingerprint
    pub fn receiver_identifier(&self) -> BFieldElement {
        self.receiver_identifier
    }
}

impl GenerationReceivingAddress {
    pub fn from_spending_key(spending_key: &GenerationSpendingKey) -> Self {
        let seed = spending_key.seed;
        let receiver_identifier = common::derive_receiver_id(seed);
        let randomness: [u8; 32] = common::shake256::<32>(&bincode::serialize(&seed).unwrap());
        let (_sk, pk) = lattice::kem::keygen(randomness);
        let privacy_digest = spending_key.privacy_preimage.hash();
        Self {
            receiver_identifier,
            encryption_key: pk,
            privacy_digest,
            spending_lock: spending_key.generate_spending_lock(),
        }
    }

    pub fn derive_from_seed(seed: Digest) -> Self {
        let spending_key = GenerationSpendingKey::derive_from_seed(seed);
        Self::from_spending_key(&spending_key)
    }

    /// Determine whether the given witness unlocks the lock defined by this receiving
    /// address.
    pub fn can_unlock_with(&self, witness: &[BFieldElement]) -> bool {
        match witness.try_into() {
            Ok(witness_array) => Digest::new(witness_array).hash() == self.spending_lock,
            Err(_) => false,
        }
    }

    pub(crate) fn encrypt(&self, payload: &UtxoNotificationPayload) -> Vec<BFieldElement> {
        let (randomness, nonce_bfe) = deterministically_derive_seed_and_nonce(payload);
        let (shared_key, kem_ctxt) = lattice::kem::enc(self.encryption_key, randomness);

        // convert payload to bytes
        let plaintext = bincode::serialize(payload).unwrap();

        // generate symmetric ciphertext
        let cipher = Aes256Gcm::new(&shared_key.into());
        let nonce_as_bytes = [nonce_bfe.value().to_be_bytes().to_vec(), vec![0u8; 4]].concat();
        let nonce = Nonce::from_slice(&nonce_as_bytes); // almost 64 bits; unique per message
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();
        let ciphertext_bfes = common::bytes_to_bfes(&ciphertext);

        // concatenate and return
        [
            std::convert::Into::<[BFieldElement; CIPHERTEXT_SIZE_IN_BFES]>::into(kem_ctxt).to_vec(),
            vec![nonce_bfe],
            ciphertext_bfes,
        ]
        .concat()
    }

    /// returns human readable prefix (hrp) of an address.
    pub(super) fn get_hrp(network: Network) -> String {
        // NOLGA: Neptune lattice-based generation address
        let mut hrp = "nolga".to_string();
        let network_byte = network_hrp_char(network);
        hrp.push(network_byte);
        hrp
    }

    pub fn to_bech32m(&self, network: Network) -> Result<String> {
        let hrp = Self::get_hrp(network);
        let payload = bincode::serialize(self)?;
        let variant = Variant::Bech32m;
        match bech32::encode(&hrp, payload.to_base32(), variant) {
            Ok(enc) => Ok(enc),
            Err(e) => bail!("Could not encode generation address as bech32m because error: {e}"),
        }
    }

    pub fn from_bech32m(encoded: &str, network: Network) -> Result<Self> {
        let (hrp, data, variant) = bech32::decode(encoded)?;

        if variant != Variant::Bech32m {
            bail!("Can only decode bech32m addresses.");
        }

        if hrp[0..=5] != Self::get_hrp(network) {
            bail!("Could not decode bech32m address because of invalid prefix");
        }

        let payload = Vec::<u8>::from_base32(&data)?;

        match bincode::deserialize(&payload) {
            Ok(ra) => Ok(ra),
            Err(e) => bail!("Could not decode bech32m address because of error: {e}"),
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
    /// it would be nice to standardize on a single prefix-len.  6 chars seems a
    /// bit much.  maybe we could shorten generation prefix to 4 somehow, eg:
    /// ngkm --> neptune-generation-key-mainnet
    pub fn to_bech32m_abbreviated(&self, network: Network) -> Result<String> {
        let bech32 = self.to_bech32m(network)?;
        let first_len = Self::get_hrp(network).len() + 8usize;
        let last_len = 8usize;

        assert!(bech32.len() > first_len + last_len);

        let (first, _) = bech32.split_at(first_len);
        let (_, last) = bech32.split_at(bech32.len() - last_len);

        Ok(format!("{}...{}", first, last))
    }

    /// generates a lock script from the spending lock.
    ///
    /// Satisfaction of this lock script establishes the UTXO owner's assent to
    /// the transaction.
    pub fn lock_script(&self) -> LockScript {
        LockScript::hash_lock(self.spending_lock)
    }

    pub(crate) fn generate_public_announcement(
        &self,
        utxo_notification_payload: &UtxoNotificationPayload,
    ) -> PublicAnnouncement {
        let encrypted_utxo_notification = EncryptedUtxoNotification {
            flag: GENERATION_FLAG_U8.into(),
            receiver_identifier: self.receiver_identifier(),
            ciphertext: self.encrypt(utxo_notification_payload),
        };

        encrypted_utxo_notification.into_public_announcement()
    }

    pub(crate) fn private_utxo_notification(
        &self,
        utxo_notification_payload: &UtxoNotificationPayload,
        network: Network,
    ) -> String {
        let encrypted_utxo_notification = EncryptedUtxoNotification {
            flag: GENERATION_FLAG_U8.into(),
            receiver_identifier: self.receiver_identifier(),
            ciphertext: self.encrypt(utxo_notification_payload),
        };

        encrypted_utxo_notification.into_bech32m(network)
    }

    /// returns the receiver_identifier, a public fingerprint
    pub fn receiver_identifier(&self) -> BFieldElement {
        self.receiver_identifier
    }

    /// returns a privacy digest which corresponds to the.privacy_preimage(),
    /// of the matching [GenerationSpendingKey]
    pub fn privacy_digest(&self) -> Digest {
        self.privacy_digest
    }

    /// returns the `spending_lock`
    pub fn spending_lock(&self) -> Digest {
        self.spending_lock
    }
}

#[cfg(test)]
mod test {
    use super::*;

    mod generation_spending_key {
        use super::*;

        // we test serialization roundtrip because we skip fields when serializing and
        // there is a custom impl Deserialization for GenerationSpendingKey
        //
        // serde crates can use either sequential or map visitor access pattern when deserializing
        // so it is important to test both.
        mod serialization {
            use super::*;

            // note: bincode uses sequential access pattern when deserializing.
            #[test]
            pub fn roundtrip_bincode() {
                let spending_key = GenerationSpendingKey::derive_from_seed(rand::random());

                let s = bincode::serialize(&spending_key).unwrap();
                let deserialized_key: GenerationSpendingKey = bincode::deserialize(&s).unwrap();

                assert_eq!(spending_key, deserialized_key);
            }

            // note serde_json uses map access pattern when deserializing.
            #[test]
            pub fn roundtrip_json() {
                let spending_key = GenerationSpendingKey::derive_from_seed(rand::random());

                let s = serde_json::to_string(&spending_key).unwrap();
                let deserialized_key: GenerationSpendingKey = serde_json::from_str(&s).unwrap();

                assert_eq!(spending_key, deserialized_key);
            }
        }
    }
}
