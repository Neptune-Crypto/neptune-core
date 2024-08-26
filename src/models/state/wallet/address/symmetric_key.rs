//! provides a symmetric key interface based on aes-256-gcm for sending and claiming [Utxo]

use super::common;
use crate::config_models::network::Network;
use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::transaction::utxo::LockScript;
use crate::models::blockchain::transaction::utxo::Utxo;
use crate::prelude::twenty_first;
use aead::Aead;
use aead::Key;
use aead::KeyInit;
use aes_gcm::Aes256Gcm;
use aes_gcm::Nonce;
use anyhow::bail;
use bech32::FromBase32;
use bech32::ToBase32;
use rand::thread_rng;
use rand::Rng;
use serde::Deserialize;
use serde::Serialize;
use twenty_first::math::b_field_element::BFieldElement;
use twenty_first::math::tip5::Digest;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;

/// represents a symmetric key decryption error
#[derive(Debug, thiserror::Error)]
pub enum DecryptError {
    #[error("invalid input to decrypt. ciphertext array is missing the nonce field")]
    MissingNonce,

    #[error(transparent)]
    ByteConversionFailed(#[from] anyhow::Error),

    #[error("decryption failed")]
    DecryptionFailed(#[from] aead::Error),

    #[error("deserialization failed")]
    DeserializationFailed(#[from] bincode::Error),
}

/// represents a symmetric key encryption error
#[derive(Debug, thiserror::Error)]
pub enum EncryptError {
    #[error("encryption failed")]
    EncryptionFailed(#[from] aead::Error),

    #[error("serialization failed")]
    SerializationFailed(#[from] bincode::Error),
}

/// This uniquely identifies the type field of a PublicAnnouncement.
/// it must not conflict with another type.
pub(super) const SYMMETRIC_KEY_FLAG_U8: u8 = 80;
pub const SYMMETRIC_KEY_FLAG: BFieldElement = BFieldElement::new(SYMMETRIC_KEY_FLAG_U8 as u64);

/// represents an AES 256 bit symmetric key
///
/// this is an opaque type.  all fields are read-only via accessor methods.
///
/// implementation note:
///
/// Presently `SymmetricKey` holds only the seed value. All other values are
/// derived on as-needed (lazy) basis.  This is memory efficient and cheap to
/// create a key, but may not be CPU efficient if duplicate operations are
/// performed with the same key.
///
/// The alternative would be to pre-calculate the various values at
/// creation-time and store them in the struct.  This has a higher up-front cost
/// to perform the necessary hashing and a higher memory usage but it quickly
/// becomes worth it when amortized over multiple operations.
///
/// a hybrid (cache-on-first-use) approach may be feasible, but would require
/// that accessor methods accept &mut self which may not be acceptable.
///
/// The implementation can be easily changed later if needed as the type is
/// opaque.
#[derive(Clone, Debug, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct SymmetricKey {
    seed: Digest, // 40 bytes
}

impl SymmetricKey {
    /// instantiate `SymmetricKey` from a random seed
    pub fn from_seed(seed: Digest) -> Self {
        Self { seed }
    }

    /// returns the secret key
    pub fn secret_key(&self) -> Key<Aes256Gcm> {
        common::shake256::<32>(
            &bincode::serialize(&self.seed).expect("serialization should always succeed"),
        )
        .into()
    }

    /// returns the privacy preimage
    pub fn privacy_preimage(&self) -> Digest {
        Hash::hash_varlen(&[&self.seed.values(), [BFieldElement::new(0)].as_slice()].concat())
    }

    /// returns the privacy digest which is a hash of the privacy_preimage
    pub fn privacy_digest(&self) -> Digest {
        self.privacy_preimage().hash::<Hash>()
    }

    /// returns the receiver_identifier, a public fingerprint
    pub fn receiver_identifier(&self) -> BFieldElement {
        common::derive_receiver_id(self.seed)
    }

    /// decrypt a ciphertext into utxo secrets (utxo, sender_randomness)
    ///
    /// The ciphertext_bfes param must contain the nonce in the first
    /// field and the ciphertext in the remaining fields.
    ///
    /// The output of `encrypt()` should be used as the input to `decrypt()`.
    pub fn decrypt(
        &self,
        ciphertext_bfes: &[BFieldElement],
    ) -> Result<(Utxo, Digest), DecryptError> {
        const NONCE_LEN: usize = 1;

        // 1. separate nonce from ciphertext.
        let (nonce_ctxt, ciphertext) = match ciphertext_bfes.len() > NONCE_LEN {
            true => ciphertext_bfes.split_at(NONCE_LEN),
            false => return Err(DecryptError::MissingNonce),
        };

        // 2. generate Nonce and cyphertext_bytes
        let nonce_as_bytes = [&nonce_ctxt[0].value().to_be_bytes(), [0u8; 4].as_slice()].concat();
        let nonce = Nonce::from_slice(&nonce_as_bytes); // almost 64 bits; unique per message
        let ciphertext_bytes = common::bfes_to_bytes(ciphertext)?;

        // 3. decypt ciphertext to plaintext
        let cipher = Aes256Gcm::new(&self.secret_key());
        let plaintext = cipher.decrypt(nonce, ciphertext_bytes.as_ref())?;

        // 4. deserialize plaintext into (utxo, sender_randomness)
        Ok(bincode::deserialize(&plaintext)?)
    }

    /// encrypts utxo secrets (utxo, sender_randomness) into ciphertext
    ///
    /// The output of `encrypt()` should be used as the input to `decrypt()`.
    pub fn encrypt(
        &self,
        utxo: &Utxo,
        sender_randomness: Digest,
    ) -> Result<Vec<BFieldElement>, EncryptError> {
        // 1. init randomness
        let mut randomness = [0u8; 32];
        let mut rng = thread_rng();
        rng.fill(&mut randomness);

        // 2. generate random nonce
        let nonce_bfe: BFieldElement = rng.gen();
        let nonce_as_bytes = [&nonce_bfe.value().to_be_bytes(), [0u8; 4].as_slice()].concat();
        let nonce = Nonce::from_slice(&nonce_as_bytes); // almost 64 bits; unique per message

        // 3. convert secrets to plaintext bytes
        let plaintext = bincode::serialize(&(utxo, sender_randomness))?;

        // 4. encrypt plaintext to symmetric ciphertext bytes
        let cipher = Aes256Gcm::new(&self.secret_key());
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())?;

        // 5. convert ciphertext bytes to [BFieldElement]
        let ciphertext_bfes = common::bytes_to_bfes(&ciphertext);

        // 6. concatenate nonce bfe + ciphertext bfes and return
        Ok([&[nonce_bfe], ciphertext_bfes.as_slice()].concat())
    }

    /// returns the unlock key
    pub fn unlock_key(&self) -> Digest {
        Hash::hash_varlen(&[self.seed.values().to_vec(), vec![BFieldElement::new(1)]].concat())
    }

    /// returns the spending lock which is a hash of unlock_key()
    pub fn spending_lock(&self) -> Digest {
        self.unlock_key().hash::<Hash>()
    }

    /// generates a lock script from the spending lock.
    ///
    /// Satisfaction of this lock script establishes the UTXO owner's assent to
    /// the transaction.
    pub fn lock_script(&self) -> LockScript {
        common::lock_script(self.spending_lock())
    }

    /// encodes the key as bech32m with network-specific prefix
    ///
    /// security: note that anyone that can view the bech32m string will be able
    /// to spend the funds. In general it is best practice to avoid display of
    /// any part of a symmetric key.
    pub fn to_bech32m(&self, network: Network) -> anyhow::Result<String> {
        let hrp = Self::get_hrp(network);
        let payload = bincode::serialize(self)?;
        let variant = bech32::Variant::Bech32m;
        match bech32::encode(&hrp, payload.to_base32(), variant) {
            Ok(enc) => Ok(enc),
            Err(e) => bail!("Could not encode SymmetricKey as bech32m because error: {e}"),
        }
    }

    /// decodes a key from bech32m with network-specific prefix
    pub fn from_bech32m(encoded: &str, network: Network) -> anyhow::Result<Self> {
        let (hrp, data, variant) = bech32::decode(encoded)?;

        if variant != bech32::Variant::Bech32m {
            bail!("Can only decode bech32m addresses.");
        }

        if hrp != *Self::get_hrp(network) {
            bail!("Could not decode bech32m address because of invalid prefix");
        }

        let payload = Vec::<u8>::from_base32(&data)?;

        match bincode::deserialize(&payload) {
            Ok(ra) => Ok(ra),
            Err(e) => bail!("Could not decode bech32m because of error: {e}"),
        }
    }

    /// returns human readable prefix (hrp) of a key, specific to `network`
    pub fn get_hrp(network: Network) -> String {
        // nsk: neptune-symmetric-key
        format!("nsk{}", common::network_hrp_char(network))
    }
}
