//! provides a symmetric key interface based on aes-256-gcm for sending and claiming [Utxo]

use aead::Aead;
use aead::Key;
use aead::KeyInit;
use aes_gcm::Aes256Gcm;
use aes_gcm::Nonce;
use anyhow::Result;
use serde::Deserialize;
use serde::Serialize;
use twenty_first::math::b_field_element::BFieldElement;
use twenty_first::math::tip5::Digest;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;

use super::common;
use super::common::deterministically_derive_seed_and_nonce;
use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::transaction::lock_script::LockScript;
use crate::models::blockchain::transaction::lock_script::LockScriptAndWitness;
use crate::models::blockchain::transaction::transaction_output::UtxoNotificationPayload;
use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::blockchain::transaction::PublicAnnouncement;
use crate::prelude::twenty_first;

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
    seed: Digest,
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
        self.privacy_preimage().hash()
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
    pub fn encrypt(&self, utxo: &Utxo, sender_randomness: Digest) -> Vec<BFieldElement> {
        // 1. init randomness
        let (_randomness, nonce_bfe) =
            deterministically_derive_seed_and_nonce(utxo, sender_randomness);

        // 2. generate random nonce
        let nonce_as_bytes = [&nonce_bfe.value().to_be_bytes(), [0u8; 4].as_slice()].concat();
        let nonce = Nonce::from_slice(&nonce_as_bytes); // almost 64 bits; unique per message

        // 3. convert secrets to plaintext bytes
        let plaintext = bincode::serialize(&(utxo, sender_randomness)).unwrap();

        // 4. encrypt plaintext to symmetric ciphertext bytes
        let cipher = Aes256Gcm::new(&self.secret_key());
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();

        // 5. convert ciphertext bytes to [BFieldElement]
        let ciphertext_bfes = common::bytes_to_bfes(&ciphertext);

        // 6. concatenate nonce bfe + ciphertext bfes and return
        [&[nonce_bfe], ciphertext_bfes.as_slice()].concat()
    }

    /// returns the unlock key
    pub fn unlock_key(&self) -> Digest {
        Hash::hash_varlen(&[self.seed.values().to_vec(), vec![BFieldElement::new(1)]].concat())
    }

    /// returns the spending lock which is a hash of unlock_key()
    pub fn spending_lock(&self) -> Digest {
        self.unlock_key().hash()
    }

    /// generates a lock script from the spending lock.
    ///
    /// Satisfaction of this lock script establishes the UTXO owner's assent to
    /// the transaction.
    pub fn lock_script(&self) -> LockScript {
        common::lock_script(self.spending_lock())
    }

    pub(crate) fn lock_script_and_witness(&self) -> LockScriptAndWitness {
        common::lock_script_and_witness(self.unlock_key())
    }

    pub(crate) fn generate_public_announcement(
        &self,
        utxo_notification_payload: UtxoNotificationPayload,
    ) -> PublicAnnouncement {
        let ciphertext = [
            &[SYMMETRIC_KEY_FLAG_U8.into(), self.receiver_identifier()],
            self.encrypt(
                &utxo_notification_payload.utxo(),
                utxo_notification_payload.sender_randomness(),
            )
            .as_slice(),
        ]
        .concat();

        PublicAnnouncement::new(ciphertext)
    }
}