//! provides a symmetric key interface based on aes-256-gcm for sending and claiming [Utxo]

use aead::Aead;
use aead::Key;
use aead::KeyInit;
use aes_gcm::Aes256Gcm;
use aes_gcm::Nonce;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::ensure;
use anyhow::Result;
#[cfg(any(test, feature = "arbitrary-impls"))]
use arbitrary::Arbitrary;
use bech32::FromBase32;
use bech32::ToBase32;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Tip5;
use tasm_lib::triton_vm::vm::NonDeterminism;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;
use tasm_lib::twenty_first::tip5::digest::Digest;

use super::common;
use super::common::deterministically_derive_seed_and_nonce;
use super::encrypted_utxo_notification::EncryptedUtxoNotification;
use crate::application::config::network::Network;
use crate::protocol::consensus::transaction::announcement::Announcement;
use crate::protocol::consensus::transaction::lock_script::LockScript;
use crate::protocol::consensus::transaction::lock_script::LockScriptAndWitness;
use crate::protocol::consensus::transaction::utxo::Utxo;
use crate::state::wallet::utxo_notification::UtxoNotificationPayload;

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
#[cfg_attr(any(test, feature = "arbitrary-impls"), derive(Arbitrary))]
pub struct SymmetricKey {
    seed: Digest,
}

// future improvements: a strong argument can be made that this type should not
// have any methods with outside types as parameters or return types.  for
// example:
//
// pub(crate) fn generate_announcement(
//     &self,
//     utxo_notification_payload: &UtxoNotificationPayload,
// ) -> Announcement;
//
// this method is dealing with types far outside the concern of
// a key, which means the method belongs elsewhere.
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

    /// returns the receiver preimage
    pub fn receiver_preimage(&self) -> Digest {
        Tip5::hash_varlen(&[&self.seed.values(), [BFieldElement::new(0)].as_slice()].concat())
    }

    /// returns the receiver postimage which is a hash of the receiver preimage
    pub fn receiver_postimage(&self) -> Digest {
        self.receiver_preimage().hash()
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

        // 2. generate Nonce and ciphertext_bytes
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
    pub(crate) fn encrypt(&self, payload: &UtxoNotificationPayload) -> Vec<BFieldElement> {
        // 1. init randomness
        let (_randomness, nonce_bfe) = deterministically_derive_seed_and_nonce(payload);

        // 2. generate random nonce
        let nonce_as_bytes = [&nonce_bfe.value().to_be_bytes(), [0u8; 4].as_slice()].concat();
        let nonce = Nonce::from_slice(&nonce_as_bytes); // almost 64 bits; unique per message

        // 3. convert secrets to plaintext bytes
        let plaintext = bincode::serialize(payload).unwrap();

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
        Tip5::hash_varlen(&[self.seed.values().to_vec(), vec![BFieldElement::new(1)]].concat())
    }

    /// returns the spending lock which is a hash of unlock_key()
    pub fn lock_after_image(&self) -> Digest {
        self.unlock_key().hash()
    }

    /// generates a lock script from the spending lock.
    ///
    /// Satisfaction of this lock script establishes the UTXO owner's assent to
    /// the transaction.
    pub fn lock_script(&self) -> LockScript {
        LockScript::standard_hash_lock_from_after_image(self.lock_after_image())
    }

    pub(crate) fn lock_script_and_witness(&self) -> LockScriptAndWitness {
        let lock_script = self.lock_script();
        LockScriptAndWitness::new_with_nondeterminism(
            lock_script.program,
            NonDeterminism::new(self.unlock_key().reversed().values()),
        )
    }

    pub(crate) fn generate_announcement(
        &self,
        utxo_notification_payload: &UtxoNotificationPayload,
    ) -> Announcement {
        let encrypted_utxo_notification = EncryptedUtxoNotification {
            flag: SYMMETRIC_KEY_FLAG_U8.into(),
            receiver_identifier: self.receiver_identifier(),
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
            flag: SYMMETRIC_KEY_FLAG_U8.into(),
            receiver_identifier: self.receiver_identifier(),
            ciphertext: self.encrypt(utxo_notification_payload),
        };

        encrypted_utxo_notification.into_bech32m(network)
    }

    /// encodes the key as bech32m with network-specific prefix
    ///
    /// security: note that anyone that can view the bech32m string will be able
    /// to spend the funds. In general it is best practice to avoid display of
    /// any part of a symmetric key.
    pub fn to_bech32m(&self, network: Network) -> Result<String> {
        let hrp = Self::get_hrp(network);
        let payload = bincode::serialize(self)?;
        let variant = bech32::Variant::Bech32m;
        match bech32::encode(&hrp, payload.to_base32(), variant) {
            Ok(enc) => Ok(enc),
            Err(e) => bail!("Could not encode SymmetricKey as bech32m because error: {e}"),
        }
    }

    /// returns the privacy_preimage() digest encoded as bech32m string.
    /// this is suitable for display purposes as it does not give away the
    /// secret key.
    pub fn to_display_bech32m(&self, network: Network) -> Result<String> {
        let hrp = Self::get_hrp(network);
        let payload = bincode::serialize(&self.receiver_preimage())?;
        let variant = bech32::Variant::Bech32m;
        match bech32::encode(&hrp, payload.to_base32(), variant) {
            Ok(enc) => Ok(enc),
            Err(e) => bail!("Could not encode SymmetricKey as bech32m because error: {e}"),
        }
    }

    /// decodes a key from bech32m with network-specific prefix
    pub fn from_bech32m(encoded: &str, network: Network) -> Result<Self> {
        let (hrp, data, variant) = bech32::decode(encoded)?;

        ensure!(
            variant == bech32::Variant::Bech32m,
            "Can only decode bech32m addresses.",
        );
        ensure!(
            hrp == *Self::get_hrp(network),
            "Could not decode bech32m address because of invalid prefix",
        );

        let payload = Vec::<u8>::from_base32(&data)?;
        bincode::deserialize(&payload)
            .map_err(|e| anyhow!("Could not decode bech32m because of error: {e}"))
    }

    /// returns human readable prefix (hrp) of a key, specific to `network`
    pub(super) fn get_hrp(network: Network) -> String {
        // nsk: neptune-symmetric-key
        format!("nsymk{}", common::network_hrp_char(network))
    }
}
