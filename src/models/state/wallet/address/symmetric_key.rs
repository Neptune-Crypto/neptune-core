use super::generation_address;
use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::transaction::utxo::LockScript;
use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::blockchain::transaction::AnnouncedUtxo;
use crate::models::blockchain::transaction::PublicAnnouncement;
use crate::models::blockchain::transaction::Transaction;
use crate::prelude::{triton_vm, twenty_first};
use crate::util_types::mutator_set::commit;
use aead::Aead;
use aead::Key;
use aead::KeyInit;
use aes_gcm::Aes256Gcm;
use aes_gcm::Nonce;
use itertools::Itertools;
use rand::thread_rng;
use rand::Rng;
use serde::Deserialize;
use serde::Serialize;
use tracing::warn;
use triton_vm::triton_asm;
use triton_vm::triton_instr;
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
pub const SYMMETRIC_KEY_FLAG: BFieldElement = BFieldElement::new(80);

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
        generation_address::shake256::<32>(
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
        generation_address::derive_receiver_id(self.seed)
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
        // pre-compute these.
        let receiver_identifier = self.receiver_identifier();
        let receiver_preimage = self.privacy_preimage();
        let receiver_digest = receiver_preimage.hash::<Hash>();

        // for all public announcements
        transaction
            .kernel
            .public_announcements
            .iter()

            // ... that are marked as symmetric key encrypted
            .filter(|pa| Self::public_announcement_is_marked_symkey(pa))

            // ... that match the receiver_id of this key
            .filter(move |pa| {
                matches!(generation_address::receiver_identifier_from_public_announcement(pa), Ok(r) if r == receiver_identifier)
            })

            // ... that have a ciphertext field
            .filter_map(|pa| self.ok_warn(generation_address::ciphertext_from_public_announcement(pa)) )

            // ... which can be decrypted with this key
            .filter_map(|c| self.ok_warn(self.decrypt(&c).map_err(|e| e.into())))

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

    /// decrypt a ciphertext into utxo secrets (utxo, sender_randomness)
    ///
    /// The ciphertext_bfes param must contain the nonce in the first
    /// field and the ciphertext in the remaining fields.
    ///
    /// The output of `encrypt()` should be used as the input to `decrypt()`.
    fn decrypt(&self, ciphertext_bfes: &[BFieldElement]) -> Result<(Utxo, Digest), DecryptError> {
        const NONCE_LEN: usize = 1;

        // 1. separate nonce from ciphertext.
        let (nonce_ctxt, ciphertext) = match ciphertext_bfes.len() > NONCE_LEN {
            true => ciphertext_bfes.split_at(NONCE_LEN),
            false => return Err(DecryptError::MissingNonce),
        };

        // 2. generate Nonce and cyphertext_bytes
        let nonce_as_bytes = [&nonce_ctxt[0].value().to_be_bytes(), [0u8; 4].as_slice()].concat();
        let nonce = Nonce::from_slice(&nonce_as_bytes); // almost 64 bits; unique per message
        let ciphertext_bytes = generation_address::bfes_to_bytes(ciphertext)?;

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
        let ciphertext_bfes = generation_address::bytes_to_bfes(&ciphertext);

        // 6. concatenate nonce bfe + ciphertext bfes and return
        Ok([&[nonce_bfe], ciphertext_bfes.as_slice()].concat())
    }

    /// generates a public announcement
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
    ) -> Result<PublicAnnouncement, EncryptError> {
        let ciphertext = [
            &[SYMMETRIC_KEY_FLAG, self.receiver_identifier()],
            self.encrypt(utxo, sender_randomness)?.as_slice(),
        ]
        .concat();
        Ok(PublicAnnouncement::new(ciphertext))
    }

    /// generates a lock script from the spending lock.
    ///
    /// Satisfaction of this lock script establishes the UTXO owner's assent to
    /// the transaction.
    pub fn lock_script(&self) -> LockScript {
        let push_spending_lock_digest_to_stack = self
            .spending_lock()
            .values()
            .iter()
            .rev()
            .map(|elem| triton_instr!(push elem.value()))
            .collect_vec();

        let instructions = triton_asm!(
            divine 5
            hash
            {&push_spending_lock_digest_to_stack}
            assert_vector
            read_io 5
            halt
        );

        instructions.into()
    }

    /// returns the unlock key
    pub fn unlock_key(&self) -> Digest {
        Hash::hash_varlen(&[self.seed.values().to_vec(), vec![BFieldElement::new(1)]].concat())
    }

    /// returns the spending lock which is a hash of unlock_key()
    fn spending_lock(&self) -> Digest {
        self.unlock_key().hash::<Hash>()
    }

    /// Determine if the public announcement is flagged to indicate it
    /// contains ciphertext encrypted to a symmetric key
    fn public_announcement_is_marked_symkey(announcement: &PublicAnnouncement) -> bool {
        matches!(announcement.message.first(), Some(&SYMMETRIC_KEY_FLAG))
    }

    /// converts a result into an Option and logs a warning on any error
    fn ok_warn<T>(&self, result: anyhow::Result<T>) -> Option<T> {
        match result {
            Ok(v) => Some(v),
            Err(e) => {
                warn!("possible loss of funds! skipping public announcement for symmetric key with receiver_identifier: {}.  error: {}", self.receiver_identifier(), e.to_string());
                None
            }
        }
    }
}

#[cfg(test)]
mod test {
    use itertools::Itertools;
    use rand::{random, thread_rng, Rng};
    use twenty_first::{math::tip5::Digest, util_types::algebraic_hasher::AlgebraicHasher};

    use crate::{
        models::blockchain::{
            shared::Hash, transaction::utxo::Utxo, type_scripts::neptune_coins::NeptuneCoins,
        },
        tests::shared::make_mock_transaction,
    };

    use super::*;

    /// This tests encrypting and decrypting with a symmetric key
    #[test]
    fn test_encrypt_decrypt() {
        let mut rng = thread_rng();

        // 1. generate key from random seed.
        let symmetric_key = SymmetricKey::from_seed(rng.gen());

        // 2. create utxo with random amount
        let amount = NeptuneCoins::new(rng.gen_range(0..42000000));
        let utxo = Utxo::new_native_coin(symmetric_key.lock_script(), amount);

        // 3. generate sender randomness
        let sender_randomness: Digest = rng.gen();

        // 4. encrypt secrets (utxo, sender_randomness)
        let ciphertext = symmetric_key.encrypt(&utxo, sender_randomness).unwrap();
        println!("ciphertext.get_size() = {}", ciphertext.len() * 8);

        // 5. decrypt secrets
        let (utxo_again, sender_randomness_again) = symmetric_key.decrypt(&ciphertext).unwrap();

        // 6. verify that decrypted secrets match original secrets
        assert_eq!(utxo, utxo_again);
        assert_eq!(sender_randomness, sender_randomness_again);
    }

    /// this tests the generate_public_announcement() and
    /// scan_for_announced_utxos() methods
    ///
    /// a PublicAnnouncement is created with generate_public_announcement() and
    /// added to a Tx.  It is then found by scanning for announced_utoxs.  Then
    /// we verify that the data matches the original/expected values.
    #[test]
    fn scan_for_announced_utxos_test() {
        let mut rng = thread_rng();

        // 1. generete a symmetric key from random seed
        let symmetric_key = SymmetricKey::from_seed(rng.gen());

        // 2. generate a utxo with amount = 10
        let utxo = Utxo::new_native_coin(symmetric_key.lock_script(), NeptuneCoins::new(10));

        // 3. generate sender randomness
        let sender_randomness: Digest = random();

        // 4. create an addition record to verify against later.
        let expected_addition_record = commit(
            Hash::hash(&utxo),
            sender_randomness,
            symmetric_key.privacy_digest(),
        );

        // 5. create a mock tx with no inputs or outputs
        let mut mock_tx = make_mock_transaction(vec![], vec![]);

        // 6. verify that no announced utxos exist for this key
        assert!(symmetric_key
            .scan_for_announced_utxos(&mock_tx)
            .collect_vec()
            .is_empty());

        // 7. generate a symmetric key public announcement for this key
        let public_announcement = symmetric_key
            .generate_public_announcement(&utxo, sender_randomness)
            .unwrap();

        // 8. verify that the public_announcement is marked as SymmetricKey
        assert!(SymmetricKey::public_announcement_is_marked_symkey(
            &public_announcement
        ));

        // 9. add the public announcement to the mock tx.
        mock_tx
            .kernel
            .public_announcements
            .push(public_announcement);

        // 10. scan tx public announcements for announced utxos
        let announced_utxos = symmetric_key
            .scan_for_announced_utxos(&mock_tx)
            .collect_vec();

        // 11. verify there is exactly 1 announced_utxo and obtain it.
        assert_eq!(1, announced_utxos.len());
        let announced_utxo = announced_utxos.into_iter().next().unwrap();

        // 12. verify each field of the announced_utxo matches original values.
        assert_eq!(utxo, announced_utxo.utxo);
        assert_eq!(expected_addition_record, announced_utxo.addition_record);
        assert_eq!(sender_randomness, announced_utxo.sender_randomness);
        assert_eq!(
            symmetric_key.privacy_preimage(),
            announced_utxo.receiver_preimage
        );
    }
}
