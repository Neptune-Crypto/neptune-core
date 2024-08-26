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

use super::common;
use crate::config_models::network::Network;
use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::transaction::utxo::LockScript;
use crate::models::blockchain::transaction::utxo::Utxo;
use crate::prelude::twenty_first;
use aead::Aead;
use aead::KeyInit;
use aes_gcm::Aes256Gcm;
use aes_gcm::Nonce;
use anyhow::bail;
use anyhow::Result;
use bech32::FromBase32;
use bech32::ToBase32;
use bech32::Variant;
use rand::thread_rng;
use rand::Rng;
use serde_derive::Deserialize;
use serde_derive::Serialize;
use twenty_first::math::b_field_element::BFieldElement;
use twenty_first::math::lattice;
use twenty_first::math::lattice::kem::CIPHERTEXT_SIZE_IN_BFES;
use twenty_first::math::tip5::Digest;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;

pub(super) const GENERATION_FLAG_U8: u8 = 79;
pub const GENERATION_FLAG: BFieldElement = BFieldElement::new(GENERATION_FLAG_U8 as u64);

#[derive(Clone, Debug, Copy, Serialize, Deserialize)]
pub struct GenerationSpendingKey {
    pub receiver_identifier: BFieldElement,
    pub decryption_key: lattice::kem::SecretKey,
    pub privacy_preimage: Digest,
    pub unlock_key: Digest,
    pub seed: Digest,
}

// 2168 bytes.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct GenerationReceivingAddress {
    pub receiver_identifier: BFieldElement,      //    8 bytes
    pub encryption_key: lattice::kem::PublicKey, // 2080 bytes
    pub privacy_digest: Digest,                  //   40 bytes
    pub spending_lock: Digest,                   //   40 bytes
}

impl GenerationSpendingKey {
    pub fn to_address(&self) -> GenerationReceivingAddress {
        let randomness: [u8; 32] = common::shake256::<32>(&bincode::serialize(&self.seed).unwrap());
        let (_sk, pk) = lattice::kem::keygen(randomness);
        let privacy_digest = self.privacy_preimage.hash::<Hash>();
        GenerationReceivingAddress {
            receiver_identifier: self.receiver_identifier,
            encryption_key: pk,
            privacy_digest,
            spending_lock: self.generate_spending_lock(),
        }
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
        self.unlock_key.hash::<Hash>()
    }
}

impl GenerationReceivingAddress {
    pub fn from_spending_key(spending_key: &GenerationSpendingKey) -> Self {
        let seed = spending_key.seed;
        let receiver_identifier = common::derive_receiver_id(seed);
        let randomness: [u8; 32] = common::shake256::<32>(&bincode::serialize(&seed).unwrap());
        let (_sk, pk) = lattice::kem::keygen(randomness);
        let privacy_digest = spending_key.privacy_preimage.hash::<Hash>();
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
            Ok(witness_array) => Digest::new(witness_array).hash::<Hash>() == self.spending_lock,
            Err(_) => false,
        }
    }

    pub fn encrypt(&self, utxo: &Utxo, sender_randomness: Digest) -> Result<Vec<BFieldElement>> {
        // derive shared key
        let mut randomness = [0u8; 32];
        let mut rng = thread_rng();
        rng.fill(&mut randomness);
        let (shared_key, kem_ctxt) = lattice::kem::enc(self.encryption_key, randomness);

        // sample nonce
        let nonce_bfe: BFieldElement = rng.gen();

        // convert payload to bytes
        let plaintext = bincode::serialize(&(utxo, sender_randomness))?;

        // generate symmetric ciphertext
        let cipher = Aes256Gcm::new(&shared_key.into());
        let nonce_as_bytes = [nonce_bfe.value().to_be_bytes().to_vec(), vec![0u8; 4]].concat();
        let nonce = Nonce::from_slice(&nonce_as_bytes); // almost 64 bits; unique per message
        let ciphertext = match cipher.encrypt(nonce, plaintext.as_ref()) {
            Ok(ctxt) => ctxt,
            Err(_) => bail!("Could not encrypt payload."),
        };
        let ciphertext_bfes = common::bytes_to_bfes(&ciphertext);

        // concatenate and return
        Ok([
            std::convert::Into::<[BFieldElement; CIPHERTEXT_SIZE_IN_BFES]>::into(kem_ctxt).to_vec(),
            vec![nonce_bfe],
            ciphertext_bfes,
        ]
        .concat())
    }

    /// returns human readable prefix (hrp) of an address, specific to `network`.
    pub fn get_hrp(network: Network) -> String {
        // nolga: Neptune lattice-based generation address
        format!("nolga{}", common::network_hrp_char(network))
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

        if hrp != Self::get_hrp(network) {
            bail!("Could not decode bech32m address because of invalid prefix");
        }

        let payload = Vec::<u8>::from_base32(&data)?;

        match bincode::deserialize(&payload) {
            Ok(ra) => Ok(ra),
            Err(e) => bail!("Could not decode bech32m address because of error: {e}"),
        }
    }

    /// generates a lock script from the spending lock.
    ///
    /// Satisfaction of this lock script establishes the UTXO owner's assent to
    /// the transaction.
    pub fn lock_script(&self) -> LockScript {
        common::lock_script(self.spending_lock)
    }

    /// returns the privacy digest
    pub fn privacy_digest(&self) -> Digest {
        self.privacy_digest
    }
}
