use rand::thread_rng;
use secp256k1::{ecdsa, Secp256k1};
use serde::{Deserialize, Serialize};
use twenty_first::shared_math::{
    b_field_element::BFieldElement,
    traits::{GetRandomElements, IdentityValues},
};

use super::digest::{
    Digest, DEVNET_MSG_DIGEST_SIZE_IN_BYTES, DEVNET_SECRET_KEY_SIZE_IN_BYTES,
    RESCUE_PRIME_OUTPUT_SIZE_IN_BFES,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Wallet {
    pub name: String,
    pub secret: Digest,
    pub version: u8,
}

impl Wallet {
    pub fn new_random_wallet(name: &str, version: u8) -> Self {
        let mut rng = thread_rng();
        let entropy: Vec<BFieldElement> =
            BFieldElement::random_elements(RESCUE_PRIME_OUTPUT_SIZE_IN_BFES, &mut rng);

        // Sanity check to verify that entropy was actually set
        assert!(
            !entropy.iter().all(|elem| elem.is_zero()),
            "Entropy for secret key must be initialized. All elements cannot be zero."
        );
        assert!(
            !entropy.iter().all(|elem| *elem == entropy[0]),
            "Entropy for secret key must be initialized. All elements cannot be equal."
        );

        Self {
            name: name.to_string(),
            secret: entropy.into(),
            version,
        }
    }

    fn _get_ecdsa_sk(&self) -> secp256k1::SecretKey {
        let bytes: [u8; DEVNET_SECRET_KEY_SIZE_IN_BYTES] = self.secret.into();
        secp256k1::SecretKey::from_slice(&bytes).unwrap()
    }

    fn _sign(&self, msg_hash: secp256k1::Message) -> ecdsa::Signature {
        let sk = self._get_ecdsa_sk();
        sk.sign_ecdsa(msg_hash)
    }

    pub fn _sign_digest(&self, msg_digest: Digest) -> ecdsa::Signature {
        let sk = self._get_ecdsa_sk();
        let msg_bytes: [u8; DEVNET_MSG_DIGEST_SIZE_IN_BYTES] = msg_digest.into();
        let msg = secp256k1::Message::from_slice(&msg_bytes).unwrap();
        sk.sign_ecdsa(msg)
    }

    pub fn get_public_key(&self) -> secp256k1::PublicKey {
        let secp = Secp256k1::new();
        let bytes: [u8; DEVNET_SECRET_KEY_SIZE_IN_BYTES] = self.secret.into();
        let ecdsa_secret_key: secp256k1::SecretKey =
            secp256k1::SecretKey::from_slice(&bytes).unwrap();

        secp256k1::PublicKey::from_secret_key(&secp, &ecdsa_secret_key)
    }
}

#[cfg(test)]
mod ordered_digest_tests {
    use twenty_first::{
        shared_math::rescue_prime_xlix::RP_DEFAULT_OUTPUT_SIZE, util_types::simple_hasher::Hasher,
    };

    use crate::models::blockchain::{digest::DEVNET_MSG_DIGEST_SIZE_IN_BYTES, shared::Hash};

    use super::*;

    #[test]
    fn new_random_wallet_base_test() {
        let wallet = Wallet::new_random_wallet("test wallet 1", 6);
        let pk = wallet.get_public_key();
        let msg_vec: Vec<BFieldElement> = wallet.secret.values().to_vec();
        let digest_vec: Vec<BFieldElement> = Hash::new().hash(&msg_vec, RP_DEFAULT_OUTPUT_SIZE);
        let digest: Digest = digest_vec.into();
        let msg_bytes: [u8; DEVNET_MSG_DIGEST_SIZE_IN_BYTES] = digest.into();
        let msg = secp256k1::Message::from_slice(&msg_bytes).unwrap();
        let signature = wallet._sign(msg);
        assert!(
            signature.verify(&msg, &pk).is_ok(),
            "DEVNET signature must verify"
        );

        let signature_alt = wallet._sign_digest(digest);
        assert!(
            signature_alt.verify(&msg, &pk).is_ok(),
            "DEVNET signature must verify"
        );
    }
}
