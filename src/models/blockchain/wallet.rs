use rand::thread_rng;
use secp256k1::{ecdsa, Secp256k1};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::info;
use twenty_first::shared_math::{
    b_field_element::BFieldElement,
    traits::{GetRandomElements, IdentityValues},
};

use super::digest::{
    Digest, DEVNET_MSG_DIGEST_SIZE_IN_BYTES, DEVNET_SECRET_KEY_SIZE_IN_BYTES,
    RESCUE_PRIME_OUTPUT_SIZE_IN_BFES,
};

pub const WALLET_FILE_NAME: &str = "wallet.dat";
pub const STANDARD_WALLET_NAME: &str = "standard";
pub const STANDARD_WALLET_VERSION: u8 = 0;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Wallet {
    pub name: String,
    pub secret: Digest,
    pub version: u8,
}

impl Wallet {
    pub fn wallet_path(root_data_dir_path: &Path) -> PathBuf {
        let mut pb = root_data_dir_path.to_path_buf();
        pb.push(WALLET_FILE_NAME);
        pb
    }

    pub fn new_from_secret_key(name: &str, version: u8, secret: Digest) -> Self {
        Self {
            name: name.to_string(),
            secret,
            version,
        }
    }

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

        Self::new_from_secret_key(name, version, entropy.into())
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

    /// Read the wallet from disk. Create one if none exists.
    pub fn initialize_wallet(wallet_file: &Path, name: &str, version: u8) -> Wallet {
        // Check if file exists
        let wallet: Wallet = if wallet_file.exists() {
            info!("Found wallet file: {}", wallet_file.to_string_lossy());

            // Read wallet from disk
            let file_content: String = match fs::read_to_string(wallet_file) {
                Ok(fc) => fc,
                Err(err) => panic!(
                    "Failed to read file {}. Got error: {}",
                    wallet_file.to_string_lossy(),
                    err
                ),
            };

            // Parse wallet as JSON and return result
            match serde_json::from_str(&file_content) {
                Ok(stored_wallet) => stored_wallet,
                Err(err) => {
                    panic!(
                    "Failed to parse {} as Wallet in JSON format. Is the wallet file corrupted? Error: {}",
                    wallet_file.to_string_lossy(),
                    err
                )
                }
            }
        } else {
            info!(
                "Creating new wallet file: {}",
                wallet_file.to_string_lossy()
            );

            // New wallet must be made and stored to disk
            let new_wallet: Wallet = Wallet::new_random_wallet(name, version);
            let wallet_as_json: String =
                serde_json::to_string(&new_wallet).expect("wallet serialization must succeed");

            // Store to disk, with the right permissions
            if cfg!(target_family = "unix") {
                Self::create_wallet_file_unix(&wallet_file.to_path_buf(), wallet_as_json);
            } else {
                Self::create_wallet_file_windows(&wallet_file.to_path_buf(), wallet_as_json);
            }

            new_wallet
        };

        // Sanity check that wallet file was stored on disk.
        assert!(
            wallet_file.exists(),
            "wallet file must exist on disk after creation."
        );

        wallet
    }

    /// Create a wallet file, and set restrictive permissions
    #[cfg(target_family = "unix")]
    fn create_wallet_file_unix(path: &PathBuf, wallet_as_json: String) {
        // On Unix/Linux we set the file permissions to 600, to disallow
        // other users on the same machine to access the secrets.
        use std::os::unix::prelude::OpenOptionsExt;
        fs::OpenOptions::new()
            .create(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        fs::write(path.clone(), wallet_as_json).expect("Failed to write wallet file to disk");
    }

    /// Create a wallet file, without setting restrictive UNIX permissions
    // #[cfg(not(target_family = "unix"))]
    fn create_wallet_file_windows(path: &PathBuf, wallet_as_json: String) {
        fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(path)
            .unwrap();
        fs::write(path.clone(), wallet_as_json).expect("Failed to write wallet file to disk");
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
