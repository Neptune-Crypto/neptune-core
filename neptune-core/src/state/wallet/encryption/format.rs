//! Encrypted wallet file format and serialization
//!
//! Defines the on-disk format for encrypted wallets with all necessary parameters
//! for decryption and verification.

use super::{WalletCipher, WalletKeyManager};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Argon2id parameters stored in encrypted wallet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Argon2Params {
    pub memory_cost_kib: u32, // 256 * 1024 = 256 MB
    pub time_cost: u32,       // 4 iterations
    pub parallelism: u32,     // 4 threads
    pub salt: [u8; 32],       // Random salt
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            memory_cost_kib: 262144, // 256 MB
            time_cost: 4,
            parallelism: 4,
            salt: WalletKeyManager::generate_salt(),
        }
    }
}

/// AES-256-GCM parameters stored in encrypted wallet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AesGcmParams {
    pub nonce: [u8; 12], // Random 96-bit nonce
}

impl Default for AesGcmParams {
    fn default() -> Self {
        Self {
            nonce: WalletCipher::generate_nonce(),
        }
    }
}

/// Encrypted wallet file format
///
/// This is the structure written to `wallet.encrypted` on disk.
/// All fields are required for successful decryption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedWalletFile {
    /// File format version (for future migrations)
    pub version: u32,

    /// Wallet name (plaintext, for user convenience)
    pub wallet_name: String,

    /// Argon2id key derivation parameters
    pub argon2_params: Argon2Params,

    /// AES-256-GCM cipher parameters
    pub aes_gcm_params: AesGcmParams,

    /// Encrypted wallet data (ciphertext + authentication tag)
    /// This is the JSON-serialized SecretKeyMaterial, encrypted
    pub ciphertext: Vec<u8>,

    /// Timestamp of encryption (for auditing)
    pub encrypted_at: u64, // Unix timestamp
}

impl EncryptedWalletFile {
    /// Current file format version
    pub const CURRENT_VERSION: u32 = 1;

    /// Create new encrypted wallet file from plaintext data
    ///
    /// # Arguments
    /// * `wallet_name` - Name for the wallet (e.g., "standard_wallet")
    /// * `plaintext_json` - JSON-serialized SecretKeyMaterial
    /// * `password` - User-provided password
    pub fn encrypt(wallet_name: String, plaintext_json: &str, password: &str) -> Result<Self> {
        // Generate random parameters
        let argon2_params = Argon2Params::default();
        let aes_gcm_params = AesGcmParams::default();

        // Derive encryption key from password
        let key_manager = WalletKeyManager::from_password(password, &argon2_params.salt)?;
        let wallet_key = key_manager.derive_wallet_key();

        // Encrypt wallet data
        let cipher = WalletCipher::new(&wallet_key)?;
        let ciphertext = cipher.encrypt(plaintext_json.as_bytes(), &aes_gcm_params.nonce)?;

        Ok(Self {
            version: Self::CURRENT_VERSION,
            wallet_name,
            argon2_params,
            aes_gcm_params,
            ciphertext,
            encrypted_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }

    /// Decrypt wallet file to plaintext JSON
    ///
    /// # Arguments
    /// * `password` - User-provided password
    ///
    /// # Returns
    /// Decrypted JSON string (SecretKeyMaterial)
    pub fn decrypt(&self, password: &str) -> Result<Zeroizing<String>> {
        // Verify version
        if self.version != Self::CURRENT_VERSION {
            return Err(anyhow!(
                "Unsupported wallet file version: {}. Current version: {}",
                self.version,
                Self::CURRENT_VERSION
            ));
        }

        // Derive decryption key from password
        let key_manager = WalletKeyManager::from_password(password, &self.argon2_params.salt)?;
        let wallet_key = key_manager.derive_wallet_key();

        // Decrypt wallet data
        let cipher = WalletCipher::new(&wallet_key)?;
        let plaintext_bytes = cipher.decrypt(&self.ciphertext, &self.aes_gcm_params.nonce)?;

        // Convert to string
        let plaintext_string = String::from_utf8(plaintext_bytes)
            .map_err(|e| anyhow!("Decrypted data is not valid UTF-8: {}", e))?;

        Ok(Zeroizing::new(plaintext_string))
    }

    /// Serialize to JSON for writing to disk
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| anyhow!("Failed to serialize encrypted wallet: {}", e))
    }

    /// Deserialize from JSON read from disk
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json)
            .map_err(|e| anyhow!("Failed to deserialize encrypted wallet: {}", e))
    }

    /// Write to file
    pub fn write_to_file(&self, path: &std::path::Path) -> Result<()> {
        let json = self.to_json()?;
        std::fs::write(path, json).map_err(|e| {
            anyhow!(
                "Failed to write encrypted wallet to {}: {}",
                path.display(),
                e
            )
        })
    }

    /// Read from file
    pub fn read_from_file(path: &std::path::Path) -> Result<Self> {
        let json = std::fs::read_to_string(path).map_err(|e| {
            anyhow!(
                "Failed to read encrypted wallet from {}: {}",
                path.display(),
                e
            )
        })?;
        Self::from_json(&json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_WALLET_JSON: &str = r#"{"name":"test_wallet","secret_seed":{"coefficients":[1234567890,9876543210,1111111111]},"version":0}"#;
    const TEST_PASSWORD: &str = "MySecureTestPassword123!";

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let encrypted = EncryptedWalletFile::encrypt(
            "test_wallet".to_string(),
            TEST_WALLET_JSON,
            TEST_PASSWORD,
        )
        .unwrap();

        let decrypted = encrypted.decrypt(TEST_PASSWORD).unwrap();
        assert_eq!(TEST_WALLET_JSON, decrypted.as_str());
    }

    #[test]
    fn test_wrong_password_fails() {
        let encrypted = EncryptedWalletFile::encrypt(
            "test_wallet".to_string(),
            TEST_WALLET_JSON,
            TEST_PASSWORD,
        )
        .unwrap();

        let result = encrypted.decrypt("WrongPassword123!");
        assert!(result.is_err());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let encrypted = EncryptedWalletFile::encrypt(
            "test_wallet".to_string(),
            TEST_WALLET_JSON,
            TEST_PASSWORD,
        )
        .unwrap();

        let json = encrypted.to_json().unwrap();
        let deserialized = EncryptedWalletFile::from_json(&json).unwrap();

        // Should be able to decrypt the deserialized version
        let decrypted = deserialized.decrypt(TEST_PASSWORD).unwrap();
        assert_eq!(TEST_WALLET_JSON, decrypted.as_str());
    }

    #[test]
    fn test_version_check() {
        let mut encrypted = EncryptedWalletFile::encrypt(
            "test_wallet".to_string(),
            TEST_WALLET_JSON,
            TEST_PASSWORD,
        )
        .unwrap();

        // Tamper with version
        encrypted.version = 999;

        let result = encrypted.decrypt(TEST_PASSWORD);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Unsupported wallet file version"));
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let mut encrypted = EncryptedWalletFile::encrypt(
            "test_wallet".to_string(),
            TEST_WALLET_JSON,
            TEST_PASSWORD,
        )
        .unwrap();

        // Tamper with ciphertext
        if !encrypted.ciphertext.is_empty() {
            encrypted.ciphertext[0] ^= 0xFF;
        }

        let result = encrypted.decrypt(TEST_PASSWORD);
        assert!(result.is_err());
    }

    #[test]
    fn test_different_salts_different_ciphertexts() {
        let encrypted1 = EncryptedWalletFile::encrypt(
            "test_wallet".to_string(),
            TEST_WALLET_JSON,
            TEST_PASSWORD,
        )
        .unwrap();

        let encrypted2 = EncryptedWalletFile::encrypt(
            "test_wallet".to_string(),
            TEST_WALLET_JSON,
            TEST_PASSWORD,
        )
        .unwrap();

        // Different salts = different ciphertexts (even with same password + plaintext)
        assert_ne!(encrypted1.argon2_params.salt, encrypted2.argon2_params.salt);
        assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext);
    }
}
