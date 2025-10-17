//! AES-256-GCM authenticated encryption for wallet data
//!
//! This module provides symmetric encryption with authentication using AES-256-GCM.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Result};
use rand::Rng;

/// Handles AES-256-GCM encryption/decryption
pub struct WalletCipher {
    cipher: Aes256Gcm,
}

impl WalletCipher {
    /// Create cipher from 256-bit key
    pub fn new(key: &[u8; 32]) -> Result<Self> {
        let cipher =
            Aes256Gcm::new_from_slice(key).map_err(|e| anyhow!("Invalid AES key: {}", e))?;
        Ok(Self { cipher })
    }

    /// Generate random 96-bit nonce
    pub fn generate_nonce() -> [u8; 12] {
        let mut nonce = [0u8; 12];
        rand::rng().fill(&mut nonce);
        nonce
    }

    /// Encrypt plaintext with authenticated encryption
    ///
    /// Returns ciphertext with authentication tag appended
    pub fn encrypt(&self, plaintext: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>> {
        let nonce = Nonce::from_slice(nonce);

        self.cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow!("Encryption failed: {}", e))
    }

    /// Decrypt ciphertext with authentication verification
    pub fn decrypt(&self, ciphertext: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>> {
        let nonce = Nonce::from_slice(nonce);

        self.cipher.decrypt(nonce, ciphertext).map_err(|e| {
            anyhow!(
                "Decryption failed (wrong password or corrupted data): {}",
                e
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [42u8; 32];
        let cipher = WalletCipher::new(&key).unwrap();

        let plaintext = b"secret wallet data";
        let nonce = WalletCipher::generate_nonce();

        let ciphertext = cipher.encrypt(plaintext, &nonce).unwrap();
        let decrypted = cipher.decrypt(&ciphertext, &nonce).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];

        let cipher1 = WalletCipher::new(&key1).unwrap();
        let cipher2 = WalletCipher::new(&key2).unwrap();

        let plaintext = b"secret";
        let nonce = WalletCipher::generate_nonce();

        let ciphertext = cipher1.encrypt(plaintext, &nonce).unwrap();

        // Wrong key should fail to decrypt
        assert!(cipher2.decrypt(&ciphertext, &nonce).is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = [42u8; 32];
        let cipher = WalletCipher::new(&key).unwrap();

        let plaintext = b"secret";
        let nonce = WalletCipher::generate_nonce();

        let mut ciphertext = cipher.encrypt(plaintext, &nonce).unwrap();

        // Tamper with ciphertext
        ciphertext[0] ^= 0xFF;

        // Should fail authentication
        assert!(cipher.decrypt(&ciphertext, &nonce).is_err());
    }
}
