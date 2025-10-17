//! Argon2id key derivation for wallet encryption
//!
//! This module implements password-based key derivation using Argon2id,
//! a memory-hard function resistant to GPU/ASIC attacks and side-channel attacks.

use anyhow::{anyhow, Result};
use argon2::{Argon2, ParamsBuilder, Version};
use hkdf::Hkdf;
use rand::Rng;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Manages cryptographic keys derived from user password
pub struct WalletKeyManager {
    /// Master key derived from password (zeroed on drop)
    master_key: Zeroizing<[u8; 32]>,
}

impl WalletKeyManager {
    /// Derive master key from password using Argon2id
    ///
    /// Parameters:
    /// - Memory cost: 256 MB (m_cost = 262144 KiB)
    /// - Time cost: 4 iterations
    /// - Parallelism: 4 threads
    /// - Takes ~1 second on modern hardware
    pub fn from_password(password: &str, salt: &[u8; 32]) -> Result<Self> {
        // Configure Argon2id parameters
        // Memory: 256 MB = 262144 KiB
        // Time: 4 iterations
        // Parallelism: 4 threads
        let params = ParamsBuilder::new()
            .m_cost(262144) // 256 MB
            .t_cost(4) // 4 iterations
            .p_cost(4) // 4 threads
            .build()
            .map_err(|e| anyhow!("Invalid Argon2 parameters: {}", e))?;

        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

        // Derive 32-byte master key
        let mut master_key = Zeroizing::new([0u8; 32]);
        argon2
            .hash_password_into(password.as_bytes(), salt, &mut *master_key)
            .map_err(|e| anyhow!("Argon2id key derivation failed: {}", e))?;

        Ok(Self { master_key })
    }

    /// Generate random salt for new wallet
    pub fn generate_salt() -> [u8; 32] {
        let mut salt = [0u8; 32];
        rand::rng().fill(&mut salt);
        salt
    }

    /// Derive wallet file encryption key using HKDF-SHA256
    pub fn derive_wallet_key(&self) -> Zeroizing<[u8; 32]> {
        let hkdf = Hkdf::<Sha256>::new(None, &*self.master_key);
        let mut key = Zeroizing::new([0u8; 32]);
        hkdf.expand(b"neptune-wallet-encryption-v1", &mut *key)
            .expect("HKDF expand failed (bug)");
        key
    }
}

// Ensure master key is zeroed when dropped
impl Drop for WalletKeyManager {
    fn drop(&mut self) {
        // Zeroizing<T> handles this automatically, but explicit for clarity
        tracing::debug!("Zeroing wallet master key from memory");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_derivation() {
        let password = "correct-horse-battery-staple";
        let salt = [42u8; 32];

        let km1 = WalletKeyManager::from_password(password, &salt).unwrap();
        let km2 = WalletKeyManager::from_password(password, &salt).unwrap();

        // Same password + salt = same key
        assert_eq!(
            km1.derive_wallet_key().as_ref(),
            km2.derive_wallet_key().as_ref()
        );
    }

    #[test]
    fn test_different_passwords_different_keys() {
        let salt = [42u8; 32];

        let km1 = WalletKeyManager::from_password("password1", &salt).unwrap();
        let km2 = WalletKeyManager::from_password("password2", &salt).unwrap();

        // Different passwords = different keys
        assert_ne!(
            km1.derive_wallet_key().as_ref(),
            km2.derive_wallet_key().as_ref()
        );
    }

    #[test]
    fn test_different_salts_different_keys() {
        let password = "same-password";
        let salt1 = [1u8; 32];
        let salt2 = [2u8; 32];

        let km1 = WalletKeyManager::from_password(password, &salt1).unwrap();
        let km2 = WalletKeyManager::from_password(password, &salt2).unwrap();

        // Different salts = different keys
        assert_ne!(
            km1.derive_wallet_key().as_ref(),
            km2.derive_wallet_key().as_ref()
        );
    }

    #[test]
    fn test_generate_salt_randomness() {
        let salt1 = WalletKeyManager::generate_salt();
        let salt2 = WalletKeyManager::generate_salt();

        // Two generated salts should be different (with overwhelming probability)
        assert_ne!(salt1, salt2);
    }
}
