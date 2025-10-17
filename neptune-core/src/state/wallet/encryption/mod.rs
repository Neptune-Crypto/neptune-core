//! Wallet encryption system using Argon2id + AES-256-GCM
//!
//! This module provides cryptographic protection for wallet seed files at rest.
//!
//! ## Security Properties
//!
//! - **Key Derivation**: Argon2id (memory-hard, side-channel resistant)
//! - **Encryption**: AES-256-GCM (authenticated encryption)
//! - **Key Management**: HKDF-SHA256 for sub-key derivation
//! - **Memory Safety**: Zeroizing for all secret keys
//!
//! ## Architecture
//!
//! ```text
//! User Password (UTF-8)
//!     ↓ Argon2id (256 MB RAM, 4 iterations, ~1 second)
//! Master Key (256 bits)
//!     ↓ HKDF-SHA256
//! Wallet Encryption Key (256 bits)
//!     ↓ AES-256-GCM (authenticated encryption)
//! Encrypted Wallet File
//! ```
//!
//! ## Usage
//!
//! ```no_run
//! use neptune_cash::state::wallet::encryption::{EncryptedWalletFile, PasswordManager};
//! use neptune_cash::state::wallet::wallet_file::WalletFile;
//!
//! # fn main() -> anyhow::Result<()> {
//! # let path = std::path::Path::new("wallet.encrypted");
//! // Create new encrypted wallet
//! let wallet = WalletFile::new_random();
//! let password = PasswordManager::prompt_new_password()?;
//! let encrypted = EncryptedWalletFile::encrypt(&wallet, &password)?;
//! encrypted.save_to_file(path)?;
//!
//! // Load and decrypt
//! let encrypted = EncryptedWalletFile::load_from_file(path)?;
//! let password = PasswordManager::prompt_password("Enter password: ")?;
//! let wallet = encrypted.decrypt(&password)?;
//! # Ok(())
//! # }
//! ```

// Re-export public API
pub use cipher::WalletCipher;
pub use format::{AesGcmParams, Argon2Params, EncryptedWalletFile};
pub use key_manager::WalletKeyManager;
pub use password::{PasswordManager, PasswordStrength};

// Internal modules
mod cipher;
mod format;
mod key_manager;
mod password;

#[cfg(test)]
mod tests;
