# Wallet Encryption Integration Points

**Branch:** `feature/wallet-security-hardening`
**Phase:** Day 1 - Structure & Integration Mapping
**Date:** 2025-10-16

---

## Table of Contents

1. [New Module Structure](#new-module-structure)
2. [Files to Create](#files-to-create)
3. [Files to Modify](#files-to-modify)
4. [Integration Points](#integration-points)
5. [Dependency Tree](#dependency-tree)
6. [Call Flow Diagram](#call-flow-diagram)
7. [Testing Structure](#testing-structure)

---

## New Module Structure

### Complete Directory Layout

```
neptune-core/
├── Cargo.toml                          # MODIFY: Add new dependencies
├── src/
│   ├── lib.rs                          # NO CHANGE (encryption transparent to main)
│   └── state/
│       └── wallet/
│           ├── mod.rs                  # MODIFY: Re-export encryption module
│           ├── wallet_file.rs          # MODIFY: Add encryption support
│           ├── wallet_state.rs         # MINOR: Error handling updates
│           ├── secret_key_material.rs  # NO CHANGE
│           ├── wallet_entropy.rs       # NO CHANGE
│           │
│           └── encryption/             # NEW MODULE
│               ├── mod.rs              # NEW: Module root & public API
│               ├── key_manager.rs      # NEW: Argon2id key derivation
│               ├── cipher.rs           # NEW: AES-256-GCM encryption
│               ├── password.rs         # NEW: Password input & validation
│               └── format.rs           # NEW: Encrypted file format
│
├── tests/
│   └── wallet_encryption_test.rs       # NEW: Integration tests
│
└── docs/
    ├── user-guides/
    │   └── wallet-encryption.md        # NEW: User documentation
    └── security/
        └── encryption-technical-spec.md # NEW: Technical specification
```

---

## Files to Create

### 1. Core Encryption Module (NEW)

#### `neptune-core/src/state/wallet/encryption/mod.rs`

```rust
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
//!     ↓ Argon2id (256 MB, 4 iterations)
//! Master Key (256 bits)
//!     ↓ HKDF-SHA256
//! Wallet Encryption Key (256 bits)
//!     ↓ AES-256-GCM
//! Encrypted Wallet File
//! ```
//! 
//! ## Usage
//! 
//! ```rust
//! use neptune_cash::state::wallet::encryption::{EncryptedWalletFile, PasswordManager};
//! use neptune_cash::state::wallet::wallet_file::WalletFile;
//! 
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
```

**Location:** `neptune-core/src/state/wallet/encryption/mod.rs`
**Lines:** ~60
**Dependencies:** None (just re-exports)

---

#### `neptune-core/src/state/wallet/encryption/key_manager.rs`

**Content:** As defined in fast-track plan (Day 2)
**Location:** `neptune-core/src/state/wallet/encryption/key_manager.rs`
**Lines:** ~150
**Dependencies:** `argon2`, `hkdf`, `sha2`, `rand`, `zeroize`

---

#### `neptune-core/src/state/wallet/encryption/cipher.rs`

**Content:** As defined in fast-track plan (Day 3)
**Location:** `neptune-core/src/state/wallet/encryption/cipher.rs`
**Lines:** ~120
**Dependencies:** `aes-gcm`, `rand`, `zeroize`

---

#### `neptune-core/src/state/wallet/encryption/password.rs`

**Content:** As defined in fast-track plan (Day 4)
**Location:** `neptune-core/src/state/wallet/encryption/password.rs`
**Lines:** ~150
**Dependencies:** `rpassword`, `zeroize`

---

#### `neptune-core/src/state/wallet/encryption/format.rs`

**Content:** As defined in fast-track plan (Day 5)
**Location:** `neptune-core/src/state/wallet/encryption/format.rs`
**Lines:** ~250
**Dependencies:** `serde`, `bincode`, uses `key_manager` and `cipher`

---

#### `neptune-core/src/state/wallet/encryption/tests.rs`

```rust
//! Integration tests for encryption module
//! 
//! Tests the complete encryption workflow end-to-end

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::state::wallet::secret_key_material::SecretKeyMaterial;
    use crate::state::wallet::wallet_file::WalletFile;
    use tempfile::tempdir;
    
    #[test]
    fn test_full_encryption_workflow() {
        // Create wallet → Encrypt → Save → Load → Decrypt → Verify
        let original_wallet = WalletFile::new(SecretKeyMaterial(rand::random()));
        let password = "test-password-12345";
        
        // Encrypt
        let encrypted = EncryptedWalletFile::encrypt(&original_wallet, password).unwrap();
        
        // Save to disk
        let temp_dir = tempdir().unwrap();
        let wallet_path = temp_dir.path().join("wallet.encrypted");
        encrypted.save_to_file(&wallet_path).unwrap();
        
        // Load from disk
        let loaded_encrypted = EncryptedWalletFile::load_from_file(&wallet_path).unwrap();
        
        // Decrypt
        let decrypted_wallet = loaded_encrypted.decrypt(password).unwrap();
        
        // Verify
        assert_eq!(
            original_wallet.secret_key(),
            decrypted_wallet.secret_key()
        );
    }
    
    #[test]
    fn test_different_passwords_produce_different_ciphertexts() {
        let wallet = WalletFile::new(SecretKeyMaterial(rand::random()));
        
        let encrypted1 = EncryptedWalletFile::encrypt(&wallet, "password1").unwrap();
        let encrypted2 = EncryptedWalletFile::encrypt(&wallet, "password2").unwrap();
        
        // Different passwords = different salts = different ciphertexts
        assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext);
        assert_ne!(encrypted1.kdf_params.salt, encrypted2.kdf_params.salt);
    }
    
    #[test]
    fn test_file_permissions_unix() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            
            let wallet = WalletFile::new(SecretKeyMaterial(rand::random()));
            let encrypted = EncryptedWalletFile::encrypt(&wallet, "test").unwrap();
            
            let temp_dir = tempdir().unwrap();
            let wallet_path = temp_dir.path().join("wallet.encrypted");
            encrypted.save_to_file(&wallet_path).unwrap();
            
            // Verify permissions are 0600
            let metadata = std::fs::metadata(&wallet_path).unwrap();
            let permissions = metadata.permissions();
            assert_eq!(permissions.mode() & 0o777, 0o600);
        }
    }
}
```

**Location:** `neptune-core/src/state/wallet/encryption/tests.rs`
**Lines:** ~100
**Purpose:** Module-level integration tests

---

### 2. Integration Tests (NEW)

#### `neptune-core/tests/wallet_encryption_test.rs`

```rust
//! End-to-end tests for wallet encryption
//! 
//! Tests the full lifecycle including migration from plaintext

use neptune_cash::state::wallet::encryption::{EncryptedWalletFile, PasswordManager};
use neptune_cash::state::wallet::wallet_file::{WalletFile, WalletFileContext};
use neptune_cash::state::wallet::secret_key_material::SecretKeyMaterial;
use std::path::PathBuf;
use tempfile::tempdir;

#[tokio::test]
async fn test_encrypted_wallet_lifecycle() {
    let temp_dir = tempdir().unwrap();
    let wallet_dir = temp_dir.path().join("wallet");
    std::fs::create_dir_all(&wallet_dir).unwrap();
    
    // Create encrypted wallet
    let wallet = WalletFile::new(SecretKeyMaterial(rand::random()));
    let password = "test-password-123";
    let encrypted = EncryptedWalletFile::encrypt(&wallet, password).unwrap();
    
    let wallet_path = wallet_dir.join("wallet.encrypted");
    encrypted.save_to_file(&wallet_path).unwrap();
    
    // Load and verify
    let loaded = EncryptedWalletFile::load_from_file(&wallet_path).unwrap();
    let decrypted = loaded.decrypt(password).unwrap();
    
    assert_eq!(wallet.secret_key(), decrypted.secret_key());
}

#[tokio::test]
async fn test_plaintext_migration() {
    let temp_dir = tempdir().unwrap();
    let wallet_dir = temp_dir.path().join("wallet");
    std::fs::create_dir_all(&wallet_dir).unwrap();
    
    // Create plaintext wallet (old format)
    let wallet = WalletFile::new(SecretKeyMaterial(rand::random()));
    let plaintext_path = wallet_dir.join("wallet.dat");
    wallet.save_to_disk(&plaintext_path).unwrap();
    
    // TODO: Test automatic migration when loading WalletFileContext
    // This will be implemented in Day 6
}

#[tokio::test]
async fn test_wrong_password_fails_gracefully() {
    let wallet = WalletFile::new(SecretKeyMaterial(rand::random()));
    let encrypted = EncryptedWalletFile::encrypt(&wallet, "correct-password").unwrap();
    
    let result = encrypted.decrypt("wrong-password");
    assert!(result.is_err());
    
    let error_message = format!("{}", result.unwrap_err());
    assert!(error_message.contains("wrong password"));
}

#[tokio::test]
async fn test_corrupted_ciphertext_fails() {
    let wallet = WalletFile::new(SecretKeyMaterial(rand::random()));
    let password = "test-password";
    let mut encrypted = EncryptedWalletFile::encrypt(&wallet, password).unwrap();
    
    // Corrupt ciphertext
    encrypted.ciphertext[0] ^= 0xFF;
    
    let result = encrypted.decrypt(password);
    assert!(result.is_err());
}
```

**Location:** `neptune-core/tests/wallet_encryption_test.rs`
**Lines:** ~100
**Purpose:** End-to-end integration tests

---

## Files to Modify

### 1. Cargo.toml (ADD DEPENDENCIES)

**File:** `neptune-core/Cargo.toml`

**Changes:**
```toml
# Add after existing [dependencies] section

# Wallet Encryption (Phase 1 - v0.4.1)
argon2 = { version = "0.5", features = ["std"] }
aes-gcm = "0.10"
hkdf = "0.12"
sha2 = "0.10"
zeroize = { version = "1.7", features = ["derive"] }
rpassword = "7.3"
```

**Impact:** Adds 6 new dependencies (~5 unique, zeroize might already exist)

---

### 2. wallet/mod.rs (RE-EXPORT ENCRYPTION MODULE)

**File:** `neptune-core/src/state/wallet/mod.rs`

**Current Structure:**
```rust
// Current exports (partial)
pub mod address;
pub mod coin_with_possible_timelock;
pub mod incoming_utxo;
pub mod secret_key_material;
pub mod wallet_entropy;
pub mod wallet_file;
pub mod wallet_state;
// ... more modules
```

**Changes:**
```rust
// Add after existing module declarations
pub mod encryption;  // NEW: Encryption module

// Re-export commonly used encryption types
pub use encryption::{
    EncryptedWalletFile,
    PasswordManager,
    PasswordStrength,
};
```

**Lines Changed:** +5
**Impact:** Makes encryption types available to rest of codebase

---

### 3. wallet_file.rs (MAJOR MODIFICATIONS)

**File:** `neptune-core/src/state/wallet/wallet_file.rs`

**Current Key Functions:**
- `WalletFileContext::read_from_file_or_create()`
- `WalletFile::read_from_file()`
- `WalletFile::save_to_disk()`

**Changes Required:**

#### A. Add imports

```rust
// Add at top of file
use super::encryption::{EncryptedWalletFile, PasswordManager};
use std::env;
```

#### B. Modify `WalletFileContext::read_from_file_or_create()`

**Current (lines 58-129):**
```rust
pub fn read_from_file_or_create(wallet_directory_path: &Path) -> Result<Self> {
    let wallet_secret_path = Self::wallet_secret_path(wallet_directory_path);
    let wallet_is_new;
    let wallet_secret = if wallet_secret_path.exists() {
        info!("***** Reading wallet from {} *****\n\n\n", ...);
        wallet_is_new = false;
        WalletFile::read_from_file(&wallet_secret_path)?
    } else {
        info!("***** Creating new wallet in {} *****\n\n\n", ...);
        let new_wallet = WalletFile::new_random();
        new_wallet.save_to_disk(&wallet_secret_path)?;
        wallet_is_new = true;
        new_wallet
    };
    // ... rest of function
}
```

**New (replace entire function):**
```rust
pub fn read_from_file_or_create(wallet_directory_path: &Path) -> Result<Self> {
    let wallet_secret_path = Self::wallet_secret_path(wallet_directory_path);
    let encrypted_wallet_path = wallet_directory_path.join("wallet.encrypted");
    
    let wallet_is_new;
    let wallet_secret = if encrypted_wallet_path.exists() {
        // Load encrypted wallet
        info!("***** Reading encrypted wallet from {} *****\n\n\n",
              encrypted_wallet_path.display());
        wallet_is_new = false;
        Self::load_encrypted_wallet(&encrypted_wallet_path)?
        
    } else if wallet_secret_path.exists() {
        // Migrate plaintext wallet to encrypted format
        info!("***** Migrating plaintext wallet to encrypted format *****\n");
        wallet_is_new = false;
        Self::migrate_plaintext_wallet(&wallet_secret_path, &encrypted_wallet_path)?
        
    } else {
        // Create new encrypted wallet
        info!("***** Creating new encrypted wallet in {} *****\n\n\n",
              encrypted_wallet_path.display());
        wallet_is_new = true;
        Self::create_new_encrypted_wallet(&encrypted_wallet_path)?
    };
    
    // ... rest of function unchanged (randomness files, etc.)
}
```

**Lines Changed:** ~40 (function body replacement)

#### C. Add new helper functions (after `read_from_file_or_create`)

```rust
/// Load and decrypt an encrypted wallet file
fn load_encrypted_wallet(path: &Path) -> Result<WalletFile> {
    let encrypted = EncryptedWalletFile::load_from_file(path)?;
    
    // Check for password in environment variable (for automation)
    let password = if let Ok(env_password) = env::var("NEPTUNE_WALLET_PASSWORD") {
        warn!("⚠️  Using password from NEPTUNE_WALLET_PASSWORD environment variable");
        warn!("⚠️  This is insecure for interactive use!");
        zeroize::Zeroizing::new(env_password)
    } else {
        PasswordManager::prompt_password("🔐 Enter wallet password: ")?
    };
    
    encrypted.decrypt(&password)
        .context("Failed to decrypt wallet (wrong password?)")
}

/// Migrate a plaintext wallet to encrypted format
fn migrate_plaintext_wallet(old_path: &Path, new_path: &Path) -> Result<WalletFile> {
    // Read plaintext wallet
    let wallet = WalletFile::read_from_file(old_path)?;
    
    info!("╔══════════════════════════════════════════════════════════╗");
    info!("║  ⚠️  SECURITY UPGRADE: WALLET ENCRYPTION               ║");
    info!("╚══════════════════════════════════════════════════════════╝");
    info!("");
    info!("Your wallet is currently stored UNENCRYPTED on disk.");
    info!("We'll now encrypt it to protect your funds from theft.");
    info!("");
    
    // Prompt for new password
    let password = PasswordManager::prompt_new_password()?;
    
    // Encrypt and save
    let encrypted = EncryptedWalletFile::encrypt(&wallet, &password)?;
    encrypted.save_to_file(new_path)?;
    
    // Backup old wallet
    let backup_path = old_path.with_extension("dat.backup");
    std::fs::copy(old_path, &backup_path)?;
    info!("✅ Backup of plaintext wallet saved to: {}", backup_path.display());
    
    // Delete old wallet
    std::fs::remove_file(old_path)?;
    info!("✅ Plaintext wallet securely deleted");
    
    info!("");
    info!("╔══════════════════════════════════════════════════════════╗");
    info!("║  ✅ WALLET ENCRYPTED SUCCESSFULLY                       ║");
    info!("╚══════════════════════════════════════════════════════════╝");
    info!("📁 New location: {}", new_path.display());
    info!("💾 Backup: {}", backup_path.display());
    info!("");
    info!("⚠️  CRITICAL: WRITE DOWN YOUR PASSWORD!");
    info!("⚠️  If you lose it, your funds are PERMANENTLY LOST.");
    info!("");
    
    Ok(wallet)
}

/// Create a new encrypted wallet
fn create_new_encrypted_wallet(path: &Path) -> Result<WalletFile> {
    let wallet = WalletFile::new_random();
    
    info!("╔══════════════════════════════════════════════════════════╗");
    info!("║  🆕 CREATING NEW ENCRYPTED WALLET                      ║");
    info!("╚══════════════════════════════════════════════════════════╝");
    info!("");
    
    // Prompt for password
    let password = PasswordManager::prompt_new_password()?;
    
    // Encrypt and save
    let encrypted = EncryptedWalletFile::encrypt(&wallet, &password)?;
    encrypted.save_to_file(path)?;
    
    info!("");
    info!("╔══════════════════════════════════════════════════════════╗");
    info!("║  ✅ WALLET CREATED AND ENCRYPTED                       ║");
    info!("╚══════════════════════════════════════════════════════════╝");
    info!("📁 Location: {}", path.display());
    info!("");
    info!("⚠️  CRITICAL: BACK UP BOTH:");
    info!("    1. Your seed phrase (write it down!)");
    info!("    2. Your wallet password");
    info!("");
    info!("If you lose either, your funds are PERMANENTLY LOST!");
    info!("");
    
    Ok(wallet)
}
```

**Lines Added:** ~150 (3 new helper functions)

**Total Impact on wallet_file.rs:**
- Lines modified: ~40
- Lines added: ~150
- New dependencies: `encryption` module
- Breaking changes: None (backwards compatible)

---

### 4. wallet_state.rs (MINOR ERROR HANDLING)

**File:** `neptune-core/src/state/wallet/wallet_state.rs`

**Changes:** Only if `WalletFile` loading errors need better context

**Likely changes:**
```rust
// In try_new_from_context() around line 290
let wallet_file_context =
    WalletFileContext::read_from_file_or_create(&data_directory.wallet_directory_path())
        .context("Failed to load or create wallet (check password if prompted)")?;
```

**Lines Changed:** ~5 (minor error message improvements)
**Impact:** Minimal, just better error messages

---

## Integration Points

### 1. Node Startup Flow

```
neptune-core startup
    ↓
lib.rs::initialize()
    ↓
GlobalState::try_new()
    ↓
WalletFileContext::read_from_file_or_create()  ← INTEGRATION POINT #1
    ↓
    ├─→ wallet.encrypted exists?
    │   └─→ load_encrypted_wallet()
    │       └─→ EncryptedWalletFile::load_from_file()
    │           └─→ PasswordManager::prompt_password()  ← USER INTERACTION
    │               └─→ EncryptedWalletFile::decrypt()
    │
    ├─→ wallet.dat exists (plaintext)?
    │   └─→ migrate_plaintext_wallet()  ← INTEGRATION POINT #2
    │       ├─→ WalletFile::read_from_file()
    │       ├─→ PasswordManager::prompt_new_password()  ← USER INTERACTION
    │       ├─→ EncryptedWalletFile::encrypt()
    │       ├─→ save → wallet.encrypted
    │       └─→ backup → wallet.dat.backup
    │
    └─→ No wallet exists?
        └─→ create_new_encrypted_wallet()  ← INTEGRATION POINT #3
            ├─→ WalletFile::new_random()
            ├─→ PasswordManager::prompt_new_password()  ← USER INTERACTION
            ├─→ EncryptedWalletFile::encrypt()
            └─→ save → wallet.encrypted
    ↓
WalletState::try_new_from_context()
    ↓
Continue normal startup...
```

**Key Integration Points:**
1. **Load existing encrypted wallet** - Password prompt on startup
2. **Migrate plaintext wallet** - One-time migration with password setup
3. **Create new encrypted wallet** - Password setup for new users

---

### 2. RPC Server Integration (Future)

**Note:** Not implemented in Phase 1, but showing integration point for Phase 2

```
neptune-cli command
    ↓
RPC call to neptune-core
    ↓
handlers.rs (RPC handlers)
    ↓
Access WalletState (already decrypted)
    ↓
No password needed (wallet unlocked during startup)
```

**Phase 1:** No changes to RPC handlers
**Phase 2 (future):** Could add `wallet_lock()` / `wallet_unlock()` RPC commands

---

### 3. Environment Variable Integration

```bash
# For automation/CI/testing only
export NEPTUNE_WALLET_PASSWORD="my-secure-password"
neptune-core

# wallet_file.rs checks:
if let Ok(env_password) = env::var("NEPTUNE_WALLET_PASSWORD") {
    // Use env password (with warning)
} else {
    // Prompt user
}
```

**Integration Point:** `wallet_file.rs::load_encrypted_wallet()`

---

## Dependency Tree

### Module Dependencies

```
neptune-core/src/state/wallet/encryption/
├── mod.rs                    (no internal deps)
├── key_manager.rs
│   ├── argon2 (external)
│   ├── hkdf (external)
│   ├── sha2 (external)
│   ├── rand (external)
│   └── zeroize (external)
├── cipher.rs
│   ├── aes-gcm (external)
│   ├── rand (external)
│   └── zeroize (external)
├── password.rs
│   ├── rpassword (external)
│   └── zeroize (external)
└── format.rs
    ├── key_manager (internal)
    ├── cipher (internal)
    ├── serde (external, existing)
    └── bincode (external, existing)

wallet_file.rs
├── encryption::* (internal, NEW)
├── WalletFile (internal, existing)
└── std::env (external, existing)

wallet_state.rs
└── wallet_file (internal, existing) - no changes needed
```

### External Crate Dependencies (NEW)

```
argon2 = "0.5"
    └── password-hash = "0.5"
        └── rand_core = "0.6"

aes-gcm = "0.10"
    └── aes = "0.8"
    └── aead = "0.5"

hkdf = "0.12"
    └── hmac = "0.12"

sha2 = "0.10"
    └── digest = "0.10"

zeroize = "1.7"  (may already exist)

rpassword = "7.3"
    └── libc (Unix)
    └── winapi (Windows)
```

**Total New Dependencies:** ~15 crates (including transitive)
**Binary Size Impact:** ~200-300 KB (negligible)

---

## Call Flow Diagram

### Normal Startup (Encrypted Wallet Exists)

```
User runs: neptune-core
    ↓
main() → initialize()
    ↓
DataDirectory::get()
    ↓
GlobalState::try_new()
    ↓
[1] WalletFileContext::read_from_file_or_create()
    ↓
[2] Checks: wallet.encrypted exists? → YES
    ↓
[3] load_encrypted_wallet()
    ↓
[4] EncryptedWalletFile::load_from_file()
    ↓
[5] Read JSON from disk
    ↓
[6] Deserialize EncryptedWalletFile
    ↓
[7] Check env::var("NEPTUNE_WALLET_PASSWORD")
    ├─→ Found? → Use it (with warning)
    └─→ Not found? → Prompt user
        ↓
[8]     PasswordManager::prompt_password("🔐 Enter wallet password: ")
        ↓
[9]     User types password (hidden)
    ↓
[10] EncryptedWalletFile::decrypt(password)
    ↓
[11] WalletKeyManager::from_password(password, salt)
    ↓
[12] Argon2id key derivation (~1 second) 💤
    ↓
[13] HKDF derive encryption key
    ↓
[14] WalletCipher::new(key)
    ↓
[15] cipher.decrypt(ciphertext, nonce)
    ↓
[16] Verify authentication tag
    ├─→ Success? → Continue
    └─→ Failure? → Error: "Wrong password"
    ↓
[17] bincode::deserialize(plaintext)
    ↓
[18] Return WalletFile
    ↓
Continue normal startup with decrypted wallet...
    ↓
WalletState::try_new_from_context()
    ↓
Load UTXOs, sync, etc.
    ↓
Node running! 🚀
```

**Time Breakdown:**
- Steps 1-6: ~10ms (file I/O)
- Steps 7-9: ~100ms (user input) or instant (env var)
- **Step 12: ~1 second (Argon2id - intentionally slow for security)**
- Steps 13-18: ~10ms (decryption + deserialization)
- **Total: ~1.1 seconds** (acceptable security trade-off)

---

### First-Time Migration (Plaintext Wallet Exists)

```
User runs: neptune-core (first time after update)
    ↓
[1-6] Same as above...
    ↓
[7] Checks: wallet.encrypted exists? → NO
    ↓
[8] Checks: wallet.dat exists? → YES
    ↓
[9] migrate_plaintext_wallet()
    ↓
[10] WalletFile::read_from_file(wallet.dat)
    ↓
[11] Deserialize plaintext JSON
    ↓
[12] Print security warning:
     "⚠️  Your wallet is currently UNENCRYPTED!"
    ↓
[13] PasswordManager::prompt_new_password()
    ↓
[14] User types password (hidden)
    ↓
[15] Validate password strength
     ├─→ Weak? → Warn user, confirm
     └─→ Strong? → Continue
    ↓
[16] User confirms password
    ↓
[17] EncryptedWalletFile::encrypt(wallet, password)
    ↓
[18] Argon2id key derivation (~1 second) 💤
    ↓
[19] AES-256-GCM encryption
    ↓
[20] Save to wallet.encrypted
    ↓
[21] Copy wallet.dat → wallet.dat.backup
    ↓
[22] Delete wallet.dat
    ↓
[23] Print success message:
     "✅ Wallet encrypted successfully!"
     "📁 Backup: wallet.dat.backup"
     "⚠️  Write down your password!"
    ↓
Continue normal startup...
```

**Time Breakdown:**
- Steps 1-12: ~100ms
- Steps 13-16: ~5 seconds (user interaction)
- **Step 18: ~1 second (Argon2id)**
- Steps 19-23: ~50ms
- **Total: ~6 seconds** (one-time migration)

---

### New Wallet Creation

```
User runs: neptune-core (no wallet exists)
    ↓
[1-6] Same as above...
    ↓
[7] Checks: wallet.encrypted exists? → NO
    ↓
[8] Checks: wallet.dat exists? → NO
    ↓
[9] create_new_encrypted_wallet()
    ↓
[10] WalletFile::new_random()
    ↓
[11] Generate random XFieldElement seed
    ↓
[12] Print welcome message:
     "🆕 Creating new wallet..."
    ↓
[13] PasswordManager::prompt_new_password()
    ↓
[14] User types password
    ↓
[15] Validate + confirm
    ↓
[16] EncryptedWalletFile::encrypt(wallet, password)
    ↓
[17] Argon2id (~1 second) 💤
    ↓
[18] AES-256-GCM encryption
    ↓
[19] Save to wallet.encrypted
    ↓
[20] Print success + warnings
    ↓
Continue normal startup...
```

---

## Testing Structure

### Unit Tests (Per Module)

```
neptune-core/src/state/wallet/encryption/
├── key_manager.rs
│   └── tests::
│       ├── test_deterministic_derivation
│       ├── test_different_passwords_different_keys
│       └── test_different_salts_different_keys
│
├── cipher.rs
│   └── tests::
│       ├── test_encrypt_decrypt_roundtrip
│       ├── test_wrong_key_fails
│       ├── test_wrong_nonce_fails
│       └── test_tampered_ciphertext_fails
│
├── password.rs
│   └── tests::
│       └── test_password_strength
│
└── format.rs
    └── tests::
        ├── test_encrypt_decrypt_roundtrip
        ├── test_wrong_password_fails
        └── test_file_roundtrip
```

### Integration Tests

```
neptune-core/tests/
└── wallet_encryption_test.rs
    ├── test_encrypted_wallet_lifecycle
    ├── test_plaintext_migration
    ├── test_wrong_password_fails_gracefully
    └── test_corrupted_ciphertext_fails
```

### Manual Testing Checklist

```
[ ] Fresh install (no wallet)
    [ ] Create wallet with password
    [ ] Restart node
    [ ] Enter correct password → Success
    [ ] Enter wrong password → Fail gracefully

[ ] Migration (plaintext wallet exists)
    [ ] Start node
    [ ] See migration prompt
    [ ] Set password
    [ ] Verify wallet.encrypted created
    [ ] Verify wallet.dat.backup exists
    [ ] Verify wallet.dat deleted
    [ ] Restart node → Success

[ ] Environment variable
    [ ] Set NEPTUNE_WALLET_PASSWORD
    [ ] Start node (no prompt)
    [ ] Verify warning logged
    [ ] Wallet unlocked successfully

[ ] Error cases
    [ ] Wrong password → Clear error message
    [ ] Corrupted file → Clear error message
    [ ] Disk full during encryption → Rollback
    [ ] Permission denied → Clear error message
```

---

## Summary

### Files Created: 10

1. `neptune-core/src/state/wallet/encryption/mod.rs`
2. `neptune-core/src/state/wallet/encryption/key_manager.rs`
3. `neptune-core/src/state/wallet/encryption/cipher.rs`
4. `neptune-core/src/state/wallet/encryption/password.rs`
5. `neptune-core/src/state/wallet/encryption/format.rs`
6. `neptune-core/src/state/wallet/encryption/tests.rs`
7. `neptune-core/tests/wallet_encryption_test.rs`
8. `docs/user-guides/wallet-encryption.md`
9. `docs/security/encryption-technical-spec.md`
10. `docs/security/integration-points-map.md` (this file)

### Files Modified: 3

1. `neptune-core/Cargo.toml` (+6 dependencies)
2. `neptune-core/src/state/wallet/mod.rs` (+5 lines)
3. `neptune-core/src/state/wallet/wallet_file.rs` (+190 lines, ~40 modified)

### Files Unchanged (Integration Transparent): Many

- `lib.rs` - No changes needed
- `wallet_state.rs` - Minimal (just error messages)
- All RPC handlers - No changes
- All other wallet modules - No changes

### Total Code: ~1,200 lines

- Encryption module: ~670 lines
- wallet_file.rs changes: ~190 lines
- Integration tests: ~100 lines
- Module tests: ~240 lines

---

**Status:** ✅ Ready for Day 1 implementation
**Next Step:** Begin Day 1 - Add dependencies + create module skeleton

