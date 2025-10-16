# Phase 1 Fast-Track: Wallet Encryption Implementation

**Branch:** `feature/wallet-security-hardening`
**Current Version:** v0.4.0 (Sea of Freedom fork)
**Target Version:** v0.4.1 (security patch) or v0.5.0 (minor release)
**Priority:** CRITICAL
**Timeline:** 2-3 weeks (compressed from 4 weeks)

---

## Table of Contents

1. [Critical Security Context](#critical-security-context)
2. [Fast-Track Strategy](#fast-track-strategy)
3. [Week 1: Core Encryption](#week-1-core-encryption)
4. [Week 2: Integration & Testing](#week-2-integration--testing)
5. [Week 3: Polish & Release](#week-3-polish--release)
6. [Implementation Checklist](#implementation-checklist)
7. [Dependencies & Crates](#dependencies--crates)
8. [Testing Strategy](#testing-strategy)
9. [Migration Plan](#migration-plan)
10. [Rollout Plan](#rollout-plan)

---

## Critical Security Context

### Current Vulnerability

**CONFIRMED:** Wallet seed stored as plaintext JSON:
```json
{
  "name": "standard_wallet",
  "secret_seed": {
    "coefficients": [1234567890123456, 9876543210987654, 1111111111111111]
  },
  "version": 0
}
```

**Risk Level:** CRITICAL
- ❌ Anyone with file read access = complete wallet compromise
- ❌ Cloud backup exposes master seed
- ❌ Malware can trivially steal funds
- ❌ Disk forensics recovers deleted wallets

**Impact:** Every Neptune Core user is vulnerable

---

## Fast-Track Strategy

### What We're Cutting

**DEFERRED to Phase 2 (v0.5.x or v0.6.0):**
- ❌ Data directory decoupling (wallet vs blockchain separation)
- ❌ Database encryption (LevelDB wrapper)
- ❌ Windows ACL implementation
- ❌ Keychain integration (macOS/Linux/Windows)
- ❌ Hardware wallet support

**KEEPING in Phase 1 (v0.4.1/v0.5.0):**
- ✅ Wallet file encryption (Argon2id + AES-256-GCM)
- ✅ Password management (interactive prompt)
- ✅ Automatic migration (plaintext → encrypted)
- ✅ Backwards compatibility
- ✅ Comprehensive tests

### Aggressive Timeline

| Week | Focus | Deliverables |
|------|-------|--------------|
| **Week 1** | Core encryption system | Working encrypt/decrypt, password mgmt |
| **Week 2** | Integration & migration | CLI integration, auto-migration, tests |
| **Week 3** | Polish & release | Documentation, security audit, release |

**Total:** 15 working days

---

## Week 1: Core Encryption (Days 1-5)

### Day 1: Project Setup & Dependencies

**Goal:** Add dependencies, create module structure

**Tasks:**
1. Add required crates to `Cargo.toml`
2. Create module structure in `neptune-core/src/state/wallet/encryption/`
3. Write module documentation

**Code:**

```toml
# neptune-core/Cargo.toml
[dependencies]
# Existing dependencies...

# Wallet encryption (Phase 1)
argon2 = "0.5"           # Password hashing
aes-gcm = "0.10"         # Authenticated encryption
hkdf = "0.12"            # Key derivation
sha2 = "0.10"            # SHA-256 for HKDF
rand = "0.8"             # Random salt/nonce generation
zeroize = "1.7"          # Secure memory cleanup
rpassword = "7.3"        # Password input
```

**Module Structure:**
```
neptune-core/src/state/wallet/
├── encryption/              # NEW
│   ├── mod.rs              # Module root
│   ├── key_manager.rs      # Argon2 key derivation
│   ├── cipher.rs           # AES-GCM encrypt/decrypt
│   ├── password.rs         # Password input/validation
│   └── format.rs           # Encrypted file format
├── wallet_file.rs          # UPDATE: Add encryption support
└── ...
```

**Deliverable:** Module skeleton with documentation

---

### Day 2: Key Derivation (Argon2id)

**Goal:** Implement `WalletKeyManager` with Argon2id

**File:** `neptune-core/src/state/wallet/encryption/key_manager.rs`

**Implementation:**

```rust
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2, ParamsBuilder, Version,
};
use hkdf::Hkdf;
use rand::rngs::OsRng;
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
    /// - Memory cost: 256 MB
    /// - Time cost: 4 iterations
    /// - Parallelism: 4 threads
    /// - Takes ~1 second on modern hardware
    pub fn from_password(password: &str, salt: &[u8; 32]) -> Result<Self> {
        let mut master_key = Zeroizing::new([0u8; 32]);
        
        // Configure Argon2id (memory-hard, side-channel resistant)
        let params = ParamsBuilder::new()
            .m_cost(256 * 1024)  // 256 MB RAM
            .t_cost(4)           // 4 iterations (~1 second)
            .p_cost(4)           // 4 parallel threads
            .output_len(32)      // 256-bit key
            .build()
            .map_err(|e| anyhow!("Invalid Argon2 params: {}", e))?;
        
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,  // Hybrid (data + time)
            Version::V0x13,                // Latest version
            params,
        );
        
        // Derive key (expensive operation)
        argon2.hash_password_into(
            password.as_bytes(),
            salt,
            &mut *master_key,
        )?;
        
        Ok(Self { master_key })
    }
    
    /// Generate random salt for new wallet
    pub fn generate_salt() -> [u8; 32] {
        let mut salt = [0u8; 32];
        use rand::RngCore;
        OsRng.fill_bytes(&mut salt);
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
        
        let km1 = WalletKeyManager::from_password(password, &[1u8; 32]).unwrap();
        let km2 = WalletKeyManager::from_password(password, &[2u8; 32]).unwrap();
        
        // Different salts = different keys
        assert_ne!(
            km1.derive_wallet_key().as_ref(),
            km2.derive_wallet_key().as_ref()
        );
    }
}
```

**Testing:**
```bash
cargo test --package neptune-core --lib wallet::encryption::key_manager
```

**Deliverable:** Working key derivation with tests

---

### Day 3: AES-GCM Encryption

**Goal:** Implement `WalletCipher` with AES-256-GCM

**File:** `neptune-core/src/state/wallet/encryption/cipher.rs`

**Implementation:**

```rust
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use zeroize::Zeroizing;

/// Handles AES-256-GCM encryption/decryption
pub struct WalletCipher {
    cipher: Aes256Gcm,
}

impl WalletCipher {
    /// Create cipher from 256-bit key
    pub fn new(key: &[u8; 32]) -> Result<Self> {
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| anyhow!("Invalid AES key: {}", e))?;
        Ok(Self { cipher })
    }
    
    /// Generate random 96-bit nonce
    pub fn generate_nonce() -> [u8; 12] {
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        nonce
    }
    
    /// Encrypt plaintext with authenticated encryption
    ///
    /// Returns: (ciphertext, auth_tag)
    pub fn encrypt(&self, plaintext: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>> {
        let nonce = Nonce::from_slice(nonce);
        
        self.cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow!("Encryption failed: {}", e))
    }
    
    /// Decrypt ciphertext with authentication verification
    pub fn decrypt(&self, ciphertext: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>> {
        let nonce = Nonce::from_slice(nonce);
        
        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow!("Decryption failed (wrong password or corrupted data): {}", e))
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
    fn test_wrong_nonce_fails() {
        let key = [42u8; 32];
        let cipher = WalletCipher::new(&key).unwrap();
        
        let plaintext = b"secret";
        let nonce1 = [1u8; 12];
        let nonce2 = [2u8; 12];
        
        let ciphertext = cipher.encrypt(plaintext, &nonce1).unwrap();
        
        // Wrong nonce should fail to decrypt (authentication failure)
        assert!(cipher.decrypt(&ciphertext, &nonce2).is_err());
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
```

**Deliverable:** Working encryption with tests

---

### Day 4: Password Management

**Goal:** Implement `PasswordManager` for interactive password input

**File:** `neptune-core/src/state/wallet/encryption/password.rs`

**Implementation:**

```rust
use rpassword::prompt_password;
use zeroize::Zeroizing;

/// Password strength levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordStrength {
    VeryWeak,
    Weak,
    Medium,
    Strong,
    VeryStrong,
}

impl PasswordStrength {
    pub fn emoji(&self) -> &'static str {
        match self {
            Self::VeryWeak => "💀",
            Self::Weak => "⚠️",
            Self::Medium => "🔸",
            Self::Strong => "✅",
            Self::VeryStrong => "🔐",
        }
    }
}

/// Manages password input and validation
pub struct PasswordManager;

impl PasswordManager {
    /// Prompt user for password (interactive, terminal only)
    pub fn prompt_new_password() -> Result<Zeroizing<String>> {
        loop {
            let password = prompt_password("🔐 Enter new wallet password: ")?;
            
            if password.is_empty() {
                eprintln!("❌ Password cannot be empty");
                continue;
            }
            
            let strength = Self::validate_strength(&password);
            println!("{} Password strength: {:?}", strength.emoji(), strength);
            
            if matches!(strength, PasswordStrength::VeryWeak | PasswordStrength::Weak) {
                eprintln!("⚠️  Warning: Weak password! Minimum 12 characters recommended.");
                eprint!("Continue anyway? (yes/no): ");
                use std::io::{self, BufRead};
                let mut response = String::new();
                io::stdin().lock().read_line(&mut response)?;
                if response.trim() != "yes" {
                    continue;
                }
            }
            
            let confirm = prompt_password("🔐 Confirm password: ")?;
            
            if password != confirm {
                eprintln!("❌ Passwords do not match");
                continue;
            }
            
            return Ok(Zeroizing::new(password));
        }
    }
    
    /// Prompt user for existing password
    pub fn prompt_password(prompt: &str) -> Result<Zeroizing<String>> {
        let password = prompt_password(prompt)?;
        
        if password.is_empty() {
            anyhow::bail!("Password cannot be empty");
        }
        
        Ok(Zeroizing::new(password))
    }
    
    /// Validate password strength
    pub fn validate_strength(password: &str) -> PasswordStrength {
        let length = password.len();
        let has_uppercase = password.chars().any(|c| c.is_uppercase());
        let has_lowercase = password.chars().any(|c| c.is_lowercase());
        let has_digit = password.chars().any(|c| c.is_numeric());
        let has_special = password.chars().any(|c| !c.is_alphanumeric());
        
        let score =
            (length >= 12) as u8 * 2 +
            (length >= 16) as u8 * 2 +
            has_uppercase as u8 +
            has_lowercase as u8 +
            has_digit as u8 +
            has_special as u8;
        
        match score {
            0..=3 => PasswordStrength::VeryWeak,
            4..=5 => PasswordStrength::Weak,
            6..=7 => PasswordStrength::Medium,
            8..=9 => PasswordStrength::Strong,
            _ => PasswordStrength::VeryStrong,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_password_strength() {
        assert_eq!(
            PasswordManager::validate_strength("weak"),
            PasswordStrength::VeryWeak
        );
        
        assert_eq!(
            PasswordManager::validate_strength("WeakPassword"),
            PasswordStrength::Weak
        );
        
        assert_eq!(
            PasswordManager::validate_strength("Medium-Pass-123"),
            PasswordStrength::Medium
        );
        
        assert_eq!(
            PasswordManager::validate_strength("Strong-Pass-2025!"),
            PasswordStrength::Strong
        );
        
        assert_eq!(
            PasswordManager::validate_strength("Very-Strong-Passphrase-2025!@#$"),
            PasswordStrength::VeryStrong
        );
    }
}
```

**Deliverable:** Password input with strength validation

---

### Day 5: Encrypted File Format

**Goal:** Define `EncryptedWalletFile` format and implement serialization

**File:** `neptune-core/src/state/wallet/encryption/format.rs`

**Implementation:**

```rust
use serde::{Deserialize, Serialize};
use super::{WalletKeyManager, WalletCipher};
use crate::state::wallet::wallet_file::WalletFile;

/// Argon2id parameters for key derivation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Argon2Params {
    pub memory_cost_kib: u32,  // 256 * 1024 = 256 MB
    pub time_cost: u32,         // 4 iterations
    pub parallelism: u32,       // 4 threads
    pub salt: [u8; 32],         // Random salt
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            memory_cost_kib: 256 * 1024,
            time_cost: 4,
            parallelism: 4,
            salt: WalletKeyManager::generate_salt(),
        }
    }
}

/// AES-GCM parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AesGcmParams {
    pub nonce: [u8; 12],  // Random 96-bit nonce
}

/// On-disk format for encrypted wallet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedWalletFile {
    /// Format version (for future migrations)
    pub version: u8,
    
    /// Encryption algorithm identifier
    pub algorithm: String,
    
    /// Argon2id parameters
    pub kdf_params: Argon2Params,
    
    /// AES-GCM parameters
    pub cipher_params: AesGcmParams,
    
    /// Encrypted wallet data (includes auth tag)
    pub ciphertext: Vec<u8>,
}

impl EncryptedWalletFile {
    /// Current format version
    pub const VERSION: u8 = 1;
    
    /// Algorithm identifier
    pub const ALGORITHM: &'static str = "argon2id-aes256gcm";
    
    /// Encrypt a wallet file with password
    pub fn encrypt(wallet: &WalletFile, password: &str) -> Result<Self> {
        // 1. Generate random parameters
        let kdf_params = Argon2Params::default();
        let nonce = WalletCipher::generate_nonce();
        
        // 2. Derive encryption key from password
        let key_manager = WalletKeyManager::from_password(password, &kdf_params.salt)?;
        let encryption_key = key_manager.derive_wallet_key();
        
        // 3. Serialize wallet to binary
        let plaintext = bincode::serialize(wallet)
            .map_err(|e| anyhow!("Failed to serialize wallet: {}", e))?;
        
        // 4. Encrypt with AES-256-GCM (includes auth tag)
        let cipher = WalletCipher::new(&encryption_key)?;
        let ciphertext = cipher.encrypt(&plaintext, &nonce)?;
        
        Ok(Self {
            version: Self::VERSION,
            algorithm: Self::ALGORITHM.to_string(),
            kdf_params,
            cipher_params: AesGcmParams { nonce },
            ciphertext,
        })
    }
    
    /// Decrypt wallet file with password
    pub fn decrypt(&self, password: &str) -> Result<WalletFile> {
        // 1. Verify version
        if self.version != Self::VERSION {
            anyhow::bail!("Unsupported wallet version: {}", self.version);
        }
        
        if self.algorithm != Self::ALGORITHM {
            anyhow::bail!("Unsupported encryption algorithm: {}", self.algorithm);
        }
        
        // 2. Derive decryption key from password
        let key_manager = WalletKeyManager::from_password(password, &self.kdf_params.salt)?;
        let decryption_key = key_manager.derive_wallet_key();
        
        // 3. Decrypt with AES-256-GCM (verifies auth tag)
        let cipher = WalletCipher::new(&decryption_key)?;
        let plaintext = cipher.decrypt(&self.ciphertext, &self.cipher_params.nonce)
            .map_err(|e| anyhow!("Decryption failed (wrong password?): {}", e))?;
        
        // 4. Deserialize wallet from binary
        let wallet: WalletFile = bincode::deserialize(&plaintext)
            .map_err(|e| anyhow!("Failed to deserialize wallet: {}", e))?;
        
        Ok(wallet)
    }
    
    /// Save encrypted wallet to file
    pub fn save_to_file(&self, path: &std::path::Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        
        #[cfg(unix)]
        {
            use std::fs::OpenOptions;
            use std::os::unix::fs::OpenOptionsExt;
            use std::io::Write;
            
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .mode(0o600)  // Owner read/write only
                .open(path)?;
            
            file.write_all(json.as_bytes())?;
        }
        
        #[cfg(not(unix))]
        {
            std::fs::write(path, json)?;
        }
        
        Ok(())
    }
    
    /// Load encrypted wallet from file
    pub fn load_from_file(path: &std::path::Path) -> Result<Self> {
        let json = std::fs::read_to_string(path)?;
        let encrypted: Self = serde_json::from_str(&json)?;
        Ok(encrypted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::wallet::secret_key_material::SecretKeyMaterial;
    
    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let wallet = WalletFile::new(SecretKeyMaterial(rand::random()));
        let password = "test-password-123";
        
        let encrypted = EncryptedWalletFile::encrypt(&wallet, password).unwrap();
        let decrypted = encrypted.decrypt(password).unwrap();
        
        assert_eq!(wallet.secret_key(), decrypted.secret_key());
    }
    
    #[test]
    fn test_wrong_password_fails() {
        let wallet = WalletFile::new(SecretKeyMaterial(rand::random()));
        
        let encrypted = EncryptedWalletFile::encrypt(&wallet, "correct").unwrap();
        
        assert!(encrypted.decrypt("wrong").is_err());
    }
    
    #[test]
    fn test_file_roundtrip() {
        use tempfile::tempdir;
        
        let wallet = WalletFile::new(SecretKeyMaterial(rand::random()));
        let password = "test-password";
        
        let encrypted = EncryptedWalletFile::encrypt(&wallet, password).unwrap();
        
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("wallet.encrypted");
        
        encrypted.save_to_file(&file_path).unwrap();
        let loaded = EncryptedWalletFile::load_from_file(&file_path).unwrap();
        let decrypted = loaded.decrypt(password).unwrap();
        
        assert_eq!(wallet.secret_key(), decrypted.secret_key());
    }
}
```

**Deliverable:** Complete encryption/decryption system with file I/O

---

## Week 2: Integration & Migration (Days 6-10)

### Day 6: Integrate with WalletFile

**Goal:** Update `wallet_file.rs` to support encryption

**File:** `neptune-core/src/state/wallet/wallet_file.rs`

**Changes:**

```rust
// Add to WalletFileContext
impl WalletFileContext {
    pub fn read_from_file_or_create(wallet_directory_path: &Path) -> Result<Self> {
        let wallet_secret_path = Self::wallet_secret_path(wallet_directory_path);
        let encrypted_wallet_path = wallet_directory_path.join("wallet.encrypted");
        
        let wallet_is_new;
        let wallet_secret = if encrypted_wallet_path.exists() {
            // Load encrypted wallet
            info!("***** Reading encrypted wallet from {} *****", encrypted_wallet_path.display());
            wallet_is_new = false;
            Self::load_encrypted_wallet(&encrypted_wallet_path)?
        } else if wallet_secret_path.exists() {
            // Migrate plaintext wallet
            info!("***** Migrating plaintext wallet to encrypted format *****");
            wallet_is_new = false;
            Self::migrate_plaintext_wallet(&wallet_secret_path, &encrypted_wallet_path)?
        } else {
            // Create new encrypted wallet
            info!("***** Creating new encrypted wallet in {} *****", encrypted_wallet_path.display());
            wallet_is_new = true;
            Self::create_new_encrypted_wallet(&encrypted_wallet_path)?
        };
        
        // ... rest of function
    }
    
    fn load_encrypted_wallet(path: &Path) -> Result<WalletFile> {
        let encrypted = EncryptedWalletFile::load_from_file(path)?;
        
        let password = PasswordManager::prompt_password("🔐 Enter wallet password: ")?;
        
        encrypted.decrypt(&password)
            .context("Failed to decrypt wallet (wrong password?)")
    }
    
    fn migrate_plaintext_wallet(old_path: &Path, new_path: &Path) -> Result<WalletFile> {
        // Read plaintext wallet
        let wallet = WalletFile::read_from_file(old_path)?;
        
        println!("⚠️  SECURITY: Your wallet is currently unencrypted!");
        println!("📦 We'll now encrypt it to protect your funds.");
        println!();
        
        // Prompt for new password
        let password = PasswordManager::prompt_new_password()?;
        
        // Encrypt and save
        let encrypted = EncryptedWalletFile::encrypt(&wallet, &password)?;
        encrypted.save_to_file(new_path)?;
        
        // Backup old wallet
        let backup_path = old_path.with_extension("dat.backup");
        std::fs::copy(old_path, &backup_path)?;
        info!("✅ Backup of plaintext wallet saved to: {}", backup_path.display());
        
        // Delete old wallet (secure delete if possible)
        std::fs::remove_file(old_path)?;
        info!("✅ Plaintext wallet deleted");
        
        println!("✅ Wallet encrypted successfully!");
        println!("📁 New location: {}", new_path.display());
        println!("💾 Backup: {}", backup_path.display());
        println!();
        println!("⚠️  IMPORTANT: Write down your password! If you lose it, your funds are GONE.");
        
        Ok(wallet)
    }
    
    fn create_new_encrypted_wallet(path: &Path) -> Result<WalletFile> {
        let wallet = WalletFile::new_random();
        
        println!("🆕 Creating new wallet...");
        println!();
        
        // Prompt for password
        let password = PasswordManager::prompt_new_password()?;
        
        // Encrypt and save
        let encrypted = EncryptedWalletFile::encrypt(&wallet, &password)?;
        encrypted.save_to_file(path)?;
        
        println!("✅ Wallet created and encrypted!");
        println!("📁 Location: {}", path.display());
        println!();
        println!("⚠️  CRITICAL: Back up your seed phrase AND password!");
        
        Ok(wallet)
    }
}
```

**Deliverable:** Wallet file integration with auto-migration

---

### Day 7-8: CLI Integration & Testing

**Goal:** Add CLI flags, comprehensive tests

**CLI Changes:** (minimal for fast-track)
```rust
// neptune-core-cli/src/main.rs
#[derive(Parser)]
pub struct Args {
    // ... existing args
    
    /// Skip wallet password prompt (use env var NEPTUNE_WALLET_PASSWORD)
    /// WARNING: Not recommended for interactive use
    #[arg(long)]
    pub no_password_prompt: bool,
}
```

**Environment Variable Support:**
```bash
export NEPTUNE_WALLET_PASSWORD="my-secure-password"
neptune-core --no-password-prompt
```

**Integration Tests:**
```rust
// neptune-core/tests/wallet_encryption_test.rs
#[tokio::test]
async fn test_encrypted_wallet_lifecycle() {
    // Test: Create → Save → Load → Decrypt
}

#[tokio::test]
async fn test_plaintext_migration() {
    // Test: Old plaintext → Encrypted migration
}

#[tokio::test]
async fn test_wrong_password_fails() {
    // Test: Wrong password properly rejected
}
```

**Deliverable:** CLI integration + comprehensive tests

---

### Day 9: Documentation

**Goal:** User-facing documentation

**Files to Create:**
1. `docs/user-guides/wallet-encryption.md` - User guide
2. `docs/security/encryption-technical-spec.md` - Technical spec
3. Update `README.md` - Highlight encryption feature

**Key Topics:**
- How to encrypt existing wallet
- Password best practices
- What happens if you lose your password
- Migration process
- Security guarantees

**Deliverable:** Complete documentation

---

### Day 10: Security Audit & Review

**Goal:** Internal security review

**Checklist:**
- [ ] Key derivation parameters reviewed
- [ ] No secrets in logs/debug output
- [ ] Memory cleanup verified (Zeroizing)
- [ ] File permissions correct (0600 Unix)
- [ ] Error messages don't leak info
- [ ] Tests cover attack scenarios
- [ ] Code review by 2nd developer

**Deliverable:** Security audit report

---

## Week 3: Polish & Release (Days 11-15)

### Day 11-12: Bug Fixes & Edge Cases

**Focus:**
- Handle disk full errors
- Handle corrupted encrypted files
- Handle interrupted migrations
- Password complexity edge cases
- Cross-platform testing (Linux, macOS, Windows)

### Day 13: Performance Testing

**Benchmarks:**
- Key derivation time (target: ~1 second)
- Encryption time (target: <100ms)
- Decryption time (target: <100ms)
- Memory usage during encryption

### Day 14: Release Preparation

**Tasks:**
- Version bump (v0.4.0 → v0.4.1 or v0.5.0)
- Changelog update
- Release notes
- Tag release in git

### Day 15: Community Communication

**Deliverables:**
- Security advisory (describe vulnerability + fix)
- Migration guide
- FAQ document
- Discord/Twitter announcement

---

## Implementation Checklist

### Core Encryption System
- [ ] Day 1: Dependencies + module structure
- [ ] Day 2: WalletKeyManager (Argon2id)
- [ ] Day 3: WalletCipher (AES-256-GCM)
- [ ] Day 4: PasswordManager
- [ ] Day 5: EncryptedWalletFile format

### Integration
- [ ] Day 6: Integrate with WalletFile
- [ ] Day 7: CLI integration
- [ ] Day 8: Integration tests
- [ ] Day 9: Documentation
- [ ] Day 10: Security audit

### Polish
- [ ] Day 11-12: Bug fixes
- [ ] Day 13: Performance testing
- [ ] Day 14: Release prep
- [ ] Day 15: Communication

---

## Dependencies & Crates

### Required (Add to Cargo.toml)

```toml
[dependencies]
# Password hashing
argon2 = { version = "0.5", features = ["std"] }

# Authenticated encryption
aes-gcm = "0.10"

# Key derivation
hkdf = "0.12"
sha2 = "0.10"

# Secure memory
zeroize = { version = "1.7", features = ["derive"] }

# Password input
rpassword = "7.3"

# Already have:
# - rand
# - serde
# - anyhow
# - bincode
```

**Total New Dependencies:** 5 crates

---

## Testing Strategy

### Unit Tests (Per Module)
- `key_manager_test.rs` - Key derivation tests
- `cipher_test.rs` - Encryption/decryption tests
- `password_test.rs` - Password validation tests
- `format_test.rs` - Serialization tests

### Integration Tests
- `wallet_encryption_test.rs` - Full encryption lifecycle
- `migration_test.rs` - Plaintext → encrypted migration
- `cli_test.rs` - CLI integration

### Security Tests
- Wrong password rejection
- Tampered ciphertext detection
- Memory cleanup verification
- File permission verification (Unix)

### Performance Tests
- Key derivation benchmarks
- Encryption/decryption speed
- Memory usage

**Target Coverage:** >90% for encryption module

---

## Migration Plan

### Automatic Migration Flow

```
User starts neptune-core
    ↓
Detect wallet.dat (plaintext)
    ↓
Print security warning
    ↓
Prompt for new password (with confirmation)
    ↓
Validate password strength
    ↓
Encrypt wallet → wallet.encrypted
    ↓
Backup wallet.dat → wallet.dat.backup
    ↓
Delete wallet.dat (secure if possible)
    ↓
Success message + backup location
```

### Manual Migration (CLI Command)

```bash
# For users who want to migrate without starting node
neptune-cli encrypt-wallet

# Or with explicit paths
neptune-cli encrypt-wallet --wallet-path ~/.config/neptune/core/main/wallet/wallet.dat
```

### Rollback (Emergency)

If migration fails:
1. `wallet.dat.backup` is preserved
2. User can manually restore: `mv wallet.dat.backup wallet.dat`
3. Try migration again with bug fix

---

## Rollout Plan

### Phase 1: Testing Release (Days 11-12)
- Internal testing
- Select beta testers (5-10 users)
- Collect feedback

### Phase 2: Announcement (Day 13)
- Security advisory published
- Explain vulnerability + fix
- Migration guide released

### Phase 3: Release (Day 14)
- Tag v0.4.1 or v0.5.0
- Publish binaries
- Update documentation

### Phase 4: Support (Day 15+)
- Monitor Discord/GitHub for issues
- Rapid bug fixes if needed
- Collect feedback for Phase 2 (data decoupling)

---

## Success Metrics

### Security
- ✅ 0 wallets compromised by file-level attacks (post-encryption)
- ✅ 0 password recovery attacks successful (Argon2 resistance)
- ✅ 0 authentication bypass (AES-GCM integrity)

### Adoption
- ✅ >90% of active users migrate within 1 month
- ✅ 0 users lose funds due to migration bugs
- ✅ <5% of users report migration issues

### Performance
- ✅ Key derivation: 0.8-1.2 seconds (target: ~1s)
- ✅ Encryption: <100ms
- ✅ Node startup delay: <2s (acceptable for security)

---

## Risk Mitigation

### Risk: Password Loss
**Mitigation:**
- Prominent warnings about password importance
- Suggest password manager usage
- Backup wallet.dat.backup for emergency recovery
- Consider future recovery mechanism (Shamir secret sharing)

### Risk: Migration Bugs
**Mitigation:**
- Extensive testing (unit + integration)
- Beta testing phase
- Keep wallet.dat.backup for rollback
- Clear error messages

### Risk: Performance Issues
**Mitigation:**
- Benchmark early (Day 13)
- Tune Argon2 parameters if needed
- Document expected delay
- Consider async key derivation for UI responsiveness

### Risk: Cross-Platform Issues
**Mitigation:**
- Test on Linux, macOS, Windows
- Document platform-specific behavior
- Fallback for missing features (e.g., secure delete)

---

## Communication Plan

### Security Advisory Template

```markdown
# Security Advisory: Wallet Encryption (v0.4.1)

**Severity:** Critical
**Affected Versions:** v0.4.0 and earlier
**Fixed In:** v0.4.1

## Vulnerability
Prior to v0.4.1, Neptune Core wallet seeds were stored unencrypted on disk.
Any malware or user with file read access could steal funds.

## Fix
v0.4.1 introduces wallet encryption using Argon2id + AES-256-GCM.
Existing wallets are automatically migrated on startup.

## Action Required
1. Update to v0.4.1
2. Start neptune-core (migration happens automatically)
3. Choose a strong password (12+ characters)
4. Write down your password (cannot be recovered!)

## Timeline
- Disclosure: [Date]
- Patch Released: [Date]
- Recommended Update By: [Date + 7 days]
```

---

## Next Steps

1. **Review this plan** - Adjustments needed?
2. **Approve timeline** - 2-3 weeks realistic?
3. **Assign resources** - Solo or team effort?
4. **Start Day 1** - Add dependencies + module structure

---

**Status:** ✅ Ready to implement
**Estimated Completion:** ~15 working days (3 weeks)
**Priority:** CRITICAL

**Let's fast-track this and protect our users! 🔐**

