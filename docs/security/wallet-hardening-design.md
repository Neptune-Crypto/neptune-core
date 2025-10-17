# Wallet Security Hardening - Design Document

**Branch:** `feature/wallet-security-hardening`
**Status:** Planning Phase
**Priority:** Critical
**Target Release:** v0.3.0

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Architecture Overview](#architecture-overview)
3. [Phase 1: Wallet Encryption](#phase-1-wallet-encryption)
4. [Phase 2: Data Directory Decoupling](#phase-2-data-directory-decoupling)
5. [Phase 3: Windows Security](#phase-3-windows-security)
6. [Implementation Plan](#implementation-plan)
7. [Testing Strategy](#testing-strategy)
8. [Migration & Backwards Compatibility](#migration--backwards-compatibility)
9. [Performance Considerations](#performance-considerations)
10. [Security Audit Checklist](#security-audit-checklist)

---

## Executive Summary

This document outlines the design and implementation plan for three critical wallet security enhancements:

1. **Wallet Encryption at Rest** - Password-based encryption for wallet seed and database
2. **Data Directory Decoupling** - Separation of wallet and blockchain data
3. **Windows File Security** - Proper ACL-based file permissions for Windows

**Goals:**
- ✅ Protect wallet seed from file-system level attacks
- ✅ Enable encrypted backups and cloud storage
- ✅ Separate wallet data (small, critical) from blockchain data (large, replaceable)
- ✅ Achieve parity between Unix and Windows security
- ✅ Maintain backwards compatibility with existing wallets

---

## Architecture Overview

### Current Architecture (Problematic)

```
~/.config/neptune/core/main/
├── wallet/
│   ├── wallet.dat                    # ❌ Plaintext JSON
│   ├── incoming_randomness.dat       # ❌ Plaintext append-only
│   └── outgoing_randomness.dat       # ❌ Plaintext append-only
└── database/                         # ❌ Tightly coupled
    ├── wallet/                       # Wallet DB (LevelDB)
    ├── block_index/                  # Blockchain DB
    ├── mutator_set/                  # Blockchain DB
    └── ...
```

### Proposed Architecture (Hardened)

```
# Wallet Directory (encrypted, small, critical)
~/.config/neptune/wallet/main/
├── wallet.encrypted                  # ✅ Encrypted with Argon2 + AES-256-GCM
├── wallet_metadata.json              # ✅ Public metadata (version, salt, nonce)
├── database/
│   └── wallet/                       # ✅ Encrypted LevelDB wrapper
└── secrets/                          # ✅ Encrypted randomness files
    ├── incoming_randomness.encrypted
    └── outgoing_randomness.encrypted

# Blockchain Directory (not encrypted, large, replaceable)
~/.local/share/neptune/blockchain/main/
├── database/
│   ├── block_index/
│   ├── mutator_set/
│   ├── archival_block_mmr/
│   └── banned_ips/
└── blocks/
    ├── block_0000.dat
    └── ...
```

**Key Changes:**
- ✅ Wallet and blockchain physically separated
- ✅ Wallet data encrypted with user password
- ✅ Wallet directory ~10 MB vs blockchain ~200+ GB
- ✅ Different backup/retention policies per directory
- ✅ Can mount wallet on encrypted volume separately

---

## Phase 1: Wallet Encryption

### 1.1 Encryption System Design

#### **Encryption Stack**

```
User Password (UTF-8)
    ↓
Argon2id (memory-hard KDF, 256 MB RAM, 4 iterations)
    ↓
Master Key (256 bits)
    ↓ (HKDF-SHA256)
    ├─→ Wallet File Encryption Key (256 bits)
    ├─→ Database Encryption Key (256 bits)
    └─→ Secrets Encryption Key (256 bits)
    ↓
AES-256-GCM (authenticated encryption)
    ↓
Ciphertext + Authentication Tag
```

**Why Argon2id?**
- Memory-hard (resists GPU/ASIC attacks)
- Winner of Password Hashing Competition (2015)
- Configurable memory/time cost
- Side-channel resistant

**Why AES-256-GCM?**
- Authenticated encryption (confidentiality + integrity)
- Hardware acceleration (AES-NI on modern CPUs)
- Nonce-misuse resistant variant (GCM-SIV) for database
- NIST approved

#### **File Format: Encrypted Wallet**

```rust
/// On-disk format for encrypted wallet file
#[derive(Serialize, Deserialize)]
pub struct EncryptedWalletFile {
    /// Format version for future migrations
    version: u8,
    
    /// Encryption algorithm identifier
    algorithm: EncryptionAlgorithm,  // "argon2id-aes256gcm"
    
    /// Argon2 parameters
    kdf_params: Argon2Params {
        memory_cost_kib: u32,  // 256 * 1024 (256 MB)
        time_cost: u32,        // 4 iterations
        parallelism: u32,      // Number of threads
        salt: [u8; 32],        // Random salt
    },
    
    /// AES-GCM parameters
    cipher_params: AesGcmParams {
        nonce: [u8; 12],       // Random nonce (96 bits)
    },
    
    /// Encrypted wallet data
    ciphertext: Vec<u8>,
    
    /// Authentication tag (128 bits)
    auth_tag: [u8; 16],
    
    /// Optional: backup encryption with different password
    backup_ciphertext: Option<Vec<u8>>,
    backup_auth_tag: Option<[u8; 16]>,
    backup_nonce: Option<[u8; 12]>,
}

/// Plaintext wallet data (encrypted)
#[derive(Serialize, Deserialize)]
pub struct WalletFile {
    name: String,
    secret_seed: SecretKeyMaterial,  // XFieldElement (192 bits)
    version: u8,
    
    /// New: timestamp for key rotation tracking
    created_at: SystemTime,
    last_key_rotation: SystemTime,
}
```

#### **Metadata File (Public, Not Encrypted)**

```json
{
  "version": 1,
  "wallet_type": "encrypted",
  "encryption_algorithm": "argon2id-aes256gcm",
  "created_at": "2025-10-16T12:00:00Z",
  "wallet_id": "a1b2c3d4...",  // Hash of public key, for identification
  "network": "main",
  "requires_password": true,
  "backup_enabled": false
}
```

### 1.2 Key Derivation & Management

#### **Master Key Derivation**

```rust
use argon2::{Argon2, ParamsBuilder, Version};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

pub struct WalletKeyManager {
    master_key: Zeroizing<[u8; 32]>,  // Zeroed on drop
}

impl WalletKeyManager {
    /// Derive master key from password
    pub fn from_password(password: &str, salt: &[u8; 32]) -> Result<Self> {
        let mut master_key = Zeroizing::new([0u8; 32]);
        
        let params = ParamsBuilder::new()
            .m_cost(256 * 1024)  // 256 MB RAM
            .t_cost(4)           // 4 iterations
            .p_cost(4)           // 4 parallel threads
            .build()
            .map_err(|e| anyhow!("Invalid Argon2 params: {}", e))?;
        
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            Version::V0x13,
            params,
        );
        
        argon2.hash_password_into(
            password.as_bytes(),
            salt,
            &mut *master_key,
        )?;
        
        Ok(Self { master_key })
    }
    
    /// Derive sub-keys using HKDF
    pub fn derive_wallet_key(&self) -> Zeroizing<[u8; 32]> {
        let hkdf = Hkdf::<Sha256>::new(None, &*self.master_key);
        let mut key = Zeroizing::new([0u8; 32]);
        hkdf.expand(b"neptune-wallet-encryption-v1", &mut *key)
            .expect("HKDF expand failed");
        key
    }
    
    pub fn derive_database_key(&self) -> Zeroizing<[u8; 32]> {
        let hkdf = Hkdf::<Sha256>::new(None, &*self.master_key);
        let mut key = Zeroizing::new([0u8; 32]);
        hkdf.expand(b"neptune-database-encryption-v1", &mut *key)
            .expect("HKDF expand failed");
        key
    }
    
    pub fn derive_secrets_key(&self) -> Zeroizing<[u8; 32]> {
        let hkdf = Hkdf::<Sha256>::new(None, &*self.master_key);
        let mut key = Zeroizing::new([0u8; 32]);
        hkdf.expand(b"neptune-secrets-encryption-v1", &mut *key)
            .expect("HKDF expand failed");
        key
    }
}
```

#### **Encryption/Decryption Implementation**

```rust
pub struct WalletEncryption {
    key_manager: WalletKeyManager,
}

impl WalletEncryption {
    pub fn encrypt_wallet(&self, wallet: &WalletFile) -> Result<EncryptedWalletFile> {
        // 1. Serialize wallet
        let plaintext = bincode::serialize(wallet)?;
        
        // 2. Generate random salt and nonce
        let salt = generate_random_salt();
        let nonce_bytes = generate_random_nonce();
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // 3. Derive encryption key
        let encryption_key = self.key_manager.derive_wallet_key();
        let cipher = Aes256Gcm::new_from_slice(&*encryption_key)?;
        
        // 4. Encrypt
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;
        
        // 5. Split ciphertext and auth tag
        let (ct, tag) = ciphertext.split_at(ciphertext.len() - 16);
        let auth_tag: [u8; 16] = tag.try_into()?;
        
        Ok(EncryptedWalletFile {
            version: 1,
            algorithm: EncryptionAlgorithm::Argon2idAes256Gcm,
            kdf_params: Argon2Params { /* ... */ },
            cipher_params: AesGcmParams { nonce: nonce_bytes },
            ciphertext: ct.to_vec(),
            auth_tag,
            backup_ciphertext: None,
            backup_auth_tag: None,
            backup_nonce: None,
        })
    }
    
    pub fn decrypt_wallet(&self, encrypted: &EncryptedWalletFile) -> Result<WalletFile> {
        // 1. Verify version and algorithm
        if encrypted.version != 1 {
            anyhow::bail!("Unsupported wallet version: {}", encrypted.version);
        }
        
        // 2. Derive decryption key
        let decryption_key = self.key_manager.derive_wallet_key();
        let cipher = Aes256Gcm::new_from_slice(&*decryption_key)?;
        
        // 3. Reconstruct ciphertext with auth tag
        let mut full_ciphertext = encrypted.ciphertext.clone();
        full_ciphertext.extend_from_slice(&encrypted.auth_tag);
        
        // 4. Decrypt
        let nonce = Nonce::from_slice(&encrypted.cipher_params.nonce);
        let plaintext = cipher.decrypt(nonce, full_ciphertext.as_ref())
            .map_err(|e| anyhow!("Decryption failed (wrong password?): {}", e))?;
        
        // 5. Deserialize
        let wallet: WalletFile = bincode::deserialize(&plaintext)?;
        Ok(wallet)
    }
}
```

### 1.3 Password Management

#### **Password Input Methods**

```rust
pub enum PasswordSource {
    /// Interactive prompt (default)
    Interactive,
    
    /// Environment variable (CI/automation)
    Environment(String),
    
    /// File containing password (0600 permissions required)
    File(PathBuf),
    
    /// OS keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service)
    Keychain,
    
    /// Hardware security module / YubiKey
    Hardware,
}

pub struct PasswordManager {
    source: PasswordSource,
}

impl PasswordManager {
    pub fn get_password(&self) -> Result<Zeroizing<String>> {
        match &self.source {
            PasswordSource::Interactive => {
                self.prompt_password()
            }
            PasswordSource::Environment(var_name) => {
                self.read_from_env(var_name)
            }
            PasswordSource::File(path) => {
                self.read_from_file(path)
            }
            PasswordSource::Keychain => {
                self.read_from_keychain()
            }
            PasswordSource::Hardware => {
                self.read_from_hardware()
            }
        }
    }
    
    fn prompt_password(&self) -> Result<Zeroizing<String>> {
        use rpassword::prompt_password;
        
        let password = prompt_password("Enter wallet password: ")?;
        
        // Verify password strength
        if password.len() < 12 {
            warn!("⚠️  Password is weak (< 12 characters). Consider a stronger password.");
        }
        
        Ok(Zeroizing::new(password))
    }
    
    fn read_from_keychain(&self) -> Result<Zeroizing<String>> {
        #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
        {
            use keyring::Entry;
            let entry = Entry::new("neptune-core", "wallet-password")?;
            let password = entry.get_password()?;
            Ok(Zeroizing::new(password))
        }
        
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        {
            anyhow::bail!("Keychain not supported on this platform")
        }
    }
}
```

#### **Password Strength Validation**

```rust
pub struct PasswordValidator;

impl PasswordValidator {
    pub fn validate(password: &str) -> PasswordStrength {
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
```

### 1.4 Database Encryption Wrapper

```rust
use aes_gcm_siv::Aes256GcmSiv;  // Nonce-misuse resistant
use rusty_leveldb::{DB, Options};

pub struct EncryptedLevelDB {
    inner: DB,
    cipher: Aes256GcmSiv,
}

impl EncryptedLevelDB {
    pub fn open(path: &Path, encryption_key: &[u8; 32]) -> Result<Self> {
        let mut opts = Options::default();
        opts.create_if_missing = true;
        
        let inner = DB::open(path, opts)?;
        let cipher = Aes256GcmSiv::new_from_slice(encryption_key)?;
        
        Ok(Self { inner, cipher })
    }
    
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let encrypted = self.inner.get(key);
        
        match encrypted {
            Some(ciphertext) => {
                let plaintext = self.decrypt(&ciphertext)?;
                Ok(Some(plaintext))
            }
            None => Ok(None),
        }
    }
    
    pub fn put(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        let ciphertext = self.encrypt(value)?;
        self.inner.put(key, &ciphertext)?;
        Ok(())
    }
    
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        // Generate deterministic nonce from key (safe with AES-GCM-SIV)
        let nonce = self.derive_nonce(plaintext);
        
        self.cipher.encrypt(&nonce, plaintext)
            .map_err(|e| anyhow!("Encryption failed: {}", e))
    }
    
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.derive_nonce(ciphertext);
        
        self.cipher.decrypt(&nonce, ciphertext)
            .map_err(|e| anyhow!("Decryption failed: {}", e))
    }
    
    fn derive_nonce(&self, data: &[u8]) -> Nonce {
        // Derive deterministic nonce from data hash
        use sha2::{Sha256, Digest};
        let hash = Sha256::digest(data);
        Nonce::from_slice(&hash[..12])
    }
}
```

---

## Phase 2: Data Directory Decoupling

### 2.1 New Directory Structure

```rust
pub struct DataDirectoryV2 {
    /// Wallet directory (small, encrypted, critical)
    /// Default: ~/.config/neptune/wallet/<network>/
    wallet_root: PathBuf,
    
    /// Blockchain directory (large, unencrypted, replaceable)
    /// Default: ~/.local/share/neptune/blockchain/<network>/
    blockchain_root: PathBuf,
    
    /// Network (main, testnet, etc.)
    network: Network,
}

impl DataDirectoryV2 {
    pub fn new(
        wallet_dir: Option<PathBuf>,
        blockchain_dir: Option<PathBuf>,
        network: Network,
    ) -> Result<Self> {
        let wallet_root = wallet_dir.unwrap_or_else(|| {
            Self::default_wallet_directory(network)
        });
        
        let blockchain_root = blockchain_dir.unwrap_or_else(|| {
            Self::default_blockchain_directory(network)
        });
        
        Ok(Self {
            wallet_root,
            blockchain_root,
            network,
        })
    }
    
    fn default_wallet_directory(network: Network) -> PathBuf {
        let project_dirs = ProjectDirs::from("org", "neptune", "neptune")
            .expect("Could not determine config directory");
        
        // ~/.config/neptune/wallet/<network>/
        project_dirs.config_dir()
            .join("wallet")
            .join(network.to_string())
    }
    
    fn default_blockchain_directory(network: Network) -> PathBuf {
        let project_dirs = ProjectDirs::from("org", "neptune", "neptune")
            .expect("Could not determine data directory");
        
        // ~/.local/share/neptune/blockchain/<network>/
        project_dirs.data_dir()
            .join("blockchain")
            .join(network.to_string())
    }
    
    // Wallet paths
    pub fn wallet_file_path(&self) -> PathBuf {
        self.wallet_root.join("wallet.encrypted")
    }
    
    pub fn wallet_metadata_path(&self) -> PathBuf {
        self.wallet_root.join("wallet_metadata.json")
    }
    
    pub fn wallet_database_dir(&self) -> PathBuf {
        self.wallet_root.join("database")
    }
    
    pub fn wallet_secrets_dir(&self) -> PathBuf {
        self.wallet_root.join("secrets")
    }
    
    // Blockchain paths
    pub fn block_index_database_dir(&self) -> PathBuf {
        self.blockchain_root.join("database").join("block_index")
    }
    
    pub fn mutator_set_database_dir(&self) -> PathBuf {
        self.blockchain_root.join("database").join("mutator_set")
    }
    
    pub fn blocks_dir(&self) -> PathBuf {
        self.blockchain_root.join("blocks")
    }
}
```

### 2.2 Migration Strategy

```rust
pub struct DataDirectoryMigrator {
    old_layout: DataDirectory,      // Current layout
    new_layout: DataDirectoryV2,    // Target layout
}

impl DataDirectoryMigrator {
    pub async fn migrate(&self) -> Result<()> {
        info!("🔄 Starting data directory migration...");
        
        // Step 1: Detect old layout
        if !self.old_layout.root_dir_path().exists() {
            info!("✅ No old wallet found, nothing to migrate");
            return Ok(());
        }
        
        // Step 2: Create new directories
        self.create_new_directories().await?;
        
        // Step 3: Migrate wallet files
        info!("📁 Migrating wallet files...");
        self.migrate_wallet_files().await?;
        
        // Step 4: Migrate wallet database
        info!("💾 Migrating wallet database...");
        self.migrate_wallet_database().await?;
        
        // Step 5: Link blockchain data (no need to move)
        info!("🔗 Linking blockchain data...");
        self.link_blockchain_data().await?;
        
        // Step 6: Create migration marker
        self.create_migration_marker().await?;
        
        info!("✅ Migration complete!");
        info!("📍 Old wallet: {}", self.old_layout.root_dir_path().display());
        info!("📍 New wallet: {}", self.new_layout.wallet_root.display());
        info!("📍 Blockchain: {}", self.new_layout.blockchain_root.display());
        
        Ok(())
    }
    
    async fn migrate_wallet_files(&self) -> Result<()> {
        // Read old wallet
        let old_wallet_path = self.old_layout.wallet_directory_path()
            .join("wallet.dat");
        
        if !old_wallet_path.exists() {
            anyhow::bail!("Old wallet file not found: {}", old_wallet_path.display());
        }
        
        let wallet_file = WalletFile::read_from_file(&old_wallet_path)?;
        
        // Prompt for encryption password
        let password_manager = PasswordManager::new(PasswordSource::Interactive);
        let password = password_manager.get_password()?;
        
        // Encrypt and save
        let key_manager = WalletKeyManager::from_password(&password, &generate_random_salt())?;
        let encryption = WalletEncryption { key_manager };
        let encrypted = encryption.encrypt_wallet(&wallet_file)?;
        
        // Write encrypted wallet
        let new_wallet_path = self.new_layout.wallet_file_path();
        let encrypted_json = serde_json::to_string_pretty(&encrypted)?;
        tokio::fs::write(&new_wallet_path, encrypted_json).await?;
        
        // Set restrictive permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            tokio::fs::set_permissions(&new_wallet_path, perms).await?;
        }
        
        info!("✅ Wallet file migrated and encrypted");
        Ok(())
    }
    
    async fn migrate_wallet_database(&self) -> Result<()> {
        // Copy wallet database from old location to new
        let old_db = self.old_layout.wallet_database_dir_path();
        let new_db = self.new_layout.wallet_database_dir();
        
        if old_db.exists() {
            copy_dir_recursive(&old_db, &new_db).await?;
            info!("✅ Wallet database copied to new location");
        }
        
        Ok(())
    }
    
    async fn link_blockchain_data(&self) -> Result<()> {
        // Option 1: Symlink (fast, requires symlink support)
        // Option 2: Move data (slow, but works everywhere)
        // Option 3: Keep in place, update paths (backwards compat)
        
        // For now, use symlink with fallback to move
        let old_blockchain = self.old_layout.database_dir_path();
        let new_blockchain = self.new_layout.blockchain_root.join("database");
        
        #[cfg(unix)]
        {
            if let Err(e) = tokio::fs::symlink(&old_blockchain, &new_blockchain).await {
                warn!("⚠️  Could not create symlink, moving data: {}", e);
                move_dir_recursive(&old_blockchain, &new_blockchain).await?;
            }
        }
        
        #[cfg(not(unix))]
        {
            move_dir_recursive(&old_blockchain, &new_blockchain).await?;
        }
        
        Ok(())
    }
}
```

### 2.3 CLI Arguments

```rust
#[derive(Parser, Debug)]
pub struct Args {
    // Existing args...
    
    /// Wallet directory (overrides default)
    #[arg(long, value_name = "DIR")]
    pub wallet_dir: Option<PathBuf>,
    
    /// Blockchain data directory (overrides default)
    #[arg(long, value_name = "DIR")]
    pub blockchain_dir: Option<PathBuf>,
    
    /// Wallet password (for automation, not recommended for interactive use)
    #[arg(long, env = "NEPTUNE_WALLET_PASSWORD")]
    pub wallet_password: Option<String>,
    
    /// Password source (interactive, env, file, keychain)
    #[arg(long, default_value = "interactive")]
    pub password_source: PasswordSourceArg,
    
    /// Auto-migrate old wallet layout (no prompt)
    #[arg(long)]
    pub auto_migrate: bool,
}
```

---

## Phase 3: Windows Security

### 3.1 Windows ACL Implementation

```rust
#[cfg(windows)]
mod windows_security {
    use windows::Win32::Foundation::*;
    use windows::Win32::Security::*;
    use windows::Win32::Storage::FileSystem::*;
    
    pub fn create_wallet_file_secure(
        path: &Path,
        content: &[u8],
    ) -> Result<()> {
        // 1. Get current user SID
        let user_sid = get_current_user_sid()?;
        
        // 2. Create security descriptor
        let sd = create_security_descriptor_owner_only(&user_sid)?;
        
        // 3. Create file with security attributes
        let path_wide = to_wide_string(path);
        
        let mut sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.as_ptr() as *mut _,
            bInheritHandle: FALSE,
        };
        
        let handle = unsafe {
            CreateFileW(
                path_wide.as_ptr(),
                FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                FILE_SHARE_NONE,  // No sharing
                Some(&mut sa),
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                HANDLE::default(),
            )?
        };
        
        // 4. Write content
        let mut bytes_written = 0u32;
        unsafe {
            WriteFile(
                handle,
                Some(content),
                Some(&mut bytes_written),
                None,
            )?;
        }
        
        // 5. Close handle
        unsafe { CloseHandle(handle)?; }
        
        Ok(())
    }
    
    fn get_current_user_sid() -> Result<Vec<u8>> {
        // Implementation using GetTokenInformation
        // ...
    }
    
    fn create_security_descriptor_owner_only(sid: &[u8]) -> Result<Vec<u8>> {
        // Create ACL that grants access only to owner
        // ...
    }
}
```

---

## Implementation Plan

### Timeline (Estimated)

| Phase | Task | Duration | Dependencies |
|-------|------|----------|--------------|
| **1A** | Encryption system architecture | 2 days | - |
| **1B** | Password management & validation | 2 days | 1A |
| **1C** | Wallet file encryption implementation | 3 days | 1B |
| **1D** | Database encryption wrapper | 3 days | 1C |
| **1E** | Keychain integration | 3 days | 1B |
| **2A** | Data directory refactoring | 2 days | - |
| **2B** | Migration tool | 4 days | 1C, 2A |
| **2C** | CLI arguments & flags | 2 days | 2A |
| **3A** | Windows ACL implementation | 3 days | - |
| **4A** | Unit tests (encryption) | 3 days | 1D |
| **4B** | Integration tests (migration) | 3 days | 2B |
| **4C** | End-to-end tests | 2 days | All |
| **5A** | Documentation | 2 days | All |
| **5B** | Security audit | 3 days | All |

**Total Estimated Duration:** ~35 days (7 weeks)

### Development Phases

#### **Week 1-2: Encryption System**
- [ ] Implement `WalletKeyManager`
- [ ] Implement `WalletEncryption`
- [ ] Implement `PasswordManager`
- [ ] Unit tests for encryption/decryption
- [ ] Benchmark encryption overhead

#### **Week 3-4: Database & Secrets**
- [ ] Implement `EncryptedLevelDB`
- [ ] Encrypt randomness files
- [ ] Keychain integration (macOS, Linux, Windows)
- [ ] Integration tests

#### **Week 5-6: Data Directory Decoupling**
- [ ] Refactor `DataDirectory` → `DataDirectoryV2`
- [ ] Implement migration tool
- [ ] CLI argument parsing
- [ ] Migration tests

#### **Week 7: Windows & Finalization**
- [ ] Windows ACL implementation
- [ ] End-to-end testing
- [ ] Documentation
- [ ] Security audit

---

## Testing Strategy

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_password_derivation() {
        let password = "correct-horse-battery-staple";
        let salt = [0u8; 32];
        
        let km1 = WalletKeyManager::from_password(password, &salt).unwrap();
        let km2 = WalletKeyManager::from_password(password, &salt).unwrap();
        
        // Same password + salt = same key
        assert_eq!(km1.derive_wallet_key(), km2.derive_wallet_key());
    }
    
    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let wallet = WalletFile::new_random();
        let password = "test-password-123";
        let salt = generate_random_salt();
        
        let key_manager = WalletKeyManager::from_password(password, &salt).unwrap();
        let encryption = WalletEncryption { key_manager };
        
        let encrypted = encryption.encrypt_wallet(&wallet).unwrap();
        let decrypted = encryption.decrypt_wallet(&encrypted).unwrap();
        
        assert_eq!(wallet, decrypted);
    }
    
    #[test]
    fn test_wrong_password_fails() {
        let wallet = WalletFile::new_random();
        let salt = generate_random_salt();
        
        let km1 = WalletKeyManager::from_password("password1", &salt).unwrap();
        let enc1 = WalletEncryption { key_manager: km1 };
        let encrypted = enc1.encrypt_wallet(&wallet).unwrap();
        
        let km2 = WalletKeyManager::from_password("password2", &salt).unwrap();
        let enc2 = WalletEncryption { key_manager: km2 };
        
        // Wrong password should fail
        assert!(enc2.decrypt_wallet(&encrypted).is_err());
    }
    
    #[test]
    fn test_password_strength() {
        assert_eq!(
            PasswordValidator::validate("weak"),
            PasswordStrength::VeryWeak
        );
        
        assert_eq!(
            PasswordValidator::validate("Correct-Horse-Battery-Staple-2025!"),
            PasswordStrength::VeryStrong
        );
    }
}
```

### Integration Tests

```rust
#[tokio::test]
async fn test_full_wallet_lifecycle() {
    let temp_dir = tempdir().unwrap();
    let password = "test-password";
    
    // 1. Create encrypted wallet
    let wallet = WalletFile::new_random();
    let wallet_path = temp_dir.path().join("wallet.encrypted");
    
    // ... create and save encrypted wallet
    
    // 2. Load wallet with correct password
    let loaded = load_encrypted_wallet(&wallet_path, password).await.unwrap();
    assert_eq!(wallet.secret_seed, loaded.secret_seed);
    
    // 3. Attempt load with wrong password (should fail)
    assert!(load_encrypted_wallet(&wallet_path, "wrong").await.is_err());
}

#[tokio::test]
async fn test_migration_old_to_new() {
    // Create old-layout wallet
    let old_dir = create_old_layout_wallet().await;
    
    // Run migration
    let new_dir = tempdir().unwrap();
    let migrator = DataDirectoryMigrator::new(old_dir.path(), new_dir.path());
    migrator.migrate().await.unwrap();
    
    // Verify new layout exists and is encrypted
    assert!(new_dir.path().join("wallet/wallet.encrypted").exists());
    assert!(new_dir.path().join("blockchain/database").exists());
}
```

---

## Migration & Backwards Compatibility

### Compatibility Matrix

| Old Version | New Version | Auto-Migrate | Manual Steps |
|-------------|-------------|--------------|--------------|
| v0.2.x (plaintext) | v0.3.x (encrypted) | ✅ Yes | Prompt for password |
| v0.1.x (very old) | v0.3.x (encrypted) | ⚠️ Partial | Manual export/import |

### Migration Workflow

```
Old wallet detected
    ↓
Prompt user: "Encrypt wallet? (Recommended)"
    ↓ [Yes]
Prompt for password (with strength indicator)
    ↓
Confirm password
    ↓
Encrypt wallet file
    ↓
Migrate to new directory structure
    ↓
Verify migration success
    ↓
Backup old wallet (encrypted)
    ↓
Update config to use new paths
    ↓
Complete ✅
```

### Rollback Strategy

```rust
pub struct MigrationBackup {
    backup_path: PathBuf,
    timestamp: SystemTime,
}

impl MigrationBackup {
    pub fn create(old_layout: &DataDirectory) -> Result<Self> {
        let timestamp = SystemTime::now();
        let backup_path = old_layout.root_dir_path()
            .parent()
            .unwrap()
            .join(format!("wallet_backup_{}", timestamp_to_string(timestamp)));
        
        // Copy entire old directory
        copy_dir_recursive(&old_layout.root_dir_path(), &backup_path)?;
        
        Ok(Self { backup_path, timestamp })
    }
    
    pub fn rollback(&self, target: &Path) -> Result<()> {
        // Restore from backup
        copy_dir_recursive(&self.backup_path, target)?;
        Ok(())
    }
}
```

---

## Performance Considerations

### Encryption Overhead Benchmarks

**Target Performance:**
- Wallet file encryption: < 100ms
- Wallet file decryption: < 100ms
- Database read (encrypted): < 2ms overhead
- Database write (encrypted): < 2ms overhead

**Argon2 Parameters Tuning:**

| Memory (MB) | Time Cost | Iterations/sec | Security Level |
|-------------|-----------|----------------|----------------|
| 64 | 2 | ~5/sec | Minimum |
| 256 | 4 | ~1/sec | **Recommended** |
| 512 | 8 | ~0.5/sec | High security |
| 1024 | 16 | ~0.2/sec | Paranoid |

**Recommendation:** 256 MB / 4 iterations (1 second key derivation on modern hardware)

---

## Security Audit Checklist

### Pre-Release Security Review

- [ ] **Cryptographic Primitives**
  - [ ] Argon2id parameters reviewed by cryptographer
  - [ ] AES-256-GCM implementation audit
  - [ ] Random number generation (salt, nonce) uses CSRNG
  - [ ] Key derivation (HKDF) properly implemented

- [ ] **Memory Safety**
  - [ ] Secrets zeroized on drop (`Zeroizing<T>`)
  - [ ] No secrets in logs/debug output
  - [ ] No secrets on heap without protection
  - [ ] Core dumps disabled for wallet process

- [ ] **File System Security**
  - [ ] Unix permissions (0600) verified
  - [ ] Windows ACLs properly configured
  - [ ] Temporary files securely deleted
  - [ ] Migration backups encrypted

- [ ] **Attack Resistance**
  - [ ] Timing attack resistance (constant-time comparisons)
  - [ ] Side-channel resistance (Argon2id)
  - [ ] Brute-force resistance (password strength validation)
  - [ ] Replay attack resistance (nonces)

- [ ] **Implementation Quality**
  - [ ] No panics in production code
  - [ ] All errors properly handled
  - [ ] Comprehensive test coverage (>80%)
  - [ ] Fuzz testing for encryption/decryption

---

## Next Steps

1. **Review this design document** with team/community
2. **Get feedback** on architecture decisions
3. **Prioritize** which features to implement first
4. **Create GitHub issues** for each task
5. **Start implementation** of Phase 1A (encryption system)

---

**Document Status:** ✅ Complete - Ready for Review
**Last Updated:** 2025-10-16
**Authors:** Sea of Freedom Security Team

