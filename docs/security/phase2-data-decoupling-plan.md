# Phase 2: Data Decoupling - Design & Implementation Plan

## Executive Summary

**Goal:** Separate wallet and blockchain data into independent directories to enable:
- Wallet-only backups (without 200+ GB blockchain data)
- Separate encryption and permission policies
- Wallet portability across machines
- Better security isolation

**Status:** Planning Phase
**Prerequisites:** ✅ Phase 1 (Wallet Encryption) Complete
**Compatibility:** ✅ Fully compatible with encrypted wallet system

---

## Table of Contents

1. [Current Architecture Analysis](#1-current-architecture-analysis)
2. [Proposed Architecture](#2-proposed-architecture)
3. [Implementation Strategy](#3-implementation-strategy)
4. [Migration Plan](#4-migration-plan)
5. [Code Changes Required](#5-code-changes-required)
6. [Testing Strategy](#6-testing-strategy)
7. [Risk Assessment](#7-risk-assessment)
8. [Timeline](#8-timeline)

---

## 1. Current Architecture Analysis

### 1.1 Current Directory Structure

```
~/.config/neptune/core/<network>/          # Single monolithic root
├── wallet/                                 # Wallet files (KB-MB range)
│   ├── wallet.encrypted                    # Master seed (encrypted)
│   ├── wallet.dat.backup                   # Migration backup
│   ├── incoming_randomness.dat             # UTXO notification data
│   └── outgoing_randomness.dat             # Sent UTXO data
│
├── database/                               # LevelDB databases (GB range)
│   ├── wallet/                             # ⚠️ Wallet DB (UTXO set, keys)
│   ├── block_index/                        # Block headers
│   ├── mutator_set/                        # Cryptographic accumulator
│   ├── archival_block_mmr/                 # Merkle Mountain Range
│   └── banned_ips/                         # P2P ban list
│
├── blocks/                                 # Block bodies (200+ GB)
│   ├── block_0000.dat
│   ├── block_0001.dat
│   └── ...
│
├── utxo-transfer/                          # Off-chain UTXO transfer files
└── .cookie                                 # RPC authentication cookie
```

### 1.2 Problems with Current Architecture

| Problem | Impact | Severity |
|---------|--------|----------|
| Wallet DB in shared `database/` | Can't backup wallet without blockchain | **HIGH** |
| Single root directory | Can't apply different encryption policies | **HIGH** |
| Wallet files scattered | Harder to secure wallet-only | **MEDIUM** |
| 200+ GB blockchain mixed with wallet | Backup complexity | **HIGH** |
| No separation of concerns | Operational inflexibility | **MEDIUM** |

### 1.3 Code Locations Responsible for Current Structure

**Primary Components:**

1. **`DataDirectory` struct** (`neptune-core/src/application/config/data_directory.rs`)
   - **Lines 29-31**: Single `data_dir: PathBuf` field
   - **Lines 95-217**: Methods that derive all paths from single root
   - **Critical methods:**
     - `root_dir_path()` (line 83)
     - `database_dir_path()` (line 95)
     - `wallet_directory_path()` (line 123)
     - `wallet_database_dir_path()` (line 130) ← **Key issue**

2. **`WalletFileContext`** (`neptune-core/src/state/wallet/wallet_file.rs`)
   - **Lines 134-142**: Stores wallet file paths
   - **Lines 145-164**: Static methods to compute wallet paths
   - **Lines 185-233**: `read_from_file_or_create()` - uses `wallet_directory_path`

3. **`WalletConfiguration`** (`neptune-core/src/state/wallet/wallet_configuration.rs`)
   - **Lines 26**: Holds `data_directory: DataDirectory`
   - **Lines 92-96**: `incoming_secrets_path()` - uses `wallet_directory_path()`
   - **Lines 103-105**: `data_directory()` getter

4. **`WalletState`** (`neptune-core/src/state/wallet/wallet_state.rs`)
   - **Lines 317-318**: Opens wallet DB from `wallet_database_dir_path()`
   - **Lines 260-266**: Reads randomness files from wallet directory

5. **`GlobalState`** (`neptune-core/src/state/mod.rs`)
   - **Lines 636-660**: `try_new()` - initializes all state from single `DataDirectory`
   - **Lines 642-653**: Wallet initialization using `wallet_directory_path()`

6. **CLI Arguments** (`neptune-core/src/application/config/cli_args.rs`)
   - **Lines 42-43**: `--data-dir` flag (single directory only)

---

## 2. Proposed Architecture

### 2.1 New Directory Structure

```
# WALLET DATA (sensitive, ~100 MB max)
~/.config/neptune/wallet/<network>/
├── files/                                  # Wallet secret files
│   ├── wallet.encrypted                    # Master seed (encrypted)
│   ├── incoming_randomness.dat             # UTXO notifications
│   └── outgoing_randomness.dat             # Sent UTXO data
│
├── database/                               # Wallet-specific database
│   └── wallet/                             # UTXO set, keys, sync state
│
└── utxo-transfer/                          # Off-chain transfer files
    └── *.neptune-tx


# BLOCKCHAIN DATA (public, 200+ GB)
~/.local/share/neptune/blockchain/<network>/
├── database/                               # Blockchain databases
│   ├── block_index/                        # Block headers
│   ├── mutator_set/                        # Cryptographic accumulator
│   ├── archival_block_mmr/                 # Merkle Mountain Range
│   └── banned_ips/                         # P2P ban list
│
└── blocks/                                 # Block bodies
    ├── block_0000.dat
    └── ...


# SHARED/NODE DATA (ephemeral, ~1 KB)
~/.config/neptune/core/<network>/
└── .cookie                                 # RPC auth cookie (regenerated)
```

### 2.2 Design Principles

1. **Separation of Concerns:**
   - **Wallet data**: Sensitive, small, needs encryption
   - **Blockchain data**: Public, large, no encryption needed
   - **Node data**: Ephemeral, regenerable

2. **XDG Base Directory Compliance:**
   - **Config** (`~/.config/neptune/`): User-specific configuration and wallet secrets
   - **Data** (`~/.local/share/neptune/`): Application data (blockchain)
   - **Cache** (`~/.cache/neptune/`): Future use for temporary data

3. **Backward Compatibility:**
   - Old layout detection and automatic migration
   - Fallback to old paths if new structure doesn't exist
   - Migration tool for manual upgrades

4. **Security Benefits:**
   - Wallet directory can be on encrypted volume
   - Different backup policies (hourly wallet, weekly blockchain)
   - Easier to secure wallet-only (restrictive permissions)
   - Blockchain can be pruned without wallet risk

---

## 3. Implementation Strategy

### 3.1 New `DataDirectory` Structure

**Current:**
```rust
pub struct DataDirectory {
    data_dir: PathBuf,  // Single root for everything
}
```

**Proposed:**
```rust
pub struct DataDirectory {
    wallet_root: PathBuf,      // ~/.config/neptune/wallet/<network>/
    blockchain_root: PathBuf,  // ~/.local/share/neptune/blockchain/<network>/
    node_root: PathBuf,        // ~/.config/neptune/core/<network>/
    
    /// Legacy mode: if true, use old monolithic structure
    legacy_mode: bool,
}
```

### 3.2 Path Resolution Logic

**Priority order for initialization:**

1. **Check CLI flags:**
   - `--wallet-dir <path>` → Use explicit wallet directory
   - `--blockchain-dir <path>` → Use explicit blockchain directory
   - `--data-dir <path>` → Use legacy monolithic structure

2. **Check new structure:**
   - If `~/.config/neptune/wallet/<network>/files/wallet.encrypted` exists → Use new structure

3. **Check old structure:**
   - If `~/.config/neptune/core/<network>/wallet/wallet.encrypted` exists → Use legacy mode

4. **Default (new installation):**
   - Use new separated structure

### 3.3 Integration with Encrypted Wallet System

**✅ No changes needed to wallet encryption:**
- `EncryptedWalletFile` is location-agnostic
- `PasswordManager` works anywhere
- `WalletFileContext` just needs updated path calculation

**Key integration points:**

```rust
// In wallet_file.rs
impl WalletFileContext {
    pub fn read_from_file_or_create(
        wallet_directory_path: &Path,  // ← Can be anywhere now
        cli_password: Option<&str>,
        allow_interactive: bool,
    ) -> Result<Self> {
        // Encryption logic unchanged - just reads from new path
        let encrypted_path = Self::wallet_encrypted_path(wallet_directory_path);
        // ... rest of encryption logic is identical
    }
}
```

---

## 4. Migration Plan

### 4.1 Automatic Migration

**Trigger:** First startup with new version detecting old structure.

**Process:**

```
1. Detect old structure:
   - Check for ~/.config/neptune/core/<network>/wallet/wallet.encrypted
   
2. Create new structure:
   - mkdir -p ~/.config/neptune/wallet/<network>/files/
   - mkdir -p ~/.config/neptune/wallet/<network>/database/
   - mkdir -p ~/.local/share/neptune/blockchain/<network>/database/
   - mkdir -p ~/.local/share/neptune/blockchain/<network>/blocks/
   
3. Move wallet data:
   - mv core/<network>/wallet/* → wallet/<network>/files/
   - mv core/<network>/database/wallet/ → wallet/<network>/database/wallet/
   - mv core/<network>/utxo-transfer/ → wallet/<network>/utxo-transfer/
   
4. Move blockchain data:
   - mv core/<network>/database/block_index/ → blockchain/<network>/database/block_index/
   - mv core/<network>/database/mutator_set/ → blockchain/<network>/database/mutator_set/
   - mv core/<network>/database/archival_block_mmr/ → blockchain/<network>/database/
   - mv core/<network>/database/banned_ips/ → blockchain/<network>/database/banned_ips/
   - mv core/<network>/blocks/ → blockchain/<network>/blocks/
   
5. Create marker file:
   - touch core/<network>/.migrated_to_v2
   
6. Symlinks for backward compat (optional):
   - ln -s ../../wallet/<network>/files/ core/<network>/wallet
   - ln -s ../../../.local/share/neptune/blockchain/<network>/ core/<network>/database
```

**Safety measures:**
- Backup entire old directory before migration
- Atomic operations (move, not copy+delete)
- Rollback capability if migration fails
- Clear user messaging about what's happening

### 4.2 Manual Migration Tool

```bash
neptune-cli migrate-data-layout \
  --from ~/.config/neptune/core/main \
  --wallet-to ~/.config/neptune/wallet/main \
  --blockchain-to ~/.local/share/neptune/blockchain/main \
  --backup-to ~/neptune-migration-backup-$(date +%Y%m%d)
```

### 4.3 Migration Verification

**Checklist after migration:**
- [ ] `wallet.encrypted` is accessible
- [ ] Wallet DB can be opened
- [ ] Block index DB can be opened
- [ ] Mutator set DB can be opened
- [ ] Latest block can be loaded
- [ ] Wallet balance matches pre-migration
- [ ] Old directory backed up
- [ ] Disk space freed from old location (after verification)

---

## 5. Code Changes Required

### 5.1 Core Struct Changes

#### **File: `neptune-core/src/application/config/data_directory.rs`**

**Changes:**

```rust
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DataDirectory {
    // NEW: Separate roots for each data category
    wallet_root: PathBuf,
    blockchain_root: PathBuf,
    node_root: PathBuf,
    
    // NEW: Track if we're in legacy mode for backward compat
    legacy_mode: bool,
}

impl DataDirectory {
    /// Create a DataDirectory with separate wallet/blockchain roots (new layout)
    pub fn get_separated(
        wallet_root: Option<PathBuf>,
        blockchain_root: Option<PathBuf>,
        network: Network,
    ) -> Result<Self> {
        // Default to XDG-compliant paths
        let wallet_root = wallet_root.unwrap_or_else(|| {
            Self::default_wallet_root(network)
        });
        
        let blockchain_root = blockchain_root.unwrap_or_else(|| {
            Self::default_blockchain_root(network)
        });
        
        let node_root = Self::default_node_root(network);
        
        Ok(DataDirectory {
            wallet_root,
            blockchain_root,
            node_root,
            legacy_mode: false,
        })
    }
    
    /// Create a DataDirectory with legacy monolithic structure (backward compat)
    pub fn get_legacy(root_dir: Option<PathBuf>, network: Network) -> Result<Self> {
        let project_dirs = root_dir
            .map(ProjectDirs::from_path)
            .unwrap_or_else(|| ProjectDirs::from("org", "neptune", "neptune"))
            .context("Could not determine data directory")?;

        let network_dir = network.to_string();
        let network_path = Path::new(&network_dir);
        let data_dir = project_dirs.data_dir().to_path_buf().join(network_path);
        
        Ok(DataDirectory {
            wallet_root: data_dir.clone(),
            blockchain_root: data_dir.clone(),
            node_root: data_dir,
            legacy_mode: true,
        })
    }
    
    /// Smart constructor: detects layout and chooses appropriate mode
    pub fn get(
        root_dir: Option<PathBuf>,
        wallet_dir: Option<PathBuf>,
        blockchain_dir: Option<PathBuf>,
        network: Network,
    ) -> Result<Self> {
        // Priority 1: Explicit CLI flags
        if wallet_dir.is_some() || blockchain_dir.is_some() {
            return Self::get_separated(wallet_dir, blockchain_dir, network);
        }
        
        // Priority 2: Explicit legacy flag
        if let Some(root) = root_dir {
            return Self::get_legacy(Some(root), network);
        }
        
        // Priority 3: Auto-detect existing structure
        let default_wallet = Self::default_wallet_root(network);
        let default_legacy = Self::default_legacy_root(network);
        
        if Self::has_new_structure(&default_wallet) {
            // New structure detected
            Self::get_separated(None, None, network)
        } else if Self::has_old_structure(&default_legacy) {
            // Old structure detected - use legacy mode
            Self::get_legacy(None, network)
        } else {
            // Fresh install - use new structure
            Self::get_separated(None, None, network)
        }
    }
    
    /// Default wallet root: ~/.config/neptune/wallet/<network>/
    fn default_wallet_root(network: Network) -> PathBuf {
        ProjectDirs::from("org", "neptune", "neptune")
            .unwrap()
            .config_dir()
            .join("wallet")
            .join(network.to_string())
    }
    
    /// Default blockchain root: ~/.local/share/neptune/blockchain/<network>/
    fn default_blockchain_root(network: Network) -> PathBuf {
        ProjectDirs::from("org", "neptune", "neptune")
            .unwrap()
            .data_dir()
            .join("blockchain")
            .join(network.to_string())
    }
    
    /// Default node root: ~/.config/neptune/core/<network>/
    fn default_node_root(network: Network) -> PathBuf {
        ProjectDirs::from("org", "neptune", "neptune")
            .unwrap()
            .config_dir()
            .join("core")
            .join(network.to_string())
    }
    
    /// Default legacy root: ~/.config/neptune/core/<network>/
    fn default_legacy_root(network: Network) -> PathBuf {
        ProjectDirs::from("org", "neptune", "neptune")
            .unwrap()
            .data_dir()
            .join(network.to_string())
    }
    
    /// Check if new structure exists
    fn has_new_structure(wallet_root: &Path) -> bool {
        wallet_root.join("files").join("wallet.encrypted").exists()
            || wallet_root.join("files").join("wallet.dat").exists()
    }
    
    /// Check if old structure exists
    fn has_old_structure(legacy_root: &Path) -> bool {
        legacy_root.join("wallet").join("wallet.encrypted").exists()
            || legacy_root.join("wallet").join("wallet.dat").exists()
    }
    
    // =========================================================================
    // Path getters - updated to use appropriate root
    // =========================================================================
    
    /// Wallet file directory: <wallet_root>/files/
    pub fn wallet_directory_path(&self) -> PathBuf {
        if self.legacy_mode {
            self.wallet_root.join("wallet")
        } else {
            self.wallet_root.join("files")
        }
    }
    
    /// Wallet database directory: <wallet_root>/database/wallet/
    pub fn wallet_database_dir_path(&self) -> PathBuf {
        if self.legacy_mode {
            self.wallet_root.join("database").join("wallet")
        } else {
            self.wallet_root.join("database").join("wallet")
        }
    }
    
    /// UTXO transfer directory: <wallet_root>/utxo-transfer/
    pub fn utxo_transfer_directory_path(&self) -> PathBuf {
        if self.legacy_mode {
            self.wallet_root.join("utxo-transfer")
        } else {
            self.wallet_root.join("utxo-transfer")
        }
    }
    
    /// Blockchain database root: <blockchain_root>/database/
    pub fn database_dir_path(&self) -> PathBuf {
        self.blockchain_root.join("database")
    }
    
    /// Block bodies directory: <blockchain_root>/blocks/
    pub fn block_dir_path(&self) -> PathBuf {
        self.blockchain_root.join("blocks")
    }
    
    /// Block index database: <blockchain_root>/database/block_index/
    pub fn block_index_database_dir_path(&self) -> PathBuf {
        self.database_dir_path().join("block_index")
    }
    
    /// Mutator set database: <blockchain_root>/database/mutator_set/
    pub fn mutator_set_database_dir_path(&self) -> PathBuf {
        self.database_dir_path().join("mutator_set")
    }
    
    /// Archival MMR database: <blockchain_root>/database/archival_block_mmr/
    pub fn archival_block_mmr_dir_path(&self) -> PathBuf {
        self.database_dir_path().join("archival_block_mmr")
    }
    
    /// Banned IPs database: <blockchain_root>/database/banned_ips/
    pub fn banned_ips_database_dir_path(&self) -> PathBuf {
        self.database_dir_path().join("banned_ips")
    }
    
    /// RPC cookie file: <node_root>/.cookie
    pub fn rpc_cookie_file_path(&self) -> PathBuf {
        self.node_root.join(".cookie")
    }
    
    /// DB migration backups: <blockchain_root>/database/migration_backups/
    pub fn db_migration_backups_dir_path(&self) -> PathBuf {
        self.database_dir_path().join("migration_backups")
    }
    
    /// Get all roots for display/logging
    pub fn roots(&self) -> DataDirectoryRoots {
        DataDirectoryRoots {
            wallet: self.wallet_root.clone(),
            blockchain: self.blockchain_root.clone(),
            node: self.node_root.clone(),
            legacy_mode: self.legacy_mode,
        }
    }
}

/// Helper struct for displaying/logging directory structure
#[derive(Debug, Clone)]
pub struct DataDirectoryRoots {
    pub wallet: PathBuf,
    pub blockchain: PathBuf,
    pub node: PathBuf,
    pub legacy_mode: bool,
}

impl std::fmt::Display for DataDirectoryRoots {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.legacy_mode {
            write!(f, "Legacy mode: {}", self.wallet.display())
        } else {
            write!(
                f,
                "Wallet: {}, Blockchain: {}, Node: {}",
                self.wallet.display(),
                self.blockchain.display(),
                self.node.display()
            )
        }
    }
}
```

### 5.2 CLI Argument Changes

#### **File: `neptune-core/src/application/config/cli_args.rs`**

**Add new flags:**

```rust
#[derive(Parser, Debug, Clone)]
#[clap(author, version, about)]
pub struct Args {
    /// The data directory that contains the wallet and blockchain state (LEGACY)
    ///
    /// Using this flag enables legacy mode with monolithic directory structure.
    /// For new installations, prefer --wallet-dir and --blockchain-dir instead.
    ///
    /// Default (legacy mode): ~/.config/neptune/core/<network>/
    #[clap(long, value_name = "DIR", conflicts_with_all = &["wallet_dir", "blockchain_dir"])]
    pub data_dir: Option<PathBuf>,
    
    /// The wallet directory (NEW)
    ///
    /// Contains wallet secrets, database, and UTXO transfer files.
    /// This directory should be backed up regularly.
    ///
    /// Default: ~/.config/neptune/wallet/<network>/
    #[clap(long, value_name = "DIR")]
    pub wallet_dir: Option<PathBuf>,
    
    /// The blockchain directory (NEW)
    ///
    /// Contains block data, indices, and mutator set.
    /// This directory can be large (200+ GB) and is prunable.
    ///
    /// Default: ~/.local/share/neptune/blockchain/<network>/
    #[clap(long, value_name = "DIR")]
    pub blockchain_dir: Option<PathBuf>,
    
    // ... rest of existing flags
}
```

### 5.3 GlobalState Initialization Changes

#### **File: `neptune-core/src/state/mod.rs`**

**Update `try_new()` method:**

```rust
impl GlobalState {
    pub async fn try_new(
        data_directory: DataDirectory,
        genesis: Block,
        cli: cli_args::Args,
    ) -> Result<Self> {
        // Log which layout we're using
        info!("Data directory layout: {}", data_directory.roots());
        
        // Rest of initialization unchanged - DataDirectory handles path resolution
        let wallet_dir = data_directory.wallet_directory_path();
        DataDirectory::create_dir_if_not_exists(&wallet_dir).await?;

        // ... rest of existing code unchanged
    }
}
```

### 5.4 Migration Module (NEW)

#### **File: `neptune-core/src/application/migration/layout_v2.rs`**

```rust
//! Data layout migration from v1 (monolithic) to v2 (separated)

use std::path::{Path, PathBuf};
use anyhow::{Context, Result};
use tracing::{info, warn};

pub struct LayoutMigration {
    old_root: PathBuf,
    new_wallet_root: PathBuf,
    new_blockchain_root: PathBuf,
    backup_root: Option<PathBuf>,
}

impl LayoutMigration {
    pub fn new(
        old_root: PathBuf,
        new_wallet_root: PathBuf,
        new_blockchain_root: PathBuf,
    ) -> Self {
        Self {
            old_root,
            new_wallet_root,
            new_blockchain_root,
            backup_root: None,
        }
    }
    
    pub fn with_backup(mut self, backup_root: PathBuf) -> Self {
        self.backup_root = Some(backup_root);
        self
    }
    
    /// Execute the migration
    pub async fn migrate(&self) -> Result<()> {
        info!("🔄 Starting data layout migration v1 → v2");
        
        // Step 1: Backup old structure
        if let Some(backup) = &self.backup_root {
            self.backup_old_structure(backup).await?;
        }
        
        // Step 2: Create new directory structure
        self.create_new_structure().await?;
        
        // Step 3: Move wallet data
        self.migrate_wallet_data().await?;
        
        // Step 4: Move blockchain data
        self.migrate_blockchain_data().await?;
        
        // Step 5: Create migration marker
        self.create_migration_marker().await?;
        
        info!("✅ Data layout migration complete");
        Ok(())
    }
    
    async fn backup_old_structure(&self, backup_root: &Path) -> Result<()> {
        info!("📦 Backing up old structure to {}", backup_root.display());
        // Implementation: recursive copy
        Ok(())
    }
    
    async fn create_new_structure(&self) -> Result<()> {
        info!("📁 Creating new directory structure");
        
        tokio::fs::create_dir_all(self.new_wallet_root.join("files")).await?;
        tokio::fs::create_dir_all(self.new_wallet_root.join("database")).await?;
        tokio::fs::create_dir_all(self.new_wallet_root.join("utxo-transfer")).await?;
        
        tokio::fs::create_dir_all(self.new_blockchain_root.join("database")).await?;
        tokio::fs::create_dir_all(self.new_blockchain_root.join("blocks")).await?;
        
        Ok(())
    }
    
    async fn migrate_wallet_data(&self) -> Result<()> {
        info!("🔐 Migrating wallet data");
        
        // Move wallet files
        self.move_if_exists(
            &self.old_root.join("wallet"),
            &self.new_wallet_root.join("files"),
        ).await?;
        
        // Move wallet database
        self.move_if_exists(
            &self.old_root.join("database/wallet"),
            &self.new_wallet_root.join("database/wallet"),
        ).await?;
        
        // Move UTXO transfer files
        self.move_if_exists(
            &self.old_root.join("utxo-transfer"),
            &self.new_wallet_root.join("utxo-transfer"),
        ).await?;
        
        Ok(())
    }
    
    async fn migrate_blockchain_data(&self) -> Result<()> {
        info!("⛓️  Migrating blockchain data (this may take a while for large databases)");
        
        // Move block index
        self.move_if_exists(
            &self.old_root.join("database/block_index"),
            &self.new_blockchain_root.join("database/block_index"),
        ).await?;
        
        // Move mutator set
        self.move_if_exists(
            &self.old_root.join("database/mutator_set"),
            &self.new_blockchain_root.join("database/mutator_set"),
        ).await?;
        
        // Move archival MMR
        self.move_if_exists(
            &self.old_root.join("database/archival_block_mmr"),
            &self.new_blockchain_root.join("database/archival_block_mmr"),
        ).await?;
        
        // Move banned IPs
        self.move_if_exists(
            &self.old_root.join("database/banned_ips"),
            &self.new_blockchain_root.join("database/banned_ips"),
        ).await?;
        
        // Move blocks
        self.move_if_exists(
            &self.old_root.join("blocks"),
            &self.new_blockchain_root.join("blocks"),
        ).await?;
        
        Ok(())
    }
    
    async fn create_migration_marker(&self) -> Result<()> {
        let marker = self.old_root.join(".migrated_to_v2");
        tokio::fs::write(marker, b"Migrated to separated layout").await?;
        Ok(())
    }
    
    async fn move_if_exists(&self, from: &Path, to: &Path) -> Result<()> {
        if tokio::fs::try_exists(from).await? {
            info!("  Moving {} → {}", from.display(), to.display());
            tokio::fs::rename(from, to).await?;
        }
        Ok(())
    }
}
```

---

## 6. Testing Strategy

### 6.1 Unit Tests

**Test coverage for:**
- `DataDirectory::get()` layout detection
- Path resolution in both legacy and new modes
- Migration logic (dry-run tests)

### 6.2 Integration Tests

**Scenarios:**

1. **Fresh install (new layout)**
   - Create wallet with `--wallet-dir` and `--blockchain-dir`
   - Verify directory structure
   - Sync a few blocks
   - Restart node, ensure continuity

2. **Legacy install (no migration)**
   - Start with old `--data-dir`
   - Verify legacy mode active
   - Ensure full functionality

3. **Automatic migration**
   - Start with old structure
   - Remove `--data-dir` flag
   - Node detects old structure
   - Performs automatic migration
   - Verify all data accessible

4. **Manual migration**
   - Use `neptune-cli migrate-data-layout`
   - Verify backup created
   - Verify new structure correct
   - Restart node, ensure works

5. **Mixed CLI flags**
   - Test conflict resolution (`--data-dir` vs `--wallet-dir`)
   - Verify error messages are clear

### 6.3 Cross-Platform Testing

- **Linux**: Test XDG compliance
- **macOS**: Test `~/Library/Application Support/` paths
- **Windows**: Test `%APPDATA%` and `%LOCALAPPDATA%` paths

### 6.4 Performance Testing

- **Migration speed**: Time to migrate 100 GB blockchain
- **Startup time**: Compare legacy vs new layout
- **I/O patterns**: Ensure no regression

---

## 7. Risk Assessment

### 7.1 High-Risk Areas

| Risk | Mitigation |
|------|------------|
| Data loss during migration | Mandatory backup before migration |
| Path resolution bugs | Extensive unit tests for all path methods |
| Breaking existing setups | Legacy mode with automatic fallback |
| Cross-platform path issues | Test on Linux/macOS/Windows |
| Database corruption | Atomic operations, verification step |

### 7.2 Rollback Plan

If migration fails:
1. Stop node
2. Restore from backup (created automatically)
3. Use `--data-dir` to force legacy mode
4. Report bug with logs

### 7.3 Communication Plan

**Before release:**
- Documentation update
- Blog post explaining benefits
- Migration guide
- FAQ

**On first startup:**
```
🔔 NOTICE: Neptune Core v0.5.0 introduces separated wallet/blockchain directories.

Your existing data has been detected at:
  ~/.config/neptune/core/main/

For better security and flexibility, we recommend migrating to the new layout:
  Wallet:     ~/.config/neptune/wallet/main/
  Blockchain: ~/.local/share/neptune/blockchain/main/

Options:
  1. Migrate now (recommended): neptune-cli migrate-data-layout
  2. Continue with current layout: Add --data-dir flag to your startup command
  3. Learn more: https://docs.neptune.cash/data-layout-migration

Would you like to migrate now? [y/N]:
```

---

## 8. Timeline

### Week 1: Core Implementation
- **Days 1-2**: Refactor `DataDirectory` struct
- **Days 3-4**: Update all path resolution methods
- **Day 5**: CLI argument integration

### Week 2: Migration & Testing
- **Days 1-2**: Implement migration module
- **Days 3-4**: Write unit tests
- **Day 5**: Integration tests

### Week 3: Cross-Platform & Polish
- **Days 1-2**: Cross-platform testing (Linux/macOS/Windows)
- **Day 3**: Performance testing
- **Days 4-5**: Documentation and migration guide

### Week 4: Review & Release Prep
- **Days 1-2**: Code review, bug fixes
- **Day 3**: Security audit of migration code
- **Days 4-5**: Release notes, blog post, community communication

**Total:** ~4 weeks for Phase 2 completion.

---

## 9. Success Criteria

✅ **Phase 2 is complete when:**

1. Users can specify `--wallet-dir` and `--blockchain-dir` independently
2. New installations use separated layout by default
3. Existing installations auto-migrate or continue in legacy mode seamlessly
4. All tests pass on Linux, macOS, and Windows
5. Migration tool successfully tested with 200+ GB blockchain
6. Documentation complete (user guide + technical spec)
7. No regressions in wallet encryption functionality
8. Wallet-only backup script provided
9. Zero data loss reports from beta testers

---

## 10. Post-Phase 2 Opportunities

Once data is decoupled, we enable:

1. **Phase 3 enhancements:**
   - Encrypt wallet database separately
   - Different retention policies (wallet = permanent, blockchain = prunable)
   - Mount wallet on encrypted volume

2. **Operational benefits:**
   - Wallet backup script: `rsync ~/.config/neptune/wallet/ backup/`
   - Blockchain re-sync without wallet risk
   - Network-attached storage for blockchain (wallet stays local)

3. **Future features:**
   - Watch-only wallets (wallet + blockchain on different machines)
   - Hardware wallet integration (wallet files on HSM)
   - Multi-wallet support (multiple wallet dirs, shared blockchain)

---

**Document Version:** 1.0
**Last Updated:** 2025-10-17
**Status:** Planning Complete - Ready for Implementation
**Dependencies:** Phase 1 (Wallet Encryption) ✅ Complete
**Author:** Sea of Freedom Development Team

