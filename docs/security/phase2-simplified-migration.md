# Phase 2: Data Decoupling - Simplified Migration Strategy

## Executive Summary

**Goal:** Separate wallet and blockchain data using simple file moves, no symlinks.

**New Default Location:** `~/.neptune/` (hidden directory in home folder)

**Strategy:** One-time automatic migration on upgrade, fully cross-platform.

---

## 1. Simplified Directory Structure

### Before (v0.4.x and earlier)

```
~/.config/neptune/core/main/           # Old location
├── wallet/
│   ├── wallet.encrypted
│   ├── incoming_randomness.dat
│   └── outgoing_randomness.dat
├── database/
│   ├── wallet/                        # Wallet DB
│   ├── block_index/                   # Blockchain DB
│   ├── mutator_set/
│   └── banned_ips/
└── blocks/
    └── block_*.dat
```

### After (v0.5.0+) - NEW DEFAULT

```
~/.neptune/                            # NEW: Simple hidden directory in home
├── main/                              # Network name
│   ├── wallet/                        # Wallet data (~100 MB)
│   │   ├── wallet.encrypted
│   │   ├── incoming_randomness.dat
│   │   ├── outgoing_randomness.dat
│   │   └── db/                        # Wallet database
│   │       └── wallet/
│   │
│   └── chain/                         # Blockchain data (~200 GB)
│       ├── db/                        # Blockchain databases
│       │   ├── block_index/
│       │   ├── mutator_set/
│       │   ├── archival_block_mmr/
│       │   └── banned_ips/
│       └── blocks/
│           └── block_*.dat
│
├── testnet/                           # Same structure for testnet
│   ├── wallet/
│   └── chain/
│
└── .config                            # Optional: Node-level config
    └── neptune.toml
```

**Benefits of `~/.neptune/`:**

- ✅ Cross-platform (works on Windows, macOS, Linux)
- ✅ Simple hidden directory in home folder
- ✅ No XDG path complexity
- ✅ Easy for users to find and backup
- ✅ Convention used by many crypto projects (`.bitcoin`, `.ethereum`, etc.)

---

## 2. Migration Strategy (Simplified)

### First Startup After Upgrade

**Detection Logic:**

```
1. Check for ~/.neptune/main/ (new layout)
   → Use it

2. Check for old location (~/.config/neptune/core/main/)
   → Prompt user to migrate

3. Neither exists
   → Fresh install, use ~/.neptune/main/
```

### Migration Prompt (Simple)

```
🚀 Neptune Core v0.5.0 starting...

📂 Old data directory detected: ~/.config/neptune/core/main/

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔄 ONE-TIME DATA MIGRATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Neptune Core v0.5.0 uses a new directory structure for better
organization and easier backups.

What will happen:
  1. Move wallet data → ~/.neptune/main/wallet/
  2. Move blockchain data → ~/.neptune/main/chain/
  3. Keep backup of old location (can delete later)

Estimated time: 5-30 minutes (depending on blockchain size)
Disk space needed: None (files are moved, not copied)

Options:
  [1] Migrate now (recommended)
  [2] Keep old location (add --data-dir flag required)

Choice [1]: _
```

**If user chooses Option 1 (Migrate):**

```
✓ Creating backup marker at old location...
✓ Creating new directory structure...

📦 Moving wallet data...
  ✓ wallet.encrypted (52 KB)
  ✓ randomness files (2.3 MB)
  ✓ wallet database (48 MB)

⛓️  Moving blockchain data...
  ✓ block_index (1.2 GB)
  ✓ mutator_set (3.8 GB)
  ✓ archival_block_mmr (2.1 GB)
  ✓ banned_ips (128 KB)
  [====================================] 45% (92.1 GB / 205.3 GB)
  Estimated time remaining: 8 minutes
  ✓ blocks (198 GB)

✓ Migration complete!

New locations:
  Wallet:     ~/.neptune/main/wallet/
  Blockchain: ~/.neptune/main/chain/

Old location backed up at:
  ~/.config/neptune/core/main.backup/

💡 After verifying everything works, you can delete the backup:
   rm -rf ~/.config/neptune/core/main.backup/

🚀 Starting Neptune Core...
```

**If user chooses Option 2 (Keep old):**

```
✓ Continuing with old location

⚠️  To use the old location, add this flag when starting:
    --data-dir ~/.config/neptune/core/main/

You can migrate later with:
    neptune-cli migrate-data

🚀 Starting Neptune Core...
```

---

## 3. Implementation

### 3.1 DataDirectory Struct (Simplified)

```rust
#[derive(Debug, Clone)]
pub struct DataDirectory {
    /// Root directory for all neptune data
    /// Default: ~/.neptune/<network>/
    root: PathBuf,

    /// Network name (main, testnet, etc.)
    network: Network,

    /// Whether we're in legacy mode
    legacy_mode: bool,
}

impl DataDirectory {
    /// Smart constructor with automatic migration
    pub async fn get(
        explicit_data_dir: Option<PathBuf>,
        network: Network,
        allow_interactive: bool,
    ) -> Result<Self> {
        // Priority 1: Explicit --data-dir flag (legacy mode)
        if let Some(data_dir) = explicit_data_dir {
            return Ok(Self::legacy(data_dir, network));
        }

        // Priority 2: Check for new layout
        let new_root = Self::default_root();
        let new_network_dir = new_root.join(network.to_string());

        if Self::has_new_structure(&new_network_dir) {
            // New structure exists - use it
            return Ok(Self::new_layout(new_root, network));
        }

        // Priority 3: Check for old layout
        let old_root = Self::old_default_root(network);

        if Self::has_old_structure(&old_root) {
            // Old structure detected - migrate or use legacy
            if allow_interactive {
                let should_migrate = Self::prompt_migration().await?;

                if should_migrate {
                    Self::migrate_old_to_new(&old_root, &new_network_dir).await?;
                    return Ok(Self::new_layout(new_root, network));
                } else {
                    warn!("💡 TIP: Add --data-dir flag to skip this prompt");
                    return Ok(Self::legacy(old_root, network));
                }
            } else {
                // Non-interactive: auto-migrate (safe operation)
                info!("Non-interactive mode: auto-migrating to new layout");
                Self::migrate_old_to_new(&old_root, &new_network_dir).await?;
                return Ok(Self::new_layout(new_root, network));
            }
        }

        // Priority 4: Fresh install - use new layout
        Ok(Self::new_layout(new_root, network))
    }

    /// Default root for new layout: ~/.neptune/
    fn default_root() -> PathBuf {
        dirs::home_dir()
            .expect("Could not determine home directory")
            .join(".neptune")
    }

    /// Old default root: ~/.config/neptune/core/<network>/ (or OS equivalent)
    fn old_default_root(network: Network) -> PathBuf {
        let project_dirs = ProjectDirs::from("org", "neptune", "neptune")
            .expect("Could not determine data directory");

        project_dirs
            .data_dir()
            .join(network.to_string())
    }

    /// Create new layout instance
    fn new_layout(root: PathBuf, network: Network) -> Self {
        Self {
            root: root.join(network.to_string()),
            network,
            legacy_mode: false,
        }
    }

    /// Create legacy layout instance
    fn legacy(root: PathBuf, network: Network) -> Self {
        Self {
            root,
            network,
            legacy_mode: true,
        }
    }

    /// Check if new structure exists
    fn has_new_structure(network_dir: &Path) -> bool {
        network_dir.join("wallet/wallet.encrypted").exists()
            || network_dir.join("wallet/wallet.dat").exists()
    }

    /// Check if old structure exists
    fn has_old_structure(old_root: &Path) -> bool {
        old_root.join("wallet/wallet.encrypted").exists()
            || old_root.join("wallet/wallet.dat").exists()
    }

    /// Migrate from old to new layout
    async fn migrate_old_to_new(old_root: &Path, new_root: &Path) -> Result<()> {
        info!("🔄 Starting data migration...");

        // 1. Create backup marker at old location
        let backup_marker = old_root.join(".migrated_to_v2");
        tokio::fs::write(&backup_marker,
            format!("Migrated to: {}\nDate: {}",
                new_root.display(),
                chrono::Utc::now())
        ).await?;

        // 2. Create new directory structure
        tokio::fs::create_dir_all(new_root.join("wallet/db")).await?;
        tokio::fs::create_dir_all(new_root.join("chain/db")).await?;
        tokio::fs::create_dir_all(new_root.join("chain/blocks")).await?;

        // 3. Move wallet files
        info!("📦 Moving wallet data...");
        Self::move_if_exists(
            old_root.join("wallet"),
            new_root.join("wallet"),
            &["wallet.encrypted", "wallet.dat", "*.dat"],
        ).await?;

        // 4. Move wallet database
        Self::move_if_exists(
            old_root.join("database/wallet"),
            new_root.join("wallet/db/wallet"),
            &["*"],
        ).await?;

        // 5. Move UTXO transfer files (if exist)
        if old_root.join("utxo-transfer").exists() {
            Self::move_if_exists(
                old_root.join("utxo-transfer"),
                new_root.join("wallet/utxo-transfer"),
                &["*"],
            ).await?;
        }

        // 6. Move blockchain databases
        info!("⛓️  Moving blockchain data...");
        let blockchain_dbs = [
            "block_index",
            "mutator_set",
            "archival_block_mmr",
            "banned_ips",
        ];

        for db_name in &blockchain_dbs {
            Self::move_if_exists(
                old_root.join(format!("database/{}", db_name)),
                new_root.join(format!("chain/db/{}", db_name)),
                &["*"],
            ).await?;
        }

        // 7. Move blocks
        Self::move_if_exists(
            old_root.join("blocks"),
            new_root.join("chain/blocks"),
            &["*"],
        ).await?;

        // 8. Rename old directory to .backup
        let backup_dir = old_root.with_extension("backup");
        tokio::fs::rename(old_root, &backup_dir).await?;

        info!("✓ Migration complete!");
        info!("  New location: {}", new_root.display());
        info!("  Backup: {}", backup_dir.display());

        Ok(())
    }

    /// Move files/directories if they exist
    async fn move_if_exists(
        from: impl AsRef<Path>,
        to: impl AsRef<Path>,
        patterns: &[&str],
    ) -> Result<()> {
        let from = from.as_ref();
        let to = to.as_ref();

        if !from.exists() {
            return Ok(());
        }

        // Ensure parent directory exists
        if let Some(parent) = to.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        // Move entire directory if pattern is "*"
        if patterns == &["*"] {
            tokio::fs::rename(from, to).await?;
            return Ok(());
        }

        // Otherwise, move specific files
        for entry in std::fs::read_dir(from)? {
            let entry = entry?;
            let file_name = entry.file_name();
            let file_name_str = file_name.to_string_lossy();

            // Check if file matches any pattern
            for pattern in patterns {
                if pattern.contains('*') {
                    // Simple wildcard matching
                    let prefix = pattern.trim_end_matches('*');
                    let suffix = pattern.trim_start_matches('*');

                    if file_name_str.starts_with(prefix) && file_name_str.ends_with(suffix) {
                        let dest = to.join(&file_name);
                        tokio::fs::rename(entry.path(), dest).await?;
                        break;
                    }
                } else if &file_name_str == pattern {
                    let dest = to.join(&file_name);
                    tokio::fs::rename(entry.path(), dest).await?;
                    break;
                }
            }
        }

        Ok(())
    }

    /// Interactive migration prompt
    async fn prompt_migration() -> Result<bool> {
        use dialoguer::{Confirm, theme::ColorfulTheme};

        println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("🔄 ONE-TIME DATA MIGRATION");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
        println!("Neptune Core v0.5.0 uses a new directory structure:");
        println!("  Wallet:     ~/.neptune/main/wallet/");
        println!("  Blockchain: ~/.neptune/main/chain/\n");
        println!("Files will be MOVED (not copied), so no extra disk space needed.");
        println!("Your old location will be renamed to .backup for safety.\n");

        let should_migrate = Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Migrate now?")
            .default(true)
            .interact()?;

        Ok(should_migrate)
    }

    // =========================================================================
    // Path getters
    // =========================================================================

    /// Wallet directory: <root>/wallet/ or <root>/wallet/ (legacy)
    pub fn wallet_directory_path(&self) -> PathBuf {
        if self.legacy_mode {
            self.root.join("wallet")
        } else {
            self.root.join("wallet")
        }
    }

    /// Wallet database: <root>/wallet/db/wallet/ or <root>/database/wallet/ (legacy)
    pub fn wallet_database_dir_path(&self) -> PathBuf {
        if self.legacy_mode {
            self.root.join("database/wallet")
        } else {
            self.root.join("wallet/db/wallet")
        }
    }

    /// UTXO transfer: <root>/wallet/utxo-transfer/ or <root>/utxo-transfer/ (legacy)
    pub fn utxo_transfer_directory_path(&self) -> PathBuf {
        if self.legacy_mode {
            self.root.join("utxo-transfer")
        } else {
            self.root.join("wallet/utxo-transfer")
        }
    }

    /// Blockchain database root: <root>/chain/db/ or <root>/database/ (legacy)
    pub fn database_dir_path(&self) -> PathBuf {
        if self.legacy_mode {
            self.root.join("database")
        } else {
            self.root.join("chain/db")
        }
    }

    /// Blocks: <root>/chain/blocks/ or <root>/blocks/ (legacy)
    pub fn block_dir_path(&self) -> PathBuf {
        if self.legacy_mode {
            self.root.join("blocks")
        } else {
            self.root.join("chain/blocks")
        }
    }

    /// Block index database
    pub fn block_index_database_dir_path(&self) -> PathBuf {
        self.database_dir_path().join("block_index")
    }

    /// Mutator set database
    pub fn mutator_set_database_dir_path(&self) -> PathBuf {
        self.database_dir_path().join("mutator_set")
    }

    /// Archival MMR database
    pub fn archival_block_mmr_dir_path(&self) -> PathBuf {
        self.database_dir_path().join("archival_block_mmr")
    }

    /// Banned IPs database
    pub fn banned_ips_database_dir_path(&self) -> PathBuf {
        self.database_dir_path().join("banned_ips")
    }

    /// RPC cookie file
    pub fn rpc_cookie_file_path(&self) -> PathBuf {
        self.root.join(".cookie")
    }

    /// DB migration backups
    pub fn db_migration_backups_dir_path(&self) -> PathBuf {
        self.database_dir_path().join("migration_backups")
    }

    /// Block file path
    pub fn block_file_path(&self, file_index: u32) -> PathBuf {
        let block_file_name = format!("block_{:04}.dat", file_index);
        self.block_dir_path().join(block_file_name)
    }

    /// Get wallet root (for backup purposes)
    pub fn wallet_root(&self) -> PathBuf {
        if self.legacy_mode {
            self.root.clone()
        } else {
            self.root.join("wallet")
        }
    }

    /// Get blockchain root (for separate storage/backup)
    pub fn blockchain_root(&self) -> PathBuf {
        if self.legacy_mode {
            self.root.clone()
        } else {
            self.root.join("chain")
        }
    }
}

impl std::fmt::Display for DataDirectory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.legacy_mode {
            write!(f, "Legacy: {}", self.root.display())
        } else {
            write!(
                f,
                "Wallet: {}, Chain: {}",
                self.wallet_root().display(),
                self.blockchain_root().display()
            )
        }
    }
}
```

### 3.2 CLI Arguments (Simplified)

```rust
#[derive(Parser, Debug, Clone)]
pub struct Args {
    /// Data directory (legacy mode)
    ///
    /// If not specified, uses ~/.neptune/<network>/
    ///
    /// For legacy compatibility, specify the old location:
    ///   --data-dir ~/.config/neptune/core/main/
    #[clap(long, value_name = "DIR")]
    pub data_dir: Option<PathBuf>,

    // ... rest of existing flags
}
```

### 3.3 Wallet Backup Command (Simplified)

```rust
/// Backup wallet data only (no blockchain)
pub async fn backup_wallet(output_path: Option<&Path>) -> Result<()> {
    let data_dir = DataDirectory::get(None, Network::Main, false).await?;

    let backup_name = format!(
        "neptune-wallet-backup-{}.tar.gz",
        chrono::Utc::now().format("%Y%m%d-%H%M%S")
    );

    let output = output_path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::env::current_dir().unwrap().join(&backup_name));

    info!("📦 Creating wallet backup: {}", output.display());

    let file = std::fs::File::create(&output)?;
    let encoder = GzEncoder::new(file, Compression::default());
    let mut tar = Builder::new(encoder);

    // Backup entire wallet directory
    tar.append_dir_all("wallet", data_dir.wallet_root())?;
    tar.finish()?;

    let size = tokio::fs::metadata(&output).await?.len();
    info!("✓ Backup complete: {} ({:.1} MB)", output.display(), size as f64 / 1_000_000.0);
    info!("💡 Store this backup securely - it contains your wallet secrets!");

    Ok(())
}
```

---

## 4. Cross-Platform Compatibility

### Path Resolution

```rust
/// Cross-platform home directory
fn home_dir() -> PathBuf {
    dirs::home_dir().expect("Could not determine home directory")
}

/// Default root: ~/.neptune/
/// Works on Windows, macOS, Linux
fn default_root() -> PathBuf {
    home_dir().join(".neptune")
}
```

**Resolves to:**

- **Linux:** `/home/alice/.neptune/`
- **macOS:** `/Users/Alice/.neptune/`
- **Windows:** `C:\Users\Alice\.neptune\`

### File Operations

- ✅ Use `tokio::fs::rename()` for moves (atomic, cross-platform)
- ✅ Use `tokio::fs::create_dir_all()` for directory creation
- ✅ No symlinks (not reliable on Windows)
- ✅ No special permissions (works on all platforms)

---

## 5. Benefits of Simplified Approach

### For Users

- ✅ **Simple:** One hidden folder in home directory
- ✅ **Predictable:** Same location on all platforms
- ✅ **Familiar:** Follows crypto convention (`.bitcoin`, `.ethereum`)
- ✅ **Easy backup:** Just `tar -czf backup.tar.gz ~/.neptune/main/wallet/`
- ✅ **No complexity:** No symlinks, no multiple root paths

### For Developers

- ✅ **Less code:** ~300 lines vs 900+ lines with symlinks
- ✅ **Easier testing:** Simple file operations
- ✅ **Cross-platform:** Works identically everywhere
- ✅ **Maintainable:** Straightforward logic
- ✅ **No edge cases:** No symlink breakage, permission issues

### Technical Benefits

- ✅ **Atomic moves:** `rename()` is atomic on all platforms
- ✅ **Fast migration:** Moving files is instant (same filesystem)
- ✅ **Safe:** Backup marker prevents data loss
- ✅ **Clean:** Old location renamed to `.backup`, easy to delete later

---

## 6. Migration Examples

### Linux Example

```bash
# Before
~/.config/neptune/core/main/
├── wallet/
├── database/
└── blocks/

# After migration
~/.neptune/main/
├── wallet/
│   ├── wallet.encrypted
│   └── db/wallet/
└── chain/
    ├── db/
    │   ├── block_index/
    │   └── mutator_set/
    └── blocks/

# Old location backed up
~/.config/neptune/core/main.backup/
└── .migrated_to_v2
```

### Windows Example

```
Before:
C:\Users\Alice\AppData\Roaming\neptune\main\
├── wallet\
├── database\
└── blocks\

After:
C:\Users\Alice\.neptune\main\
├── wallet\
│   ├── wallet.encrypted
│   └── db\wallet\
└── chain\
    ├── db\
    └── blocks\

Backup:
C:\Users\Alice\AppData\Roaming\neptune\main.backup\
```

---

## 7. Rollback (If Needed)

```bash
# Stop node
neptune-cli stop

# Restore from backup
rm -rf ~/.neptune/main/
mv ~/.config/neptune/core/main.backup/ ~/.config/neptune/core/main/

# Start with legacy flag
neptune-core --data-dir ~/.config/neptune/core/main/
```

**Time:** < 1 minute

---

## 8. Testing Checklist

- [ ] Fresh install uses `~/.neptune/main/`
- [ ] Legacy user gets migration prompt
- [ ] Migration completes successfully with 200 GB blockchain
- [ ] Backup is created at old location
- [ ] Wallet balance unchanged after migration
- [ ] Blockchain syncs correctly from new location
- [ ] `--data-dir` flag works for legacy mode
- [ ] Works on Linux, macOS, Windows
- [ ] Wallet backup command works
- [ ] Rollback procedure works

---

## 9. Timeline

**Week 1:**

- Day 1-2: Refactor `DataDirectory` struct
- Day 3-4: Implement migration logic
- Day 5: CLI integration

**Week 2:**

- Day 1-2: Testing on Linux/macOS/Windows
- Day 3-4: Edge case handling
- Day 5: Documentation

**Total:** 2 weeks for clean, simple implementation

---

## 10. Summary

**What we're doing:**

- Move data from `~/.config/neptune/core/main/` to `~/.neptune/main/`
- Split into `wallet/` and `chain/` subdirectories
- One-time automatic migration on first startup
- Legacy mode via `--data-dir` flag

**What we're NOT doing:**

- ❌ No symlinks
- ❌ No XDG complexity
- ❌ No multiple root directories
- ❌ No in-place decoupling tricks

**Result:**

- Simple, clean, cross-platform solution
- Easy for users to understand
- Maintainable code
- Achieves all Phase 2 goals

---

**Document Version:** 2.0
**Last Updated:** 2025-10-17
**Status:** Ready for Implementation
**Replaces:** phase2-migration-ux-detailed.md (deleted)
**Author:** Sea of Freedom Development Team
