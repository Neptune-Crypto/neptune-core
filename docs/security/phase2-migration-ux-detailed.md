# Phase 2: Migration UX - Detailed User Experience

## Executive Summary

**The Challenge:** Legacy users have their data at `~/.config/neptune/core/main/`. We want to decouple wallet/blockchain data without breaking their setup or forcing disruptive changes.

**The Solution:** Multi-tier migration strategy with three options:
1. **In-place decoupling** (safest, no data move)
2. **Full migration** (recommended, separates directories)
3. **Legacy mode** (no changes, backward compatible)

---

## Table of Contents

1. [Migration Options Compared](#1-migration-options-compared)
2. [Option 1: In-Place Decoupling (Recommended Default)](#2-option-1-in-place-decoupling-recommended-default)
3. [Option 2: Full Migration](#3-option-2-full-migration)
4. [Option 3: Legacy Mode](#4-option-3-legacy-mode)
5. [First Startup Experience](#5-first-startup-experience)
6. [Implementation Details](#6-implementation-details)
7. [Recovery Scenarios](#7-recovery-scenarios)

---

## 1. Migration Options Compared

### Quick Comparison Table

| Feature | In-Place Decoupling | Full Migration | Legacy Mode |
|---------|---------------------|----------------|-------------|
| **Data Location** | Same dir, logical separation | Physically separated dirs | Unchanged |
| **Backup Required** | No (reads only) | Yes (moves data) | No |
| **Disk Space** | 0 extra (no copy) | 0 extra (moves, not copies) | 0 extra |
| **Time Required** | < 1 second | 5-30 minutes (large blockchain) | Instant |
| **Risk Level** | ⭐ Very Low | ⭐⭐ Low (with backup) | ⭐ Very Low |
| **Benefits** | Logical separation, easy rollback | Physical separation, full XDG compliance | No changes |
| **Wallet-Only Backup** | ✅ Yes (via directory list) | ✅ Yes (via separate path) | ❌ No |
| **Rollback** | Instant (just restart) | Via backup restore | N/A |
| **Recommended For** | 95% of users | Power users, fresh machines | Users with custom scripts |

### Visual Representation

**Before (Legacy):**
```
~/.config/neptune/core/main/
├── wallet/
├── database/wallet/
├── database/block_index/
├── database/mutator_set/
└── blocks/
```

**After In-Place Decoupling:**
```
~/.config/neptune/core/main/          # Same location!
├── wallet/                             # Wallet root (logical)
│   ├── files/ → ../wallet_files/      # Symlink to actual wallet files
│   └── database/ → ../database/wallet # Symlink to wallet DB
│
├── blockchain/                         # Blockchain root (logical)
│   ├── database/ → ../database        # Symlink to blockchain DBs
│   └── blocks/ → ../blocks            # Symlink to blocks
│
├── wallet_files/                       # Actual wallet files (unchanged location)
│   ├── wallet.encrypted
│   └── ...
│
└── database/                           # Actual databases (unchanged location)
    ├── wallet/
    ├── block_index/
    └── ...
```

**After Full Migration:**
```
~/.config/neptune/wallet/main/
├── files/
│   └── wallet.encrypted
└── database/
    └── wallet/

~/.local/share/neptune/blockchain/main/
├── database/
│   ├── block_index/
│   └── mutator_set/
└── blocks/

~/.config/neptune/core/main/           # Old location (backed up or removed)
└── .migrated_to_v2
```

---

## 2. Option 1: In-Place Decoupling (Recommended Default)

### What It Does

Creates a **logical separation** within the existing directory using symlinks and metadata, without moving any data.

### Key Features

- ✅ **Zero data movement** - files stay exactly where they are
- ✅ **Instant operation** - completes in < 1 second
- ✅ **No backup needed** - read-only operation
- ✅ **Easy rollback** - just delete symlinks and restart old version
- ✅ **Wallet-only backups enabled** - via metadata file listing wallet paths
- ✅ **100% safe** - no risk of data loss

### How It Works

1. **Create logical roots:**
   ```bash
   mkdir -p ~/.config/neptune/core/main/wallet/
   mkdir -p ~/.config/neptune/core/main/blockchain/
   ```

2. **Create symlinks to existing data:**
   ```bash
   # Wallet symlinks
   ln -s ../../wallet_files ~/.config/neptune/core/main/wallet/files
   ln -s ../../database/wallet ~/.config/neptune/core/main/wallet/database
   
   # Blockchain symlinks
   ln -s ../database ~/.config/neptune/core/main/blockchain/database
   ln -s ../blocks ~/.config/neptune/core/main/blockchain/blocks
   ```

3. **Rename original wallet dir to avoid confusion:**
   ```bash
   mv ~/.config/neptune/core/main/wallet ~/.config/neptune/core/main/wallet_files
   ```

4. **Create metadata file:**
   ```json
   // ~/.config/neptune/core/main/.layout_v2.json
   {
     "version": 2,
     "layout_type": "in_place_decoupled",
     "wallet_root": "wallet/",
     "blockchain_root": "blockchain/",
     "created_at": "2025-10-17T12:34:56Z"
   }
   ```

### Benefits for Users

- **No waiting** - Migration happens instantly
- **No risk** - Original data untouched
- **Wallet backups work** - Use the included backup script:
  ```bash
  neptune-backup-wallet ~/.config/neptune/core/main/
  # Creates: ~/neptune-wallet-backup-20251017.tar.gz
  # Contains: Only wallet files and DB (~100 MB)
  ```

### DataDirectory Implementation

```rust
pub struct DataDirectory {
    wallet_root: PathBuf,      // .../core/main/wallet/
    blockchain_root: PathBuf,  // .../core/main/blockchain/
    node_root: PathBuf,        // .../core/main/
    
    layout_mode: LayoutMode,
}

pub enum LayoutMode {
    /// Legacy: Single root, no separation
    Legacy,
    
    /// In-place: Logical separation with symlinks in same dir
    InPlaceDecoupled {
        base_root: PathBuf,  // Original .../core/main/ location
    },
    
    /// Separated: Physical separation across different dirs
    FullySeparated,
}
```

### Rollback Process

If user wants to revert to old version:

```bash
# 1. Stop new node
systemctl stop neptune-core

# 2. Remove symlinks
rm ~/.config/neptune/core/main/wallet
rm ~/.config/neptune/core/main/blockchain

# 3. Restore original wallet dir name
mv ~/.config/neptune/core/main/wallet_files ~/.config/neptune/core/main/wallet

# 4. Remove metadata
rm ~/.config/neptune/core/main/.layout_v2.json

# 5. Start old version
/path/to/old/neptune-core --data-dir ~/.config/neptune/core/main/
```

**Time to rollback:** < 5 seconds

---

## 3. Option 2: Full Migration

### What It Does

Physically moves data to XDG-compliant separated directories.

### When to Use

- Fresh machine or reinstallation
- User wants full XDG compliance
- User wants encrypted volume for wallet only
- User wants network-attached storage for blockchain

### Process

**Same as documented in main plan**, but with these additions:

1. **Pre-flight checks:**
   ```
   ✓ Checking available disk space...
   ✓ Verifying source data integrity...
   ✓ Ensuring destination paths available...
   ```

2. **Backup creation:**
   ```
   📦 Creating safety backup...
   Backup location: ~/.config/neptune/core/main.backup-20251017/
   Size: 205.3 GB
   [====================================] 100%
   ✓ Backup complete
   ```

3. **Migration with progress:**
   ```
   🔐 Moving wallet data...
   [====================================] 100% (52.3 MB)
   
   ⛓️  Moving blockchain data...
   [====================================] 45% (92.1 GB / 205.3 GB)
   Estimated time remaining: 8 minutes
   ```

4. **Verification:**
   ```
   ✓ Wallet files accessible
   ✓ Wallet DB opens successfully
   ✓ Blockchain DB opens successfully
   ✓ Latest block readable
   ✓ Balance matches pre-migration: 1,234.56 NP
   ```

5. **Cleanup option:**
   ```
   Migration complete! 🎉
   
   Backup location: ~/.config/neptune/core/main.backup-20251017/
   
   Options:
   1. Keep backup (recommended for 7 days)
   2. Delete backup (frees 205 GB)
   3. Delete old directory after backup (frees 205 GB, keep backup)
   
   Choice [1]: _
   ```

### Rollback Process

```bash
# 1. Stop node
systemctl stop neptune-core

# 2. Remove new directories
rm -rf ~/.config/neptune/wallet/main/
rm -rf ~/.local/share/neptune/blockchain/main/

# 3. Restore from backup
mv ~/.config/neptune/core/main.backup-20251017/ \
   ~/.config/neptune/core/main/

# 4. Start with legacy flag
neptune-core --data-dir ~/.config/neptune/core/main/
```

**Time to rollback:** 5-30 minutes (depending on data size)

---

## 4. Option 3: Legacy Mode

### What It Does

Continue using the old monolithic structure with zero changes.

### When to Use

- User has custom scripts that hardcode paths
- Docker deployments with specific volume mounts
- User doesn't want any changes
- User is on a system with limited permissions

### How to Enable

**Explicitly:**
```bash
neptune-core --data-dir ~/.config/neptune/core/main/
```

**Automatically:** If no migration happens, legacy mode stays active.

### Long-Term Support

Legacy mode will be supported **indefinitely** with these considerations:

- **v0.5.x - v0.6.x**: Fully supported, no deprecation warnings
- **v0.7.x+**: Soft deprecation notice at startup (skippable)
- **v1.0+**: Legacy mode may move to separate binary `neptune-core-legacy`

---

## 5. First Startup Experience

### Scenario A: Existing User (Old Structure Detected)

```
🚀 Neptune Core v0.5.0 starting...

📂 Data directory detected: ~/.config/neptune/core/main/
⚠️  Using legacy monolithic structure

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔔 DATA LAYOUT UPGRADE AVAILABLE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Neptune Core v0.5.0 can separate your wallet and blockchain data
for better security and easier backups.

Current layout:
  All data: ~/.config/neptune/core/main/ (205 GB)

Recommended options:

  1. In-place decoupling (RECOMMENDED)
     • Instant (~1 second)
     • No data movement
     • Zero risk
     • Enables wallet-only backups
     • Easy rollback
     
  2. Full migration (for power users)
     • Separates directories physically
     • Wallet: ~/.config/neptune/wallet/main/
     • Blockchain: ~/.local/share/neptune/blockchain/main/
     • Takes 5-30 minutes
     • Requires backup
     
  3. Keep legacy layout
     • No changes
     • Works with existing scripts
     • You can migrate later

Choose an option:
  [1] In-place decoupling (default)
  [2] Full migration
  [3] Keep legacy layout
  [?] Learn more

Choice [1]: _
```

**If user presses Enter (defaults to Option 1):**

```
✓ Creating in-place decoupled layout...
✓ Wallet root: ~/.config/neptune/core/main/wallet/
✓ Blockchain root: ~/.config/neptune/core/main/blockchain/
✓ Layout upgraded successfully!

💡 TIP: Backup your wallet anytime with:
    neptune-cli backup-wallet

🚀 Starting Neptune Core...
```

**If user chooses Option 2 (Full migration):**

```
⚠️  IMPORTANT: Full migration will move data.

Pre-flight checks:
  ✓ Available disk space: 300 GB (need: 205 GB)
  ✓ Write permissions: OK
  ✓ Data integrity: OK

This will:
  1. Create backup at: ~/.config/neptune/core/main.backup-20251017/
  2. Move wallet to: ~/.config/neptune/wallet/main/
  3. Move blockchain to: ~/.local/share/neptune/blockchain/main/
  4. Verify all data accessible

Estimated time: 15 minutes

Proceed? [y/N]: _
```

**If user chooses Option 3 (Legacy):**

```
✓ Continuing with legacy layout

⚠️  Note: To use this layout permanently, add this flag:
    --data-dir ~/.config/neptune/core/main/

You can migrate later with:
    neptune-cli migrate-data-layout

🚀 Starting Neptune Core...
```

### Scenario B: New User (No Existing Data)

```
🚀 Neptune Core v0.5.0 starting...

📂 No existing data directory found
✓ Creating separated layout (recommended)

Wallet directory:     ~/.config/neptune/wallet/main/
Blockchain directory: ~/.local/share/neptune/blockchain/main/

💡 Benefits:
   • Easy wallet backups (without 200+ GB blockchain)
   • Better security (separate encryption policies)
   • Flexible storage (blockchain can be on NAS)

🔐 Enter password for wallet encryption:
```

---

## 6. Implementation Details

### 6.1 DataDirectory Refactor (Updated)

```rust
#[derive(Debug, Clone)]
pub struct DataDirectory {
    wallet_root: PathBuf,
    blockchain_root: PathBuf,
    node_root: PathBuf,
    
    layout_mode: LayoutMode,
}

#[derive(Debug, Clone, PartialEq)]
pub enum LayoutMode {
    /// Legacy: Single root, no separation (v0.1-v0.4)
    Legacy {
        root: PathBuf,
    },
    
    /// In-place: Logical separation with symlinks (v0.5+ default for migrations)
    InPlaceDecoupled {
        root: PathBuf,  // Base directory (e.g., ~/.config/neptune/core/main/)
    },
    
    /// Separated: Physical separation across different dirs (v0.5+ fresh installs)
    FullySeparated,
}

impl DataDirectory {
    /// Smart constructor with interactive migration prompt
    pub async fn get_with_migration_prompt(
        root_dir: Option<PathBuf>,
        wallet_dir: Option<PathBuf>,
        blockchain_dir: Option<PathBuf>,
        network: Network,
        allow_interactive: bool,
    ) -> Result<Self> {
        // Priority 1: Explicit CLI flags (no prompts)
        if wallet_dir.is_some() || blockchain_dir.is_some() {
            return Self::get_separated(wallet_dir, blockchain_dir, network);
        }
        
        if let Some(root) = root_dir {
            return Self::get_legacy(root, network);
        }
        
        // Priority 2: Auto-detect existing structure
        let default_legacy_root = Self::default_legacy_root(network);
        
        if Self::has_old_structure(&default_legacy_root) {
            // Old structure detected - offer migration
            if allow_interactive {
                // Show interactive prompt
                let choice = Self::prompt_migration_choice().await?;
                
                match choice {
                    MigrationChoice::InPlaceDecouple => {
                        Self::perform_in_place_decoupling(&default_legacy_root, network).await?;
                        Self::get_in_place_decoupled(default_legacy_root, network)
                    }
                    MigrationChoice::FullMigration => {
                        Self::perform_full_migration(&default_legacy_root, network).await?;
                        Self::get_separated(None, None, network)
                    }
                    MigrationChoice::KeepLegacy => {
                        warn!("💡 TIP: Add --data-dir flag to skip this prompt in future");
                        Self::get_legacy(None, network)
                    }
                }
            } else {
                // Non-interactive: default to in-place decoupling (safest)
                info!("Non-interactive mode: performing in-place decoupling");
                Self::perform_in_place_decoupling(&default_legacy_root, network).await?;
                Self::get_in_place_decoupled(default_legacy_root, network)
            }
        } else {
            // Fresh install - use separated layout
            Self::get_separated(None, None, network)
        }
    }
    
    /// Get in-place decoupled layout
    fn get_in_place_decoupled(root: PathBuf, network: Network) -> Result<Self> {
        Ok(DataDirectory {
            wallet_root: root.join("wallet"),
            blockchain_root: root.join("blockchain"),
            node_root: root.clone(),
            layout_mode: LayoutMode::InPlaceDecoupled { root },
        })
    }
    
    /// Perform in-place decoupling (instant, no data movement)
    async fn perform_in_place_decoupling(root: &Path, network: Network) -> Result<()> {
        info!("✨ Creating in-place decoupled layout...");
        
        // 1. Rename original wallet dir to avoid confusion
        let old_wallet = root.join("wallet");
        let wallet_files = root.join("wallet_files");
        if old_wallet.exists() {
            tokio::fs::rename(&old_wallet, &wallet_files).await?;
        }
        
        // 2. Create logical structure directories
        tokio::fs::create_dir_all(root.join("wallet")).await?;
        tokio::fs::create_dir_all(root.join("blockchain")).await?;
        
        // 3. Create symlinks for wallet
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(
                &wallet_files,
                root.join("wallet/files"),
            )?;
            std::os::unix::fs::symlink(
                root.join("database/wallet"),
                root.join("wallet/database"),
            )?;
        }
        
        // 4. Create symlinks for blockchain
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(
                root.join("database"),
                root.join("blockchain/database"),
            )?;
            std::os::unix::fs::symlink(
                root.join("blocks"),
                root.join("blockchain/blocks"),
            )?;
        }
        
        // 5. Create metadata file
        let metadata = LayoutMetadata {
            version: 2,
            layout_type: "in_place_decoupled".to_string(),
            wallet_root: "wallet/".to_string(),
            blockchain_root: "blockchain/".to_string(),
            created_at: chrono::Utc::now(),
        };
        
        let metadata_json = serde_json::to_string_pretty(&metadata)?;
        tokio::fs::write(root.join(".layout_v2.json"), metadata_json).await?;
        
        info!("✓ In-place decoupling complete!");
        info!("✓ Wallet root: {}", root.join("wallet").display());
        info!("✓ Blockchain root: {}", root.join("blockchain").display());
        
        Ok(())
    }
    
    /// Interactive migration prompt
    async fn prompt_migration_choice() -> Result<MigrationChoice> {
        use dialoguer::{Select, theme::ColorfulTheme};
        
        println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("🔔 DATA LAYOUT UPGRADE AVAILABLE");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
        
        let choices = vec![
            "In-place decoupling (RECOMMENDED) - Instant, no data movement",
            "Full migration - Physically separate wallet/blockchain directories",
            "Keep legacy layout - No changes",
        ];
        
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Choose upgrade option")
            .items(&choices)
            .default(0)
            .interact()?;
        
        Ok(match selection {
            0 => MigrationChoice::InPlaceDecouple,
            1 => MigrationChoice::FullMigration,
            2 => MigrationChoice::KeepLegacy,
            _ => unreachable!(),
        })
    }
}

#[derive(Debug)]
enum MigrationChoice {
    InPlaceDecouple,
    FullMigration,
    KeepLegacy,
}

#[derive(Debug, Serialize, Deserialize)]
struct LayoutMetadata {
    version: u8,
    layout_type: String,
    wallet_root: String,
    blockchain_root: String,
    created_at: chrono::DateTime<chrono::Utc>,
}
```

### 6.2 Wallet Backup Script (NEW)

**File: `neptune-core-cli/src/commands/backup_wallet.rs`**

```rust
//! Wallet backup command - creates minimal backup of wallet data only

use anyhow::Result;
use std::path::Path;
use tar::Builder;
use flate2::Compression;
use flate2::write::GzEncoder;

pub async fn backup_wallet(data_dir: &Path, output_path: Option<&Path>) -> Result<()> {
    let layout = detect_layout(data_dir)?;
    
    let backup_name = format!(
        "neptune-wallet-backup-{}.tar.gz",
        chrono::Utc::now().format("%Y%m%d-%H%M%S")
    );
    
    let output = output_path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::env::current_dir().unwrap().join(&backup_name));
    
    info!("📦 Creating wallet backup...");
    info!("Output: {}", output.display());
    
    let file = std::fs::File::create(&output)?;
    let encoder = GzEncoder::new(file, Compression::default());
    let mut tar = Builder::new(encoder);
    
    match layout {
        LayoutMode::InPlaceDecoupled { root } => {
            // Backup wallet files
            tar.append_dir_all("wallet/files", root.join("wallet_files"))?;
            // Backup wallet database
            tar.append_dir_all("wallet/database", root.join("database/wallet"))?;
            // Backup UTXO transfer files
            if root.join("utxo-transfer").exists() {
                tar.append_dir_all("utxo-transfer", root.join("utxo-transfer"))?;
            }
        }
        LayoutMode::FullySeparated { wallet_root } => {
            tar.append_dir_all("wallet", wallet_root)?;
        }
        LayoutMode::Legacy { root } => {
            tar.append_dir_all("wallet/files", root.join("wallet"))?;
            tar.append_dir_all("wallet/database", root.join("database/wallet"))?;
            if root.join("utxo-transfer").exists() {
                tar.append_dir_all("utxo-transfer", root.join("utxo-transfer"))?;
            }
        }
    }
    
    tar.finish()?;
    
    let size = tokio::fs::metadata(&output).await?.len();
    info!("✓ Backup complete: {} ({} MB)", output.display(), size / 1_000_000);
    info!("💡 Store this backup securely - it contains your wallet secrets!");
    
    Ok(())
}
```

---

## 7. Recovery Scenarios

### Scenario 1: In-Place Decoupling Gone Wrong

**Problem:** Symlinks broken, node won't start

**Recovery:**
```bash
# Quick fix: Just use legacy mode
neptune-core --data-dir ~/.config/neptune/core/main/

# Or: Restore original structure
rm -rf ~/.config/neptune/core/main/wallet/
rm -rf ~/.config/neptune/core/main/blockchain/
mv ~/.config/neptune/core/main/wallet_files ~/.config/neptune/core/main/wallet
rm ~/.config/neptune/core/main/.layout_v2.json
```

### Scenario 2: Full Migration Interrupted

**Problem:** Power loss during migration

**Recovery:**
```bash
# Restore from auto-created backup
rm -rf ~/.config/neptune/wallet/main/
rm -rf ~/.local/share/neptune/blockchain/main/
mv ~/.config/neptune/core/main.backup-20251017/ \
   ~/.config/neptune/core/main/
```

### Scenario 3: Wallet Backup Restore

**Problem:** Need to restore wallet from backup

**Recovery:**
```bash
# Extract backup
tar -xzf neptune-wallet-backup-20251017.tar.gz -C /tmp/

# Stop node
systemctl stop neptune-core

# Restore wallet files
rsync -av /tmp/wallet/ ~/.config/neptune/wallet/main/

# Restart node
systemctl start neptune-core
```

---

## 8. Success Metrics

**In-Place Decoupling:**
- ✅ Completes in < 1 second
- ✅ Zero data loss reports
- ✅ 100% rollback success rate
- ✅ Wallet backup script works

**Full Migration:**
- ✅ < 0.1% data loss (all from user error, not migration bugs)
- ✅ > 95% completion rate (not abandoned mid-migration)
- ✅ < 30 minutes for 200 GB blockchain
- ✅ Automatic backup created every time

**User Satisfaction:**
- ✅ > 80% choose in-place decoupling (validates default choice)
- ✅ < 5% choose legacy mode (shows upgrade value)
- ✅ < 1% support requests related to migration

---

## 9. FAQ for Users

**Q: Which option should I choose?**
**A:** For 95% of users, "In-place decoupling" (option 1) is perfect. It's instant, safe, and gives you all the benefits of separation without any risk.

**Q: Can I switch from in-place to full migration later?**
**A:** Yes! Run `neptune-cli migrate-data-layout --full` anytime.

**Q: What if I have custom scripts that use hardcoded paths?**
**A:** Choose "Keep legacy layout" (option 3) and use `--data-dir` flag. Your scripts will work unchanged.

**Q: Will this affect my wallet balance?**
**A:** No. This only reorganizes files, it doesn't change any wallet or blockchain data.

**Q: How do I backup just my wallet now?**
**A:** Use `neptune-cli backup-wallet` - it creates a small backup (~100 MB) with just your wallet, no blockchain.

**Q: Can I undo the in-place decoupling?**
**A:** Yes, it takes < 5 seconds. See "Rollback Process" above.

---

**Document Version:** 1.0
**Last Updated:** 2025-10-17
**Status:** Ready for Implementation
**Depends On:** Phase 2 Main Plan
**Author:** Sea of Freedom Development Team

