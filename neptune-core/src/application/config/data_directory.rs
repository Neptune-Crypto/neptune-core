use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;
use directories::ProjectDirs;
use serde::Deserialize;
use serde::Serialize;
use tracing::{info, warn};

use crate::application::config::network::Network;
use crate::state::archival_state::ARCHIVAL_BLOCK_MMR_DIRECTORY_NAME;
use crate::state::archival_state::BLOCK_INDEX_DB_NAME;
use crate::state::archival_state::MUTATOR_SET_DIRECTORY_NAME;
use crate::state::database::DATABASE_DIRECTORY_ROOT_NAME;
use crate::state::networking_state::BANNED_IPS_DB_NAME;
use crate::state::shared::BLOCK_FILENAME_EXTENSION;
use crate::state::shared::BLOCK_FILENAME_PREFIX;
use crate::state::shared::DIR_NAME_FOR_BLOCKS;
use crate::state::wallet::wallet_file::WALLET_DB_NAME;
use crate::state::wallet::wallet_file::WALLET_DIRECTORY;
use crate::state::wallet::wallet_file::WALLET_OUTPUT_COUNT_DB_NAME;

const UTXO_TRANSFER_DIRECTORY: &str = "utxo-transfer";
const RPC_COOKIE_FILE_NAME: &str = ".cookie"; // matches bitcoin-core name.
const DB_MIGRATION_BACKUPS_DIR: &str = "migration_backups";

// Phase 2: New layout constants
const WALLET_SUBDIR: &str = "wallet";
const CHAIN_SUBDIR: &str = "chain";
const WALLET_DB_SUBDIR: &str = "db";
const CHAIN_DB_SUBDIR: &str = "db";
const BLOCKS_SUBDIR: &str = "blocks";

/// Layout mode for data directory organization
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
enum LayoutMode {
    /// Legacy mode: Monolithic structure (v0.1-v0.4)
    /// All data in one directory: ~/.config/neptune/core/<network>/
    Legacy,

    /// New mode: Separated structure (v0.5+)
    /// wallet/ and chain/ subdirectories: ~/.neptune/<network>/
    Separated,
}

// TODO: Add `rusty_leveldb::Options` and `fs::OpenOptions` here too, since they keep being repeated.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DataDirectory {
    /// Root directory for all neptune data
    /// - Legacy mode: ~/.config/neptune/core/<network>/
    /// - New mode: ~/.neptune/<network>/
    root: PathBuf,

    /// Network name (main, testnet, etc.)
    network: Network,

    /// Layout mode: Legacy or Separated
    layout_mode: LayoutMode,
}

impl DataDirectory {
    ///////////////////////////////////////////////////////////////////////////
    ///
    /// Get data directory with smart layout detection and migration support
    ///
    /// Priority order:
    /// 1. Explicit `root_dir` → Use as legacy mode
    /// 2. New layout exists (~/.neptune/<network>/) → Use it
    /// 3. Old layout exists (~/.config/neptune/core/<network>/) → Migrate and use new layout
    /// 4. Neither exists → Create new layout
    ///
    /// New default location: ~/.neptune/<network>/
    /// Legacy location: ~/.config/neptune/core/<network>/
    pub async fn get(root_dir: Option<PathBuf>, network: Network) -> Result<Self> {
        // Priority 1: Explicit root_dir → Legacy mode
        if let Some(explicit_root) = root_dir {
            info!(
                "Using explicit data directory (legacy mode): {}",
                explicit_root.display()
            );
            return Ok(Self {
                root: explicit_root,
                network,
                layout_mode: LayoutMode::Legacy,
            });
        }

        // Get default paths for detection
        let new_root = Self::default_new_root();
        let new_network_dir = new_root.join(network.to_string());
        let old_root = Self::default_old_root(network)?;

        // Priority 2: New layout exists → Use it
        if Self::has_new_layout(&new_network_dir) {
            info!("Using new data layout: {}", new_network_dir.display());
            return Ok(Self {
                root: new_network_dir,
                network,
                layout_mode: LayoutMode::Separated,
            });
        }

        // Priority 3: Old layout exists → Migrate to new layout
        if Self::has_old_layout(&old_root) {
            warn!("⚠️  Detected legacy data layout: {}", old_root.display());
            info!("🔄 Automatically migrating to new layout...");

            // Perform migration
            Self::migrate_to_new_layout(&old_root, &new_network_dir, network).await?;

            info!(
                "✅ Migration successful! Using new layout: {}",
                new_network_dir.display()
            );
            return Ok(Self {
                root: new_network_dir,
                network,
                layout_mode: LayoutMode::Separated,
            });
        }

        // Priority 4: Fresh install → Use new layout
        info!("Creating new data layout: {}", new_network_dir.display());
        Ok(Self {
            root: new_network_dir,
            network,
            layout_mode: LayoutMode::Separated,
        })
    }

    /// Default root for new layout: ~/.neptune/
    fn default_new_root() -> PathBuf {
        dirs::home_dir()
            .expect("Could not determine home directory")
            .join(".neptune")
    }

    /// Default root for old layout: tries multiple legacy locations
    /// - ~/.local/share/neptune/<network>/ (older versions)
    /// - ~/.local/share/neptune/core/<network>/ (some versions had "core" subdir)
    fn default_old_root(network: Network) -> Result<PathBuf> {
        let project_dirs = ProjectDirs::from("org", "neptune", "neptune")
            .context("Could not determine data directory")?;

        let network_dir = network.to_string();
        let base_dir = project_dirs.data_dir().to_path_buf();

        // Try direct path first (most common for main network)
        let direct_path = base_dir.join(&network_dir);
        if Self::has_old_layout(&direct_path) {
            return Ok(direct_path);
        }

        // Fall back to core subdirectory path (used by some networks like regtest)
        let core_path = base_dir.join("core").join(&network_dir);
        Ok(core_path)
    }

    /// Check if new layout exists
    fn has_new_layout(network_dir: &Path) -> bool {
        // New layout has wallet/wallet.encrypted or wallet/wallet.dat
        let wallet_dir = network_dir.join(WALLET_SUBDIR);
        wallet_dir.join("wallet.encrypted").exists() || wallet_dir.join("wallet.dat").exists()
    }

    /// Check if old layout exists
    fn has_old_layout(old_root: &Path) -> bool {
        // Old layout has wallet/wallet.encrypted or wallet/wallet.dat at root
        let wallet_dir = old_root.join(WALLET_DIRECTORY);
        wallet_dir.join("wallet.encrypted").exists() || wallet_dir.join("wallet.dat").exists()
    }

    /// Migrate from old layout to new layout
    ///
    /// Moves files from ~/.config/neptune/core/<network>/ to ~/.neptune/<network>/
    /// with wallet/ and chain/ subdirectories.
    ///
    /// This is a destructive operation but creates a backup at old_root.backup
    pub async fn migrate_to_new_layout(
        old_root: &Path,
        new_root: &Path,
        network: Network,
    ) -> Result<()> {
        info!("🔄 Starting data layout migration...");
        info!("  From: {}", old_root.display());
        info!("  To:   {}", new_root.display());

        // 1. Create backup marker at old location (before any moves)
        let backup_marker = old_root.join(".migrated_to_v2");
        let migration_info = format!(
            "Migrated to: {}\nDate: {:?}\nNetwork: {}",
            new_root.display(),
            std::time::SystemTime::now(),
            network
        );
        tokio::fs::write(&backup_marker, migration_info)
            .await
            .context("Failed to create migration marker")?;

        // 2. Create new directory structure
        info!("📁 Creating new directory structure...");
        tokio::fs::create_dir_all(new_root.join(WALLET_SUBDIR))
            .await
            .context("Failed to create wallet directory")?;
        tokio::fs::create_dir_all(new_root.join(WALLET_SUBDIR).join(WALLET_DB_SUBDIR))
            .await
            .context("Failed to create wallet db directory")?;
        tokio::fs::create_dir_all(new_root.join(CHAIN_SUBDIR).join(CHAIN_DB_SUBDIR))
            .await
            .context("Failed to create chain db directory")?;
        tokio::fs::create_dir_all(new_root.join(CHAIN_SUBDIR).join(BLOCKS_SUBDIR))
            .await
            .context("Failed to create blocks directory")?;

        // 3. Move wallet files
        info!("📦 Moving wallet data...");
        Self::move_wallet_data(old_root, new_root).await?;

        // 4. Move blockchain data
        info!("⛓️  Moving blockchain data (this may take a while)...");
        Self::move_blockchain_data(old_root, new_root).await?;

        // 5. Rename old directory to .backup
        let backup_dir = old_root.with_extension("backup");
        info!(
            "💾 Creating backup of old location: {}",
            backup_dir.display()
        );
        tokio::fs::rename(old_root, &backup_dir)
            .await
            .context("Failed to rename old directory to backup")?;

        info!("✅ Migration complete!");
        info!("  New location: {}", new_root.display());
        info!("  Backup: {}", backup_dir.display());
        info!("💡 After verifying everything works, you can delete the backup:");
        info!("   rm -rf {}", backup_dir.display());

        Ok(())
    }

    /// Move wallet data from old to new layout
    async fn move_wallet_data(old_root: &Path, new_root: &Path) -> Result<()> {
        // Move wallet files (wallet.encrypted, *.dat)
        let old_wallet_dir = old_root.join(WALLET_DIRECTORY);
        let new_wallet_dir = new_root.join(WALLET_SUBDIR);

        if old_wallet_dir.exists() {
            // Move all files from old wallet dir to new wallet dir
            Self::move_dir_contents(&old_wallet_dir, &new_wallet_dir, &["*"])
                .await
                .context("Failed to move wallet files")?;
        }

        // Move wallet database
        let old_wallet_db = old_root
            .join(DATABASE_DIRECTORY_ROOT_NAME)
            .join(WALLET_DB_NAME);
        let new_wallet_db = new_root
            .join(WALLET_SUBDIR)
            .join(WALLET_DB_SUBDIR)
            .join(WALLET_DB_NAME);

        if old_wallet_db.exists() {
            tokio::fs::rename(&old_wallet_db, &new_wallet_db)
                .await
                .with_context(|| {
                    format!(
                        "Failed to move wallet database from {} to {}",
                        old_wallet_db.display(),
                        new_wallet_db.display()
                    )
                })?;
        }

        // Move UTXO transfer files (if exist)
        let old_utxo_transfer = old_root.join(UTXO_TRANSFER_DIRECTORY);
        let new_utxo_transfer = new_root.join(WALLET_SUBDIR).join(UTXO_TRANSFER_DIRECTORY);

        if old_utxo_transfer.exists() {
            tokio::fs::rename(&old_utxo_transfer, &new_utxo_transfer)
                .await
                .with_context(|| {
                    format!(
                        "Failed to move utxo-transfer from {} to {}",
                        old_utxo_transfer.display(),
                        new_utxo_transfer.display()
                    )
                })?;
        }

        Ok(())
    }

    /// Move blockchain data from old to new layout
    async fn move_blockchain_data(old_root: &Path, new_root: &Path) -> Result<()> {
        let old_db_dir = old_root.join(DATABASE_DIRECTORY_ROOT_NAME);
        let new_db_dir = new_root.join(CHAIN_SUBDIR).join(CHAIN_DB_SUBDIR);

        // Move blockchain databases
        let blockchain_dbs = [
            BLOCK_INDEX_DB_NAME,
            MUTATOR_SET_DIRECTORY_NAME,
            ARCHIVAL_BLOCK_MMR_DIRECTORY_NAME,
            BANNED_IPS_DB_NAME,
        ];

        for db_name in &blockchain_dbs {
            let old_db = old_db_dir.join(db_name);
            let new_db = new_db_dir.join(db_name);

            if old_db.exists() {
                tokio::fs::rename(&old_db, &new_db).await.with_context(|| {
                    format!(
                        "Failed to move database {} from {} to {}",
                        db_name,
                        old_db.display(),
                        new_db.display()
                    )
                })?;
            }
        }

        // Move migration backups directory if it exists
        let old_migration_backups = old_db_dir.join(DB_MIGRATION_BACKUPS_DIR);
        let new_migration_backups = new_db_dir.join(DB_MIGRATION_BACKUPS_DIR);

        if old_migration_backups.exists() {
            tokio::fs::rename(&old_migration_backups, &new_migration_backups)
                .await
                .with_context(|| {
                    format!(
                        "Failed to move migration_backups from {} to {}",
                        old_migration_backups.display(),
                        new_migration_backups.display()
                    )
                })?;
        }

        // Move blocks
        let old_blocks = old_root.join(DIR_NAME_FOR_BLOCKS);
        let new_blocks = new_root.join(CHAIN_SUBDIR).join(BLOCKS_SUBDIR);

        if old_blocks.exists() {
            tokio::fs::rename(&old_blocks, &new_blocks)
                .await
                .with_context(|| {
                    format!(
                        "Failed to move blocks from {} to {}",
                        old_blocks.display(),
                        new_blocks.display()
                    )
                })?;
        }

        Ok(())
    }

    /// Move contents of a directory matching patterns
    async fn move_dir_contents(
        from_dir: &Path,
        to_dir: &Path,
        _patterns: &[&str], // patterns for future filtering if needed
    ) -> Result<()> {
        if !from_dir.exists() {
            return Ok(());
        }

        // Ensure destination exists
        tokio::fs::create_dir_all(to_dir).await?;

        // Read directory contents
        let mut entries = tokio::fs::read_dir(from_dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            let file_name = entry.file_name();
            let from_path = entry.path();
            let to_path = to_dir.join(&file_name);

            // Move file or directory
            tokio::fs::rename(&from_path, &to_path)
                .await
                .with_context(|| {
                    format!(
                        "Failed to move {} to {}",
                        from_path.display(),
                        to_path.display()
                    )
                })?;
        }

        Ok(())
    }

    /// Create directory if it does not exist
    pub async fn create_dir_if_not_exists(dir: &Path) -> Result<()> {
        tokio::fs::create_dir_all(dir)
            .await
            .with_context(|| format!("Failed to create data directory {}", dir.display()))
    }

    /// Open file, create parent directory if it does not exist
    pub async fn open_ensure_parent_dir_exists(file_path: &Path) -> Result<tokio::fs::File> {
        let parent_dir = file_path
            .parent()
            .with_context(|| format!("The parent directory of {:?}", file_path))?;
        Self::create_dir_if_not_exists(parent_dir).await?;

        tokio::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(file_path)
            .await
            .context("open_ensure_parent_dir_exists")
    }

    ///////////////////////////////////////////////////////////////////////////
    ///
    /// The root data directory path
    pub fn root_dir_path(&self) -> PathBuf {
        self.root.clone()
    }

    /// Get wallet root directory (for backups and isolation)
    pub fn wallet_root(&self) -> PathBuf {
        match self.layout_mode {
            LayoutMode::Legacy => self.root.clone(),
            LayoutMode::Separated => self.root.join(WALLET_SUBDIR),
        }
    }

    /// Get blockchain root directory (for separate storage)
    pub fn blockchain_root(&self) -> PathBuf {
        match self.layout_mode {
            LayoutMode::Legacy => self.root.clone(),
            LayoutMode::Separated => self.root.join(CHAIN_SUBDIR),
        }
    }

    ///////////////////////////////////////////////////////////////////////////
    ///
    /// The rpc (auth) cookie file path
    pub fn rpc_cookie_file_path(&self) -> PathBuf {
        self.root.join(RPC_COOKIE_FILE_NAME)
    }

    /// The blockchain database directory path
    /// - Legacy: <root>/database/
    /// - New: <root>/chain/db/
    pub fn database_dir_path(&self) -> PathBuf {
        match self.layout_mode {
            LayoutMode::Legacy => self.root.join(DATABASE_DIRECTORY_ROOT_NAME),
            LayoutMode::Separated => self.root.join(CHAIN_SUBDIR).join(CHAIN_DB_SUBDIR),
        }
    }

    ///////////////////////////////////////////////////////////////////////////
    ///
    /// The banned IPs database directory path.
    ///
    /// This directory lives within `DataDirectory::database_dir_path()`.
    pub fn banned_ips_database_dir_path(&self) -> PathBuf {
        self.database_dir_path().join(Path::new(BANNED_IPS_DB_NAME))
    }

    ///////////////////////////////////////////////////////////////////////////
    ///
    /// utxo-transfer path
    ///
    /// for storing off-chain serialized transfer files.
    ///
    /// note: this is not used by neptune-core, but is used/shared by
    ///       neptune-cli, neptune-dashboard
    ///
    /// - Legacy: <root>/utxo-transfer/
    /// - New: <root>/wallet/utxo-transfer/
    pub fn utxo_transfer_directory_path(&self) -> PathBuf {
        match self.layout_mode {
            LayoutMode::Legacy => self.root.join(UTXO_TRANSFER_DIRECTORY),
            LayoutMode::Separated => self.root.join(WALLET_SUBDIR).join(UTXO_TRANSFER_DIRECTORY),
        }
    }

    ///////////////////////////////////////////////////////////////////////////
    ///
    /// The wallet file directory path
    /// - Legacy: <root>/wallet/
    /// - New: <root>/wallet/
    pub fn wallet_directory_path(&self) -> PathBuf {
        match self.layout_mode {
            LayoutMode::Legacy => self.root.join(WALLET_DIRECTORY),
            LayoutMode::Separated => self.root.join(WALLET_SUBDIR),
        }
    }

    /// The wallet database directory path.
    /// - Legacy: <root>/database/wallet/
    /// - New: <root>/wallet/db/wallet/
    pub fn wallet_database_dir_path(&self) -> PathBuf {
        match self.layout_mode {
            LayoutMode::Legacy => self.database_dir_path().join(WALLET_DB_NAME),
            LayoutMode::Separated => self
                .root
                .join(WALLET_SUBDIR)
                .join(WALLET_DB_SUBDIR)
                .join(WALLET_DB_NAME),
        }
    }

    /// directory for storing database backups before migrating schema to newer version
    pub fn db_migration_backups_dir_path(&self) -> PathBuf {
        self.database_dir_path()
            .join(Path::new(DB_MIGRATION_BACKUPS_DIR))
    }

    /// returns next unused path for wallet database backup
    ///
    /// This is useful when creating a backup, to avoid overwriting
    /// a previous backup.
    ///
    /// notes:
    /// 1. backup directory is `<wallet_db_name>-schema-v<schema-version>.bak.<count>`
    /// 2. will try up to 1000 backup directory names, incrementing a counter.
    ///
    /// Returns None if:
    /// 1. wallet DB path is the filesystem root
    /// 2. 1000 backup directories already exist
    pub(crate) fn wallet_db_next_unused_migration_backup_path(
        &self,
        schema_version: u16,
    ) -> Option<PathBuf> {
        self.db_next_unused_migration_backup_path(WALLET_DB_NAME, schema_version)
    }

    // internal fn. all DBs can be backed up into the same "migration_backups" dir.
    fn db_next_unused_migration_backup_path(
        &self,
        db_name: &str,
        schema_version: u16,
    ) -> Option<PathBuf> {
        let path = self.db_migration_backups_dir_path();
        let max_tries = 1000;

        // increment filename until we find an unused path or exhaust tries.
        (1..=max_tries)
            .map(|i| path.join(format!("{}.schema-v{}.bak.{}", db_name, schema_version, i)))
            .find(|p| !p.exists())
    }

    /// The wallet output count database directory path.
    ///
    /// This directory lives within `DataDirectory::database_dir_path()`.
    pub fn wallet_output_count_database_dir_path(&self) -> PathBuf {
        self.database_dir_path()
            .join(Path::new(WALLET_OUTPUT_COUNT_DB_NAME))
    }

    ///////////////////////////////////////////////////////////////////////////
    ///
    /// The mutator set database directory path.
    ///
    /// This directory lives within `DataDirectory::database_dir_path()`.
    pub fn mutator_set_database_dir_path(&self) -> PathBuf {
        self.database_dir_path()
            .join(Path::new(MUTATOR_SET_DIRECTORY_NAME))
    }

    ///////////////////////////////////////////////////////////////////////////
    ///
    /// The archival block MMR database director path
    ///
    /// This directory lives within `DataDirectory::database_dir_path()`.
    pub fn archival_block_mmr_dir_path(&self) -> PathBuf {
        self.database_dir_path()
            .join(Path::new(ARCHIVAL_BLOCK_MMR_DIRECTORY_NAME))
    }

    ///////////////////////////////////////////////////////////////////////////
    ///
    /// The block body directory.
    /// - Legacy: <root>/blocks/
    /// - New: <root>/chain/blocks/
    pub fn block_dir_path(&self) -> PathBuf {
        match self.layout_mode {
            LayoutMode::Legacy => self.root.join(DIR_NAME_FOR_BLOCKS),
            LayoutMode::Separated => self.root.join(CHAIN_SUBDIR).join(BLOCKS_SUBDIR),
        }
    }

    /// The block index database directory path.
    ///
    /// This directory lives within `DataDirectory::database_dir_path()`.
    pub fn block_index_database_dir_path(&self) -> PathBuf {
        self.database_dir_path()
            .join(Path::new(BLOCK_INDEX_DB_NAME))
    }

    /// The file path that contains block(s) with `file_index`.
    ///
    /// Note that multiple blocks can be stored in one block file.
    ///
    /// This directory lives within `DataDirectory::block_dir_path()`.
    pub fn block_file_path(&self, file_index: u32) -> PathBuf {
        let prefix = BLOCK_FILENAME_PREFIX;
        let extension = BLOCK_FILENAME_EXTENSION;
        let block_file_name = format!("{prefix}{file_index}.{extension}");

        self.block_dir_path().join(Path::new(&block_file_name))
    }
}

impl std::fmt::Display for DataDirectory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.layout_mode {
            LayoutMode::Legacy => write!(f, "Legacy: {}", self.root.display()),
            LayoutMode::Separated => write!(
                f,
                "Wallet: {}, Chain: {}",
                self.wallet_root().display(),
                self.blockchain_root().display()
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Test that explicit data directory uses legacy mode
    #[tokio::test]
    async fn test_explicit_data_dir_uses_legacy_mode() {
        let temp_dir = TempDir::new().unwrap();
        let explicit_path = temp_dir.path().to_path_buf();

        let data_dir = DataDirectory::get(Some(explicit_path.clone()), Network::RegTest)
            .await
            .unwrap();

        assert_eq!(data_dir.layout_mode, LayoutMode::Legacy);
        assert_eq!(data_dir.root_dir_path(), explicit_path);
    }

    /// Test that new installation creates separated layout
    #[tokio::test]
    async fn test_fresh_install_creates_separated_layout() {
        let temp_dir = TempDir::new().unwrap();

        // Mock the home directory
        std::env::set_var("HOME", temp_dir.path());

        let data_dir = DataDirectory::get(None, Network::RegTest).await.unwrap();

        assert_eq!(data_dir.layout_mode, LayoutMode::Separated);
        assert!(data_dir
            .root_dir_path()
            .to_string_lossy()
            .contains("regtest"));
    }

    /// Test path resolution for separated layout
    #[tokio::test]
    async fn test_separated_layout_paths() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path().join(".neptune").join("regtest");

        let data_dir = DataDirectory {
            root: root.clone(),
            network: Network::RegTest,
            layout_mode: LayoutMode::Separated,
        };

        // Check wallet paths
        assert_eq!(data_dir.wallet_directory_path(), root.join(WALLET_SUBDIR));
        assert_eq!(
            data_dir.wallet_database_dir_path(),
            root.join(WALLET_SUBDIR)
                .join(WALLET_DB_SUBDIR)
                .join(WALLET_DB_NAME)
        );

        // Check blockchain paths
        assert_eq!(
            data_dir.database_dir_path(),
            root.join(CHAIN_SUBDIR).join(CHAIN_DB_SUBDIR)
        );
        assert_eq!(
            data_dir.block_dir_path(),
            root.join(CHAIN_SUBDIR).join(BLOCKS_SUBDIR)
        );
    }

    /// Test path resolution for legacy layout
    #[tokio::test]
    async fn test_legacy_layout_paths() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path().to_path_buf();

        let data_dir = DataDirectory {
            root: root.clone(),
            network: Network::RegTest,
            layout_mode: LayoutMode::Legacy,
        };

        // Check paths use old structure
        assert_eq!(
            data_dir.wallet_directory_path(),
            root.join(WALLET_DIRECTORY)
        );
        assert_eq!(
            data_dir.database_dir_path(),
            root.join(DATABASE_DIRECTORY_ROOT_NAME)
        );
        assert_eq!(data_dir.block_dir_path(), root.join(DIR_NAME_FOR_BLOCKS));
    }

    /// Test wallet_root and blockchain_root methods
    #[tokio::test]
    async fn test_root_getters() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path().join(".neptune").join("regtest");

        // Separated layout
        let separated = DataDirectory {
            root: root.clone(),
            network: Network::RegTest,
            layout_mode: LayoutMode::Separated,
        };

        assert_eq!(separated.wallet_root(), root.join(WALLET_SUBDIR));
        assert_eq!(separated.blockchain_root(), root.join(CHAIN_SUBDIR));

        // Legacy layout
        let legacy_root = temp_dir.path().join("legacy");
        let legacy = DataDirectory {
            root: legacy_root.clone(),
            network: Network::RegTest,
            layout_mode: LayoutMode::Legacy,
        };

        assert_eq!(legacy.wallet_root(), legacy_root);
        assert_eq!(legacy.blockchain_root(), legacy_root);
    }

    /// Test Display trait implementation
    #[tokio::test]
    async fn test_display_format() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path().to_path_buf();

        let legacy = DataDirectory {
            root: root.clone(),
            network: Network::RegTest,
            layout_mode: LayoutMode::Legacy,
        };

        let display = format!("{}", legacy);
        assert!(display.contains("Legacy"));
        assert!(display.contains(&root.display().to_string()));

        let separated = DataDirectory {
            root: root.clone(),
            network: Network::RegTest,
            layout_mode: LayoutMode::Separated,
        };

        let display = format!("{}", separated);
        assert!(display.contains("Wallet"));
        assert!(display.contains("Chain"));
    }

    /// Test that has_new_layout correctly detects new layout
    #[tokio::test]
    async fn test_has_new_layout_detection() {
        let temp_dir = TempDir::new().unwrap();
        let network_dir = temp_dir.path().join("regtest");

        // Should return false when no wallet exists
        assert!(!DataDirectory::has_new_layout(&network_dir));

        // Create wallet directory and encrypted wallet file
        let wallet_dir = network_dir.join(WALLET_SUBDIR);
        std::fs::create_dir_all(&wallet_dir).unwrap();
        std::fs::write(wallet_dir.join("wallet.encrypted"), "test").unwrap();

        // Should now detect new layout
        assert!(DataDirectory::has_new_layout(&network_dir));
    }

    /// Test that has_old_layout correctly detects old layout
    #[tokio::test]
    async fn test_has_old_layout_detection() {
        let temp_dir = TempDir::new().unwrap();
        let old_root = temp_dir.path().to_path_buf();

        // Should return false when no wallet exists
        assert!(!DataDirectory::has_old_layout(&old_root));

        // Create wallet directory and wallet.dat file (old structure)
        let wallet_dir = old_root.join(WALLET_DIRECTORY);
        std::fs::create_dir_all(&wallet_dir).unwrap();
        std::fs::write(wallet_dir.join("wallet.dat"), "test").unwrap();

        // Should now detect old layout
        assert!(DataDirectory::has_old_layout(&old_root));
    }
}
