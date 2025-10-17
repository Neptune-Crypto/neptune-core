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
    /// 3. Old layout exists (~/.config/neptune/core/<network>/) → Use legacy mode
    /// 4. Neither exists → Create new layout
    ///
    /// New default location: ~/.neptune/<network>/
    /// Legacy location: ~/.config/neptune/core/<network>/
    pub fn get(root_dir: Option<PathBuf>, network: Network) -> Result<Self> {
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

        // Priority 3: Old layout exists → Legacy mode (with migration suggestion)
        if Self::has_old_layout(&old_root) {
            warn!("⚠️  Using legacy data layout: {}", old_root.display());
            warn!("💡 Consider migrating to new layout with: neptune-cli migrate-data-layout");
            warn!("   Or the node will prompt you on next startup");
            return Ok(Self {
                root: old_root,
                network,
                layout_mode: LayoutMode::Legacy,
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

    /// Default root for old layout: ~/.config/neptune/core/<network>/ (or OS equivalent)
    fn default_old_root(network: Network) -> Result<PathBuf> {
        let project_dirs = ProjectDirs::from("org", "neptune", "neptune")
            .context("Could not determine data directory")?;

        let network_dir = network.to_string();
        let data_dir = project_dirs.data_dir().to_path_buf().join(network_dir);

        Ok(data_dir)
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
