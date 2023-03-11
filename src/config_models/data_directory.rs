use anyhow::{Context, Result};
use directories::ProjectDirs;
use std::fs;
use std::path::{Path, PathBuf};

use crate::config_models::network::Network;
use crate::models::database::DATABASE_DIRECTORY_ROOT_NAME;
use crate::models::state::archival_state::{BLOCK_INDEX_DB_NAME, MUTATOR_SET_DIRECTORY_NAME};
use crate::models::state::networking_state::BANNED_IPS_DB_NAME;
use crate::models::state::shared::{
    BLOCK_FILENAME_EXTENSION, BLOCK_FILENAME_PREFIX, DIR_NAME_FOR_BLOCKS,
};
use crate::models::state::wallet::{WALLET_DB_NAME, WALLET_FILE_NAME, WALLET_OUTPUT_COUNT_DB_NAME};

// TODO: Add `rusty_leveldb::Options` and `fs::OpenOptions` here too, since they keep being repeated.
#[derive(Debug, Clone)]
pub struct DataDirectory {
    data_dir: PathBuf,
}

impl DataDirectory {
    ///////////////////////////////////////////////////////////////////////////
    ///
    /// The data directory that contains the wallet and blockchain state
    ///
    /// The default varies by operating system, and includes the network, e.g.
    ///
    /// - Linux:   /home/alice/.config/neptune/core/main
    /// - Windows: C:\Users\Alice\AppData\Roaming\neptune\core\main
    /// - macOS:   /Users/Alice/Library/Application Support/neptune/main
    pub fn get(root_dir: Option<PathBuf>, network: Network) -> Result<Self> {
        let project_dirs = root_dir
            .map(ProjectDirs::from_path)
            .unwrap_or_else(|| ProjectDirs::from("org", "neptune", "neptune"))
            .context("Could not determine data directory")?;

        let network_dir = network.to_string();
        let network_path = Path::new(&network_dir);
        let data_dir = project_dirs.data_dir().to_path_buf().join(network_path);

        Ok(DataDirectory { data_dir })
    }

    /// Create directory if it does not exist
    pub fn create_dir_if_not_exists(dir: &Path) -> Result<()> {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("Failed to create data directory {}", dir.to_string_lossy()))
    }

    /// Open file, create parent directory if it does not exist
    pub fn open_ensure_parent_dir_exists(file_path: &Path) -> Result<fs::File> {
        let parent_dir = file_path
            .parent()
            .with_context(|| format!("The parent directory of {:?}", file_path))?;
        Self::create_dir_if_not_exists(parent_dir)?;

        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(file_path)
            .context("open_ensure_parent_dir_exists")
    }

    ///////////////////////////////////////////////////////////////////////////
    ///
    /// The root data directory path
    pub fn root_dir_path(&self) -> PathBuf {
        self.data_dir.clone()
    }

    /// The block database directory path
    pub fn database_dir_path(&self) -> PathBuf {
        self.data_dir.join(Path::new(DATABASE_DIRECTORY_ROOT_NAME))
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
    /// The wallet file path
    pub fn wallet_file_path(&self) -> PathBuf {
        self.data_dir.join(Path::new(WALLET_FILE_NAME))
    }

    /// The wallet database directory path.
    ///
    /// This directory lives within `DataDirectory::database_dir_path()`.
    pub fn wallet_database_dir_path(&self) -> PathBuf {
        self.database_dir_path().join(Path::new(WALLET_DB_NAME))
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
    /// The block body directory.
    ///
    /// This directory lives within `DataDirectory::root_dir_path()`.
    pub fn block_dir_path(&self) -> PathBuf {
        self.data_dir.join(Path::new(DIR_NAME_FOR_BLOCKS))
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
        write!(f, "{}", self.data_dir.display())
    }
}
