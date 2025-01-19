use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;
use directories::ProjectDirs;
use serde::Deserialize;
use serde::Serialize;

use crate::config_models::network::Network;
use crate::models::database::DATABASE_DIRECTORY_ROOT_NAME;
use crate::models::state::archival_state::ARCHIVAL_BLOCK_MMR_DIRECTORY_NAME;
use crate::models::state::archival_state::BLOCK_INDEX_DB_NAME;
use crate::models::state::archival_state::MUTATOR_SET_DIRECTORY_NAME;
use crate::models::state::networking_state::BANNED_IPS_DB_NAME;
use crate::models::state::shared::BLOCK_FILENAME_EXTENSION;
use crate::models::state::shared::BLOCK_FILENAME_PREFIX;
use crate::models::state::shared::DIR_NAME_FOR_BLOCKS;
use crate::models::state::wallet::WALLET_DB_NAME;
use crate::models::state::wallet::WALLET_DIRECTORY;
use crate::models::state::wallet::WALLET_OUTPUT_COUNT_DB_NAME;

const UTXO_TRANSFER_DIRECTORY: &str = "utxo-transfer";
const RPC_COOKIE_FILE_NAME: &str = ".cookie"; // matches bitcoin-core name.

// TODO: Add `rusty_leveldb::Options` and `fs::OpenOptions` here too, since they keep being repeated.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
        self.data_dir.clone()
    }

    ///////////////////////////////////////////////////////////////////////////
    ///
    /// The rpc (auth) cookie file path
    pub fn rpc_cookie_file_path(&self) -> PathBuf {
        self.data_dir.join(Path::new(RPC_COOKIE_FILE_NAME))
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
    /// utxo-transfer path
    ///
    /// for storing off-chain serialized transfer files.
    ///
    /// note: this is not used by neptune-core, but is used/shared by
    ///       neptune-cli, neptune-dashboard
    pub fn utxo_transfer_directory_path(&self) -> PathBuf {
        self.data_dir.join(Path::new(UTXO_TRANSFER_DIRECTORY))
    }

    ///////////////////////////////////////////////////////////////////////////
    ///
    /// The wallet file path
    pub fn wallet_directory_path(&self) -> PathBuf {
        self.data_dir.join(Path::new(WALLET_DIRECTORY))
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
