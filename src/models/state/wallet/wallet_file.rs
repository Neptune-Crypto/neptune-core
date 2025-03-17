use std::fs;
use std::path::Path;
use std::path::PathBuf;

use anyhow::ensure;
use anyhow::Context;
use anyhow::Result;
use rand::rng;
use rand::Rng;
use serde::Deserialize;
use serde::Serialize;
use tracing::info;
use zeroize::ZeroizeOnDrop;

use super::secret_key_material::SecretKeyMaterial;
use super::wallet_entropy::WalletEntropy;

pub const WALLET_DIRECTORY: &str = "wallet";
pub const WALLET_SECRET_FILE_NAME: &str = "wallet.dat";
pub const WALLET_OUTGOING_SECRETS_FILE_NAME: &str = "outgoing_randomness.dat";
pub const WALLET_INCOMING_SECRETS_FILE_NAME: &str = "incoming_randomness.dat";
const STANDARD_WALLET_NAME: &str = "standard_wallet";
const STANDARD_WALLET_VERSION: u8 = 0;
pub const WALLET_DB_NAME: &str = "wallet";
pub const WALLET_OUTPUT_COUNT_DB_NAME: &str = "wallout_output_count_db";

/// Wrapper around [`WalletFile`] with extra context.
#[derive(Debug, Clone)]
pub struct WalletFileContext {
    pub(crate) wallet_file: WalletFile,

    pub wallet_secret_path: PathBuf,
    pub incoming_randomness_file: PathBuf,
    pub outgoing_randomness_file: PathBuf,

    pub wallet_is_new: bool,
}

impl WalletFileContext {
    pub fn wallet_secret_path(wallet_directory_path: &Path) -> PathBuf {
        wallet_directory_path.join(WALLET_SECRET_FILE_NAME)
    }

    fn wallet_outgoing_secrets_path(wallet_directory_path: &Path) -> PathBuf {
        wallet_directory_path.join(WALLET_OUTGOING_SECRETS_FILE_NAME)
    }

    fn wallet_incoming_secrets_path(wallet_directory_path: &Path) -> PathBuf {
        wallet_directory_path.join(WALLET_INCOMING_SECRETS_FILE_NAME)
    }

    /// Read a wallet from disk or create it.
    ///
    /// Read a wallet file from the `wallet.dat` file in the given directory if
    /// it exists, or otherwise create new wallet secret and save it there.
    /// Also, create files for incoming and outgoing randomness which should be
    /// appended to with each incoming and outgoing transaction.
    pub fn read_from_file_or_create(wallet_directory_path: &Path) -> Result<Self> {
        let wallet_secret_path = Self::wallet_secret_path(wallet_directory_path);
        let wallet_is_new;
        let wallet_secret = if wallet_secret_path.exists() {
            info!(
                "***** Reading wallet from {} *****\n\n\n",
                wallet_secret_path.display()
            );
            wallet_is_new = false;
            WalletFile::read_from_file(&wallet_secret_path)?
        } else {
            info!(
                "***** Creating new wallet in {} *****\n\n\n",
                wallet_secret_path.display()
            );
            let new_wallet = WalletFile::new_random();
            new_wallet.save_to_disk(&wallet_secret_path)?;
            wallet_is_new = true;
            new_wallet
        };

        // Generate files for outgoing and ingoing randomness if those files
        // do not already exist
        let outgoing_randomness_file = Self::wallet_outgoing_secrets_path(wallet_directory_path);
        if !outgoing_randomness_file.exists() {
            WalletFile::create_empty_wallet_randomness_file(&outgoing_randomness_file)
                .unwrap_or_else(|_| {
                    panic!(
                        "Create file for outgoing randomness must succeed. \
                        Attempted to create file: {}",
                        outgoing_randomness_file.to_string_lossy()
                    )
                });
        }

        let incoming_randomness_file = Self::wallet_incoming_secrets_path(wallet_directory_path);
        if !incoming_randomness_file.exists() {
            WalletFile::create_empty_wallet_randomness_file(&incoming_randomness_file)
                .unwrap_or_else(|_| {
                    panic!(
                        "Create file for outgoing randomness must succeed. \
                        Attempted to create file: {}",
                        incoming_randomness_file.to_string_lossy()
                    )
                });
        }

        // Sanity checks that files were actually created
        ensure!(
            wallet_secret_path.exists(),
            "Wallet secret file '{}' must exist on disk after reading/creating it.",
            wallet_secret_path.display(),
        );
        ensure!(
            outgoing_randomness_file.exists(),
            "file containing outgoing randomness '{}' must exist on disk.",
            outgoing_randomness_file.display(),
        );
        ensure!(
            incoming_randomness_file.exists(),
            "file containing ingoing randomness '{}' must exist on disk.",
            incoming_randomness_file.display(),
        );

        Ok(Self {
            wallet_file: wallet_secret,
            wallet_secret_path,
            incoming_randomness_file,
            outgoing_randomness_file,
            wallet_is_new,
        })
    }

    /// Extract the entropy
    pub(crate) fn entropy(&self) -> WalletEntropy {
        self.wallet_file.entropy()
    }
}

/// Immutable secret data related to the wallet.
///
/// The struct contains all the information we want to store in a JSON file,
/// which is not updated during regular program execution.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, ZeroizeOnDrop)]
pub struct WalletFile {
    name: String,

    secret_seed: SecretKeyMaterial,
    version: u8,
}

impl WalletFile {
    pub fn new(secret_seed: SecretKeyMaterial) -> Self {
        Self {
            name: STANDARD_WALLET_NAME.to_string(),
            secret_seed,
            version: STANDARD_WALLET_VERSION,
        }
    }

    fn new_random() -> Self {
        Self::new(SecretKeyMaterial(rng().random()))
    }

    pub fn entropy(&self) -> WalletEntropy {
        WalletEntropy::new(self.secret_seed)
    }

    pub fn secret_key(&self) -> SecretKeyMaterial {
        self.entropy().into()
    }

    /// Read Wallet from file as JSON
    pub fn read_from_file(wallet_file: &Path) -> Result<Self> {
        let wallet_file_content: String = fs::read_to_string(wallet_file)
            .with_context(|| format!("Failed to read wallet from {}", wallet_file.display(),))?;

        serde_json::from_str::<WalletFile>(&wallet_file_content)
            .with_context(|| format!("Failed to decode wallet from {}", wallet_file.display(),))
    }

    /// Used to generate both the file for incoming and outgoing randomness
    fn create_empty_wallet_randomness_file(file_path: &Path) -> Result<()> {
        let init_value: String = String::default();

        #[cfg(unix)]
        {
            Self::create_wallet_file_unix(&file_path.to_path_buf(), init_value)
        }
        #[cfg(not(unix))]
        {
            Self::create_wallet_file_windows(&file_path.to_path_buf(), init_value)
        }
    }

    /// Save this wallet to disk. If necessary, create the file (with restrictive permissions).
    pub fn save_to_disk(&self, wallet_file: &Path) -> Result<()> {
        let wallet_secret_as_json: String = serde_json::to_string(self)?;

        #[cfg(unix)]
        {
            Self::create_wallet_file_unix(&wallet_file.to_path_buf(), wallet_secret_as_json)
        }
        #[cfg(not(unix))]
        {
            Self::create_wallet_file_windows(&wallet_file.to_path_buf(), wallet_secret_as_json)
        }
    }

    #[cfg(unix)]
    /// Create a wallet file, and set restrictive permissions
    fn create_wallet_file_unix(path: &PathBuf, file_content: String) -> Result<()> {
        // On Unix/Linux we set the file permissions to 600, to disallow
        // other users on the same machine to access the secrets.
        // I don't think the `std::os::unix` library can be imported on a Windows machine,
        // so this function and the below import is only compiled on Unix machines.
        use std::os::unix::prelude::OpenOptionsExt;
        fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(path)?;
        fs::write(path.clone(), file_content).context("Failed to write wallet file to disk")
    }

    #[cfg(not(unix))]
    /// Create a wallet file, without setting restrictive UNIX permissions
    fn create_wallet_file_windows(path: &PathBuf, wallet_as_json: String) -> Result<()> {
        fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(path)?;
        fs::write(path.clone(), wallet_as_json).context("Failed to write wallet file to disk")
    }
}
