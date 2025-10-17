use std::fs;
use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;
use anyhow::{anyhow, ensure};
use rand::rng;
use rand::Rng;
use serde::Deserialize;
use serde::Serialize;
use tracing::{error, info, warn};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::encryption::{EncryptedWalletFile, PasswordManager};
use super::secret_key_material::SecretKeyMaterial;
use super::wallet_entropy::WalletEntropy;

pub const WALLET_DIRECTORY: &str = "wallet";
pub const WALLET_SECRET_FILE_NAME: &str = "wallet.dat";
pub const WALLET_ENCRYPTED_FILE_NAME: &str = "wallet.encrypted";
pub const WALLET_BACKUP_SUFFIX: &str = ".backup";
pub const WALLET_OUTGOING_SECRETS_FILE_NAME: &str = "outgoing_randomness.dat";
pub const WALLET_INCOMING_SECRETS_FILE_NAME: &str = "incoming_randomness.dat";
const STANDARD_WALLET_NAME: &str = "standard_wallet";
const STANDARD_WALLET_VERSION: u8 = 0;
pub const WALLET_DB_NAME: &str = "wallet";
pub const WALLET_OUTPUT_COUNT_DB_NAME: &str = "wallout_output_count_db";

/// Environment variable for wallet password (INSECURE - only for testing/automation)
pub const WALLET_PASSWORD_ENV_VAR: &str = "NEPTUNE_WALLET_PASSWORD";

/// Password source for wallet encryption
#[derive(Debug, Clone)]
pub enum PasswordSource {
    /// Interactive prompt (most secure)
    Interactive,
    /// From CLI argument (insecure, for testing only)
    Cli(String),
    /// From environment variable (insecure, for automation)
    Environment(String),
}

impl PasswordSource {
    /// Get password from the best available source
    ///
    /// Priority order:
    /// 1. CLI argument (if provided)
    /// 2. Environment variable (if set)
    /// 3. Interactive prompt (if allowed)
    /// 4. Error (if non-interactive mode and no password available)
    pub fn get_password(
        cli_password: Option<&str>,
        allow_interactive: bool,
    ) -> Result<Zeroizing<String>> {
        // Priority 1: CLI argument
        if let Some(password) = cli_password {
            warn!("⚠️  Using password from CLI argument (INSECURE! Visible in process list)");
            return Ok(Zeroizing::new(password.to_string()));
        }

        // Priority 2: Environment variable
        if let Ok(env_password) = std::env::var(WALLET_PASSWORD_ENV_VAR) {
            warn!(
                "⚠️  Using password from environment variable {} (INSECURE!)",
                WALLET_PASSWORD_ENV_VAR
            );
            return Ok(Zeroizing::new(env_password));
        }

        // Priority 3: Interactive prompt (if allowed)
        if allow_interactive {
            return Ok(Zeroizing::new(PasswordManager::prompt_unlock_password()?));
        }

        // Priority 4: No password available and interactive disabled
        Err(anyhow!(
            "No password available. Use --wallet-password, set {}, or remove --non-interactive-password flag",
            WALLET_PASSWORD_ENV_VAR
        ))
    }

    /// Get password for new wallet creation
    pub fn get_new_password(
        cli_password: Option<&str>,
        allow_interactive: bool,
    ) -> Result<Zeroizing<String>> {
        // Priority 1: CLI argument
        if let Some(password) = cli_password {
            warn!("⚠️  Using password from CLI argument (INSECURE! Visible in process list)");
            // Validate strength even for CLI passwords
            let strength = PasswordManager::analyze_strength(password);
            if !strength.is_acceptable() {
                return Err(anyhow!(
                    "Password is too weak: {}. Minimum: 12 characters with mixed case, numbers, and symbols.",
                    strength.description()
                ));
            }
            return Ok(Zeroizing::new(password.to_string()));
        }

        // Priority 2: Environment variable
        if let Ok(env_password) = std::env::var(WALLET_PASSWORD_ENV_VAR) {
            warn!(
                "⚠️  Using password from environment variable {} (INSECURE!)",
                WALLET_PASSWORD_ENV_VAR
            );
            // Validate strength even for env passwords
            let strength = PasswordManager::analyze_strength(&env_password);
            if !strength.is_acceptable() {
                return Err(anyhow!(
                    "Password from environment is too weak: {}. Minimum: 12 characters with mixed case, numbers, and symbols.",
                    strength.description()
                ));
            }
            return Ok(Zeroizing::new(env_password));
        }

        // Priority 3: Interactive prompt (if allowed)
        if allow_interactive {
            return Ok(Zeroizing::new(PasswordManager::prompt_new_password()?));
        }

        // Priority 4: No password available and interactive disabled
        Err(anyhow!(
            "No password available for new wallet. Use --wallet-password, set {}, or remove --non-interactive-password flag",
            WALLET_PASSWORD_ENV_VAR
        ))
    }
}

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

    pub fn wallet_encrypted_path(wallet_directory_path: &Path) -> PathBuf {
        wallet_directory_path.join(WALLET_ENCRYPTED_FILE_NAME)
    }

    fn wallet_backup_path(wallet_directory_path: &Path) -> PathBuf {
        let backup_name = format!("{}{}", WALLET_SECRET_FILE_NAME, WALLET_BACKUP_SUFFIX);
        wallet_directory_path.join(backup_name)
    }

    fn wallet_outgoing_secrets_path(wallet_directory_path: &Path) -> PathBuf {
        wallet_directory_path.join(WALLET_OUTGOING_SECRETS_FILE_NAME)
    }

    fn wallet_incoming_secrets_path(wallet_directory_path: &Path) -> PathBuf {
        wallet_directory_path.join(WALLET_INCOMING_SECRETS_FILE_NAME)
    }

    /// Read a wallet from disk or create it.
    ///
    /// **Priority Order:**
    /// 1. `wallet.encrypted` (encrypted format) - **PREFERRED**
    /// 2. `wallet.dat` (plaintext format) - **DEPRECATED, auto-migrates to encrypted**
    /// 3. Create new encrypted wallet if neither exists
    ///
    /// **Security Features:**
    /// - Automatic migration from plaintext to encrypted format
    /// - Secure backup creation before migration
    /// - Atomic file operations to prevent data loss
    /// - Secure deletion of plaintext wallet after migration
    /// - Password strength validation
    /// - CLI, environment variable, or interactive password input
    ///
    /// **Parameters:**
    /// - `wallet_directory_path`: Directory containing wallet files
    /// - `cli_password`: Optional password from CLI `--wallet-password` flag
    /// - `allow_interactive`: Whether to allow interactive password prompts
    pub fn read_from_file_or_create(
        wallet_directory_path: &Path,
        cli_password: Option<&str>,
        allow_interactive: bool,
    ) -> Result<Self> {
        let encrypted_path = Self::wallet_encrypted_path(wallet_directory_path);
        let plaintext_path = Self::wallet_secret_path(wallet_directory_path);

        let (wallet_secret, wallet_is_new) = if encrypted_path.exists() {
            // CASE 1: Encrypted wallet exists - load it
            info!(
                "🔐 Loading encrypted wallet from {}",
                encrypted_path.display()
            );
            let wallet =
                Self::load_encrypted_wallet(&encrypted_path, cli_password, allow_interactive)?;
            (wallet, false)
        } else if plaintext_path.exists() {
            // CASE 2: Legacy plaintext wallet exists - migrate it
            warn!(
                "⚠️  Plaintext wallet detected at {}",
                plaintext_path.display()
            );
            warn!("⚠️  Migrating to encrypted format for security...");

            let wallet = Self::migrate_plaintext_wallet_to_encrypted(
                wallet_directory_path,
                &plaintext_path,
                &encrypted_path,
                cli_password,
                allow_interactive,
            )?;
            (wallet, false)
        } else {
            // CASE 3: No wallet exists - create new encrypted wallet
            info!(
                "🆕 Creating new encrypted wallet in {}",
                wallet_directory_path.display()
            );
            let wallet = Self::create_new_encrypted_wallet(
                wallet_directory_path,
                cli_password,
                allow_interactive,
            )?;
            (wallet, true)
        };

        // Initialize randomness files (same as before)
        let outgoing_randomness_file = Self::wallet_outgoing_secrets_path(wallet_directory_path);
        if !outgoing_randomness_file.exists() {
            WalletFile::create_empty_wallet_randomness_file(&outgoing_randomness_file)
                .context("Failed to create outgoing randomness file")?;
        }

        let incoming_randomness_file = Self::wallet_incoming_secrets_path(wallet_directory_path);
        if !incoming_randomness_file.exists() {
            WalletFile::create_empty_wallet_randomness_file(&incoming_randomness_file)
                .context("Failed to create incoming randomness file")?;
        }

        // Sanity checks
        ensure!(
            encrypted_path.exists(),
            "Encrypted wallet file '{}' must exist on disk after loading/creating it.",
            encrypted_path.display(),
        );
        ensure!(
            outgoing_randomness_file.exists(),
            "Outgoing randomness file '{}' must exist on disk.",
            outgoing_randomness_file.display(),
        );
        ensure!(
            incoming_randomness_file.exists(),
            "Incoming randomness file '{}' must exist on disk.",
            incoming_randomness_file.display(),
        );

        Ok(Self {
            wallet_file: wallet_secret,
            wallet_secret_path: encrypted_path,
            incoming_randomness_file,
            outgoing_randomness_file,
            wallet_is_new,
        })
    }

    /// Load encrypted wallet from disk with password from CLI/env/interactive
    fn load_encrypted_wallet(
        encrypted_path: &Path,
        cli_password: Option<&str>,
        allow_interactive: bool,
    ) -> Result<WalletFile> {
        let encrypted_file = EncryptedWalletFile::read_from_file(encrypted_path)?;

        // Get password from best available source
        let password = PasswordSource::get_password(cli_password, allow_interactive)?;

        // Decrypt wallet
        let plaintext_json = encrypted_file.decrypt(&password)?;
        let wallet: WalletFile = serde_json::from_str(&plaintext_json)
            .context("Failed to deserialize decrypted wallet data")?;

        info!("✅ Wallet decrypted successfully");
        Ok(wallet)
    }

    /// Migrate plaintext wallet to encrypted format with backup
    fn migrate_plaintext_wallet_to_encrypted(
        wallet_dir: &Path,
        plaintext_path: &Path,
        encrypted_path: &Path,
        cli_password: Option<&str>,
        allow_interactive: bool,
    ) -> Result<WalletFile> {
        info!("📦 Step 1/5: Creating backup of plaintext wallet...");
        let backup_path = Self::wallet_backup_path(wallet_dir);
        fs::copy(plaintext_path, &backup_path)
            .context("Failed to create backup of plaintext wallet")?;
        info!("✅ Backup created at {}", backup_path.display());

        info!("📖 Step 2/5: Reading plaintext wallet...");
        let wallet = WalletFile::read_from_file(plaintext_path)?;
        let wallet_json =
            serde_json::to_string(&wallet).context("Failed to serialize wallet for encryption")?;

        info!("🔐 Step 3/5: Encrypting wallet...");
        let password = PasswordSource::get_new_password(cli_password, allow_interactive)?;

        let encrypted_file = EncryptedWalletFile::encrypt(
            STANDARD_WALLET_NAME.to_string(),
            &wallet_json,
            &password,
        )?;

        info!("💾 Step 4/5: Writing encrypted wallet to disk...");
        encrypted_file.write_to_file(encrypted_path)?;

        // Verify we can decrypt it before deleting plaintext
        info!("🔍 Step 5/5: Verifying encrypted wallet...");
        let verify_plaintext = encrypted_file.decrypt(&password)?;
        let verify_wallet: WalletFile = serde_json::from_str(&verify_plaintext)
            .context("Verification failed: encrypted wallet cannot be decrypted")?;

        ensure!(
            verify_wallet == wallet,
            "Verification failed: decrypted wallet does not match original"
        );

        // Secure deletion of plaintext wallet
        info!("🗑️  Securely deleting plaintext wallet...");
        Self::secure_delete(plaintext_path)?;

        info!("✅ Migration complete! Wallet is now encrypted.");
        info!(
            "ℹ️  Plaintext backup retained at {} (delete manually after verification)",
            backup_path.display()
        );

        Ok(wallet)
    }

    /// Create new encrypted wallet with password from CLI/env/interactive
    fn create_new_encrypted_wallet(
        wallet_dir: &Path,
        cli_password: Option<&str>,
        allow_interactive: bool,
    ) -> Result<WalletFile> {
        let new_wallet = WalletFile::new_random();
        let wallet_json =
            serde_json::to_string(&new_wallet).context("Failed to serialize new wallet")?;

        // Get password from best available source
        let password = PasswordSource::get_new_password(cli_password, allow_interactive)?;

        // Encrypt and save
        let encrypted_file = EncryptedWalletFile::encrypt(
            STANDARD_WALLET_NAME.to_string(),
            &wallet_json,
            &password,
        )?;

        let encrypted_path = Self::wallet_encrypted_path(wallet_dir);
        encrypted_file.write_to_file(&encrypted_path)?;

        info!(
            "✅ New encrypted wallet created at {}",
            encrypted_path.display()
        );
        Ok(new_wallet)
    }

    /// Securely delete a file by overwriting with random data before deletion
    ///
    /// This is a best-effort secure deletion. True secure deletion requires
    /// filesystem-level support, but this at least prevents simple file recovery.
    fn secure_delete(path: &Path) -> Result<()> {
        // Get file size
        let metadata = fs::metadata(path)?;
        let file_size = metadata.len() as usize;

        if file_size > 0 {
            // Overwrite with random data
            let random_data: Vec<u8> = (0..file_size).map(|_| rng().random()).collect();
            fs::write(path, random_data)?;
        }

        // Delete the file
        fs::remove_file(path)
            .with_context(|| format!("Failed to delete file: {}", path.display()))?;

        Ok(())
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
