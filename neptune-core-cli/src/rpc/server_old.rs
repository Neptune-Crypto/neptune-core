use crate::rpc::auth::Cookie;
use crate::rpc::{NeptuneCliRPC, RpcResult};
use clap::CommandFactory;
use clap_complete::generate;
use clap_complete::Shell;
use neptune_cash::application::config::data_directory::DataDirectory;
use neptune_cash::application::config::network::Network;
use neptune_cash::state::wallet::address::KeyType;
use neptune_cash::state::wallet::secret_key_material::SecretKeyMaterial;
use neptune_cash::state::wallet::wallet_file::WalletFile;
use neptune_cash::state::wallet::wallet_file::WalletFileContext;
use std::path::PathBuf;
use tarpc::context;

/// RPC server implementation for neptune-cli standalone commands
pub struct NeptuneCliRPCServerImpl {
    data_directory: PathBuf,
    valid_tokens: Vec<Cookie>,
}

impl NeptuneCliRPCServerImpl {
    /// Create a new RPC server instance
    pub fn new(data_directory: PathBuf, valid_tokens: Vec<Cookie>) -> Self {
        Self {
            data_directory,
            valid_tokens,
        }
    }

    /// Get the network from string or default to main
    fn get_network(network: Option<String>) -> Network {
        match network {
            Some(net_str) => match net_str.as_str() {
                "test" => Network::TestnetMock,
                "regtest" => Network::RegTest,
                _ => Network::Main,
            },
            None => Network::Main,
        }
    }

    /// Get wallet directory for the given network
    fn get_wallet_dir(&self, network: Option<String>) -> Result<PathBuf, String> {
        let network = Self::get_network(network);
        let data_dir = DataDirectory::get(Some(self.data_directory.clone()), network)
            .map_err(|e| format!("Failed to get data directory: {}", e))?;
        Ok(data_dir.wallet_directory_path())
    }
}

impl NeptuneCliRPC for NeptuneCliRPCServerImpl {
    async fn generate_wallet(
        self,
        _: context::Context,
        network: Option<String>,
    ) -> RpcResult<String> {
        let wallet_dir = self.get_wallet_dir(network)?;

        // Create directory if it doesn't exist
        DataDirectory::create_dir_if_not_exists(&wallet_dir)
            .await
            .map_err(|e| format!("Failed to create wallet directory: {}", e))?;

        let wallet_file_context = WalletFileContext::read_from_file_or_create(&wallet_dir)
            .map_err(|e| format!("Failed to create wallet: {}", e))?;

        if wallet_file_context.wallet_is_new {
            Ok(format!(
                "New wallet generated.\nWallet stored in: {}\nTo display the seed phrase, run export_seed_phrase.",
                wallet_file_context.wallet_secret_path.display()
            ))
        } else {
            Ok(format!(
                "Not generating a new wallet because an existing one is present already.\nWallet stored in: {}",
                wallet_file_context.wallet_secret_path.display()
            ))
        }
    }

    async fn which_wallet(self, _: context::Context, network: Option<String>) -> RpcResult<String> {
        let wallet_dir = self.get_wallet_dir(network)?;
        let wallet_file = WalletFileContext::wallet_secret_path(&wallet_dir);

        if !wallet_file.exists() {
            return Err(format!(
                "No wallet file found at {}.",
                wallet_file.display()
            ));
        }

        Ok(wallet_file.display().to_string())
    }

    async fn export_seed_phrase(
        self,
        _: context::Context,
        network: Option<String>,
    ) -> RpcResult<String> {
        let wallet_dir = self.get_wallet_dir(network)?;
        let wallet_file = WalletFileContext::wallet_secret_path(&wallet_dir);

        if !wallet_file.exists() {
            return Err(format!(
                "No wallet file found at {}.",
                wallet_file.display()
            ));
        }

        let wallet_file = WalletFile::read_from_file(&wallet_file)
            .map_err(|e| format!("Failed to read wallet file: {}", e))?;

        let wallet_secret = wallet_file.secret_key();
        let phrase = wallet_secret.to_phrase();
        Ok(phrase.join(" "))
    }

    async fn import_seed_phrase(
        self,
        _: context::Context,
        seed_phrase: String,
        network: Option<String>,
    ) -> RpcResult<()> {
        let wallet_dir = self.get_wallet_dir(network)?;

        // Parse the seed phrase
        let words: Vec<String> = seed_phrase
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();
        if words.len() != 18 {
            return Err("Seed phrase must contain exactly 18 words".to_string());
        }

        let secret_key = SecretKeyMaterial::from_phrase(&words)
            .map_err(|e| format!("Invalid seed phrase: {}", e))?;

        // Create wallet file
        let wallet_file = WalletFile::new(secret_key);

        // Write wallet file
        let wallet_file_path = WalletFileContext::wallet_secret_path(&wallet_dir);
        wallet_file
            .write_to_file(&wallet_file_path)
            .map_err(|e| format!("Failed to write wallet file: {}", e))?;

        Ok(())
    }

    async fn nth_receiving_address(
        self,
        _: context::Context,
        n: u32,
        network: Option<String>,
    ) -> RpcResult<String> {
        let wallet_dir = self.get_wallet_dir(network)?;
        let wallet_file = WalletFileContext::wallet_secret_path(&wallet_dir);

        if !wallet_file.exists() {
            return Err(format!(
                "No wallet file found at {}.",
                wallet_file.display()
            ));
        }

        let wallet_file_context = WalletFileContext::read_from_file(&wallet_dir)
            .map_err(|e| format!("Failed to read wallet file: {}", e))?;

        let wallet_secret = wallet_file_context
            .wallet_secret
            .ok_or_else(|| "No wallet secret found".to_string())?;

        let network = Self::get_network(network);
        let address = wallet_secret.derive_receiving_address(KeyType::Regular, n, &network);

        Ok(address.to_bech32m())
    }

    async fn premine_receiving_address(
        self,
        _: context::Context,
        network: Option<String>,
    ) -> RpcResult<String> {
        let wallet_dir = self.get_wallet_dir(network)?;
        let wallet_file = WalletFileContext::wallet_secret_path(&wallet_dir);

        if !wallet_file.exists() {
            return Err(format!(
                "No wallet file found at {}.",
                wallet_file.display()
            ));
        }

        let wallet_file_context = WalletFileContext::read_from_file(&wallet_dir)
            .map_err(|e| format!("Failed to read wallet file: {}", e))?;

        let wallet_secret = wallet_file_context
            .wallet_secret
            .ok_or_else(|| "No wallet secret found".to_string())?;

        let network = Self::get_network(network);
        let address = wallet_secret.derive_receiving_address(KeyType::Premine, 0, &network);

        Ok(address.to_bech32m())
    }

    async fn shamir_share(
        self,
        _: context::Context,
        t: u32,
        n: u32,
        network: Option<String>,
    ) -> RpcResult<Vec<String>> {
        let wallet_dir = self.get_wallet_dir(network)?;
        let wallet_file = WalletFileContext::wallet_secret_path(&wallet_dir);

        if !wallet_file.exists() {
            return Err(format!(
                "No wallet file found at {}.",
                wallet_file.display()
            ));
        }

        let wallet_file_context = WalletFileContext::read_from_file(&wallet_dir)
            .map_err(|e| format!("Failed to read wallet file: {}", e))?;

        let wallet_secret = wallet_file_context
            .wallet_secret
            .ok_or_else(|| "No wallet secret found".to_string())?;

        // Generate Shamir shares
        let shares = wallet_secret
            .shamir_share(t, n)
            .map_err(|e| format!("Failed to generate Shamir shares: {}", e))?;

        Ok(shares)
    }

    async fn shamir_combine(
        self,
        _: context::Context,
        t: u32,
        network: Option<String>,
    ) -> RpcResult<()> {
        // This would need to be implemented with interactive input
        // For now, return an error indicating it needs to be done via CLI
        Err(
            "Shamir combine requires interactive input. Please use the CLI command directly."
                .to_string(),
        )
    }

    async fn completions(self, _: context::Context, shell: String) -> RpcResult<String> {
        let shell_enum = match shell.as_str() {
            "bash" => Shell::Bash,
            "zsh" => Shell::Zsh,
            "fish" => Shell::Fish,
            "powershell" => Shell::PowerShell,
            "elvish" => Shell::Elvish,
            _ => return Err(format!("Unsupported shell: {}", shell)),
        };

        let mut output = Vec::new();
        generate(
            shell_enum,
            &mut crate::Config::command(),
            "neptune-cli",
            &mut output,
        )
        .map_err(|e| format!("Failed to generate completions: {}", e))?;

        Ok(String::from_utf8(output)
            .map_err(|e| format!("Failed to convert completions to string: {}", e))?)
    }

    async fn help(self, _: context::Context, command: Option<String>) -> RpcResult<String> {
        let mut cmd = crate::Config::command();

        if let Some(subcommand) = command {
            if let Some(sub_cmd) = cmd.find_subcommand(&subcommand) {
                Ok(sub_cmd.render_help().to_string())
            } else {
                Err(format!("Unknown command: {}", subcommand))
            }
        } else {
            Ok(cmd.render_help().to_string())
        }
    }
}
