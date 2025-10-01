//! Authentication module for RPC server
//!
//! Handles cookie-based authentication following the same pattern as neptune-core.

use anyhow::{Context, Result};
use rand::{distr::Alphanumeric, Rng};
use std::path::PathBuf;
use hex;

/// Cookie authentication token
#[derive(Debug, Clone, PartialEq)]
pub struct Cookie([u8; 32]);

impl Cookie {
    /// Generate or load authentication cookie
    pub async fn try_new(data_dir: &PathBuf) -> Result<Self> {
        // First try to use existing neptune-core cookie
        let neptune_cookie_path = data_dir.join(".cookie");
        if neptune_cookie_path.exists() {
            if let Ok(cookie_data) = tokio::fs::read(&neptune_cookie_path).await {
                if cookie_data.len() == 32 {
                    let mut secret = [0u8; 32];
                    secret.copy_from_slice(&cookie_data);
                    return Ok(Cookie(secret));
                }
            }
        }

        // Generate new cookie for neptune-cli
        Self::try_new_with_secret(data_dir, Self::gen_secret()).await
    }

    /// Generate random secret
    fn gen_secret() -> [u8; 32] {
        let mut secret = [0u8; 32];
        rand::rng().fill(&mut secret);
        secret
    }

    /// Create cookie with specific secret
    async fn try_new_with_secret(data_dir: &PathBuf, secret: [u8; 32]) -> Result<Self> {
        let cookie_path = data_dir.join(".neptune-cli-cookie");
        let mut path_tmp = cookie_path.clone();
        let extension: String = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(16)
            .map(char::from)
            .collect();
        path_tmp.set_extension(extension);

        if let Some(parent_dir) = cookie_path.parent() {
            tokio::fs::create_dir_all(parent_dir)
                .await
                .context("Failed to create cookie directory")?;
        }

        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path_tmp)
            .await
            .context("Failed to create cookie file")?;

        use tokio::io::AsyncWriteExt;
        file.write_all(&secret)
            .await
            .context("Failed to write cookie data")?;
        file.sync_all()
            .await
            .context("Failed to sync cookie file")?;
        drop(file);

        tokio::fs::rename(&path_tmp, &cookie_path)
            .await
            .context("Failed to finalize cookie file")?;

        Ok(Cookie(secret))
    }

    /// Validate authentication token
    pub fn auth(&self, valid_tokens: &[Cookie]) -> Result<()> {
        if valid_tokens.contains(self) {
            Ok(())
        } else {
            anyhow::bail!("Invalid authentication token")
        }
    }

    /// Get cookie bytes for serialization
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Get cookie as hex string for HTTP headers
    pub fn as_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl From<[u8; 32]> for Cookie {
    fn from(secret: [u8; 32]) -> Self {
        Cookie(secret)
    }
}
