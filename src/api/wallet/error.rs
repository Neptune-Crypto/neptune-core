//! provides error types related to wallet actions.

use serde::Deserialize;
use serde::Serialize;

/// enumerates possible wallet errors
#[derive(Debug, Clone, thiserror::Error, Serialize, Deserialize)]
#[non_exhaustive]
pub enum WalletError {
    // catch-all error, eg for anyhow errors
    #[error("operation failed.  reason: {0}")]
    Failed(String),
}

// convert anyhow::Error to a WalletError::Failed.
// note that anyhow Error is not serializable.
impl From<anyhow::Error> for WalletError {
    fn from(e: anyhow::Error) -> Self {
        Self::Failed(e.to_string())
    }
}
