//! provides error types related to regtest api.

use serde::Deserialize;
use serde::Serialize;

/// enumerates possible transaction send errors
#[derive(Debug, Clone, thiserror::Error, Serialize, Deserialize)]
#[non_exhaustive]
pub enum RegTestError {
    #[error("wrong network.  network is not regtest")]
    WrongNetwork,

    // catch-all error, eg for anyhow errors
    #[error("transaction could not be created.  reason: {0}")]
    Failed(String),
}

// convert anyhow::Error to a CreateTxError::Failed.
// note that anyhow Error is not serializable.
impl From<anyhow::Error> for RegTestError {
    fn from(e: anyhow::Error) -> Self {
        Self::Failed(e.to_string())
    }
}
