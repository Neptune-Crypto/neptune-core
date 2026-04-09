use serde::Deserialize;
use serde::Serialize;

use crate::application::rpc::server::error::RpcError;

impl From<ClaimError> for RpcError {
    fn from(err: ClaimError) -> Self {
        RpcError::ClaimError(err.to_string())
    }
}

/// Enumerates errors related to the claim (wallet registration) of UTXOs.
#[derive(Debug, Clone, thiserror::Error, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ClaimError {
    #[error("utxo does not match any known wallet key")]
    UtxoUnknown,

    #[error("invalid type script in claim utxo")]
    InvalidTypeScript,

    // catch-all error, eg for anyhow errors
    #[error("claim unsuccessful")]
    Failed(String),
}

// convert anyhow::Error to a ClaimError::Failed.
// note that anyhow Error is not serializable.
impl From<anyhow::Error> for ClaimError {
    fn from(e: anyhow::Error) -> Self {
        Self::Failed(e.to_string())
    }
}
