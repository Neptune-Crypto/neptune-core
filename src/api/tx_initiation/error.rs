//! provides error types related to initiating transactions.

use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;

use crate::api::export::BlockHeight;
use crate::api::export::NativeCurrencyAmount;
use crate::api::export::WitnessValidationError;

/// enumerates possible transaction send errors
#[derive(Debug, Clone, thiserror::Error, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CreateTxError {
    #[error("missing required data to build transaction")]
    MissingRequirement,

    #[error("Transaction with negative fees not allowed")]
    NegativeFee,

    #[error("total spend amount is too large")]
    TotalSpendTooLarge,

    #[error(
        "insufficient funds. requested: {}, available: {}",
        requested,
        available
    )]
    InsufficientFunds {
        requested: NativeCurrencyAmount,
        available: NativeCurrencyAmount,
    },

    #[error("ChangePolicy = ExactChange, but input amount exceeds output amount")]
    NotExactChange,

    #[error("provided key_type cannot be used for receiving change.")]
    InvalidKeyForChange,

    #[error("cannot generate change key for immutable wallet.")]
    CantGenChangeKeyForImmutableWallet,

    #[error("witness validation failed")]
    WitnessValidationFailed(#[from] WitnessValidationError),

    // catch-all error, eg for anyhow errors
    #[error("transaction could not be created.  reason: {0}")]
    Failed(String),
}

/// enumerates possible transaction send errors
#[derive(Debug, Clone, thiserror::Error, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CreateProofError {
    #[error("missing required data to build proof")]
    MissingRequirement,

    #[error("machine too weak to generate transaction proofs")]
    TooWeak,

    // catch-all error, eg for anyhow errors
    #[error("transaction could not be created.  reason: {0}")]
    Failed(String),
}

/// enumerates possible transaction send errors
#[derive(Debug, Clone, thiserror::Error, Serialize, Deserialize)]
#[non_exhaustive]
pub enum UpgradeProofError {
    #[error("transaction is not found in mempool")]
    TxNotInMempool,

    #[error("input proof is not an upgrade.  ignoring.")]
    ProofNotAnUpgrade,

    #[error("provided proof is not valid for specified transaction.")]
    InvalidProof,
}

/// enumerates possible transaction send errors
#[derive(Debug, Clone, thiserror::Error, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SendError {
    #[error("send() is not supported by this node")]
    Unsupported,

    #[error("transaction could not be broadcast.")]
    NotBroadcast,

    #[error(transparent)]
    Tx(#[from] CreateTxError),

    #[error(transparent)]
    Proof(#[from] CreateProofError),

    // catch-all error, eg for anyhow errors
    #[error("transaction could not be sent.  reason: {0}")]
    Failed(String),

    #[error("Send rate limit reached for block height {height} ({digest}). A maximum of {max} tx may be sent per block.", digest = tip_digest.to_hex())]
    RateLimit {
        height: BlockHeight,
        tip_digest: Digest,
        max: usize,
    },
}

// convert anyhow::Error to a CreateTxError::Failed.
// note that anyhow Error is not serializable.
impl From<anyhow::Error> for CreateTxError {
    fn from(e: anyhow::Error) -> Self {
        Self::Failed(e.to_string())
    }
}

// convert anyhow::Error to a CreateProofError::Failed.
// note that anyhow Error is not serializable.
impl From<anyhow::Error> for CreateProofError {
    fn from(e: anyhow::Error) -> Self {
        Self::Failed(e.to_string())
    }
}

// convert anyhow::Error to a SendError::Failed.
// note that anyhow Error is not serializable.
impl From<anyhow::Error> for SendError {
    fn from(e: anyhow::Error) -> Self {
        Self::Failed(e.to_string())
    }
}
