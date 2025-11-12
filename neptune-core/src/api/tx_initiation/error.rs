//! provides error types related to initiating transactions.

use tasm_lib::prelude::Digest;

use crate::api::export::BlockHeight;
use crate::api::export::NativeCurrencyAmount;
use crate::api::export::RecordTransactionError;
use crate::application::job_queue::errors::AddJobError;
use crate::application::job_queue::errors::JobHandleError;
use crate::protocol::consensus::transaction::transaction_proof::TransactionProofType;
use crate::protocol::proof_abstractions::tasm::prover_job::ProverJobError;
use crate::state::transaction::tx_proving_capability::TxProvingCapability;

/// enumerates possible transaction send errors
#[derive(Debug, Clone, thiserror::Error)]
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

    #[error("tip does not have mutator-set-after")]
    NoMutatorSetAccumulatorAfter,
}

#[derive(Debug, Clone, thiserror::Error, strum::Display)]
#[non_exhaustive]
pub enum ProofRequirement {
    Program,
    Claim,
    NonDeterminism,
    ProofJobOptions,
    TransactionProofInput,
    ConsensusRuleSet,
}

/// enumerates possible proof generation errors
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CreateProofError {
    #[error("missing required data to build proof: {0}")]
    MissingRequirement(#[from] ProofRequirement),

    #[error(
        "machine capability {capability} is insufficient to generate proof of type: {proof_type}"
    )]
    TooWeak {
        proof_type: TransactionProofType,
        capability: TxProvingCapability,
    },

    #[error("target proof type {0} is not a triton-vm proof.")]
    NotVmProof(TransactionProofType),

    #[error(transparent)]
    AddJobError(#[from] AddJobError),

    #[error(transparent)]
    ProverJobError(#[from] ProverJobError),

    #[error(transparent)]
    JobHandleError(#[from] JobHandleError),

    #[error("Could not forward job cancellation msg to proving job. {0}")]
    JobCancelSendError(#[from] tokio::sync::watch::error::SendError<()>),
}

/// enumerates possible upgrade-proof errors
#[derive(Debug, Clone, thiserror::Error)]
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
#[derive(Debug, thiserror::Error)]
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

    #[error(transparent)]
    RecordTransaction(#[from] RecordTransactionError),

    #[error("Send rate limit reached for block height {height} ({digest}). A maximum of {max} tx may be sent per block.", digest = tip_digest.to_hex())]
    RateLimit {
        height: BlockHeight,
        tip_digest: Digest,
        max: usize,
    },
}
