//! Error types for Triton-VM proof generation.

use neptune_job_queue::errors::AddJobError;
use neptune_job_queue::errors::JobHandleError;

use crate::proof_abstractions::tasm::prover_job::ProverJobError;
use crate::proof_abstractions::tx_proving_capability::TxProvingCapability;
use crate::transaction::transaction_proof::TransactionProofType;

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

    #[error(
        "Cannot produce Triton Vm proofs for old consensus rule sets. Are you fully synced yet?"
    )]
    DeprecatedConsensusRules,
}
