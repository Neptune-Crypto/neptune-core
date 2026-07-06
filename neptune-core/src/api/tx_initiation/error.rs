//! provides error types related to initiating transactions.

use neptune_consensus::proof_abstractions::error::CreateProofError;
use neptune_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use neptune_mutator_set::MutatorSetError;
use neptune_primitives::block_height::BlockHeight;
use tasm_lib::prelude::Digest;

use crate::api::export::RecordTransactionError;

/// enumerates possible transaction send errors
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
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

    #[error(
        "The input selection policy cannot be satisfied due to a limit \
     in the number of allowed input. Either increase the number of inputs \
      allowed for this transaction, or choose another input priority."
    )]
    TooManyInputs,

    #[error(
        "Transaction requires lustration, i.e. revealing the values of the \
     inputs. But the flag to accept lustrations was not set."
    )]
    RequiresLustration,

    #[error("Mutator set error: {0}")]
    MutatorSetError(MutatorSetError),
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
