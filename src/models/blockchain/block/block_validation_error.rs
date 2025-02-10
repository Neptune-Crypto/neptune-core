/// Enumerates the reasons why a [`Block`] can fail to be valid.
///
/// Conversely, defines what it means for a block to be "valid".
#[derive(Debug, Clone, Copy, thiserror::Error)]
pub(super) enum BlockValidationError {
    // 0. `previous_block` is consistent with current block
    ///   0.a) Block height is previous plus one
    #[error("block height must equal that of predecessor plus one")]
    BlockHeight,
    ///   0.b) Block header points to previous block
    #[error("block header must point to predecessor block")]
    PrevBlockDigest,
    ///   0.c) Block mmr updated correctly
    #[error("block mmr must contain predecessor digest")]
    BlockMmrUpdate,
    ///   0.d) Block timestamp is greater than (or equal to) timestamp of
    ///      previous block plus minimum block time
    #[error("block timestamp must be later than predecessor in excess of minimum block time")]
    MinimumBlockTime,
    ///   0.e) Target difficulty was updated correctly
    #[error("target difficulty must be updated correctly")]
    Difficulty,
    /// 0.f) Cumulative PoW was updated correctly
    #[error("block cumulative proof-of-work must be updated correctly")]
    CumulativeProofOfWork,
    ///   0.g) Block timestamp is less than host-time (utc) + 5 minutes
    #[error("block must not be from the future")]
    FutureDating,

    // 1. Block proof is valid
    ///   1.a) Verify appendix contains required claims
    #[error("block appendix must contain expected claims")]
    AppendixMissingClaim,
    ///   1.b) Disallow appendices with too many claims
    #[error("block appendix cannot contain too many claims")]
    AppendixTooLarge,
    ///   1.c) Block proof must be SingleProof
    #[error("block proof must be SingleProof")]
    ProofQuality,
    ///   1.d) Block proof is valid
    #[error("block proof must be valid")]
    ProofValidity,
    ///   1.e) Max block size is not exceeded
    #[error("block must not exceed max size")]
    MaxSize,

    // 2. The transaction is valid.
    ///   2.a) Verify that MS removal records are valid, done against previous
    ///      `mutator_set_accumulator`,
    #[error("all removal records must be valid relative to predecessor block's mutator set")]
    RemovalRecordsValid,
    ///   2.b) Verify that all removal records have unique index sets
    #[error("all removal records must be unique")]
    RemovalRecordsUnique,
    ///   2.c) Verify that the mutator set update induced by the block
    ///        is possible
    #[error("mutator set update must be possible")]
    MutatorSetUpdatePossible,
    ///   2.d) Verify that the mutator set update induced by the block sends
    ///      the old mutator set accumulator to the new one.
    #[error("mutator set must evolve in accordance with transaction")]
    MutatorSetUpdateIntegral,
    ///   2.e) transaction timestamp <= block timestamp
    #[error("transaction timestamp must not exceed block timestamp")]
    TransactionTimestamp,
    ///   2.f) transaction coinbase <= block subsidy, and not negative.
    #[error("coinbase cannot exceed block subsidy")]
    CoinbaseTooBig,
    ///   2.g) transaction coinbase <= block subsidy, and not negative.
    #[error("coinbase cannot be negative")]
    CoinbaseTooSmall,
    ///   2.h) 0 <= transaction fee (also checked in block program).
    #[error("fee must be non-negative")]
    NegativeFee,
}
