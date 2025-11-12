use crate::util_types::mutator_set::removal_record::removal_record_list::RemovalRecordListUnpackError;

/// The reasons why a [`Block`](crate::protocol::consensus::block::Block) can be
/// invalid.
///
/// Conversely, defines what it means for a block to be "valid".
#[derive(Debug, Clone, Copy, thiserror::Error, PartialEq, Eq)]
pub enum BlockValidationError {
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
    ///   2.a) Unpack the transaction's inputs (removal records). This operation
    ///        is fallible but must succeed.
    #[error("cannot unpack removal records")]
    RemovalRecordsUnpackFailure,
    ///   2.b) Verify that MS removal records are valid, done against previous
    ///      `mutator_set_accumulator`,
    #[error("all removal records must be valid relative to predecessor block's mutator set")]
    RemovalRecordsValidity,
    ///   2.c) Verify that all removal records have unique index sets
    #[error("all removal records must be unique")]
    RemovalRecordsUniqueness,
    ///   2.d) Verify that the mutator set update induced by the block
    ///        is possible
    #[error("mutator set update must be possible")]
    MutatorSetUpdateImpossible,
    ///   2.e) Verify that the mutator set update induced by the block sends
    ///      the old mutator set accumulator to the new one.
    #[error("mutator set must evolve in accordance with transaction")]
    MutatorSetUpdateIntegrity,
    ///   2.f) transaction timestamp <= block timestamp
    #[error("transaction timestamp must not exceed block timestamp")]
    TransactionTimestamp,
    ///   2.g) transaction coinbase <= block subsidy, and not negative.
    #[error("coinbase cannot exceed block subsidy")]
    CoinbaseTooBig,
    ///   2.h) transaction coinbase <= block subsidy, and not negative.
    #[error("coinbase cannot be negative")]
    NegativeCoinbase,
    ///   2.i) 0 <= transaction fee (also checked in block program).
    #[error("fee must be non-negative")]
    NegativeFee,
    ///   2.j) restrict number of inputs.
    #[error("number of inputs may not be too large")]
    TooManyInputs,
    ///   2.k) restrict number of outputs.
    #[error("number of outputs may not be too large")]
    TooManyOutputs,
    ///   2.l) restrict number of announcements.
    #[error("number of announcements may not be too large")]
    TooManyAnnouncements,
}

impl From<RemovalRecordListUnpackError> for BlockValidationError {
    fn from(_: RemovalRecordListUnpackError) -> Self {
        Self::RemovalRecordsUnpackFailure
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::Just;
    use proptest::prop_assert_eq;
    use proptest::prop_assume;
    use proptest::test_runner::RngSeed;
    use proptest_arbitrary_interop::arb;
    use tasm_lib::triton_vm::prelude::BFieldElement;
    use tasm_lib::triton_vm::proof::Claim;
    use tasm_lib::twenty_first::bfe;
    use test_strategy::proptest;

    use super::*;
    use crate::api::export::NativeCurrencyAmount;
    use crate::api::export::NeptuneProof;
    use crate::api::export::Network;
    use crate::api::export::Timestamp;
    use crate::protocol::consensus::block::block_appendix::BlockAppendix;
    use crate::protocol::consensus::block::block_appendix::MAX_NUM_CLAIMS;
    use crate::protocol::consensus::block::difficulty_control;
    use crate::protocol::consensus::block::difficulty_control::Difficulty;
    use crate::protocol::consensus::block::tests::DIFFICULTY_LIMIT_FOR_TESTS;
    use crate::protocol::consensus::block::validity::block_program::BlockProgram;
    use crate::protocol::consensus::block::Block;
    use crate::protocol::consensus::block::BlockProof;
    use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
    use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelProxy;
    use crate::protocol::proof_abstractions::verifier::cache_true_claim;
    use crate::tests::shared::blocks::fake_valid_successor_for_tests;
    use crate::tests::shared::blocks::invalid_empty_block;
    use crate::tests::shared::blocks::invalid_empty_block_with_timestamp;
    use crate::tests::shared::strategies::block_with_arbkernel;
    use crate::tests::shared::Randomness;
    use crate::util_types::mutator_set::addition_record::AdditionRecord;

    proptest::prop_compose! {
        fn setup() (
            rness in arb::<Randomness<2, 2>>(),
            d in 1..DIFFICULTY_LIMIT_FOR_TESTS,
            b in block_with_arbkernel()
        ) (
            ts in (
                Timestamp::hours(1) + b.kernel.header.timestamp
            ).0.value()..=BFieldElement::MAX,
            rness in Just(rness), mut b in Just(b), difficulty in Just(d)
        ) -> (crate::protocol::consensus::block::Block, Timestamp, Randomness<2, 2>) {
            b.kernel.header.difficulty = Difficulty::from(difficulty);
            (b, Timestamp(bfe![ts]), rness)
        }
    }

    #[proptest(async = "tokio", cases = 1, rng_seed = RngSeed::Fixed(0))]
    async fn block_with_block_height_error_fails_0a(
        #[strategy(block_with_arbkernel())] b_prev: Block,
        #[strategy(block_with_arbkernel())] b_new: Block,
    ) {
        prop_assume!(b_new.kernel.header.height.value() != 1 + b_prev.kernel.header.height.value());

        prop_assert_eq!(
            BlockValidationError::BlockHeight,
            b_new
                .validate(
                    &b_prev,
                    b_prev.kernel.header.timestamp + Timestamp(bfe![60]),
                    Network::Main
                )
                .await
                .err()
                .unwrap()
        );
    }

    #[proptest(async = "tokio", cases = 1, rng_seed = RngSeed::Fixed(0))]
    async fn block_with_prev_block_digest_error_fails_0b(
        #[strategy(block_with_arbkernel())] b_prev: Block,
        #[strategy(block_with_arbkernel())] mut b_new: Block,
    ) {
        b_new.kernel.header.height = b_prev.kernel.header.height + 1;
        prop_assert_eq!(
            BlockValidationError::PrevBlockDigest,
            b_new
                .validate(
                    &b_prev,
                    b_prev.kernel.header.timestamp + Timestamp(bfe![60]),
                    Network::Main
                )
                .await
                .err()
                .unwrap()
        );
    }

    #[proptest(async = "tokio", cases = 1, rng_seed = RngSeed::Fixed(0))]
    async fn block_with_block_mmr_update_error_fails_0c(
        #[strategy(block_with_arbkernel())] b_prev: Block,
        #[strategy(block_with_arbkernel())] mut b_new: Block,
    ) {
        b_new.kernel.header.height = b_prev.kernel.header.height + 1;
        b_new.kernel.header.prev_block_digest = b_prev.hash();
        prop_assert_eq!(
            BlockValidationError::BlockMmrUpdate,
            b_new
                .validate(
                    &b_prev,
                    b_prev.kernel.header.timestamp + Timestamp(bfe![60]),
                    Network::Main
                )
                .await
                .err()
                .unwrap()
        );
    }

    #[proptest(async = "tokio", cases = 1, rng_seed = RngSeed::Fixed(0))]
    async fn block_with_minimum_block_time_error_fails_0d(
        #[strategy(setup())] s: (Block, Timestamp, Randomness<2, 2>),
        #[strategy(0..60000u64)] ts_small: u64,
    ) {
        let network = Network::Main;
        let (b_prev, ts, _) = s;

        prop_assert_eq!(
            BlockValidationError::MinimumBlockTime,
            invalid_empty_block_with_timestamp(
                &b_prev,
                b_prev.kernel.header.timestamp + Timestamp(bfe![ts_small]),
                network,
            )
            .validate(&b_prev, ts, network)
            .await
            .err()
            .unwrap()
        );
    }

    #[proptest(async = "tokio", cases = 1, rng_seed = RngSeed::Fixed(0))]
    async fn block_with_difficulty_error_fails_0e(
        #[strategy(setup())] s: (Block, Timestamp, Randomness<2, 2>),
        #[strategy(arb())] d: Difficulty,
    ) {
        let network = Network::Main;
        let (b_prev, ts, rness) = s;

        let mut b_new = fake_valid_successor_for_tests(&b_prev, ts, rness, network).await;

        prop_assume!(d != b_new.kernel.header.difficulty);
        b_new.kernel.header.difficulty = d;

        prop_assert_eq!(
            BlockValidationError::Difficulty,
            b_new.validate(&b_prev, ts, network).await.err().unwrap()
        );
    }

    #[proptest(async = "tokio", cases = 1, rng_seed = RngSeed::Fixed(0))]
    async fn block_with_cumulative_proof_of_work_error_fails_0f(
        #[strategy(setup())] s: (Block, Timestamp, Randomness<2, 2>),
        #[strategy(arb())] cumul: difficulty_control::ProofOfWork,
    ) {
        let network = Network::Main;
        let (b_prev, ts, _) = s;

        let mut b_new = invalid_empty_block_with_timestamp(&b_prev, ts, network);
        prop_assume!(cumul != b_new.kernel.header.cumulative_proof_of_work);
        b_new.kernel.header.cumulative_proof_of_work = cumul;
        prop_assert_eq!(
            BlockValidationError::CumulativeProofOfWork,
            b_new.validate(&b_prev, ts, network).await.err().unwrap()
        );
    }

    #[proptest(async = "tokio", cases = 1, rng_seed = RngSeed::Fixed(0))]
    async fn block_with_future_dating_fails_0g(
        #[strategy(setup())] s: (Block, Timestamp, Randomness<2, 2>),
        #[strategy(#s.1.0.value() + 1288490188500000u64..=BFieldElement::MAX)] ts_f: u64,
    ) {
        let network = Network::Main;
        let (b_prev, ts, _) = s;

        let mut b_new = invalid_empty_block_with_timestamp(&b_prev, ts, network);
        b_new.kernel.header.timestamp = Timestamp(bfe![ts_f]);
        b_new.kernel.header.difficulty = difficulty_control::difficulty_control(
            b_new.header().timestamp,
            b_prev.header().timestamp,
            b_prev.header().difficulty,
            network.target_block_interval(),
            b_prev.header().height,
        );
        prop_assert_eq!(
            BlockValidationError::FutureDating,
            b_new.validate(&b_prev, ts, network).await.err().unwrap()
        );
    }

    #[proptest(async = "tokio", cases = 1, rng_seed = RngSeed::Fixed(0))]
    async fn block_with_appendix_missing_claim_fails_1a(
        #[strategy(setup())] s: (Block, Timestamp, Randomness<2, 2>),
    ) {
        let network = Network::Main;
        let (b_prev, ts, _) = s;

        prop_assert_eq!(
            BlockValidationError::AppendixMissingClaim,
            invalid_empty_block(&b_prev, network)
                .validate(&b_prev, ts, network)
                .await
                .err()
                .unwrap()
        );
    }

    #[tracing_test::traced_test]
    #[proptest(async = "tokio", cases = 1, rng_seed = RngSeed::Fixed(0))]
    async fn block_with_appendix_too_large_fails_1b(
        #[strategy(setup())] s: (Block, Timestamp, Randomness<2, 2>),
    ) {
        let network = Network::Main;
        let (b_prev, ts, rness) = s;

        let mut b_new = fake_valid_successor_for_tests(&b_prev, ts, rness, network).await;

        let mut large_claims = b_new.kernel.appendix._claims().clone();
        large_claims.append(&mut vec![Claim::new(Default::default()); MAX_NUM_CLAIMS]);
        b_new.kernel.appendix = BlockAppendix::new(large_claims);

        prop_assert_eq!(
            BlockValidationError::AppendixTooLarge,
            b_new.validate(&b_prev, ts, network).await.err().unwrap()
        );
    }

    #[proptest(async = "tokio", cases = 1, rng_seed = RngSeed::Fixed(0))]
    async fn block_with_proof_quality_error_fails_1c(
        #[strategy(setup())] s: (Block, Timestamp, Randomness<2, 2>),
    ) {
        let network = Network::Main;
        let (b_prev, ts, rness) = s;

        let mut b_new = fake_valid_successor_for_tests(&b_prev, ts, rness, network).await;
        b_new.proof = BlockProof::Invalid;

        prop_assert_eq!(
            BlockValidationError::ProofQuality,
            b_new.validate(&b_prev, ts, network).await.err().unwrap()
        );
    }

    #[proptest(async = "tokio", cases = 1, rng_seed = RngSeed::Fixed(0))]
    async fn block_with_max_size_error_fails_1e(
        #[strategy(setup())] s: (Block, Timestamp, Randomness<2, 2>),
    ) {
        let network = Network::Main;
        let (b_prev, ts, rness) = s;

        let mut b_new = fake_valid_successor_for_tests(&b_prev, ts, rness, network).await;

        let big_size =
            ConsensusRuleSet::infer_from(network, b_prev.header().height).max_block_size() + 1;
        b_new.proof =
            BlockProof::SingleProof(NeptuneProof::from(vec![Default::default(); big_size]));

        prop_assert_eq!(
            BlockValidationError::MaxSize,
            b_new.validate(&b_prev, ts, network).await.err().unwrap()
        );
    }

    #[proptest(async = "tokio", cases = 1, rng_seed = RngSeed::Fixed(0))]
    async fn block_with_mutator_set_update_integrity_error_fails_2e(
        #[strategy(setup())] s: (Block, Timestamp, Randomness<2, 2>),
        #[strategy(arb())] record_addition_an: AdditionRecord,
    ) {
        let network = Network::Main;
        let (mut b_prev, ts, rness) = s;
        let b_new = fake_valid_successor_for_tests(&b_prev, ts, rness, network).await;

        b_prev
            .kernel
            .body
            .mutator_set_accumulator
            .add(&record_addition_an);
        b_prev.kernel.appendix = BlockAppendix::new(BlockAppendix::consensus_claims(
            b_prev.body(),
            ConsensusRuleSet::infer_from(Network::Main, b_prev.header().height),
        ));

        prop_assert_eq!(
            BlockValidationError::MutatorSetUpdateIntegrity,
            b_new.validate(&b_prev, ts, network).await.err().unwrap()
        );
    }

    #[proptest(async = "tokio", cases = 1, rng_seed = RngSeed::Fixed(0))]
    async fn block_with_transaction_timestamp_too_large_fails_2f(
        #[strategy(setup())] s: (Block, Timestamp, Randomness<2, 2>),
        #[strategy(#s.1.0.value()..=BFieldElement::MAX)] ts_kernel: u64,
    ) {
        let network = Network::Main;
        let (b_prev, ts, rness) = s;

        let mut b_new = fake_valid_successor_for_tests(&b_prev, ts, rness, network).await;

        let mut tx_kernel_ts =
            TransactionKernelProxy::from(b_new.kernel.body.transaction_kernel.clone());
        tx_kernel_ts.timestamp = Timestamp(bfe![ts_kernel]);
        b_new.kernel.body.transaction_kernel = tx_kernel_ts.into_kernel();
        b_new.kernel.appendix = BlockAppendix::new(BlockAppendix::consensus_claims(
            b_new.body(),
            ConsensusRuleSet::infer_from(network, b_prev.header().height),
        ));
        cache_true_claim(BlockProgram::claim(b_new.body(), &b_new.kernel.appendix)).await;

        prop_assert_eq!(
            BlockValidationError::TransactionTimestamp,
            b_new.validate(&b_prev, ts, network).await.err().unwrap()
        );
    }

    #[proptest(async = "tokio", cases = 1, rng_seed = RngSeed::Fixed(0))]
    async fn block_with_coinbase_too_big_fails_2g(
        #[strategy(setup())] s: (Block, Timestamp, Randomness<2, 2>),
    ) {
        let network = Network::Main;
        let (b_prev, ts, rness) = s;

        let mut b_new = fake_valid_successor_for_tests(&b_prev, ts, rness, network).await;

        let too_big_coinbase =
            NativeCurrencyAmount::one_nau() + Block::block_subsidy(b_new.header().height);
        let mut tx_kernel_big_coinbase =
            TransactionKernelProxy::from(b_new.kernel.body.transaction_kernel.clone());
        tx_kernel_big_coinbase.coinbase = Some(too_big_coinbase);
        b_new.kernel.body.transaction_kernel = tx_kernel_big_coinbase.into_kernel();
        b_new.kernel.appendix = BlockAppendix::new(BlockAppendix::consensus_claims(
            b_new.body(),
            ConsensusRuleSet::infer_from(network, b_prev.header().height),
        ));
        cache_true_claim(BlockProgram::claim(b_new.body(), &b_new.kernel.appendix)).await;

        prop_assert_eq!(
            BlockValidationError::CoinbaseTooBig,
            b_new.validate(&b_prev, ts, network).await.err().unwrap()
        );
    }

    #[proptest(async = "tokio", cases = 1, rng_seed = RngSeed::Fixed(0))]
    async fn block_with_negative_coinbase_fails_2h(
        #[strategy(setup())] s: (Block, Timestamp, Randomness<2, 2>),
    ) {
        let network = Network::Main;
        let (b_prev, ts, rness) = s;

        let mut b_new = fake_valid_successor_for_tests(&b_prev, ts, rness, network).await;

        let mut tx_kernel_neg_coinbase =
            TransactionKernelProxy::from(b_new.kernel.body.transaction_kernel.clone());
        tx_kernel_neg_coinbase.coinbase = Some(-NativeCurrencyAmount::one_nau());

        b_new.kernel.body.transaction_kernel = tx_kernel_neg_coinbase.into_kernel();
        b_new.kernel.appendix = BlockAppendix::new(BlockAppendix::consensus_claims(
            b_new.body(),
            ConsensusRuleSet::infer_from(network, b_prev.header().height),
        ));
        cache_true_claim(BlockProgram::claim(b_new.body(), &b_new.kernel.appendix)).await;

        prop_assert_eq!(
            BlockValidationError::NegativeCoinbase,
            b_new.validate(&b_prev, ts, network).await.err().unwrap()
        );
    }

    #[proptest(async = "tokio", cases = 1, rng_seed = RngSeed::Fixed(0))]
    async fn block_with_negative_fee_fails_2i(
        #[strategy(setup())] s: (Block, Timestamp, Randomness<2, 2>),
    ) {
        let network = Network::Main;
        let (b_prev, ts, rness) = s;

        let mut b_new = fake_valid_successor_for_tests(&b_prev, ts, rness, network).await;

        let mut tx_kernel_fee_neg =
            TransactionKernelProxy::from(b_new.kernel.body.transaction_kernel.clone());
        tx_kernel_fee_neg.fee = -NativeCurrencyAmount::one_nau();
        b_new.kernel.body.transaction_kernel = tx_kernel_fee_neg.into_kernel();
        b_new.kernel.appendix = BlockAppendix::new(BlockAppendix::consensus_claims(
            b_new.body(),
            ConsensusRuleSet::infer_from(network, b_prev.header().height),
        ));
        cache_true_claim(BlockProgram::claim(b_new.body(), &b_new.kernel.appendix)).await;

        prop_assert_eq!(
            BlockValidationError::NegativeFee,
            b_new.validate(&b_prev, ts, network).await.err().unwrap()
        );
    }
}
