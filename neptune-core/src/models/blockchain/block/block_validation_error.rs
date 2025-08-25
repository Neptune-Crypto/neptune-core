use crate::util_types::mutator_set::removal_record::removal_record_list::RemovalRecordListUnpackError;

/// The reasons why a [`Block`](crate::models::blockchain::block::Block) can be
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
    use super::*;
    use proptest::prelude::Just;
    use proptest::test_runner::RngSeed;
    use proptest::{prop_assert_eq, prop_assume};
    use proptest_arbitrary_interop::arb;
    use tasm_lib::triton_vm::{prelude::BFieldElement, proof::Claim};
    use tasm_lib::twenty_first::bfe;
    use test_strategy::proptest;

    use crate::api::export::{NativeCurrencyAmount, NeptuneProof, Network, Timestamp};
    use crate::models::blockchain::block::block_appendix::{BlockAppendix, MAX_NUM_CLAIMS};
    use crate::models::blockchain::block::difficulty_control::{self, Difficulty};
    use crate::models::blockchain::block::validity::block_program::BlockProgram;
    use crate::models::blockchain::block::{Block, BlockProof};
    use crate::models::blockchain::consensus_rule_set::ConsensusRuleSet;
    use crate::models::blockchain::transaction::transaction_kernel::TransactionKernelProxy;
    use crate::models::proof_abstractions::verifier::cache_true_claim;
    use crate::tests::shared::blocks::fake_valid_successor_for_tests;
    use crate::tests::shared::{strategies::block_with_arbkernel, Randomness};
    use crate::util_types::mutator_set::addition_record::AdditionRecord;

    proptest::prop_compose! {
        fn setup() (
            rness in arb::<Randomness<2, 2>>(),
            d in 1..crate::tests::shared::blocks::DIFFICULTY_LIMIT, // it is a divisor down the line
            b in block_with_arbkernel()
        ) (
            ts in (
                Timestamp::hours(1) + b.kernel.header.timestamp
            ).0.value()..=BFieldElement::MAX,
            rness in Just(rness), mut b in Just(b), difficulty in Just(d)
        ) -> (crate::models::blockchain::block::Block, Timestamp, Randomness<2, 2>) {
            b.kernel.header.difficulty = Difficulty::from(difficulty);
            (b, Timestamp(bfe![ts]), rness)
        }
    }

    #[proptest(async = "tokio", cases = 1, rng_seed = RngSeed::Fixed(0))]
    async fn block_with_mutator_set_update_integrity_error_fails(
        #[strategy(setup())] s: (Block, Timestamp, Randomness<2, 2>),
        #[strategy(arb())] record_addition_an: AdditionRecord,
    ) {
        let (mut b_prev, ts, rness) = s;
        let b_new = fake_valid_successor_for_tests(&b_prev, ts, rness, Network::Main).await;

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
            b_new
                .validate(&b_prev, ts, Network::Main)
                .await
                .err()
                .unwrap()
        );
    }

    #[proptest(async = "tokio", cases = 1, rng_seed = RngSeed::Fixed(0))]
    async fn block_with_negative_coinbase_fails(
        #[strategy(setup())] s: (Block, Timestamp, Randomness<2, 2>),
    ) {
        let (b_prev, ts, rness) = s;

        let mut b_new = fake_valid_successor_for_tests(&b_prev, ts, rness, Network::Main).await;

        let coinbase_newblock = b_new
            .kernel
            .body
            .transaction_kernel
            .coinbase
            .expect("IIRC `fake_valid_successor_for_tests` produces `Some` `coinbase`");

        if !coinbase_newblock.is_negative() {
            let mut tx_kernel_neg_coinbase =
                TransactionKernelProxy::from(b_new.kernel.body.transaction_kernel.clone());
            tx_kernel_neg_coinbase.coinbase = Some(-NativeCurrencyAmount::one_nau());

            b_new.kernel.body.transaction_kernel = tx_kernel_neg_coinbase.into_kernel();
            b_new.kernel.appendix = BlockAppendix::new(BlockAppendix::consensus_claims(
                b_new.body(),
                ConsensusRuleSet::infer_from(Network::Main, b_prev.header().height),
            ));
            cache_true_claim(BlockProgram::claim(b_new.body(), &b_new.kernel.appendix)).await;
        }

        prop_assert_eq!(
            BlockValidationError::NegativeCoinbase,
            b_new
                .validate(&b_prev, ts, Network::Main)
                .await
                .err()
                .unwrap()
        );
    }

    #[proptest(async = "tokio", cases = 1, rng_seed = RngSeed::Fixed(0))]
    async fn block_with_coinbase_too_big_fails(
        #[strategy(setup())] s: (Block, Timestamp, Randomness<2, 2>),
    ) {
        let (b_prev, ts, rness) = s;

        let mut b_new = fake_valid_successor_for_tests(&b_prev, ts, rness, Network::Main).await;

        let mut tx_kernel_big_coinbase =
            TransactionKernelProxy::from(b_new.kernel.body.transaction_kernel.clone());
        tx_kernel_big_coinbase.coinbase =
            Some(NativeCurrencyAmount::one_nau() + Block::block_subsidy(b_new.header().height));
        b_new.kernel.body.transaction_kernel = tx_kernel_big_coinbase.into_kernel();
        b_new.kernel.appendix = BlockAppendix::new(BlockAppendix::consensus_claims(
            b_new.body(),
            ConsensusRuleSet::infer_from(Network::Main, b_prev.header().height),
        ));
        cache_true_claim(BlockProgram::claim(b_new.body(), &b_new.kernel.appendix)).await;

        prop_assert_eq!(
            BlockValidationError::CoinbaseTooBig,
            b_new
                .validate(&b_prev, ts, Network::Main)
                .await
                .err()
                .unwrap()
        );
    }

    #[proptest(async = "tokio", cases = 1, rng_seed = RngSeed::Fixed(0))]
    async fn block_with_appendix_too_large_fails(
        #[strategy(setup())] s: (Block, Timestamp, Randomness<2, 2>),
    ) {
        let (b_prev, ts, rness) = s;

        let mut b_new = fake_valid_successor_for_tests(&b_prev, ts, rness, Network::Main).await;

        let mut large_claims = b_new.kernel.appendix._claims().clone();
        large_claims.append(&mut vec![Claim::new(Default::default()); MAX_NUM_CLAIMS]);
        b_new.kernel.appendix = BlockAppendix::new(large_claims);

        prop_assert_eq!(
            BlockValidationError::AppendixTooLarge,
            b_new
                .validate(&b_prev, ts, Network::Main)
                .await
                .err()
                .unwrap()
        );
    }

    #[proptest(async = "tokio", cases = 1, rng_seed = RngSeed::Fixed(0))]
    async fn block_with_transaction_timestamp_error_fails(
        #[strategy(setup())] s: (Block, Timestamp, Randomness<2, 2>),
        #[strategy(#s.1.0.value()..=BFieldElement::MAX)] ts_kernel: u64,
    ) {
        let (b_prev, ts, rness) = s;

        let mut b_new = fake_valid_successor_for_tests(&b_prev, ts, rness, Network::Main).await;

        let mut tx_kernel_ts =
            TransactionKernelProxy::from(b_new.kernel.body.transaction_kernel.clone());
        tx_kernel_ts.timestamp = Timestamp(bfe![ts_kernel]);
        tx_kernel_ts.inputs = Vec::new();
        b_new.kernel.body.transaction_kernel = tx_kernel_ts.into_kernel();
        b_new.kernel.appendix = BlockAppendix::new(BlockAppendix::consensus_claims(
            b_new.body(),
            ConsensusRuleSet::infer_from(Network::Main, b_prev.header().height),
        ));
        cache_true_claim(BlockProgram::claim(b_new.body(), &b_new.kernel.appendix)).await;

        prop_assert_eq!(
            BlockValidationError::TransactionTimestamp,
            b_new
                .validate(&b_prev, ts, Network::Main)
                .await
                .err()
                .unwrap()
        );
    }

    #[proptest(async = "tokio", cases = 1, rng_seed = RngSeed::Fixed(0))]
    async fn block_with_negative_fee_fails(
        #[strategy(setup())] s: (Block, Timestamp, Randomness<2, 2>),
    ) {
        let (b_prev, ts, rness) = s;

        let mut b_new = fake_valid_successor_for_tests(&b_prev, ts, rness, Network::Main).await;

        if !b_new.kernel.body.transaction_kernel.fee.is_negative() {
            let mut tx_kernel_fee_neg =
                TransactionKernelProxy::from(b_new.kernel.body.transaction_kernel.clone());
            tx_kernel_fee_neg.fee = -NativeCurrencyAmount::one_nau();
            b_new.kernel.body.transaction_kernel = tx_kernel_fee_neg.into_kernel();
            b_new.kernel.appendix = BlockAppendix::new(BlockAppendix::consensus_claims(
                b_new.body(),
                ConsensusRuleSet::infer_from(Network::Main, b_prev.header().height),
            ));
            cache_true_claim(BlockProgram::claim(b_new.body(), &b_new.kernel.appendix)).await;
        }

        prop_assert_eq!(
            BlockValidationError::NegativeFee,
            b_new
                .validate(&b_prev, ts, Network::Main)
                .await
                .err()
                .unwrap()
        );
    }

    #[proptest(async = "tokio", cases = 1, rng_seed = RngSeed::Fixed(0))]
    async fn block_with_proof_quality_error_fails(
        #[strategy(setup())] s: (Block, Timestamp, Randomness<2, 2>),
    ) {
        let (b_prev, ts, rness) = s;

        let mut b_new = fake_valid_successor_for_tests(&b_prev, ts, rness, Network::Main).await;

        b_new.proof = BlockProof::Invalid;

        prop_assert_eq!(
            BlockValidationError::ProofQuality,
            b_new
                .validate(&b_prev, ts, Network::Main)
                .await
                .err()
                .unwrap()
        );
    }

    #[proptest(async = "tokio", cases = 1, rng_seed = RngSeed::Fixed(0))]
    async fn block_with_max_size_error_fails(
        #[strategy(setup())] s: (Block, Timestamp, Randomness<2, 2>),
    ) {
        let (b_prev, ts, rness) = s;

        let mut b_new = fake_valid_successor_for_tests(&b_prev, ts, rness, Network::Main).await;

        b_new.proof = BlockProof::SingleProof(NeptuneProof::from(vec![
            Default::default();
            1 + ConsensusRuleSet::infer_from(Network::Main, b_prev.header().height).max_block_size()
        ]));

        prop_assert_eq!(
            BlockValidationError::MaxSize,
            b_new
                .validate(&b_prev, ts, Network::Main)
                .await
                .err()
                .unwrap()
        );
    }

    #[proptest(async = "tokio", cases = 1, rng_seed = RngSeed::Fixed(0))]
    async fn block_with_appendix_missing_claim_fails(
        #[strategy(setup())] s: (Block, Timestamp, Randomness<2, 2>),
    ) {
        let (b_prev, ts, _) = s;

        prop_assert_eq!(
            BlockValidationError::AppendixMissingClaim,
            crate::tests::shared::blocks::invalid_empty_block(&b_prev, Network::Main)
                .validate(&b_prev, ts, Network::Main)
                .await
                .err()
                .unwrap()
        );
    }

    #[proptest(async = "tokio", cases = 1, rng_seed = RngSeed::Fixed(0))]
    async fn block_with_future_dating_fails(
        #[strategy(setup())] s: (Block, Timestamp, Randomness<2, 2>),
        #[strategy(#s.1.0.value() + 1288490188500000u64..=BFieldElement::MAX)] ts_f: u64,
    ) {
        let (b_prev, ts, _) = s;

        let mut b_new = crate::tests::shared::blocks::invalid_empty_block_with_timestamp(
            &b_prev,
            ts,
            Network::Main,
        );
        b_new.kernel.header.timestamp = Timestamp(bfe![ts_f]);
        b_new.kernel.header.difficulty = if Block::should_reset_difficulty(
            Network::Main,
            b_new.header().timestamp,
            b_prev.header().timestamp,
        ) {
            Network::Main.genesis_difficulty()
        } else {
            difficulty_control::difficulty_control(
                b_new.header().timestamp,
                b_prev.header().timestamp,
                b_prev.header().difficulty,
                Network::Main.target_block_interval(),
                b_prev.header().height,
            )
        };
        prop_assert_eq!(
            BlockValidationError::FutureDating,
            b_new
                .validate(&b_prev, ts, Network::Main)
                .await
                .err()
                .unwrap()
        );
    }

    #[proptest(async = "tokio", cases = 1, rng_seed = RngSeed::Fixed(0))]
    async fn block_with_cumulative_proof_of_work_error_fails(
        #[strategy(setup())] s: (Block, Timestamp, Randomness<2, 2>),
        #[strategy(arb())] cumul: difficulty_control::ProofOfWork,
    ) {
        let (b_prev, ts, _) = s;

        let mut b_new = crate::tests::shared::blocks::invalid_empty_block_with_timestamp(
            &b_prev,
            ts,
            Network::Main,
        );
        prop_assume!(cumul != b_new.kernel.header.cumulative_proof_of_work);
        b_new.kernel.header.cumulative_proof_of_work = cumul;
        prop_assert_eq!(
            BlockValidationError::CumulativeProofOfWork,
            b_new
                .validate(&b_prev, ts, Network::Main)
                .await
                .err()
                .unwrap()
        );
    }

    #[proptest(async = "tokio", cases = 1, rng_seed = RngSeed::Fixed(0))]
    async fn block_with_difficulty_error_fails(
        #[strategy(setup())] s: (Block, Timestamp, Randomness<2, 2>),
        #[strategy(arb())] d: Difficulty,
    ) {
        let (b_prev, ts, rness) = s;

        let mut b_new = fake_valid_successor_for_tests(&b_prev, ts, rness, Network::Main).await;

        prop_assume!(d != b_new.kernel.header.difficulty);
        b_new.kernel.header.difficulty = d;

        prop_assert_eq!(
            BlockValidationError::Difficulty,
            b_new
                .validate(&b_prev, ts, Network::Main)
                .await
                .err()
                .unwrap()
        );
    }

    #[proptest(async = "tokio", cases = 1, rng_seed = RngSeed::Fixed(0))]
    async fn block_with_minimum_block_time_error_fails(
        #[strategy(setup())] s: (Block, Timestamp, Randomness<2, 2>),
        #[strategy(0..60u64)] ts_small: u64,
    ) {
        let (b_prev, ts, _) = s;

        prop_assert_eq!(
            BlockValidationError::MinimumBlockTime,
            crate::tests::shared::blocks::invalid_empty_block_with_timestamp(
                &b_prev,
                b_prev.kernel.header.timestamp + Timestamp(bfe![ts_small]),
                Network::Main,
            )
            .validate(&b_prev, ts, Network::Main)
            .await
            .err()
            .unwrap()
        );
    }

    #[proptest(async = "tokio", cases = 1, rng_seed = RngSeed::Fixed(0))]
    async fn block_with_block_mmr_update_error_fails(
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
    async fn block_with_prev_block_digest_error_fails(
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
    async fn block_with_block_height_error_fails(
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

    /* snippets for the uncreachable variants
    ========================================== */
    // let mut err_checking = BlockValidationError::MutatorSetUpdateImpossible;
    /* > @skaunov:
    Is that ok two identical addition records in a tx kernel proxy doesn't trigger a validation error (at least up to the digests  comparison for integrity)? I mean I can imagine some deduplication under the hood hence asking. I thought it's the simplest way to hit BlockValidationError::MutatorSetUpdateImpossible (renamed a bit); but maybe there's a better path to it?

    > @sword-smith:
    There might be an error wrt. mutator set update that cannot be reached.

    > @sword-smith:
    I'm not sure it's possible to hit the `BlockValidationError::MutatorSetUpdatePossible` error.
    */

    // err_checking = BlockValidationError::ProofValidity;
    /* @skaunov, [12.07.2025 18:30]
    >> ... So, you already did the negative test for this case back than: `block_with_invalid_proof_fails` it is, am I correct?

    @sword-smith, [15.07.2025 20:02]
    > Yeah. I added that negative test. */
    // proptest::proptest!(
    //     deterministic,
    //     |((b_prev, ts, rness) in n_strategy(), proof in arb::<NeptuneProof>(),
    //     tx_kernel in crate::tests::shared::strategies::txkernel::default(true))|
    //     {
    //         // fake_block_successor_with_merged_tx

    //         // let t = crate::tests::tokio_runtime().block_on(async {
    //         //     let mut b_new = crate::tests::shared::blocks::fake_valid_block_from_tx_for_tests(
    //         //         Network::Main,
    //         //         &b_prev,
    //         //         Transaction{kernel: tx_kernel, proof: TransactionProof::SingleProof(proof.clone())},
    //         //         rness.bytes_arr[0],
    //         //     ).await;
    //         //     dbg!(b_new.proof);
    //         //     b_new.proof = super::super::BlockProof::SingleProof(dbg!(proof));
    //         //     b_new.kernel.appendix = BlockAppendix::new(BlockAppendix::consensus_claims(b_new.body()));
    //         //     b_new.validate(&b_prev, ts, Network::Main).await
    //         // });

    //         let t = crate::tests::tokio_runtime().block_on(async {
    //             let mut b_new = fake_valid_successor_for_tests(
    //                 &b_prev,
    //                 ts,
    //                 rness,
    //                 Network::Main,
    //             ).await;
    //             // dbg!(b_new.proof);
    //             b_new.proof = super::super::BlockProof::SingleProof(Proof::invalid());
    //             // b_new.kernel.appendix = BlockAppendix::new(BlockAppendix::consensus_claims(b_new.body()));
    //             b_new.validate(&b_prev, ts, Network::Main).await
    //         });
    //         prop_assert_eq![BlockValidationError::ProofValidity, t.err().unwrap()];
    //     }
    // );
    // __________________________________________________________________
    // err_checking = BlockValidationError::RemovalRecordsValidity;
    // proptest::proptest!(
    //     deterministic,
    //     |(
    //         // (
    //         //     absolute_indices, target_chunks,
    //             (mut b_prev, ts, rness)
    //         // )
    //         in n_strategy(),
    //         // .prop_filter("need at least one RR for `BlockValidationError::RemovalRecordsValidity`", |(b_prev, ..)| b_prev.mutator_set_accumulator_after().unwrap().get_batch_index() > 0)
    //         // .prop_flat_map(|(b_prev, ts, rness)| {
    //         //     // due to currently defaulting the mutator set this is just `0` currently btw, but this approach should be working for the other stuff too
    //         //     let i = b_prev.mutator_set_accumulator_after().unwrap().get_batch_index();
    //         //     (
    //         //         crate::util_types::mutator_set::removal_record::tests::propcompose_absindset_with_limit(i),
    //         //         crate::util_types::mutator_set::chunk_dictionary::tests::propcompose_chunkdict_with_leafs_limit(i),
    //         //         Just((b_prev, ts, rness)),
    //         //     )
    //         // }),
    //         // msa_an in arb::<MutatorSetAccumulator>()
    //         rr in arb::<crate::util_types::mutator_set::removal_record::RemovalRecord>()
    //     )|
    //     {
    //         // let mut b_new =
    //         // crate::tests::shared::blocks::invalid_block_with_transaction(
    //         // crate::tests::tokio_runtime().block_on(

    //             // dbg!("`fake_valid_successor_for_tests`");
    //             // fake_valid_successor_for_tests(
    //             //     &b_prev,
    //             //     ts,
    //             //     rness,
    //             //     Network::Main,
    //             // )

    //             // crate::tests::shared::blocks::fake_valid_block_proposal_from_tx(
    //                 // Network::Main,
    //                 // &b_prev,
    //                 // crate::tests::shared::mock_tx::make_mock_transaction_with_mutator_set_hash_and_timestamp(
    //                 //     vec![crate::util_types::mutator_set::removal_record::RemovalRecord{
    //                 //         absolute_indices,
    //                 //         target_chunks
    //                 //     }], vec![],
    //                 //     b_prev.mutator_set_accumulator_after().unwrap().hash(),
    //                 //     ts,
    //                 // )
    //             // )
    //         // );

    //         // prop_assume!({
    //         //     let prev_msa = &b_prev.mutator_set_accumulator_after().unwrap();
    //         //     // prev_msa. &&

    //         //     dbg!(b_new.kernel.body.transaction_kernel.inputs.len());
    //         //     b_new.kernel.body.transaction_kernel.inputs.iter().any(
    //         //         |removal_record| !prev_msa.can_remove(removal_record)
    //         //     )
    //         // });

    //         let t = crate::tests::tokio_runtime().block_on(async {
    //             b_prev.kernel.body.mutator_set_accumulator.remove(rr);

    //             let mut b_new = fake_valid_successor_for_tests(
    //                 &b_prev,
    //                 ts,
    //                 rness,
    //                 Network::Main,
    //             ).await;

    //             // dbg!("&msa_an");
    //             // b_new.kernel.body.mutator_set_accumulator = msa_an;
    //             // dbg!("claim(s) update");
    //             // b_new.kernel.appendix = BlockAppendix::new(BlockAppendix::consensus_claims(b_new.body()));

    //             dbg!("`.validate`");
    //             b_new.validate(&b_prev, ts, Network::Main).await
    //         });
    //         prop_assert_eq![err, t.err().unwrap()];
    //     }
    // );
    /* feels like primitive witness guards again `RemovalRecordsValidity` so even producing a block body such that a new block validation would go this far is not possible with the tools we have for normal/good block production */

    // err_checking = BlockValidationError::TooManyAnnouncements;
    // Not reachable without moving a #submethod from `.validate`. See #625 for the details.
    // proptest::proptest!(
    //     singlecase_config,
    //     |((b_prev, ts, rness) in n_strategy())|
    //     {
    //         let t = crate::tests::tokio_runtime().block_on(async {
    //             let mut b_new = fake_valid_successor_for_tests(
    //                 &b_prev,
    //                 ts,
    //                 rness,
    //                 Network::Main,
    //             ).await;

    //             let mut tx_kernel_many_announcements = TransactionKernelProxy::from(
    //                 b_new
    //                     .kernel
    //                     .body
    //                     .transaction_kernel
    //                     .clone(),
    //             );
    //             tx_kernel_many_announcements.inputs = Vec::new();
    //             tx_kernel_many_announcements.public_announcements = vec![
    //                 crate::models::blockchain::transaction::announcement::Announcement::default();
    //                 super::super::MAX_NUM_INPUTS_OUTPUTS_ANNOUNCEMENTS + 1
    //             ];
    //             b_new.kernel.body.transaction_kernel =
    //                 tx_kernel_many_announcements.into_kernel();
    //             b_new.kernel.appendix = BlockAppendix::new(BlockAppendix::consensus_claims(b_new.body(), ConsensusRuleSet::infer_from(Network::Main, b_prev.header().height)));
    //             cache_true_claim(BlockProgram::claim(b_new.body(), &b_new.kernel.appendix)).await;

    //             b_new.validate_limit_announcements(
    //                 // &b_prev, ts, Network::Main
    //             )
    //             // .await
    //         });
    //         prop_assert_eq![err, t.err().unwrap()];
    //     }
    // );

    // err_checking = BlockValidationError::TooManyOutputs;
    // #submethod
    // proptest::proptest!(
    //     singlecase_config,
    //     |((b_prev, ts, rness) in n_strategy(), record_addition_an in arb::<AdditionRecord>())|
    //     {
    //         let t = crate::tests::tokio_runtime().block_on(async {
    //             let mut b_new = fake_valid_successor_for_tests(
    //                 &b_prev,
    //                 ts,
    //                 rness,
    //                 Network::Main,
    //             ).await;

    //             let mut tx_kernel_many_outputs = TransactionKernelProxy::from(
    //                 b_new.kernel.body.transaction_kernel.clone(),
    //             );
    //             tx_kernel_many_outputs.inputs = Vec::new();
    //             tx_kernel_many_outputs.outputs = vec![
    //                 record_addition_an;
    //                 1 + MAX_NUM_INPUTS_OUTPUTS_PUB_ANNOUNCEMENTS_AFTER_HF_1
    //             ];
    //             b_new.kernel.body.transaction_kernel =
    //                 tx_kernel_many_outputs.into_kernel();
    //             b_new.kernel.appendix =
    //                 BlockAppendix::new(BlockAppendix::consensus_claims(b_new.body(), ConsensusRuleSet::infer_from(Network::Main, b_prev.header().height)));
    //             cache_true_claim(BlockProgram::claim(b_new.body(), &b_new.kernel.appendix)).await;

    //             b_new.validate_limit_outputs(
    //                 // &b_prev, ts, Network::Main
    //             )
    //             // .await
    //         });
    //         prop_assert_eq![err, t.err().unwrap()];
    //     }
    // );

    // err_checking = BlockValidationError::TooManyInputs;
    // #submethod
    // proptest::proptest!(singlecase_config, |((b_prev, ts, rness) in n_strategy())|
    // {
    //     let t = crate::tests::tokio_runtime().block_on(async {
    //         let mut b_new = fake_valid_successor_for_tests(
    //             &b_prev,
    //             ts,
    //             rness,
    //             Network::Main,
    //         ).await;

    //         let mut tx_kernel_many_inputs = TransactionKernelProxy::from(
    //             b_new.kernel.body.transaction_kernel.clone(),
    //         );
    //         // Create fake removal records (don't need to be valid since check happens early)
    //         let fake_removal_records: Vec<_> = (0..=MAX_NUM_INPUTS_OUTPUTS_PUB_ANNOUNCEMENTS_AFTER_HF_1)
    //             .map(|i| {
    //                 let mut indices = [0u128; crate::util_types::mutator_set::shared::NUM_TRIALS as usize];
    //                 indices[0] = i as u128;
    //                 crate::util_types::mutator_set::removal_record::RemovalRecord {
    //                     absolute_indices: crate::util_types::mutator_set::removal_record::AbsoluteIndexSet::new(&indices),
    //                     target_chunks: Default::default(),
    //                 }
    //             })
    //             .collect();
    //         tx_kernel_many_inputs.inputs = fake_removal_records;
    //         tx_kernel_many_inputs.outputs = vec![];
    //         tx_kernel_many_inputs.public_announcements = vec![];
    //         b_new.kernel.body.transaction_kernel =
    //             tx_kernel_many_inputs.into_kernel();
    //         b_new.kernel.appendix =
    //             BlockAppendix::new(BlockAppendix::consensus_claims(b_new.body(), ConsensusRuleSet::infer_from(Network::Main, b_prev.header().height)));
    //         cache_true_claim(BlockProgram::claim(b_new.body(), &b_new.kernel.appendix)).await;

    //         b_new.validate_limit_inputs(
    //             // &b_prev, ts, Network::Main
    //         )
    //         // .await
    //     });
    //     prop_assert_eq![err, t.err().unwrap()];
    // });
    // _______________________________________________________________________
    /* @skaunov am not sure if adding testing utils to test double spending
    would enable testing this with the whole `validate`, but it's something to try too */
    // err_checking = BlockValidationError::RemovalRecordsUniqueness;
    // #submethod
    // proptest::proptest!(
    //     singlecase_config,
    //     |((b_prev, ts, rness) in n_strategy(), rr in arb::<crate::util_types::mutator_set::removal_record::RemovalRecord>())|
    //     {
    //         let t = crate::tests::tokio_runtime().block_on(async {
    //             let mut b_new = fake_valid_successor_for_tests(
    //                 &b_prev,
    //                 ts,
    //                 rness,
    //                 Network::Main,
    //             ).await;

    //             let mut tx_kernel_dup =
    //                 TransactionKernelProxy::from(b_new.kernel.body.transaction_kernel.clone());
    //             tx_kernel_dup.inputs.push(rr.clone());
    //             tx_kernel_dup.inputs.push(rr);
    //             b_new.kernel.body.transaction_kernel = tx_kernel_dup.into_kernel();
    //             b_new.kernel.appendix =
    //                 BlockAppendix::new(BlockAppendix::consensus_claims(b_new.body(), ConsensusRuleSet::infer_from(Network::Main, b_prev.header().height)));
    //             cache_true_claim(BlockProgram::claim(b_new.body(), &b_new.kernel.appendix)).await;

    //             b_new.validate_rr_uniqueness(
    //                 // &b_prev, ts, Network::Main
    //             )
    //             // .await
    //         });
    //         prop_assert_eq![err, t.err().unwrap()];
    //     }
    // );
}
