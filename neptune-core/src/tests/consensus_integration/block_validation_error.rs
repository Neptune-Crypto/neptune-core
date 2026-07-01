use neptune_mutator_set::addition_record::AdditionRecord;
use neptune_primitives::timestamp::Timestamp;
use num_traits::CheckedSub;
use proptest::prelude::Just;
use proptest::prop_assert_eq;
use proptest::prop_assume;
use proptest::test_runner::RngSeed;
use proptest_arbitrary_interop::arb;
use tasm_lib::triton_vm::prelude::BFieldElement;
use tasm_lib::triton_vm::proof::Claim;
use tasm_lib::twenty_first::bfe;
use tasm_lib::twenty_first::prelude::Mmr;
use test_strategy::proptest;

use crate::protocol::consensus::block::arbitrary_kernel as block_with_arbkernel;
use crate::protocol::consensus::block::block_appendix::BlockAppendix;
use crate::protocol::consensus::block::block_appendix::MAX_NUM_CLAIMS;
use crate::protocol::consensus::block::block_height::BlockHeight;
use crate::protocol::consensus::block::block_validation_error::BlockValidationError;
use crate::protocol::consensus::block::difficulty_control;
use crate::protocol::consensus::block::difficulty_control::Difficulty;
use crate::protocol::consensus::block::pow::LustrationStatus;
use crate::protocol::consensus::block::test_helpers::invalid_empty_block;
use crate::protocol::consensus::block::test_helpers::invalid_empty_block_with_timestamp;
use crate::protocol::consensus::block::validity::block_program::BlockProgram;
use crate::protocol::consensus::block::Block;
use crate::protocol::consensus::block::BlockProof;
use crate::protocol::consensus::block::DIFFICULTY_LIMIT_FOR_TESTS;
use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
use crate::protocol::consensus::consensus_rule_set::BLOCK_HEIGHT_HARDFORK_BETA_MAIN_NET;
use crate::protocol::consensus::consensus_rule_set::TX_BACKDATING_LIMIT;
use crate::protocol::consensus::network::Network;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelModifier;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelProxy;
use crate::protocol::consensus::transaction::validity::neptune_proof::NeptuneProof;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::protocol::proof_abstractions::verifier::cache_true_claims;
use crate::tests::shared::blocks::fake_valid_successor_for_tests;
use crate::tests::shared::Randomness;

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
        b.kernel_mut().header.difficulty = Difficulty::from(difficulty);
        (b, Timestamp(bfe![ts]), rness)
    }
}

proptest::prop_compose! {
 fn setup_with_height(height: BlockHeight) (
        rness in arb::<Randomness<2, 2>>(),
        d in 1..DIFFICULTY_LIMIT_FOR_TESTS,
        b in block_with_arbkernel()
    ) (
        ts in (
            Timestamp::hours(1) + b.kernel.header.timestamp
        ).0.value()..=BFieldElement::MAX,
        rness in Just(rness), mut b in Just(b), difficulty in Just(d)
    ) -> (crate::protocol::consensus::block::Block, Timestamp, Randomness<2, 2>) {
        b.kernel_mut().header.difficulty = Difficulty::from(difficulty);
        b.set_header_height(height);
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
                Network::Main,
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
    b_new.kernel_mut().header.height = b_prev.kernel.header.height + 1;
    prop_assert_eq!(
        BlockValidationError::PrevBlockDigest,
        b_new
            .validate(
                &b_prev,
                b_prev.kernel.header.timestamp + Timestamp(bfe![60]),
                Network::Main,
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
    b_new.kernel_mut().header.height = b_prev.kernel.header.height + 1;
    b_new.kernel_mut().header.prev_block_digest = b_prev.hash();
    prop_assert_eq!(
        BlockValidationError::BlockMmrUpdate,
        b_new
            .validate(
                &b_prev,
                b_prev.kernel.header.timestamp + Timestamp(bfe![60]),
                Network::Main,
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
    b_new.kernel_mut().header.difficulty = d;

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
    b_new.kernel_mut().header.cumulative_proof_of_work = cumul;
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

    let new_timestamp = Timestamp(bfe![ts_f]);
    let new_difficulty = difficulty_control::difficulty_control(
        new_timestamp,
        b_prev.header().timestamp,
        b_prev.header().difficulty,
        network.target_block_interval(),
        b_prev.header().height,
    );
    let consensus_rule_set = ConsensusRuleSet::infer_from(network, b_new.header().height);
    let new_cum_pow = if consensus_rule_set.use_parent_difficulty() {
        None
    } else {
        Some(b_prev.header().cumulative_proof_of_work + new_difficulty)
    };

    b_new.set_difficulty_related_fields(new_timestamp, new_difficulty, new_cum_pow);
    prop_assert_eq!(
        BlockValidationError::FutureDating,
        b_new.validate(&b_prev, ts, network).await.err().unwrap()
    );
}

#[tokio::test]
async fn block_with_future_dating_fails_0g_unit_test() {
    let network = Network::Main;
    let genesis = Block::genesis(network);
    let now = Timestamp::now();
    let too_far_in_future = now + Timestamp::seconds(60) + Timestamp::millis(1);

    assert_eq!(
        BlockValidationError::FutureDating,
        invalid_empty_block_with_timestamp(&genesis, too_far_in_future, network)
            .validate(&genesis, now, network)
            .await
            .err()
            .unwrap()
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

    let mut large_claims = b_new.kernel.appendix()._claims().clone();
    large_claims.append(&mut vec![Claim::new(Default::default()); MAX_NUM_CLAIMS]);
    b_new.set_appendix(BlockAppendix::new(large_claims));

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
    b_new.set_proof(BlockProof::Invalid);

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
    b_new.set_proof(BlockProof::SingleProof(NeptuneProof::from(vec![
        Default::default();
        big_size
    ])));

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
    let mut b_new = fake_valid_successor_for_tests(&b_prev, ts, rness, network).await;

    b_prev
        .kernel_mut()
        .body
        .mutator_set_accumulator_mut()
        .add(&record_addition_an);
    let new_kernel = TransactionKernelModifier::default()
        .mutator_set_hash(b_prev.mutator_set_accumulator_after().unwrap().hash())
        .modify(b_new.kernel.body.transaction_kernel.clone());
    b_new.kernel_mut().body.transaction_kernel = new_kernel;
    let consensus_rule_set = ConsensusRuleSet::infer_from(network, b_new.header().height);
    b_new.set_appendix(BlockAppendix::new(BlockAppendix::consensus_claims(
        b_new.body(),
        consensus_rule_set,
    )));

    cache_true_claims([BlockProgram::claim(
        b_new.body(),
        b_new.kernel.appendix(),
        consensus_rule_set,
    )])
    .await;

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
    b_new.kernel_mut().body.transaction_kernel = tx_kernel_ts.into_kernel();
    let consensus_rule_set = ConsensusRuleSet::infer_from(network, b_new.header().height);
    b_new.set_appendix(BlockAppendix::new(BlockAppendix::consensus_claims(
        b_new.body(),
        consensus_rule_set,
    )));
    cache_true_claims([BlockProgram::claim(
        b_new.body(),
        b_new.kernel.appendix(),
        consensus_rule_set,
    )])
    .await;

    prop_assert_eq!(
        BlockValidationError::TransactionTimestamp,
        b_new.validate(&b_prev, ts, network).await.err().unwrap()
    );
}

#[proptest(async = "tokio", cases = 1, rng_seed = RngSeed::Fixed(0))]
async fn block_with_transaction_timestamp_too_small_fails_2f(
    #[strategy(setup())] s: (Block, Timestamp, Randomness<2, 2>),
) {
    let network = Network::Main;
    let (b_prev, ts, rness) = s;
    let mut b_new = fake_valid_successor_for_tests(&b_prev, ts, rness, network).await;
    let consensus_rule_set = ConsensusRuleSet::infer_from(network, b_new.header().height);
    prop_assume!(consensus_rule_set
        .transaction_backdating_threshold()
        .is_some());

    let mut tx_kernel_ts =
        TransactionKernelProxy::from(b_new.kernel.body.transaction_kernel.clone());
    tx_kernel_ts.timestamp = b_new.header().timestamp - TX_BACKDATING_LIMIT - Timestamp::minutes(1);
    b_new.kernel_mut().body.transaction_kernel = tx_kernel_ts.into_kernel();
    b_new.set_appendix(BlockAppendix::new(BlockAppendix::consensus_claims(
        b_new.body(),
        consensus_rule_set,
    )));
    cache_true_claims([BlockProgram::claim(
        b_new.body(),
        b_new.kernel.appendix(),
        consensus_rule_set,
    )])
    .await;

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
    b_new.kernel_mut().body.transaction_kernel = tx_kernel_big_coinbase.into_kernel();
    let consensus_rule_set = ConsensusRuleSet::infer_from(network, b_new.header().height);
    b_new.set_appendix(BlockAppendix::new(BlockAppendix::consensus_claims(
        b_new.body(),
        consensus_rule_set,
    )));
    cache_true_claims([BlockProgram::claim(
        b_new.body(),
        b_new.kernel.appendix(),
        consensus_rule_set,
    )])
    .await;

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

    b_new.kernel_mut().body.transaction_kernel = tx_kernel_neg_coinbase.into_kernel();
    let consensus_rule_set = ConsensusRuleSet::infer_from(network, b_new.header().height);
    b_new.set_appendix(BlockAppendix::new(BlockAppendix::consensus_claims(
        b_new.body(),
        consensus_rule_set,
    )));
    cache_true_claims([BlockProgram::claim(
        b_new.body(),
        b_new.kernel.appendix(),
        consensus_rule_set,
    )])
    .await;

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
    b_new.kernel_mut().body.transaction_kernel = tx_kernel_fee_neg.into_kernel();
    let consensus_rule_set = ConsensusRuleSet::infer_from(network, b_new.header().height);
    b_new.set_appendix(BlockAppendix::new(BlockAppendix::consensus_claims(
        b_new.body(),
        consensus_rule_set,
    )));
    cache_true_claims([BlockProgram::claim(
        b_new.body(),
        b_new.kernel.appendix(),
        consensus_rule_set,
    )])
    .await;

    prop_assert_eq!(
        BlockValidationError::NegativeFee,
        b_new.validate(&b_prev, ts, network).await.err().unwrap()
    );
}

#[proptest(async = "tokio", cases = 1, rng_seed = RngSeed::Fixed(0))]
async fn bad_lustration_status_encoding_fails_2m(
    #[strategy(setup())] s: (Block, Timestamp, Randomness<2, 2>),
) {
    let network = Network::Main;
    let (b_prev, ts, rness) = s;

    prop_assume!(b_prev.header().height > ConsensusRuleSet::first_lustration_block(network));

    let mut b_new = fake_valid_successor_for_tests(&b_prev, ts, rness, network).await;
    b_new.set_unparseable_lustration_status();

    let consensus_rule_set = ConsensusRuleSet::infer_from(network, b_new.header().height);
    cache_true_claims([BlockProgram::claim(
        b_new.body(),
        b_new.kernel.appendix(),
        consensus_rule_set,
    )])
    .await;

    prop_assert_eq!(
        BlockValidationError::BadLustrationCounterEncoding,
        b_new.validate(&b_prev, ts, network).await.err().unwrap()
    );
}

#[proptest(async = "tokio", cases = 1, rng_seed = RngSeed::Fixed(0))]
async fn bad_lustration_status_encoding_fails_parent_2n(
    #[strategy(setup())] s: (Block, Timestamp, Randomness<2, 2>),
) {
    let network = Network::Main;
    let (mut b_prev, ts, rness) = s;

    prop_assume!(b_prev.header().height > ConsensusRuleSet::first_lustration_block(network));

    let mut b_new = fake_valid_successor_for_tests(&b_prev, ts, rness, network).await;
    b_prev.set_unparseable_lustration_status();
    b_new.kernel_mut().header.prev_block_digest = b_prev.hash();
    b_new.kernel_mut().body.block_mmr_accumulator =
        b_prev.kernel.body.block_mmr_accumulator.clone();
    b_new
        .kernel_mut()
        .body
        .block_mmr_accumulator
        .append(b_prev.hash());
    b_new.fix_mutator_set_fields(&b_prev);
    b_new.set_lustration_status(LustrationStatus::default());
    let consensus_rule_set = ConsensusRuleSet::infer_from(network, b_new.header().height);
    b_new.set_appendix(BlockAppendix::new(BlockAppendix::consensus_claims(
        b_new.body(),
        consensus_rule_set,
    )));

    cache_true_claims([BlockProgram::claim(
        b_new.body(),
        b_new.kernel.appendix(),
        consensus_rule_set,
    )])
    .await;

    prop_assert_eq!(
        BlockValidationError::BadLustrationCounterEncodingOfParent,
        b_new.validate(&b_prev, ts, network).await.err().unwrap()
    );
}

#[proptest(async = "tokio", cases = 1, rng_seed = RngSeed::Fixed(0))]
async fn bad_lustration_status_aocl_threshold_2q(
    #[strategy(setup())] s: (Block, Timestamp, Randomness<2, 2>),
) {
    let network = Network::Testnet(42);
    let (mut b_prev, ts, rness) = s;

    prop_assume!(b_prev.header().height > ConsensusRuleSet::first_lustration_block(network));
    let parent_lustration_status = LustrationStatus::default();
    b_prev.set_lustration_status(parent_lustration_status);

    let mut b_new = fake_valid_successor_for_tests(&b_prev, ts, rness, network).await;
    b_new.set_lustration_status(LustrationStatus {
        counter: parent_lustration_status.counter,
        max_lustrating_aocl_leaf_index: parent_lustration_status.max_lustrating_aocl_leaf_index + 3,
    });
    let consensus_rule_set = ConsensusRuleSet::infer_from(network, b_new.header().height);

    cache_true_claims([BlockProgram::claim(
        b_new.body(),
        b_new.kernel.appendix(),
        consensus_rule_set,
    )])
    .await;

    assert!(matches!(
        b_new.validate(&b_prev, ts, network).await.err().unwrap(),
        BlockValidationError::BadLustrationAoclThreshold { .. }
    ));
}

#[proptest(async = "tokio", cases = 1, rng_seed = RngSeed::Fixed(0))]
async fn bad_lustration_status_counter_2p(
    #[strategy(setup())] s: (Block, Timestamp, Randomness<2, 2>),
) {
    let network = Network::Main;
    let (mut b_prev, ts, rness) = s;

    prop_assume!(b_prev.header().height > ConsensusRuleSet::first_lustration_block(network));
    let parent_lustration_status = LustrationStatus {
        max_lustrating_aocl_leaf_index: 101,
        counter: NativeCurrencyAmount::coins(600),
    };
    b_prev.set_lustration_status(parent_lustration_status);

    let mut b_new = fake_valid_successor_for_tests(&b_prev, ts, rness, network).await;
    b_new.set_lustration_status(LustrationStatus {
        counter: parent_lustration_status.counter + NativeCurrencyAmount::one_nau(),
        max_lustrating_aocl_leaf_index: parent_lustration_status.max_lustrating_aocl_leaf_index,
    });

    let consensus_rule_set = ConsensusRuleSet::infer_from(network, b_new.header().height);
    cache_true_claims([BlockProgram::claim(
        b_new.body(),
        b_new.kernel.appendix(),
        consensus_rule_set,
    )])
    .await;

    assert!(matches!(
        b_new.validate(&b_prev, ts, network).await.err().unwrap(),
        BlockValidationError::BadLustrationCounter { .. }
    ));
}

#[tokio::test]
async fn bad_lustration_status_counter_exceeds_initial_value_2p() {
    let network = Network::Testnet(42);
    let rness = Default::default();
    let b_prev = Block::genesis(network);
    let ts = b_prev.header().timestamp + Timestamp::hours(1);

    let mut b_new = fake_valid_successor_for_tests(&b_prev, ts, rness, network).await;
    let consensus_rule_set = ConsensusRuleSet::infer_from(network, b_new.header().height);
    assert_eq!(ConsensusRuleSet::HardforkGamma, consensus_rule_set);
    cache_true_claims([BlockProgram::claim(
        b_new.body(),
        b_new.kernel.appendix(),
        consensus_rule_set,
    )])
    .await;
    assert!(b_new.validate(&b_prev, ts, network).await.is_ok());

    let good_lustration_status = b_new.header().pow.lustration_status().unwrap();
    let one_nau = NativeCurrencyAmount::one_nau();
    let bad_counter = good_lustration_status
        .counter
        .checked_sub(&one_nau)
        .unwrap();
    b_new.set_lustration_status(LustrationStatus {
        counter: bad_counter,
        max_lustrating_aocl_leaf_index: good_lustration_status.max_lustrating_aocl_leaf_index,
    });

    cache_true_claims([BlockProgram::claim(
        b_new.body(),
        b_new.kernel.appendix(),
        consensus_rule_set,
    )])
    .await;

    assert!(matches!(
        b_new.validate(&b_prev, ts, network).await.err().unwrap(),
        BlockValidationError::BadLustrationCounter { .. }
    ));
}

#[tokio::test]
async fn bad_lustration_status_counter_bad_initial_threshold_2q() {
    let network = Network::Testnet(42);
    let rness = Default::default();
    let b_prev = Block::genesis(network);
    let ts = b_prev.header().timestamp + Timestamp::hours(1);

    let mut b_new = fake_valid_successor_for_tests(&b_prev, ts, rness, network).await;

    let good_lustration_status = b_new.header().pow.lustration_status().unwrap();
    b_new.set_lustration_status(LustrationStatus {
        counter: good_lustration_status.counter,
        max_lustrating_aocl_leaf_index: good_lustration_status.max_lustrating_aocl_leaf_index - 1,
    });

    let consensus_rule_set = ConsensusRuleSet::infer_from(network, b_new.header().height);
    cache_true_claims([BlockProgram::claim(
        b_new.body(),
        b_new.kernel.appendix(),
        consensus_rule_set,
    )])
    .await;

    assert!(matches!(
        b_new.validate(&b_prev, ts, network).await.err().unwrap(),
        BlockValidationError::BadLustrationAoclThreshold { .. }
    ));
}

#[proptest(async = "tokio", cases = 1, rng_seed = RngSeed::Fixed(0))]
async fn version_mismatch(
    #[strategy(setup())] s: (Block, Timestamp, Randomness<2, 2>),
    #[strategy(arb())] version: BFieldElement,
) {
    let network = Network::Main;
    let (b_prev, ts, rness) = s;
    prop_assume!(b_prev.header().height.next() >= BLOCK_HEIGHT_HARDFORK_BETA_MAIN_NET);
    prop_assume!(b_prev.header().version != version);

    let mut b_new = fake_valid_successor_for_tests(&b_prev, ts, rness, network).await;
    let consensus_rule_set = ConsensusRuleSet::infer_from(network, b_new.header().height);
    cache_true_claims([BlockProgram::claim(
        b_new.body(),
        b_new.kernel.appendix(),
        consensus_rule_set,
    )])
    .await;
    assert!(b_new.validate(&b_prev, ts, network).await.is_ok());

    b_new.set_header_version_in_pow_only(version);
    assert_eq!(
        b_new.validate(&b_prev, ts, network).await.err().unwrap(),
        BlockValidationError::VersionMismatch
    );

    b_new.set_version_in_header_only(version);
    assert_eq!(Ok(()), b_new.validate(&b_prev, ts, network).await);
}
