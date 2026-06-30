use itertools::Itertools;
use macro_rules_attr::apply;
use neptune_archival_mmr::ArchivalMmr;
use neptune_database::storage::storage_schema::SimpleRustyStorage;
use neptune_database::NeptuneLevelDb;
use neptune_primitives::timestamp::Timestamp;
use proptest::collection;
use proptest_arbitrary_interop::arb;
use rand::random;
use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use tasm_lib::twenty_first::tip5::digest::Digest;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
use tasm_lib::twenty_first::util_types::mmr::mmr_trait::LeafMutation;
use tasm_lib::twenty_first::util_types::mmr::mmr_trait::Mmr;
use tracing_test::traced_test;

use crate::application::config::cli_args;
use crate::application::config::fee_notification_policy::FeeNotificationPolicy;
use crate::application::loops::mine_loop::coinbase_distribution::CoinbaseDistribution;
use crate::application::loops::mine_loop::composer_parameters::ComposerParameters;
use crate::application::loops::mine_loop::prepare_coinbase_transaction_stateless;
use crate::application::loops::mine_loop::tests::make_coinbase_transaction_from_state_lock;
use crate::protocol::consensus::block::block_transaction::BlockOrRegularTransaction;
use crate::protocol::consensus::block::block_transaction::BlockTransaction;
use crate::protocol::consensus::block::difficulty_control::difficulty_control;
use crate::protocol::consensus::block::validity::block_primitive_witness::BlockPrimitiveWitness;
use crate::protocol::consensus::block::validity::block_proof_witness::BlockProofWitness;
use crate::protocol::consensus::block::Block;
use crate::protocol::consensus::block::BlockProof;
use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
use crate::protocol::consensus::network::Network;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelModifier;
use crate::protocol::consensus::transaction::Transaction;
use crate::protocol::consensus::transaction::TransactionProof;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::protocol::proof_abstractions::tasm::program::TritonVmProofJobOptions;
use crate::protocol::proof_abstractions::triton_vm_job_queue::TritonVmJobPriority;
use crate::protocol::proof_abstractions::triton_vm_job_queue::TritonVmJobQueue;
use crate::protocol::proof_abstractions::tx_proving_capability::TxProvingCapability;
use crate::state::mempool::upgrade_priority::UpgradePriority;
use crate::state::transaction::tx_creation_config::TxCreationConfig;
use crate::state::wallet::address::KeyType;
use crate::state::wallet::transaction_output::TxOutput;
use crate::state::wallet::wallet_entropy::WalletEntropy;
use crate::tests::shared::blocks::fake_valid_successor_for_tests;
use crate::tests::shared::blocks::make_mock_block;
use crate::tests::shared::globalstate::mock_genesis_global_state;
use crate::tests::shared_tokio_runtime;

#[traced_test]
#[apply(shared_tokio_runtime)]
async fn total_block_subsidy_is_128_coins_regardless_of_guesser_fraction() {
    let network = Network::Main;
    let a_wallet_secret = WalletEntropy::new_random();
    let a_key = a_wallet_secret.nth_generation_spending_key_for_tests(0);
    let coinbase_distribution = CoinbaseDistribution::solo(a_key.to_address().into());
    let genesis = Block::genesis(network);
    let mut rng: StdRng = SeedableRng::seed_from_u64(2225550001);
    let now = genesis.header().timestamp + Timestamp::days(1);

    let mut guesser_fraction = 0f64;
    let step = 0.05;
    while guesser_fraction + step <= 1f64 {
        let composer_parameters = ComposerParameters::new(
            coinbase_distribution.clone(),
            rng.random(),
            None,
            guesser_fraction,
            FeeNotificationPolicy::OffChain,
        );
        let (composer_txos, transaction_details) =
            prepare_coinbase_transaction_stateless(&genesis, composer_parameters, now, network);
        let coinbase_kernel = transaction_details.primitive_witness().kernel;
        let coinbase_kernel = TransactionKernelModifier::default()
            .merge_bit(true)
            .modify(coinbase_kernel); // ok: proof is invalid anyway
        let coinbase_transaction = Transaction {
            kernel: coinbase_kernel,
            proof: TransactionProof::invalid(),
        };
        let coinbase_transaction =
            BlockTransaction::try_from(coinbase_transaction).expect("merge bit was set");
        let total_composer_reward: NativeCurrencyAmount = composer_txos
            .iter()
            .map(|tx_output| tx_output.utxo().get_native_currency_amount())
            .sum();
        let block_primitive_witness =
            BlockPrimitiveWitness::new(genesis.clone(), coinbase_transaction, network);
        let block_proof_witness = BlockProofWitness::produce(block_primitive_witness.clone());
        let block1 = Block::new(
            block_primitive_witness.header(now, network.target_block_interval()),
            block_primitive_witness.body().to_owned(),
            block_proof_witness.appendix(),
            BlockProof::Invalid,
        );
        let total_guesser_reward = block1.body().total_guesser_reward().unwrap();
        let total_miner_reward = total_composer_reward + total_guesser_reward;
        assert_eq!(NativeCurrencyAmount::coins(128), total_miner_reward);

        println!("guesser_fraction: {guesser_fraction}");
        println!(
            "total_composer_reward: {total_guesser_reward}, as nau: {}",
            total_composer_reward.to_nau()
        );
        println!(
            "total_guesser_reward: {total_guesser_reward}, as nau {}",
            total_guesser_reward.to_nau()
        );
        println!(
            "total_miner_reward: {total_miner_reward}, as nau {}\n\n",
            total_miner_reward.to_nau()
        );

        guesser_fraction += step;
    }
}

#[traced_test]
#[apply(shared_tokio_runtime)]
async fn test_difficulty_control_matches() {
    let network = Network::Main;

    let a_wallet_secret = WalletEntropy::new_random();
    let a_key = a_wallet_secret.nth_generation_spending_key_for_tests(0);

    // TODO: Can this outer-loop be parallelized?
    for multiplier in [1, 10, 100, 1_000, 10_000, 100_000, 1_000_000] {
        let mut block_prev = Block::genesis(network);
        let mut now = block_prev.kernel.header.timestamp;
        let mut rng = rand::rng();

        for i in (0..10).step_by(1) {
            let duration = i as u64 * multiplier;
            now += Timestamp::millis(duration);

            let (block, _) =
                make_mock_block(&block_prev, Some(now), a_key, rng.random(), network).await;

            let control = difficulty_control(
                block.kernel.header.timestamp,
                block_prev.header().timestamp,
                block_prev.header().difficulty,
                network.target_block_interval(),
                block_prev.header().height,
            );
            assert_eq!(block.kernel.header.difficulty, control);

            block_prev = block;
        }
    }
}

#[apply(shared_tokio_runtime)]
async fn block_with_wrong_mmra_is_invalid() {
    let network = Network::Main;
    let genesis_block = Block::genesis(network);
    let now = genesis_block.kernel.header.timestamp + Timestamp::hours(2);
    let mut rng: StdRng = SeedableRng::seed_from_u64(2225550001);

    let mut block1 =
        fake_valid_successor_for_tests(&genesis_block, now, rng.random(), network).await;

    let timestamp = block1.kernel.header.timestamp;
    assert!(block1.is_valid(&genesis_block, timestamp, network).await);

    let mut mutated_leaf = genesis_block.body().block_mmr_accumulator.clone();
    let mp = mutated_leaf.append(genesis_block.hash());
    mutated_leaf.mutate_leaf(LeafMutation::new(0, random(), mp));

    let mut extra_leaf = block1.body().block_mmr_accumulator.clone();
    extra_leaf.append(block1.hash());

    let bad_new_mmrs = [
        MmrAccumulator::new_from_leafs(vec![]),
        mutated_leaf,
        extra_leaf,
    ];

    for bad_new_mmr in bad_new_mmrs {
        block1.kernel_mut().body.block_mmr_accumulator = bad_new_mmr;
        assert!(!block1.is_valid(&genesis_block, timestamp, network).await);
    }
}

#[test_strategy::proptest(async = "tokio", cases = 1)]
async fn can_prove_block_ancestry(
    #[strategy(collection::vec(arb::<Digest>(), 27))] mut sender_randomness_vec: Vec<Digest>,
    #[strategy(0..26usize)] index: usize,
    #[strategy(collection::vec(arb::<WalletEntropy>(), 27))] mut wallet_secret_vec: Vec<
        WalletEntropy,
    >,
) {
    let network = Network::RegTest;
    let genesis_block = Block::genesis(network);
    let mut blocks = vec![];
    blocks.push(genesis_block.clone());
    let db = NeptuneLevelDb::open_new_test_database(true, None, None, None)
        .await
        .unwrap();
    let mut storage = SimpleRustyStorage::new(db);
    let ammr_storage = storage.schema.new_vec::<Digest>("ammr-blocks-0").await;
    let mut ammr = ArchivalMmr::new(ammr_storage).await;
    ammr.append(genesis_block.hash()).await;
    let mut mmra = MmrAccumulator::new_from_leafs(vec![genesis_block.hash()]);

    for i in 0..27 {
        let wallet_secret = wallet_secret_vec.pop().unwrap();
        let key = wallet_secret.nth_generation_spending_key_for_tests(0);
        let (new_block, _) = make_mock_block(
            blocks.last().unwrap(),
            None,
            key,
            sender_randomness_vec.pop().unwrap(),
            network,
        )
        .await;
        if i != 26 {
            ammr.append(new_block.hash()).await;
            mmra.append(new_block.hash());
            assert_eq!(
                ammr.to_accumulator_async().await.bag_peaks(),
                mmra.bag_peaks()
            );
        }
        blocks.push(new_block);
    }

    let last_block_mmra = blocks.last().unwrap().body().block_mmr_accumulator.clone();
    assert_eq!(mmra, last_block_mmra);

    let block_digest = blocks[index].hash();

    let leaf_index = index as u64;
    let membership_proof = ammr.prove_membership_async(leaf_index).await;
    let v = membership_proof.verify(
        leaf_index,
        block_digest,
        &last_block_mmra.peaks(),
        last_block_mmra.num_leafs(),
    );
    assert!(
        v,
        "peaks: {} ({}) leaf count: {} index: {} path: {} number of blocks: {}",
        last_block_mmra.peaks().iter().join(","),
        last_block_mmra.peaks().len(),
        last_block_mmra.num_leafs(),
        leaf_index,
        membership_proof.authentication_path.iter().join(","),
        blocks.len(),
    );
    assert_eq!(last_block_mmra.num_leafs(), blocks.len() as u64 - 1);
}

mod block_is_valid {
    use macro_rules_attr::apply;
    use neptune_primitives::timestamp::Timestamp;
    use num_traits::Zero;
    use rand::rng;
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::SeedableRng;
    use tasm_lib::triton_vm::proof::Proof;
    use tracing_test::traced_test;

    use crate::application::config::cli_args;
    use crate::application::loops::mine_loop::create_block_transaction_from;
    use crate::application::loops::mine_loop::tests::make_coinbase_transaction_from_state_lock;
    use crate::application::loops::mine_loop::TxMergeOrigin;
    use crate::protocol::consensus::block::block_transaction::BlockTransaction;
    use crate::protocol::consensus::block::block_validation_error::BlockValidationError;
    use crate::protocol::consensus::block::Block;
    use crate::protocol::consensus::block::BlockProof;
    use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
    use crate::protocol::consensus::network::Network;
    use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
    use crate::protocol::proof_abstractions::tasm::program::TritonVmProofJobOptions;
    use crate::protocol::proof_abstractions::triton_vm_job_queue::vm_job_queue;
    use crate::protocol::proof_abstractions::triton_vm_job_queue::TritonVmJobQueue;
    use crate::protocol::proof_abstractions::tx_proving_capability::TxProvingCapability;
    use crate::protocol::proof_abstractions::verifier::disable_true_claims_cache;
    use crate::protocol::proof_abstractions::verifier::enable_true_claims_cache;
    use crate::state::transaction::tx_creation_config::TxCreationConfig;
    use crate::state::wallet::address::KeyType;
    use crate::state::wallet::transaction_output::TxOutput;
    use crate::state::wallet::wallet_entropy::WalletEntropy;
    use crate::tests::shared::blocks::fake_valid_successor_for_tests;
    use crate::tests::shared::globalstate::mock_genesis_global_state;
    use crate::tests::shared_tokio_runtime;

    async fn deterministic_empty_block1_proposal() -> (Block, Timestamp, Network, Block) {
        let network = Network::Main;
        let genesis = Block::genesis(network);
        let plus_one_hour = genesis.kernel.header.timestamp + Timestamp::hours(1);

        // wallet must be deterministic for block 1 to be deterministic, for
        // block proof to be reusable over test runs.
        let alice_wallet = WalletEntropy::devnet_wallet();
        let alice = mock_genesis_global_state(
            3,
            alice_wallet.clone(),
            cli_args::Args {
                guesser_fraction: 0.5,
                network,
                ..Default::default()
            },
        )
        .await;

        let job_options = TritonVmProofJobOptions::default();
        let (transaction, _) = create_block_transaction_from(
            &genesis,
            alice.clone(),
            plus_one_hour,
            job_options.clone(),
            TxMergeOrigin::ExplicitList(vec![]),
        )
        .await
        .unwrap();
        let block1_proposal = Block::compose(
            genesis.clone(),
            transaction,
            plus_one_hour,
            vm_job_queue(),
            job_options,
        )
        .await
        .unwrap();
        (genesis, plus_one_hour, network, block1_proposal)
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn block_with_valid_proof_passes() {
        let (predecesor, time, network, block) = deterministic_empty_block1_proposal().await;
        assert!(block.validate(&predecesor, time, network,).await.is_ok());
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn block_with_invalid_proof_fails() {
        let (predecesor, time, network, mut block) = deterministic_empty_block1_proposal().await;

        // Block validation fails on manipulated proof
        let BlockProof::SingleProof(block_proof) = block.proof_mut() else {
            panic!("Single proof expected");
        };
        let proof_length = block_proof.0.len();

        let mut rng = rng();
        let index = rng.random_range(0..proof_length);
        block_proof.0.get_mut(index).unwrap().increment();

        // Since the block is deterministic, it may have been validated
        // already. In a test environment, its verified-to-be-true claim
        // would have been absorbed into the true claims cache. In this
        // case, even the false proof will validate. So in order to make the
        // test meaningful, we first have to clear or disable the true
        // claims cache.
        disable_true_claims_cache().await;

        assert_eq!(
            BlockValidationError::ProofValidity,
            block
                .validate(&predecesor, time, network,)
                .await
                .unwrap_err()
        );

        enable_true_claims_cache().await;
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn block_with_empty_proof_fails() {
        let (predecesor, time, network, mut block) = deterministic_empty_block1_proposal().await;

        // Block validation fails on empty proof
        block.set_proof(BlockProof::SingleProof(Proof(vec![]).into()));
        assert_eq!(
            BlockValidationError::ProofValidity,
            block
                .validate(&predecesor, time, network,)
                .await
                .unwrap_err()
        );
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn blocks_with_0_to_10_inputs_and_successors_are_valid() {
        // Scenario: Build different blocks of height 2, with varying number
        // of inputs. Verify all are valid. The build a block of height 3
        // with non-zero inputs and verify validity. This should ensure that
        // at least one of block 2's guesser fee UTXOs shift the active
        // window of the mutator set's Bloom filter, ensuring that the
        // validity-check of a block handles guesser fee UTXOs correctly
        // when calculating the expected state of the new mutator set.
        // Cf., the bug fixed in 4d6b7013624e593c40e76ce93cb6b288b6b3f48b.

        let network = Network::Main;
        let genesis_block = Block::genesis(network);
        let plus_seven_months = genesis_block.kernel.header.timestamp + Timestamp::months(7);
        let mut rng: StdRng = SeedableRng::seed_from_u64(2225550001);
        let block1 = fake_valid_successor_for_tests(
            &genesis_block,
            plus_seven_months,
            rng.random(),
            network,
        )
        .await;

        let alice_wallet = WalletEntropy::devnet_wallet();
        let mut alice = mock_genesis_global_state(
            3,
            alice_wallet.clone(),
            cli_args::Args {
                guesser_fraction: 0.5,
                network,
                ..Default::default()
            },
        )
        .await;
        alice.set_new_tip(block1.clone()).await.unwrap();
        let alice_key = alice
            .lock_guard()
            .await
            .wallet_state
            .wallet_entropy
            .nth_spending_key(KeyType::Generation, 0);
        let output_to_self = TxOutput::onchain_native_currency(
            NativeCurrencyAmount::coins(1),
            rng.random(),
            alice_key.to_address(),
            true,
        );

        let plus_eight_months = plus_seven_months + Timestamp::months(1);
        let (coinbase_for_block2, _) = make_coinbase_transaction_from_state_lock(
            &block1,
            &alice,
            plus_eight_months,
            TritonVmProofJobOptions::default_with_network(network),
        )
        .await
        .unwrap();
        let block_height = block1.header().height;
        let consensus_rule_set_1 = ConsensusRuleSet::infer_from(network, block_height);
        let fee = NativeCurrencyAmount::coins(1);
        let plus_nine_months = plus_eight_months + Timestamp::months(1);

        let config2 = TxCreationConfig::default()
            .recover_change_on_chain(alice_key.clone())
            .with_prover_capability(TxProvingCapability::SingleProof);
        for i in 0..10 {
            println!("i: {i}");
            alice = mock_genesis_global_state(
                3,
                alice_wallet.clone(),
                cli_args::Args::default_with_network(network),
            )
            .await;
            alice.set_new_tip(block1.clone()).await.unwrap();
            let outputs = vec![output_to_self.clone(); i];

            let tx2 = alice
                .api()
                .tx_initiator_internal()
                .create_transaction(
                    outputs.into(),
                    fee,
                    plus_eight_months,
                    config2.clone(),
                    consensus_rule_set_1,
                )
                .await
                .unwrap()
                .transaction;
            let block2_tx = BlockTransaction::merge(
                coinbase_for_block2.clone().into(),
                (*tx2).clone(),
                rng.random(),
                TritonVmJobQueue::get_instance(),
                TritonVmProofJobOptions::default_with_network(network),
                consensus_rule_set_1,
            )
            .await
            .unwrap();
            let block2_without_valid_pow = Block::compose(
                block1.clone(),
                block2_tx,
                plus_eight_months,
                TritonVmJobQueue::get_instance(),
                TritonVmProofJobOptions::default_with_network(network),
            )
            .await
            .unwrap();

            assert!(
                block2_without_valid_pow
                    .is_valid(&block1, plus_eight_months, network)
                    .await,
                "Block with {i} inputs must be valid"
            );

            alice
                .set_new_tip(block2_without_valid_pow.clone())
                .await
                .unwrap();
            let (coinbase_for_block3, _) = make_coinbase_transaction_from_state_lock(
                &block2_without_valid_pow,
                &alice,
                plus_nine_months,
                TritonVmProofJobOptions::default_with_network(network),
            )
            .await
            .unwrap();

            let block_height2 = block2_without_valid_pow.header().height;
            let consensus_rule_set_2 = ConsensusRuleSet::infer_from(network, block_height2);

            let tx3 = alice
                .api()
                .tx_initiator_internal()
                .create_transaction(
                    vec![output_to_self.clone()].into(),
                    fee,
                    plus_nine_months,
                    config2.clone(),
                    consensus_rule_set_2,
                )
                .await
                .unwrap()
                .transaction;
            let block3_tx = BlockTransaction::merge(
                coinbase_for_block3.clone().into(),
                (*tx3).clone(),
                rng.random(),
                TritonVmJobQueue::get_instance(),
                TritonVmProofJobOptions::default_with_network(network),
                consensus_rule_set_2,
            )
            .await
            .unwrap();
            assert!(
                !block3_tx.kernel.inputs.len().is_zero(),
                "block transaction 3 must have inputs"
            );
            let block3_without_valid_pow = Block::compose(
                block2_without_valid_pow.clone(),
                block3_tx,
                plus_nine_months,
                TritonVmJobQueue::get_instance(),
                TritonVmProofJobOptions::default_with_network(network),
            )
            .await
            .unwrap();

            assert!(
                block3_without_valid_pow
                    .is_valid(&block2_without_valid_pow, plus_nine_months, network)
                    .await,
                "Block of height 3 after block 2 with {i} inputs must be valid"
            );
        }
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn block_with_far_future_timestamp_is_invalid() {
        let network = Network::Main;
        let genesis_block = Block::genesis(network);
        let mut now = genesis_block.kernel.header.timestamp + Timestamp::hours(2);
        let mut rng: StdRng = SeedableRng::seed_from_u64(2225550001);

        let mut block1 =
            fake_valid_successor_for_tests(&genesis_block, now, rng.random(), network).await;

        // Set block timestamp 30 seconds in the future.  (is valid)
        let future_time1 = now + Timestamp::seconds(30);
        block1.kernel_mut().header.timestamp = future_time1;
        assert!(block1.is_valid(&genesis_block, now, network).await);

        now = block1.kernel.header.timestamp;

        // Set block timestamp 1 minute in the future.  (is valid)
        let future_time2 = now + Timestamp::minutes(1);
        block1.kernel_mut().header.timestamp = future_time2;
        assert!(block1.is_valid(&genesis_block, now, network).await);

        // Set block timestamp 1 minute + 1ms in the future. (not valid)
        let future_time3 = now + Timestamp::minutes(1) + Timestamp::millis(1);
        block1.kernel_mut().header.timestamp = future_time3;
        assert!(!block1.is_valid(&genesis_block, now, network).await);

        // Set block timestamp 1 minute + 1 sec in the future. (not valid)
        let future_time4 = now + Timestamp::minutes(1) + Timestamp::seconds(1);
        block1.kernel_mut().header.timestamp = future_time4;
        assert!(!block1.is_valid(&genesis_block, now, network).await);

        // Set block timestamp 2 days in the future. (not valid)
        let future_time5 = now + Timestamp::seconds(86400 * 2);
        block1.kernel_mut().header.timestamp = future_time5;
        assert!(!block1.is_valid(&genesis_block, now, network).await);
    }
}

mod guesser_fee_utxos {
    use itertools::Itertools;
    use macro_rules_attr::apply;
    use neptune_primitives::timestamp::Timestamp;
    use rand::Rng;
    use tracing_test::traced_test;

    use crate::application::config::cli_args;
    use crate::protocol::consensus::block::block_height::BlockHeight;
    use crate::protocol::consensus::block::block_transaction::BlockTransaction;
    use crate::protocol::consensus::block::mutator_set_update::MutatorSetUpdate;
    use crate::protocol::consensus::block::test_helpers::invalid_block_with_transaction;
    use crate::protocol::consensus::block::Block;
    use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
    use crate::protocol::consensus::network::Network;
    use crate::protocol::consensus::transaction::test_helpers::make_mock_transaction;
    use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelModifier;
    use crate::protocol::consensus::transaction::utxo_triple::UtxoTriple;
    use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
    use crate::protocol::proof_abstractions::tx_proving_capability::TxProvingCapability;
    use crate::state::transaction::tx_creation_config::TxCreationConfig;
    use crate::state::wallet::address::generation_address::GenerationReceivingAddress;
    use crate::state::wallet::address::generation_address::GenerationSpendingKey;
    use crate::state::wallet::transaction_output::TxOutput;
    use crate::state::wallet::wallet_entropy::WalletEntropy;
    use crate::tests::shared::blocks::make_mock_block_with_puts_and_guesser_preimage_and_guesser_fraction;
    use crate::tests::shared::globalstate::mock_genesis_global_state;
    use crate::tests::shared_tokio_runtime;

    #[apply(shared_tokio_runtime)]
    async fn guesser_fee_addition_records_are_consistent() {
        // Ensure that multiple ways of deriving guesser-fee addition
        // records are consistent.

        let network = Network::Main;
        let mut rng = rand::rng();
        let genesis_block = Block::genesis(network);
        let a_key = GenerationSpendingKey::derive_from_seed(rng.random());
        let guesser_address = GenerationReceivingAddress::derive_from_seed(rng.random());
        let (block1, _) = make_mock_block_with_puts_and_guesser_preimage_and_guesser_fraction(
            &genesis_block,
            vec![],
            vec![],
            None,
            a_key,
            rng.random(),
            (0.4, guesser_address.into()),
            network,
        )
        .await;
        let ars = block1.guesser_fee_addition_records().unwrap();
        let ars_from_wallet = block1
            .kernel
            .guesser_fee_utxos()
            .unwrap()
            .iter()
            .map(|utxo| {
                UtxoTriple {
                    utxo: utxo.clone(),
                    sender_randomness: block1.hash(),
                    receiver_digest: guesser_address.receiver_postimage(),
                }
                .addition_record()
            })
            .collect_vec();
        assert_eq!(ars, ars_from_wallet);

        let MutatorSetUpdate {
            removals: _,
            additions,
        } = block1.mutator_set_update().unwrap();
        assert!(
            ars.iter().all(|ar| additions.contains(ar)),
            "All addition records must be present in block's mutator set update"
        );
    }

    #[test]
    fn guesser_can_unlock_guesser_fee_utxo() {
        let genesis_block = Block::genesis(Network::Main);
        let mut transaction = make_mock_transaction(vec![], vec![]);

        transaction.kernel = TransactionKernelModifier::default()
            .fee(NativeCurrencyAmount::from_nau(1337.into()))
            .modify(transaction.kernel);

        let mut block = invalid_block_with_transaction(&genesis_block, transaction);

        let guesser_key = GenerationSpendingKey::derive_from_seed(rand::rng().random());
        let guesser_address = guesser_key.to_address();
        block.set_header_guesser_data(guesser_address.into());

        let guesser_fee_utxos = block.kernel.guesser_fee_utxos().unwrap();

        let lock_script_and_witness = guesser_key.lock_script_and_witness();
        assert!(guesser_fee_utxos
            .iter()
            .all(|guesser_fee_utxo| lock_script_and_witness.can_unlock(guesser_fee_utxo)));
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn guesser_fees_are_added_to_mutator_set() {
        // Mine two blocks on top of the genesis block. Verify that the guesser
        // fee for the 1st block was added to the mutator set. The genesis
        // block awards no guesser fee.

        // This test must live in block/mod.rs because it relies on access to
        // private fields on `BlockBody`.

        let mut rng = rand::rng();
        let network = Network::Main;
        let genesis_block = Block::genesis(network);
        assert!(
            genesis_block.kernel.guesser_fee_utxos().unwrap().is_empty(),
            "Genesis block has no guesser fee UTXOs"
        );

        let launch_date = genesis_block.header().timestamp;
        let in_seven_months = launch_date + Timestamp::months(7);
        let in_eight_months = launch_date + Timestamp::months(8);
        let alice_wallet = WalletEntropy::devnet_wallet();
        let alice_key = alice_wallet.nth_generation_spending_key(0);
        let alice_address = alice_key.to_address();
        let mut alice = mock_genesis_global_state(
            0,
            alice_wallet,
            cli_args::Args::default_with_network(network),
        )
        .await;

        let output = TxOutput::offchain_native_currency(
            NativeCurrencyAmount::coins(4),
            rng.random(),
            alice_address.into(),
            true,
        );
        let fee = NativeCurrencyAmount::coins(1);
        let config1 = TxCreationConfig::default()
            .recover_change_on_chain(alice_key.into())
            .with_prover_capability(TxProvingCapability::PrimitiveWitness);
        let consensus_rule_set_0 = ConsensusRuleSet::infer_from(network, BlockHeight::genesis());
        let tx1 = alice
            .api()
            .tx_initiator_internal()
            .create_transaction(
                vec![output.clone()].into(),
                fee,
                in_seven_months,
                config1,
                consensus_rule_set_0,
            )
            .await
            .unwrap()
            .transaction;

        let tx1 = BlockTransaction::upgrade((*tx1).clone());
        let block1 = Block::block_template_invalid_proof(
            &genesis_block,
            tx1,
            in_seven_months,
            None,
            network,
        );
        alice.set_new_tip(block1.clone()).await.unwrap();

        let config2 = TxCreationConfig::default()
            .recover_change_on_chain(alice_key.into())
            .with_prover_capability(TxProvingCapability::PrimitiveWitness);
        let block_height1 = BlockHeight::genesis().next();
        let consensus_rule_set_1 = ConsensusRuleSet::infer_from(network, block_height1);
        let tx2 = alice
            .api()
            .tx_initiator_internal()
            .create_transaction(
                vec![output].into(),
                fee,
                in_eight_months,
                config2,
                consensus_rule_set_1,
            )
            .await
            .unwrap()
            .transaction;

        let tx2 = BlockTransaction::upgrade((*tx2).clone());
        let block2 =
            Block::block_template_invalid_proof(&block1, tx2, in_eight_months, None, network);

        let mut ms = block1.body().mutator_set_accumulator.clone();

        // Assumes no packing of mutator set happens on block level.
        let mutator_set_update_guesser_fees =
            MutatorSetUpdate::new(vec![], block1.guesser_fee_addition_records().unwrap());
        let mut mutator_set_update_tx = MutatorSetUpdate::new(
            block2.body().transaction_kernel.inputs.clone(),
            block2.body().transaction_kernel.outputs.clone(),
        );

        let reason = "applying mutator set update derived from block 2 \
                      to mutator set from block 1 should work";
        mutator_set_update_guesser_fees
            .apply_to_accumulator_and_records(
                &mut ms,
                &mut mutator_set_update_tx.removals.iter_mut().collect_vec(),
                &mut [],
            )
            .expect(reason);
        mutator_set_update_tx
            .apply_to_accumulator(&mut ms)
            .expect(reason);

        assert_eq!(ms.hash(), block2.body().mutator_set_accumulator.hash());
    }
}

/// Exhibits a strategy for creating one transaction by merging in many
/// small ones that spend from one's own wallet. The difficulty you run into
/// when you do this naïvely is that you end up merging in transactions that
/// spend the same UTXOs over and over. To avoid doing this, you insert the
/// transaction into the mempool thus making the wallet aware of this
/// transaction and avoiding a double-spend of a UTXO.
#[apply(shared_tokio_runtime)]
async fn avoid_reselecting_same_input_utxos() {
    let mut rng = StdRng::seed_from_u64(893423984854);
    let network = Network::Main;
    let devnet_wallet = WalletEntropy::devnet_wallet();
    let mut alice = mock_genesis_global_state(
        0,
        devnet_wallet,
        cli_args::Args::default_with_network(network),
    )
    .await;

    let job_queue = TritonVmJobQueue::get_instance();

    let genesis_block = Block::genesis(network);

    let mut blocks = vec![genesis_block];

    // Spend i inputs in block i, for i in {1,2}. The first expenditure and
    // block is guaranteed to succeed. Prior to the second block, Alice owns
    // two inputs and creates a big transaction by merging in smaller ones.
    // She needs to ensure the two transactions she merges in do not spend
    // the same UTXO.
    let launch_date = network.launch_date();
    let mut now = launch_date + Timestamp::months(6);
    for i in 1..3 {
        now += network.target_block_interval();

        // create coinbase transaction
        let (transaction, _) = make_coinbase_transaction_from_state_lock(
            &blocks[i - 1],
            &alice,
            now,
            TritonVmProofJobOptions::from((TritonVmJobPriority::Normal, None)),
        )
        .await
        .unwrap();
        let mut transaction = BlockOrRegularTransaction::from(transaction);

        let block_height = blocks.last().unwrap().header().height;
        let consensus_rule_set = ConsensusRuleSet::infer_from(network, block_height);

        // for all own UTXOs, spend to self
        for _ in 0..i {
            // create a transaction spending it to self
            let change_key = alice
                .lock_guard_mut()
                .await
                .wallet_state
                .next_unused_symmetric_key()
                .await;
            let receiving_address = alice
                .lock_guard_mut()
                .await
                .wallet_state
                .next_unused_spending_key(KeyType::Generation)
                .await
                .to_address();
            let send_amount = NativeCurrencyAmount::coins(1);
            let tx_outputs = vec![TxOutput::onchain_native_currency(
                send_amount,
                rng.random(),
                receiving_address,
                true,
            )]
            .into();
            let config = TxCreationConfig::default()
                .recover_change_on_chain(change_key.into())
                .with_prover_capability(TxProvingCapability::SingleProof)
                .use_job_queue(job_queue.clone());
            let transaction_creation_artifacts = alice
                .api()
                .tx_initiator_internal()
                .create_transaction(
                    tx_outputs,
                    NativeCurrencyAmount::coins(0),
                    now,
                    config,
                    consensus_rule_set,
                )
                .await
                .unwrap();
            let self_spending_transaction = transaction_creation_artifacts.transaction;

            // merge that transaction in
            transaction = BlockTransaction::merge(
                transaction,
                (*self_spending_transaction).clone(),
                rng.random(),
                job_queue.clone(),
                TritonVmProofJobOptions::default_with_network(network),
                consensus_rule_set,
            )
            .await
            .unwrap()
            .into();

            alice
                .lock_guard_mut()
                .await
                .mempool_insert(transaction.clone().into(), UpgradePriority::Critical)
                .await;
        }

        // compose block
        let block = Block::compose(
            blocks.last().unwrap().to_owned(),
            transaction.try_into().expect(
                "went through at least one iteration of above loop, so merge bit must be set",
            ),
            now,
            job_queue.clone(),
            TritonVmProofJobOptions::default(),
        )
        .await
        .unwrap();

        let block_is_valid = block.validate(blocks.last().unwrap(), now, network).await;
        println!("block is valid? {:?}", block_is_valid.map(|_| "yes"));
        println!();
        assert!(block_is_valid.is_ok());

        // update state with new block
        alice.set_new_tip(block.clone()).await.unwrap();

        blocks.push(block);
    }
}
