#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(super) mod tests {

    use std::collections::HashMap;
    use std::collections::HashSet;

    use anyhow::Result;
    use itertools::Itertools;
    use macro_rules_attr::apply;
    use neptune_archive::archival_state::ArchivalState;
    use neptune_archive::block_index::BlockIndexKey;
    use neptune_archive::block_index::BlockRecord;
    use neptune_archive::block_index::FileRecord;
    use neptune_archive::block_index::LastFileRecord;
    use neptune_consensus::block::block_transaction::BlockTransaction;
    use neptune_consensus::block::test_helpers::invalid_block_with_transaction;
    use neptune_consensus::block::test_helpers::invalid_empty_block;
    use neptune_consensus::block::Block;
    use neptune_consensus::consensus_rule_set::ConsensusRuleSet;
    use neptune_consensus::proof_abstractions::tasm::program::TritonVmProofJobOptions;
    use neptune_consensus::proof_abstractions::triton_vm_job_queue::TritonVmJobQueue;
    use neptune_consensus::proof_abstractions::tx_proving_capability::TxProvingCapability;
    use neptune_consensus::transaction::lock_script::LockScript;
    use neptune_consensus::transaction::utxo::Utxo;
    use neptune_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
    use neptune_database::storage::storage_vec::traits::*;
    use neptune_mutator_set::addition_record::AdditionRecord;
    use neptune_mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
    use neptune_mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
    use neptune_primitives::block_height::BlockHeight;
    use neptune_primitives::data_directory::DataDirectory;
    use neptune_primitives::network::Network;
    use neptune_primitives::timestamp::Timestamp;
    use neptune_wallet::address::KeyType;
    use neptune_wallet::expected_utxo::UtxoNotifier;
    use neptune_wallet::transaction_output::TxOutput;
    use neptune_wallet::transaction_output::TxOutputList;
    use neptune_wallet::wallet_entropy::WalletEntropy;
    use num_traits::Zero;
    use proptest::collection;
    use proptest::prop_assert;
    use proptest::prop_assert_eq;
    use proptest_arbitrary_interop::arb;
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::RngCore;
    use rand::SeedableRng;
    use tasm_lib::prelude::Digest;
    use tasm_lib::triton_vm::prelude::BFieldElement;
    use tasm_lib::twenty_first::bfe;
    use tasm_lib::twenty_first::util_types::mmr::mmr_trait::Mmr;
    use tracing_test::traced_test;

    use crate::application::config::cli_args::Args;
    use crate::application::loops::mine_loop::tests::make_coinbase_transaction_from_state_lock;
    use crate::state::transaction::tx_creation_config::TxCreationConfig;
    use crate::tests::shared::blocks::block_with_num_puts;
    use crate::tests::shared::blocks::block_with_puts;
    use crate::tests::shared::blocks::make_mock_block;
    use crate::tests::shared::files::unit_test_data_directory;
    use crate::tests::shared::globalstate::mock_genesis_global_state;
    use crate::tests::shared::mock_genesis_wallet_state;
    use crate::tests::shared_tokio_runtime;

    pub(super) async fn make_test_archival_state(cli: &Args) -> ArchivalState {
        let data_dir: DataDirectory = unit_test_data_directory(cli.network).unwrap();

        let genesis_block = Block::genesis(cli.network);
        ArchivalState::new(data_dir, genesis_block, cli.utxo_index, cli.network).await
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn initialize_archival_state_test() -> Result<()> {
        // Ensure that the archival state can be initialized without overflowing the stack
        let seed: [u8; 32] = rand::rng().random();
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let network = Network::RegTest;

        let mut archival_state0 =
            make_test_archival_state(&Args::default_with_network(network)).await;

        let b = Block::genesis(network);
        let some_wallet_secret = WalletEntropy::new_random();
        let some_key = some_wallet_secret.nth_generation_spending_key_for_tests(0);

        let (block_1, _) = make_mock_block(&b, None, some_key, rng.random(), network).await;
        archival_state0.set_new_tip(&block_1).await.unwrap();
        let _c = archival_state0
            .get_block(block_1.hash())
            .await
            .unwrap()
            .unwrap();

        Ok(())
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn archival_state_restore_test() -> Result<()> {
        let mut rng = rand::rng();
        // Verify that a restored archival mutator set is populated with the right `sync_label`
        let network = Network::Main;
        let cli_args = Args::default_with_network(network);
        let mut archival_state = make_test_archival_state(&cli_args).await;
        let genesis_wallet_state =
            mock_genesis_wallet_state(WalletEntropy::devnet_wallet(), &cli_args).await;
        let (mock_block_1, _) = make_mock_block(
            &archival_state.genesis_block,
            None,
            genesis_wallet_state
                .wallet_entropy
                .nth_generation_spending_key_for_tests(0),
            rng.random(),
            network,
        )
        .await;
        archival_state
            .update_mutator_set(&mock_block_1)
            .await
            .unwrap();

        // Create a new archival MS that should be synced to block 1, not the genesis block
        let restored_archival_state = archival_state;

        assert_eq!(
            mock_block_1.hash(),
            restored_archival_state
                .archival_mutator_set
                .get_sync_label(),
            "sync_label of restored archival mutator set must be digest of latest block",
        );

        Ok(())
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn update_mutator_set_db_write_test() {
        // Verify that `update_mutator_set` writes the active window back to disk.
        // Creates blocks and transaction with invalid proofs.

        let network = Network::Main;
        let mut rng = StdRng::seed_from_u64(107221549301u64);
        let cli_args = Args::default_with_network(network);
        let alice_wallet =
            mock_genesis_wallet_state(WalletEntropy::devnet_wallet(), &cli_args).await;
        let alice_wallet = alice_wallet.wallet_entropy;
        let mut alice = mock_genesis_global_state(0, alice_wallet, cli_args).await;
        let alice_key = alice
            .lock_guard()
            .await
            .wallet_state
            .wallet_entropy
            .nth_generation_spending_key(0);

        let genesis_block = Block::genesis(network);
        let (block1, _) =
            make_mock_block(&genesis_block, None, alice_key, rng.random(), network).await;

        alice.set_new_tip(block1.clone()).await.unwrap();
        let num_aocl_leafs = alice
            .lock_guard()
            .await
            .chain
            .archival_state()
            .archival_mutator_set
            .ams()
            .aocl
            .num_leafs()
            .await;
        assert_ne!(0, num_aocl_leafs);

        let in_seven_months = block1.kernel.header.timestamp + Timestamp::months(7);

        // Add an input to the next block's transaction. This will add a removal record
        // to the block, and this removal record will insert indices in the Bloom filter.
        let utxo = Utxo::new_native_currency(
            LockScript::anyone_can_spend().hash(),
            NativeCurrencyAmount::coins(4),
        );

        let tx_output_anyone_can_spend =
            TxOutput::no_notification(utxo, rng.random(), rng.random(), false);
        let config = TxCreationConfig::default()
            .recover_change_on_chain(alice_key.into())
            .with_prover_capability(TxProvingCapability::PrimitiveWitness);
        let block_height_1 = block1.header().height;
        let consensus_rule_set = ConsensusRuleSet::infer_from(network, block_height_1);
        let sender_tx = alice
            .api()
            .tx_initiator_internal()
            .create_transaction(
                vec![tx_output_anyone_can_spend].into(),
                NativeCurrencyAmount::coins(2),
                in_seven_months,
                config,
                consensus_rule_set,
            )
            .await
            .unwrap()
            .transaction;

        let transaction = BlockTransaction::upgrade((*sender_tx).clone());

        let mock_block_2 = Block::block_template_invalid_proof(
            &block1,
            transaction,
            in_seven_months,
            None,
            network,
        );

        // Remove an element from the mutator set, verify that the active window DB is updated.
        alice.set_new_tip(mock_block_2.clone()).await.unwrap();

        let swbf_active_sbf_len = alice
            .lock_guard()
            .await
            .chain
            .archival_state()
            .archival_mutator_set
            .ams()
            .swbf_active
            .sbf
            .len();
        assert_ne!(0, swbf_active_sbf_len);
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn update_mutator_set_rollback_ms_block_sync_test() -> Result<()> {
        let mut rng = rand::rng();
        let network = Network::Main;
        let data_dir = unit_test_data_directory(network).unwrap();
        let cli = Args::default_with_network(network);
        let mut archival_state = ArchivalState::new(
            data_dir,
            Block::genesis(network),
            cli.utxo_index,
            cli.network,
        )
        .await;

        let own_wallet = WalletEntropy::new_random();
        let own_key = own_wallet.nth_generation_spending_key_for_tests(0);

        // 1. Create new block 1 and store it to the DB
        let (mock_block_1a, _) = make_mock_block(
            &archival_state.genesis_block,
            None,
            own_key,
            rng.random(),
            network,
        )
        .await;
        archival_state.write_block_as_tip(&mock_block_1a).await?;

        // 2. Update mutator set with this
        archival_state
            .update_mutator_set(&mock_block_1a)
            .await
            .unwrap();

        // 3. Create competing block 1 and store it to DB
        let (mock_block_1b, _) = make_mock_block(
            &archival_state.genesis_block,
            None,
            own_key,
            rng.random(),
            network,
        )
        .await;
        archival_state.write_block_as_tip(&mock_block_1b).await?;

        // 4. Update mutator set with that
        archival_state
            .update_mutator_set(&mock_block_1b)
            .await
            .unwrap();

        // 5. Experience rollback
        assert_eq!(
            mock_block_1b.hash(),
            archival_state.archival_mutator_set.get_sync_label(),
        );
        assert_eq!(mock_block_1b.hash(), archival_state.get_tip().await.hash());

        Ok(())
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn update_mutator_set_rollback_ms_block_sync_multiple_inputs_outputs_in_block_test() {
        // Make a rollback of one block that contains multiple inputs and outputs.
        // This test is intended to verify that rollbacks work for non-trivial
        // blocks.
        let network = Network::RegTest;
        let consensus_rule_set = ConsensusRuleSet::infer_from(network, BlockHeight::genesis());
        let mut rng = rand::rng();
        let alice_wallet = WalletEntropy::devnet_wallet();
        let alice_key = alice_wallet.nth_generation_spending_key_for_tests(0);
        let alice_address = alice_key.to_address();
        let cli_args = Args::default_with_network(network);
        let mut alice = mock_genesis_global_state(42, alice_wallet, cli_args).await;
        let genesis_block = Block::genesis(network);

        let num_premine_utxos = Block::premine_utxos().len();

        let outputs = (0..20)
            .map(|_| {
                TxOutput::onchain_native_currency(
                    NativeCurrencyAmount::coins(1),
                    rng.random(),
                    alice_address.into(),
                    false,
                )
            })
            .collect_vec();
        let fee = NativeCurrencyAmount::zero();

        let in_seven_months = Timestamp::now() + Timestamp::months(7);
        let config_1a = TxCreationConfig::default()
            .recover_change_on_chain(alice_key.into())
            .with_prover_capability(TxProvingCapability::PrimitiveWitness);
        let big_tx = alice
            .api()
            .tx_initiator_internal()
            .create_transaction(
                outputs.clone().into(),
                fee,
                in_seven_months,
                config_1a,
                consensus_rule_set,
            )
            .await
            .unwrap()
            .transaction;
        let block_1a = invalid_block_with_transaction(&genesis_block, (*big_tx).clone());

        let config_1b = TxCreationConfig::default()
            .recover_change_on_chain(alice_key.into())
            .with_prover_capability(TxProvingCapability::PrimitiveWitness);
        let empty_tx = alice
            .api()
            .tx_initiator_internal()
            .create_transaction(
                Vec::<TxOutput>::new().into(),
                fee,
                in_seven_months,
                config_1b,
                consensus_rule_set,
            )
            .await
            .unwrap()
            .transaction;
        let block_1b = invalid_block_with_transaction(&genesis_block, (*empty_tx).clone());

        alice.set_new_tip(block_1a.clone()).await.unwrap();
        alice.set_new_tip(block_1b.clone()).await.unwrap();

        // Verify correct rollback
        assert!(
            alice
                .lock_guard()
                .await
                .chain
                .archival_state()
                .archival_mutator_set
                .ams()
                .swbf_active
                .sbf
                .is_empty(),
            "Active window must be empty when no UTXOs have been spent"
        );

        assert_eq!(
            num_premine_utxos + block_1b.kernel.guesser_fee_utxos().unwrap().len(),
            alice
                .lock_guard()
                .await
                .chain
                .archival_state()
                .archival_mutator_set
                .ams()
                .aocl
                .num_leafs()
                .await as usize,
            "AOCL leaf count must agree with blockchain after rollback"
        );
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn update_mutator_set_rollback_many_blocks_multiple_inputs_outputs_test() {
        // Make a rollback of multiple blocks that contains multiple inputs and outputs.
        // This test is intended to verify that rollbacks work for non-trivial
        // blocks, also when there are many blocks that push the active window of the
        // mutator set forwards.

        let network = Network::RegTest;
        let mut rng = rand::rng();
        let alice_wallet = WalletEntropy::devnet_wallet();
        let genesis_block = Block::genesis(network);
        let alice_key = alice_wallet.nth_generation_spending_key_for_tests(0);
        let alice_address = alice_key.to_address();
        let cli_args = Args::default_with_network(network);
        let mut alice = mock_genesis_global_state(42, alice_wallet, cli_args).await;

        let mut expected_num_utxos = Block::premine_utxos().len();
        let mut previous_block = genesis_block.clone();

        let outputs = (0..20)
            .map(|_| {
                TxOutput::onchain_native_currency(
                    NativeCurrencyAmount::coins(1),
                    rng.random(),
                    alice_address.into(),
                    false,
                )
            })
            .collect_vec();
        let fee = NativeCurrencyAmount::zero();

        let num_blocks = 30;
        for _ in 0..num_blocks {
            let timestamp = previous_block.header().timestamp + Timestamp::months(7);
            let config = TxCreationConfig::default()
                .recover_change_on_chain(alice_key.into())
                .with_prover_capability(TxProvingCapability::PrimitiveWitness);
            let previous_block_height = previous_block.header().height;
            let consensus_rule_set = ConsensusRuleSet::infer_from(network, previous_block_height);
            let tx = alice
                .api()
                .tx_initiator_internal()
                .create_transaction(
                    outputs.clone().into(),
                    fee,
                    timestamp,
                    config,
                    consensus_rule_set,
                )
                .await
                .unwrap()
                .transaction;
            let next_block = invalid_block_with_transaction(&previous_block, (*tx).clone());

            // 2. Update archival-mutator set with produced block
            alice.set_new_tip(next_block.clone()).await.unwrap();

            previous_block = next_block;
        }

        // Verify that MS-update finder works for this many blocks.
        let ams_digest_prior = alice
            .lock_guard()
            .await
            .chain
            .archival_state()
            .archival_mutator_set
            .ams()
            .hash()
            .await;
        positive_prop_ms_update_to_tip(
            &genesis_block.mutator_set_accumulator_after().unwrap(),
            alice.lock_guard_mut().await.chain.archival_state_mut(),
            num_blocks,
        )
        .await;

        // Verify that an internal function does not mutate the mutator set, as
        // it's not allowed to do that, but we can't make that guarantee through
        // the type system.
        assert_eq!(
            ams_digest_prior,
            alice
                .lock_guard()
                .await
                .chain
                .archival_state()
                .archival_mutator_set
                .ams()
                .hash()
                .await,
            "get_mutator_set_update_to_tip must leave the mutator set unchanged."
        );

        // Verify that both active and inactive SWBF are non-empty.
        assert!(
            !alice
                .lock_guard()
                .await
                .chain
                .archival_state()
                .archival_mutator_set
                .ams()
                .swbf_active
                .sbf
                .is_empty(),
            "Active window must be non-empty after many UTXOs are spent"
        );
        assert!(
            !alice
                .lock_guard()
                .await
                .chain
                .archival_state()
                .archival_mutator_set
                .ams()
                .swbf_inactive
                .num_leafs()
                .await
                .is_zero(),
            "Inactive SWBF must be non-empty after many UTXOs are spent"
        );

        {
            // 3. Create competing block 1 and treat it as new tip
            let (mock_block_1b, _) =
                make_mock_block(&genesis_block, None, alice_key, rng.random(), network).await;
            expected_num_utxos += mock_block_1b.body().transaction_kernel.outputs.len()
                + mock_block_1b.guesser_fee_addition_records().unwrap().len();

            // 4. Update mutator set with this new block of height 1.
            alice
                .lock_guard_mut()
                .await
                .chain
                .archival_state_mut()
                .update_mutator_set(&mock_block_1b)
                .await
                .unwrap();
        }

        // 5. Verify correct rollback

        // Verify that the new state of the mutator set contains exactly the
        // number of AOCL records defined in the premine and block 1b, and zero
        // removals.
        assert_eq!(
            expected_num_utxos,
            alice.lock_guard()
            .await
                .chain
                .archival_state()
                .archival_mutator_set
                .ams()
                .aocl
                .num_leafs().await as usize,
            "AOCL leaf count must agree with #premine allocations + #transaction outputs in all blocks, even after rollback"
        );
        assert!(
            alice
                .lock_guard()
                .await
                .chain
                .archival_state()
                .archival_mutator_set
                .ams()
                .swbf_active
                .sbf
                .is_empty(),
            "Active window must be empty when no UTXOs have been spent"
        );

        assert!(
            alice
                .lock_guard()
                .await
                .chain
                .archival_state()
                .archival_mutator_set
                .ams()
                .chunks
                .get_all()
                .await
                .into_iter()
                .all(|ch| ch.is_empty()),
            "Inactive SWBF must be empty"
        );
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn allow_multiple_inputs_and_outputs_in_block() {
        // Test various parts of the state update when a block contains multiple inputs and outputs
        let network = Network::Testnet(42);
        let cli_args = Args::default_with_network(network);
        let premine_rec_ws =
            mock_genesis_wallet_state(WalletEntropy::devnet_wallet(), &cli_args).await;
        let premine_rec_spending_key = premine_rec_ws.wallet_entropy.nth_generation_spending_key(0);
        let mut premine_rec = mock_genesis_global_state(
            3,
            premine_rec_ws.wallet_entropy,
            Args {
                guesser_fraction: 0.0,
                network,
                ..Default::default()
            },
        )
        .await;
        assert_eq!(
            1,
            premine_rec
                .lock_guard()
                .await
                .wallet_state
                .wallet_db
                .monitored_utxos()
                .len()
                .await,
            "Premine receiver must have non-empty list of monitored UTXOs"
        );

        let mut rng = StdRng::seed_from_u64(41251549301u64);
        let wallet_secret_alice = WalletEntropy::new_pseudorandom(rng.random());
        let alice_spending_key = wallet_secret_alice.nth_generation_spending_key(0);
        let mut alice = mock_genesis_global_state(3, wallet_secret_alice, cli_args.clone()).await;

        let wallet_secret_bob = WalletEntropy::new_pseudorandom(rng.random());
        let bob_spending_key = wallet_secret_bob.nth_generation_spending_key(0);
        let mut bob = mock_genesis_global_state(3, wallet_secret_bob, cli_args.clone()).await;

        let genesis_block = Block::genesis(network);
        let launch_date = genesis_block.header().timestamp;
        let in_seven_months = launch_date + Timestamp::months(7);

        println!("Generated initial states and genesis block");

        // Send two outputs each to Alice and Bob, from premine receiver
        let sender_randomness: Digest = rng.random();
        let alice_address = alice_spending_key.to_address();
        let receiver_data_for_alice = vec![
            TxOutput::offchain_native_currency(
                NativeCurrencyAmount::coins(1),
                sender_randomness,
                alice_address.into(),
                false,
            ),
            TxOutput::offchain_native_currency(
                NativeCurrencyAmount::coins(9),
                sender_randomness,
                alice_address.into(),
                false,
            ),
        ];

        // Two outputs for Bob
        let bob_address = bob_spending_key.to_address();

        let receiver_data_for_bob = vec![
            TxOutput::offchain_native_currency(
                NativeCurrencyAmount::coins(2),
                sender_randomness,
                bob_address.into(),
                false,
            ),
            TxOutput::offchain_native_currency(
                NativeCurrencyAmount::coins(3),
                sender_randomness,
                bob_address.into(),
                false,
            ),
        ];

        println!("Before tx creation");
        let fee = NativeCurrencyAmount::coins(1);
        let change_key = premine_rec
            .global_state_lock
            .lock_guard_mut()
            .await
            .wallet_state
            .next_unused_spending_key(KeyType::ViewingAddress)
            .await;
        let config = TxCreationConfig::default()
            .recover_change_off_chain(change_key)
            .with_prover_capability(TxProvingCapability::SingleProof);
        let consensus_rule_set_0 = ConsensusRuleSet::infer_from(network, BlockHeight::genesis());
        let artifacts_alice_and_bob = premine_rec
            .api()
            .tx_initiator_internal()
            .create_transaction(
                [
                    receiver_data_for_alice.clone(),
                    receiver_data_for_bob.clone(),
                ]
                .concat()
                .into(),
                fee,
                in_seven_months,
                config,
                consensus_rule_set_0,
            )
            .await
            .unwrap();
        let tx_to_alice_and_bob = artifacts_alice_and_bob.transaction;
        println!("Generated transaction for Alice and Bob.");

        let light_state = &premine_rec
            .global_state_lock
            .lock_guard()
            .await
            .chain
            .light_state_clone();

        let (cbtx, _composer_expected_utxos) = make_coinbase_transaction_from_state_lock(
            light_state.tip(),
            &premine_rec,
            in_seven_months,
            TritonVmProofJobOptions::default_with_network(network),
        )
        .await
        .unwrap();

        let block_tx = BlockTransaction::merge(
            cbtx.into(),
            tx_to_alice_and_bob.into(),
            Default::default(),
            TritonVmJobQueue::get_instance(),
            TritonVmProofJobOptions::default_with_network(network),
            consensus_rule_set_0,
        )
        .await
        .unwrap();
        println!("Generated block transaction");

        let block_1 = Block::compose(
            genesis_block.clone(),
            block_tx,
            in_seven_months,
            TritonVmJobQueue::get_instance(),
            TritonVmProofJobOptions::default_with_network(network),
        )
        .await
        .unwrap();
        println!("Generated block");

        // Verify validity, without requiring valid PoW.
        assert!(
            block_1
                .is_valid(&genesis_block, in_seven_months, network)
                .await
        );

        println!("Accumulated transaction into block_1.");
        println!(
            "Transaction has {} inputs (removal records) and {} outputs (addition records)",
            block_1.kernel.body.transaction_kernel.inputs.len(),
            block_1.kernel.body.transaction_kernel.outputs.len()
        );

        // Expect change UTXO, as it uses offchain notifications.
        {
            let mut premine_rec = premine_rec.lock_guard_mut().await;
            let expected_utxos = premine_rec.wallet_state.extract_expected_utxos(
                artifacts_alice_and_bob.details.tx_outputs.iter(),
                UtxoNotifier::Cli,
            );
            assert_eq!(expected_utxos.len(), 1);
            premine_rec
                .wallet_state
                .add_expected_utxos(expected_utxos)
                .await;
        }

        // UTXOs for this transaction are communicated offline. So must be
        // expected.
        {
            let mut alice_state = alice.lock_guard_mut().await;
            let expected_utxos = alice_state
                .wallet_state
                .extract_expected_utxos(receiver_data_for_alice.iter(), UtxoNotifier::Cli);
            alice_state
                .wallet_state
                .add_expected_utxos(expected_utxos)
                .await;
        }

        {
            let mut bob_state = bob.lock_guard_mut().await;
            let expected_utxos = bob_state
                .wallet_state
                .extract_expected_utxos(receiver_data_for_bob.iter(), UtxoNotifier::Cli);
            bob_state
                .wallet_state
                .add_expected_utxos(expected_utxos)
                .await;
        }

        // Update chain states
        for state_lock in [&mut premine_rec, &mut alice, &mut bob] {
            state_lock.set_new_tip(block_1.clone()).await.unwrap();
        }

        {
            assert_eq!(
                4,
                premine_rec.lock_guard().await
                    .wallet_state
                    .wallet_db
                    .monitored_utxos()
                    .len().await, "Premine receiver must have 4 UTXOs after block 1: 1 change from transaction, 2 coinbases from block 1, and 1 spent premine UTXO"
            );
        }

        // Check balances
        let block_height = block_1.header().height;
        assert_eq!(
            NativeCurrencyAmount::coins(10),
            alice
                .lock_guard()
                .await
                .get_wallet_status_for_tip()
                .await
                .confirmed_available_balance(block_height, in_seven_months)
        );
        assert_eq!(
            NativeCurrencyAmount::coins(5),
            bob.lock_guard()
                .await
                .get_wallet_status_for_tip()
                .await
                .confirmed_available_balance(block_height, in_seven_months)
        );

        let block_subsidy = Block::block_subsidy(block_1.header().height);
        let mut liquid_reward = block_subsidy;
        liquid_reward.div_two();
        assert_eq!(
            // premine receiver mined block 1: So new balance is:
            // premine + block_reward / 2 - sent_to_alice - sent_to_bob - tx-fee
            // = 20 + 64 - 10 - 5 - 1
            // = 68
            liquid_reward + NativeCurrencyAmount::coins(20 - 10 - 5 - 1),
            premine_rec
                .lock_guard()
                .await
                .get_wallet_status_for_tip()
                .await
                .confirmed_available_balance(block_1.header().height, in_seven_months)
        );

        let after_cb_timelock_expiration = block_1.header().timestamp + Timestamp::months(37);
        assert_eq!(
            block_subsidy + NativeCurrencyAmount::coins(20 - 10 - 5 - 1),
            premine_rec
                .lock_guard()
                .await
                .get_wallet_status_for_tip()
                .await
                .confirmed_available_balance(block_1.header().height, after_cb_timelock_expiration)
        );

        println!("Transactions were received in good order.");

        // Make two transactions: Alice sends two UTXOs to premine rec (1 + 8 coins and 1 in fee)
        // and Bob sends three UTXOs to premine rec (1 + 1 + 1 and 1 in fee)
        let premine_rec_addr = premine_rec_spending_key.to_address();
        let outputs_from_alice: TxOutputList = vec![
            TxOutput::offchain_native_currency(
                NativeCurrencyAmount::coins(1),
                rng.random(),
                premine_rec_addr.into(),
                false,
            ),
            TxOutput::offchain_native_currency(
                NativeCurrencyAmount::coins(8),
                rng.random(),
                premine_rec_addr.into(),
                false,
            ),
        ]
        .into();
        let alice_change_key = alice
            .lock_guard()
            .await
            .wallet_state
            .wallet_entropy
            .nth_symmetric_key_for_tests(0)
            .into();
        let config_alice = TxCreationConfig::default()
            .recover_change_off_chain(alice_change_key)
            .with_prover_capability(TxProvingCapability::SingleProof);
        let consensus_rule_set_1 = ConsensusRuleSet::infer_from(network, block_1.header().height);
        let artifacts_alice = alice
            .api()
            .tx_initiator_internal()
            .create_transaction(
                outputs_from_alice.clone(),
                NativeCurrencyAmount::coins(1),
                in_seven_months,
                config_alice,
                consensus_rule_set_1,
            )
            .await
            .unwrap();
        let tx_from_alice = artifacts_alice.transaction;
        assert_eq!(
            outputs_from_alice.len(),
            artifacts_alice.details.tx_outputs.len(),
            "no change when consuming entire balance"
        );
        let outputs_from_bob: TxOutputList = vec![
            TxOutput::offchain_native_currency(
                NativeCurrencyAmount::coins(1),
                rng.random(),
                premine_rec_addr.into(),
                false,
            ),
            TxOutput::offchain_native_currency(
                NativeCurrencyAmount::coins(1),
                rng.random(),
                premine_rec_addr.into(),
                false,
            ),
            TxOutput::offchain_native_currency(
                NativeCurrencyAmount::coins(2),
                rng.random(),
                premine_rec_addr.into(),
                false,
            ),
        ]
        .into();
        let bob_change_key = bob
            .lock_guard()
            .await
            .wallet_state
            .wallet_entropy
            .nth_symmetric_key_for_tests(0)
            .into();
        let config_bob = TxCreationConfig::default()
            .recover_change_off_chain(bob_change_key)
            .with_prover_capability(TxProvingCapability::SingleProof);
        let tx_creation_artifacts_bob = bob
            .api()
            .tx_initiator_internal()
            .create_transaction(
                outputs_from_bob.clone(),
                NativeCurrencyAmount::coins(1),
                in_seven_months,
                config_bob,
                consensus_rule_set_1,
            )
            .await
            .unwrap();
        let tx_from_bob = tx_creation_artifacts_bob.transaction;
        assert_eq!(
            outputs_from_bob.len(),
            tx_creation_artifacts_bob.details.tx_outputs.len(),
            "no change when consuming entire balance"
        );

        println!("Generated new transaction to Alice and Bob");

        let light_state_premine = &premine_rec
            .global_state_lock
            .lock_guard()
            .await
            .chain
            .light_state_clone();
        // Make block_2 with tx that contains:
        // - 4 inputs: 2 from Alice and 2 from Bob
        // - 7 outputs: 2 from Alice to premine rec, 3 from Bob to premine rec, and 2 coinbases to premine rec
        let (cbtx2, expected_composer_utxos2) = make_coinbase_transaction_from_state_lock(
            light_state_premine.tip(),
            &premine_rec,
            in_seven_months,
            TritonVmProofJobOptions::default_with_network(network),
        )
        .await
        .unwrap();
        let block_tx2 = BlockTransaction::merge(
            cbtx2.into(),
            tx_from_alice.into(),
            Default::default(),
            TritonVmJobQueue::get_instance(),
            TritonVmProofJobOptions::default_with_network(network),
            consensus_rule_set_1,
        )
        .await
        .unwrap();
        let block_tx2 = BlockTransaction::merge(
            block_tx2.into(),
            tx_from_bob.into(),
            Default::default(),
            TritonVmJobQueue::get_instance(),
            TritonVmProofJobOptions::default_with_network(network),
            consensus_rule_set_1,
        )
        .await
        .unwrap();
        let block_2 = Block::compose(
            block_1.clone(),
            block_tx2,
            in_seven_months + network.minimum_block_time(),
            TritonVmJobQueue::get_instance(),
            TritonVmProofJobOptions::default_with_network(network),
        )
        .await
        .unwrap();

        println!("Generated new block");

        // Sanity checks
        assert_eq!(4, block_2.kernel.body.transaction_kernel.inputs.len());
        assert_eq!(7, block_2.kernel.body.transaction_kernel.outputs.len());
        assert!(block_2.is_valid(&block_1, in_seven_months, network).await);

        // Expect incoming UTXOs
        {
            let mut premine_rec = premine_rec.lock_guard_mut().await;
            let expected = premine_rec.wallet_state.extract_expected_utxos(
                outputs_from_bob
                    .concat_with(Vec::from(outputs_from_alice))
                    .iter(),
                UtxoNotifier::Cli,
            );
            premine_rec.wallet_state.add_expected_utxos(expected).await;
        }

        premine_rec
            .lock_guard_mut()
            .await
            .wallet_state
            .add_expected_utxos(expected_composer_utxos2)
            .await;

        // Update chain states
        for state_lock in [&mut premine_rec, &mut alice, &mut bob] {
            state_lock.set_new_tip(block_2.clone()).await.unwrap();
        }

        assert!(alice
            .lock_guard()
            .await
            .get_wallet_status_for_tip()
            .await
            .confirmed_available_balance(block_2.header().height, in_seven_months)
            .is_zero());
        assert!(bob
            .lock_guard()
            .await
            .get_wallet_status_for_tip()
            .await
            .confirmed_available_balance(block_2.header().height, in_seven_months)
            .is_zero());

        // Verify that all ingoing UTXOs are recorded in wallet of receiver of genesis UTXO
        assert_eq!(
            11,
            premine_rec.lock_guard().await
                .wallet_state
                .wallet_db
                .monitored_utxos()
                .len().await, "Premine receiver must have 11 UTXOs after block 2: 4 after block 1, and 7 added by block 2"
        );

        // Verify that mutator sets are updated correctly and that last block is block 2
        for state_lock in [&premine_rec, &alice, &bob] {
            let state = state_lock.lock_guard().await;

            assert_eq!(
                block_2.mutator_set_accumulator_after().unwrap().hash(),
                state
                    .chain
                    .archival_state()
                    .archival_mutator_set
                    .ams()
                    .accumulator()
                    .await
                    .hash(),
                "AMS must be correctly updated"
            );
            assert_eq!(block_2, state.chain.archival_state().get_tip().await);
            assert_eq!(
                block_1,
                state.chain.archival_state().get_tip_parent().await.unwrap()
            );
        }

        // Test that the MS-update to tip functions works for blocks with inputs
        // and outputs.
        positive_prop_ms_update_to_tip(
            &genesis_block.mutator_set_accumulator_after().unwrap(),
            premine_rec
                .lock_guard_mut()
                .await
                .chain
                .archival_state_mut(),
            2,
        )
        .await;
        positive_prop_ms_update_to_tip(
            &block_1.mutator_set_accumulator_after().unwrap(),
            premine_rec
                .lock_guard_mut()
                .await
                .chain
                .archival_state_mut(),
            2,
        )
        .await;
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn get_tip_block_test() -> Result<()> {
        for network in [
            Network::Main,
            Network::RegTest,
            Network::TestnetMock,
            Network::Testnet(0),
            Network::Testnet(1),
        ] {
            let mut archival_state: ArchivalState =
                make_test_archival_state(&Args::default_with_network(network)).await;

            assert!(
                archival_state.get_tip_from_disk().await.unwrap().is_none(),
                "Must return None when no block is stored in DB"
            );
            assert_eq!(
                archival_state.genesis_block(),
                &archival_state.get_tip().await
            );
            assert!(
                archival_state.get_tip_parent().await.is_none(),
                "Genesis tip has no parent"
            );

            // Add a block to archival state and verify that this is returned
            let mut rng = rand::rng();
            let own_wallet = WalletEntropy::new_random();
            let own_key = own_wallet.nth_generation_spending_key_for_tests(0);
            let genesis = *archival_state.genesis_block.clone();
            let (mock_block_1, _) =
                make_mock_block(&genesis, None, own_key, rng.random(), network).await;
            archival_state.set_new_tip(&mock_block_1).await.unwrap();

            assert_eq!(
                mock_block_1,
                archival_state.get_tip_from_disk().await.unwrap().unwrap(),
                "Returned block must match the one inserted"
            );
            assert_eq!(mock_block_1, archival_state.get_tip().await);
            assert_eq!(
                archival_state.genesis_block(),
                &archival_state.get_tip_parent().await.unwrap()
            );

            // Add a 2nd block and verify that this new block is now returned
            let (mock_block_2, _) =
                make_mock_block(&mock_block_1, None, own_key, rng.random(), network).await;
            archival_state.set_new_tip(&mock_block_2).await.unwrap();
            let ret2 = archival_state.get_tip_from_disk().await.unwrap();
            assert!(
                ret2.is_some(),
                "Must return a block when one is stored to DB"
            );
            assert_eq!(
                mock_block_2,
                ret2.unwrap(),
                "Returned block must match the one inserted"
            );
            assert_eq!(mock_block_2, archival_state.get_tip().await);
            assert_eq!(mock_block_1, archival_state.get_tip_parent().await.unwrap());

            assert_eq!(
                mock_block_2.hash(),
                archival_state
                    .archival_block_mmr
                    .ammr()
                    .try_get_leaf(mock_block_2.header().height.into())
                    .await
                    .unwrap(),
                "Block Height must be valid leaf index in archival block-MMR"
            );
            assert!(
                archival_state
                    .archival_block_mmr
                    .ammr()
                    .try_get_leaf(mock_block_2.header().height.next().into())
                    .await
                    .is_none(),
                "Tip height plus 1 must translate into an out-of-bounds leaf index in block-MMR"
            );
        }

        Ok(())
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn get_block_test() -> Result<()> {
        let mut rng = rand::rng();
        let network = Network::Main;
        let mut archival_state =
            make_test_archival_state(&Args::default_with_network(network)).await;

        let genesis = *archival_state.genesis_block.clone();
        let own_wallet = WalletEntropy::new_random();
        let own_key = own_wallet.nth_generation_spending_key_for_tests(0);
        let (mock_block_1, _) =
            make_mock_block(&genesis.clone(), None, own_key, rng.random(), network).await;

        // Lookup a block in an empty database, expect None to be returned
        assert!(
            archival_state
                .get_block(mock_block_1.hash())
                .await?
                .is_none(),
            "Must return none when not stored to DB"
        );

        archival_state.set_new_tip(&mock_block_1).await?;
        assert_eq!(
            mock_block_1,
            archival_state
                .get_block(mock_block_1.hash())
                .await?
                .unwrap(),
            "Returned block must match the one inserted"
        );

        // Inserted a new block and verify that both blocks can be found
        let (mock_block_2, _) =
            make_mock_block(&mock_block_1.clone(), None, own_key, rng.random(), network).await;
        archival_state.set_new_tip(&mock_block_2).await?;
        let fetched2 = archival_state
            .get_block(mock_block_2.hash())
            .await?
            .unwrap();
        assert_eq!(
            mock_block_2, fetched2,
            "Returned block must match the one inserted"
        );
        let fetched1 = archival_state
            .get_block(mock_block_1.hash())
            .await?
            .unwrap();
        assert_eq!(
            mock_block_1, fetched1,
            "Returned block must match the one inserted"
        );

        // Insert N new blocks and verify that they can all be fetched
        let mut last_block = mock_block_2.clone();
        let mut blocks = vec![genesis, mock_block_1, mock_block_2];
        for _ in 0..(rand::rng().next_u32() % 20) {
            let (new_block, _) =
                make_mock_block(&last_block, None, own_key, rng.random(), network).await;
            archival_state.set_new_tip(&new_block).await?;
            blocks.push(new_block.clone());
            last_block = new_block;
        }

        for block in blocks {
            assert_eq!(
                block,
                archival_state.get_block(block.hash()).await?.unwrap()
            );
        }

        Ok(())
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn test_get_addition_record_indices() {
        let mut rng = rand::rng();
        let network = Network::Main;
        let mut archival_state =
            make_test_archival_state(&Args::default_with_network(network)).await;

        // Digest::default ==> no block found
        assert!(archival_state
            .get_addition_record_indices_for_block(Digest::default())
            .await
            .is_none());

        // genesis digest ==> matches expectation
        let genesis_block = *archival_state.genesis_block.clone();
        let genesis_addition_records = genesis_block.mutator_set_update().unwrap().additions;
        let genesis_addition_record_indices = genesis_addition_records
            .into_iter()
            .enumerate()
            .map(|(i, ar)| (ar, Some(i as u64)))
            .collect::<HashMap<_, _>>();
        assert_eq!(
            genesis_addition_record_indices,
            archival_state
                .get_addition_record_indices_for_block(genesis_block.hash())
                .await
                .unwrap()
        );

        // Remainder of this test: mine two blocks, 1a and 1b. Set tip to 1a
        // then to 1b. Check expectations.

        // mine block 1a
        let own_wallet = WalletEntropy::new_random();
        let own_key = own_wallet.nth_generation_spending_key_for_tests(0);
        let (block_1a, _) =
            make_mock_block(&genesis_block.clone(), None, own_key, rng.random(), network).await;

        // apply block 1a
        archival_state.write_block_as_tip(&block_1a).await.unwrap();
        archival_state.append_to_archival_block_mmr(&block_1a).await;
        archival_state.update_mutator_set(&block_1a).await.unwrap();

        // mine block 1b
        let (block_1b, _) =
            make_mock_block(&genesis_block.clone(), None, own_key, rng.random(), network).await;

        // apply block 1b
        archival_state.write_block_as_tip(&block_1b).await.unwrap();
        archival_state.append_to_archival_block_mmr(&block_1b).await;
        archival_state.update_mutator_set(&block_1b).await.unwrap();

        // check expectations for 1a
        let addition_records_1a = block_1a.mutator_set_update().unwrap().additions;
        let addition_record_indices_1a = addition_records_1a
            .into_iter()
            .map(|ar| (ar, None))
            .collect::<HashMap<_, _>>();
        assert_eq!(
            addition_record_indices_1a,
            archival_state
                .get_addition_record_indices_for_block(block_1a.hash())
                .await
                .unwrap()
        );

        // check expectations for 1b
        let num_addition_records_before =
            genesis_block.mutator_set_update().unwrap().additions.len();
        let addition_records_1b = block_1b.mutator_set_update().unwrap().additions;
        let addition_record_indices_1b = addition_records_1b
            .into_iter()
            .enumerate()
            .map(|(i, ar)| (ar, Some((i + num_addition_records_before) as u64)))
            .collect::<HashMap<_, _>>();
        assert_eq!(
            addition_record_indices_1b,
            archival_state
                .get_addition_record_indices_for_block(block_1b.hash())
                .await
                .unwrap()
        );
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn ms_update_to_tip_five_blocks() {
        let network = Network::Main;
        let wallet = WalletEntropy::new_random();
        let mut rng = rand::rng();
        let mut archival_state =
            make_test_archival_state(&Args::default_with_network(network)).await;
        let mut current_block = Block::genesis(network);
        let genesis_msa = current_block
            .mutator_set_accumulator_after()
            .unwrap()
            .clone();
        let compose_beneficiary = wallet.nth_generation_spending_key_for_tests(0);
        for _block_height in 1..=5 {
            let next_block = make_mock_block(
                &current_block,
                None,
                compose_beneficiary,
                rng.random(),
                network,
            )
            .await
            .0;
            archival_state.set_new_tip(&next_block).await.unwrap();
            current_block = next_block;
        }

        let current_msa = current_block.mutator_set_accumulator_after().unwrap();
        for search_depth in 0..10 {
            println!("{search_depth}");
            if search_depth < 5 {
                assert!(archival_state
                    .get_mutator_set_update_to_tip(&genesis_msa, search_depth)
                    .await
                    .is_none());
            } else {
                positive_prop_ms_update_to_tip(&genesis_msa, &mut archival_state, search_depth)
                    .await;
            }
        }

        // Walking the opposite way returns None, and does not crash.
        let mut genesis_archival_state =
            make_test_archival_state(&Args::default_with_network(network)).await;
        for i in 0..10 {
            assert!(genesis_archival_state
                .get_mutator_set_update_to_tip(&current_msa, i)
                .await
                .is_none());
        }
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn find_canonical_block_with_aocl_index_five_blocks() {
        let network = Network::Main;
        let wallet = WalletEntropy::new_random();
        let mut rng = rand::rng();
        let mut archival_state =
            make_test_archival_state(&Args::default_with_network(network)).await;
        let mut current_block = Block::genesis(network);
        let compose_beneficiary = wallet.nth_generation_spending_key_for_tests(0);
        let mut blocks = vec![current_block.clone()];
        let mut min_aocl_index = 0u64;
        for _block_height in 1..=5 {
            let (next_block, _) = make_mock_block(
                &current_block,
                None,
                compose_beneficiary,
                rng.random(),
                network,
            )
            .await;
            archival_state.set_new_tip(&next_block).await.unwrap();
            current_block = next_block;
            blocks.push(current_block.clone());

            // After each applied block, all AOCL leaf indices must match
            // expected values.
            for block in &blocks {
                let min_aocl_index_next = block
                    .mutator_set_accumulator_after()
                    .unwrap()
                    .aocl
                    .num_leafs();
                for aocl_index in min_aocl_index..min_aocl_index_next {
                    let found_block_digest = archival_state
                        .canonical_block_digest_of_aocl_index(aocl_index)
                        .await
                        .unwrap()
                        .unwrap();
                    assert_eq!(
                        block.hash(),
                        found_block_digest,
                        "AOCL leaf index {aocl_index} must be found in expected block."
                    );
                }

                min_aocl_index = min_aocl_index_next;
            }
        }

        // Any indices beyond last known AOCL index must return None.
        for term in [
            1,
            2,
            100,
            10_000,
            u64::from(u32::MAX),
            u64::MAX - min_aocl_index,
        ] {
            let aocl_index = min_aocl_index + term;
            assert!(
                archival_state
                    .canonical_block_digest_of_aocl_index(aocl_index)
                    .await
                    .unwrap()
                    .is_none(),
                "AOCL leaf index {aocl_index} does not exist yet."
            );
        }
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn ms_update_to_tip_fork_depth_1() {
        let mut rng = rand::rng();
        let network = Network::Main;
        let wallet = WalletEntropy::new_random();
        let mut archival_state =
            make_test_archival_state(&Args::default_with_network(network)).await;
        let genesis_block = Block::genesis(network);
        let genesis_msa = &genesis_block.mutator_set_accumulator_after().unwrap();
        let compose_beneficiary = wallet.nth_generation_spending_key_for_tests(0);

        let block_1a = make_mock_block(
            &genesis_block,
            None,
            compose_beneficiary,
            rng.random(),
            network,
        )
        .await
        .0;
        let block_1b = make_mock_block(
            &genesis_block,
            None,
            compose_beneficiary,
            rng.random(),
            network,
        )
        .await
        .0;
        let block_1a_msa = &block_1a.mutator_set_accumulator_after().unwrap();
        let block_1b_msa = &block_1b.mutator_set_accumulator_after().unwrap();

        // 1a is tip
        let search_depth = 1;
        archival_state.set_new_tip(&block_1a).await.unwrap();
        positive_prop_ms_update_to_tip(genesis_msa, &mut archival_state, search_depth).await;
        positive_prop_ms_update_to_tip(block_1a_msa, &mut archival_state, search_depth).await;
        assert!(archival_state
            .get_mutator_set_update_to_tip(block_1b_msa, 1)
            .await
            .is_none());

        // 1b is tip
        archival_state.set_new_tip(&block_1b).await.unwrap();
        positive_prop_ms_update_to_tip(genesis_msa, &mut archival_state, search_depth).await;
        assert!(archival_state
            .get_mutator_set_update_to_tip(block_1a_msa, 1)
            .await
            .is_none());
        positive_prop_ms_update_to_tip(block_1b_msa, &mut archival_state, search_depth).await;
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn ms_update_to_tip_fork_depth_2() {
        let mut rng = rand::rng();
        let network = Network::Main;
        let wallet = WalletEntropy::new_random();
        let mut archival_state =
            make_test_archival_state(&Args::default_with_network(network)).await;
        let genesis_block = Block::genesis(network);
        let genesis_msa = &genesis_block.mutator_set_accumulator_after().unwrap();
        let cb_beneficiary = wallet.nth_generation_spending_key_for_tests(0);

        let block_1a = make_mock_block(&genesis_block, None, cb_beneficiary, rng.random(), network)
            .await
            .0;
        let block_2a = make_mock_block(&block_1a, None, cb_beneficiary, rng.random(), network)
            .await
            .0;
        let block_1b = make_mock_block(&genesis_block, None, cb_beneficiary, rng.random(), network)
            .await
            .0;
        let block_2b = make_mock_block(&block_1b, None, cb_beneficiary, rng.random(), network)
            .await
            .0;
        let block_1a_msa = &block_1a.mutator_set_accumulator_after().unwrap();
        let block_2a_msa = &block_2a.mutator_set_accumulator_after().unwrap();
        let block_1b_msa = &block_1b.mutator_set_accumulator_after().unwrap();
        let block_2b_msa = &block_2b.mutator_set_accumulator_after().unwrap();

        // 1a is tip
        let search_depth = 10;
        archival_state.set_new_tip(&block_1a).await.unwrap();
        assert!(archival_state
            .get_mutator_set_update_to_tip(block_2a_msa, search_depth)
            .await
            .is_none());
        assert!(archival_state
            .get_mutator_set_update_to_tip(block_2b_msa, search_depth)
            .await
            .is_none());

        // 1b is tip
        archival_state.set_new_tip(&block_1b).await.unwrap();
        assert!(archival_state
            .get_mutator_set_update_to_tip(block_2a_msa, search_depth)
            .await
            .is_none());
        assert!(archival_state
            .get_mutator_set_update_to_tip(block_2b_msa, search_depth)
            .await
            .is_none());

        // 2a is tip
        archival_state.set_new_tip(&block_2a).await.unwrap();
        positive_prop_ms_update_to_tip(genesis_msa, &mut archival_state, search_depth).await;
        positive_prop_ms_update_to_tip(block_1a_msa, &mut archival_state, search_depth).await;
        positive_prop_ms_update_to_tip(block_2a_msa, &mut archival_state, search_depth).await;
        assert!(archival_state
            .get_mutator_set_update_to_tip(block_1b_msa, search_depth)
            .await
            .is_none());
        assert!(archival_state
            .get_mutator_set_update_to_tip(block_2b_msa, search_depth)
            .await
            .is_none());

        // 2b is tip
        archival_state.set_new_tip(&block_2b).await.unwrap();
        positive_prop_ms_update_to_tip(genesis_msa, &mut archival_state, search_depth).await;
        positive_prop_ms_update_to_tip(block_1b_msa, &mut archival_state, search_depth).await;
        positive_prop_ms_update_to_tip(block_2b_msa, &mut archival_state, search_depth).await;
        assert!(archival_state
            .get_mutator_set_update_to_tip(block_1a_msa, search_depth)
            .await
            .is_none());
        assert!(archival_state
            .get_mutator_set_update_to_tip(block_2a_msa, search_depth)
            .await
            .is_none());
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn find_path_simple_test() -> Result<()> {
        let mut rng = rand::rng();
        let network = Network::Main;
        let mut archival_state =
            make_test_archival_state(&Args::default_with_network(network)).await;
        let genesis = *archival_state.genesis_block.clone();

        // Test that `find_path` returns the correct result
        let (backwards_0, luca_0, forwards_0) = archival_state
            .find_path(genesis.hash(), genesis.hash())
            .await;
        assert!(
            backwards_0.is_empty(),
            "Backwards path from genesis to genesis is empty"
        );
        assert!(
            forwards_0.is_empty(),
            "Forward path from genesis to genesis is empty"
        );
        assert_eq!(
            genesis.hash(),
            luca_0,
            "Luca of genesis and genesis is genesis"
        );

        // Add a fork with genesis as LUCA and verify that correct results are returned
        let wallet = WalletEntropy::new_random();
        let key = wallet.nth_generation_spending_key_for_tests(0);
        let (mock_block_1_a, _) =
            make_mock_block(&genesis.clone(), None, key, rng.random(), network).await;
        archival_state.set_new_tip(&mock_block_1_a).await.unwrap();

        let (mock_block_1_b, _) =
            make_mock_block(&genesis.clone(), None, key, rng.random(), network).await;
        archival_state.set_new_tip(&mock_block_1_b).await.unwrap();

        // Test 1a
        let (backwards_1, luca_1, forwards_1) = archival_state
            .find_path(genesis.hash(), mock_block_1_a.hash())
            .await;
        assert!(
            backwards_1.is_empty(),
            "Backwards path from genesis to 1a is empty"
        );
        assert_eq!(
            vec![mock_block_1_a.hash()],
            forwards_1,
            "Forwards from genesis to block 1a is block 1a"
        );
        assert_eq!(genesis.hash(), luca_1, "Luca of genesis and 1a is genesis");

        // Test 1b
        let (backwards_2, luca_2, forwards_2) = archival_state
            .find_path(genesis.hash(), mock_block_1_b.hash())
            .await;
        assert!(
            backwards_2.is_empty(),
            "Backwards path from genesis to 1b is empty"
        );
        assert_eq!(
            vec![mock_block_1_b.hash()],
            forwards_2,
            "Forwards from genesis to block 1b is block 1a"
        );
        assert_eq!(genesis.hash(), luca_2, "Luca of genesis and 1b is genesis");

        // Test 1a to 1b
        let (backwards_3, luca_3, forwards_3) = archival_state
            .find_path(mock_block_1_a.hash(), mock_block_1_b.hash())
            .await;
        assert_eq!(
            vec![mock_block_1_a.hash()],
            backwards_3,
            "Backwards path from 1a to 1b is 1a"
        );
        assert_eq!(
            vec![mock_block_1_b.hash()],
            forwards_3,
            "Forwards from 1a to block 1b is block 1b"
        );
        assert_eq!(genesis.hash(), luca_3, "Luca of 1a and 1b is genesis");

        // Test 1a to genesis
        let (backwards_4, _, forwards_4) = archival_state
            .find_path(mock_block_1_a.hash(), genesis.hash())
            .await;
        assert_eq!(
            vec![mock_block_1_a.hash()],
            backwards_4,
            "Backwards path from 1a to genesis is 1a"
        );
        assert!(
            forwards_4.is_empty(),
            "Forwards from 1a to genesis is the empty list"
        );

        Ok(())
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn digest_of_ancestors_test() {
        let mut rng = rand::rng();
        let network = Network::Main;
        let mut archival_state =
            make_test_archival_state(&Args::default_with_network(network)).await;
        let genesis = *archival_state.genesis_block.clone();
        let wallet = WalletEntropy::new_random();
        let key = wallet.nth_generation_spending_key_for_tests(0);

        assert!(archival_state
            .get_ancestor_block_digests(genesis.hash(), 10)
            .await
            .is_empty());
        assert!(archival_state
            .get_ancestor_block_digests(genesis.hash(), 1)
            .await
            .is_empty());
        assert!(archival_state
            .get_ancestor_block_digests(genesis.hash(), 0)
            .await
            .is_empty());

        // Insert blocks and verify that the same result is returned
        let (mock_block_1, _) =
            make_mock_block(&genesis.clone(), None, key, rng.random(), network).await;
        archival_state.set_new_tip(&mock_block_1).await.unwrap();
        let (mock_block_2, _) =
            make_mock_block(&mock_block_1.clone(), None, key, rng.random(), network).await;
        archival_state.set_new_tip(&mock_block_2).await.unwrap();
        let (mock_block_3, _) =
            make_mock_block(&mock_block_2.clone(), None, key, rng.random(), network).await;
        archival_state.set_new_tip(&mock_block_3).await.unwrap();
        let (mock_block_4, _) =
            make_mock_block(&mock_block_3.clone(), None, key, rng.random(), network).await;
        archival_state.set_new_tip(&mock_block_4).await.unwrap();

        assert!(archival_state
            .get_ancestor_block_digests(genesis.hash(), 10)
            .await
            .is_empty());
        assert!(archival_state
            .get_ancestor_block_digests(genesis.hash(), 1)
            .await
            .is_empty());
        assert!(archival_state
            .get_ancestor_block_digests(genesis.hash(), 0)
            .await
            .is_empty());

        // Check that ancestors of block 1 and 2 return the right values
        let ancestors_of_1 = archival_state
            .get_ancestor_block_digests(mock_block_1.hash(), 10)
            .await;
        assert_eq!(1, ancestors_of_1.len());
        assert_eq!(genesis.hash(), ancestors_of_1[0]);
        assert!(archival_state
            .get_ancestor_block_digests(mock_block_1.hash(), 0)
            .await
            .is_empty());

        let ancestors_of_2 = archival_state
            .get_ancestor_block_digests(mock_block_2.hash(), 10)
            .await;
        assert_eq!(2, ancestors_of_2.len());
        assert_eq!(mock_block_1.hash(), ancestors_of_2[0]);
        assert_eq!(genesis.hash(), ancestors_of_2[1]);
        assert!(archival_state
            .get_ancestor_block_digests(mock_block_2.hash(), 0)
            .await
            .is_empty());

        // Verify that max length is respected
        let ancestors_of_4_long = archival_state
            .get_ancestor_block_digests(mock_block_4.hash(), 10)
            .await;
        assert_eq!(4, ancestors_of_4_long.len());
        assert_eq!(mock_block_3.hash(), ancestors_of_4_long[0]);
        assert_eq!(mock_block_2.hash(), ancestors_of_4_long[1]);
        assert_eq!(mock_block_1.hash(), ancestors_of_4_long[2]);
        assert_eq!(genesis.hash(), ancestors_of_4_long[3]);
        let ancestors_of_4_short = archival_state
            .get_ancestor_block_digests(mock_block_4.hash(), 2)
            .await;
        assert_eq!(2, ancestors_of_4_short.len());
        assert_eq!(mock_block_3.hash(), ancestors_of_4_short[0]);
        assert_eq!(mock_block_2.hash(), ancestors_of_4_short[1]);
        assert!(archival_state
            .get_ancestor_block_digests(mock_block_4.hash(), 0)
            .await
            .is_empty());
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn write_block_db_test() -> Result<()> {
        let network = Network::Main;
        let mut rng = rand::rng();
        let mut archival_state =
            make_test_archival_state(&Args::default_with_network(network)).await;
        let genesis = *archival_state.genesis_block.clone();
        let wallet = WalletEntropy::new_random();
        let key = wallet.nth_generation_spending_key_for_tests(0);

        let (mock_block_1, _) =
            make_mock_block(&genesis.clone(), None, key, rng.random(), network).await;
        archival_state.write_block_as_tip(&mock_block_1).await?;

        // Verify that `LastFile` value is stored correctly
        let read_last_file: LastFileRecord = archival_state
            .block_index_db
            .get(BlockIndexKey::LastFile)
            .await
            .unwrap()
            .as_last_file_record();

        assert_eq!(0, read_last_file.last_file);

        // Verify that `Height` value is stored correctly
        {
            let expected_height: u64 = 1;
            let blocks_with_height_1: Vec<Digest> = archival_state
                .block_index_db
                .get(BlockIndexKey::Height(expected_height.into()))
                .await
                .unwrap()
                .as_height_record();

            assert_eq!(1, blocks_with_height_1.len());
            assert_eq!(mock_block_1.hash(), blocks_with_height_1[0]);
        }

        // Verify that `File` value is stored correctly
        let expected_file: u32 = read_last_file.last_file;
        let last_file_record_1: FileRecord = archival_state
            .block_index_db
            .get(BlockIndexKey::File(expected_file))
            .await
            .unwrap()
            .as_file_record();

        assert_eq!(1, last_file_record_1.blocks_in_file_count);

        let expected_block_len_1 = bincode::serialize(&mock_block_1).unwrap().len();
        assert_eq!(expected_block_len_1, last_file_record_1.file_size as usize);
        assert_eq!(
            mock_block_1.kernel.header.height,
            last_file_record_1.min_block_height
        );
        assert_eq!(
            mock_block_1.kernel.header.height,
            last_file_record_1.max_block_height
        );

        // Verify that `BlockTipDigest` is stored correctly
        let tip_digest: Digest = archival_state
            .block_index_db
            .get(BlockIndexKey::BlockTipDigest)
            .await
            .unwrap()
            .as_tip_digest();

        assert_eq!(mock_block_1.hash(), tip_digest);

        // Verify that `Block` is stored correctly
        let actual_block: BlockRecord = archival_state
            .get_block_record(mock_block_1.hash())
            .await
            .unwrap();

        assert_eq!(mock_block_1.kernel.header, actual_block.block_header);
        assert_eq!(
            expected_block_len_1,
            actual_block.file_location.block_length
        );
        assert_eq!(
            0, actual_block.file_location.offset,
            "First block written to file"
        );
        assert_eq!(
            read_last_file.last_file,
            actual_block.file_location.file_index
        );

        // Store another block and verify that this block is appended to disk
        let (mock_block_2, _) =
            make_mock_block(&mock_block_1.clone(), None, key, rng.random(), network).await;
        archival_state.write_block_as_tip(&mock_block_2).await?;

        // Verify that `LastFile` value is updated correctly, unchanged
        let read_last_file_2: LastFileRecord = archival_state
            .block_index_db
            .get(BlockIndexKey::LastFile)
            .await
            .unwrap()
            .as_last_file_record();
        assert_eq!(0, read_last_file.last_file);

        // Verify that `Height` value is updated correctly
        {
            let blocks_with_height_1: Vec<Digest> = archival_state
                .block_index_db
                .get(BlockIndexKey::Height(1.into()))
                .await
                .unwrap()
                .as_height_record();
            assert_eq!(1, blocks_with_height_1.len());
            assert_eq!(mock_block_1.hash(), blocks_with_height_1[0]);
        }

        {
            let blocks_with_height_2: Vec<Digest> = archival_state
                .block_index_db
                .get(BlockIndexKey::Height(2.into()))
                .await
                .unwrap()
                .as_height_record();
            assert_eq!(1, blocks_with_height_2.len());
            assert_eq!(mock_block_2.hash(), blocks_with_height_2[0]);
        }
        // Verify that `File` value is updated correctly
        let expected_file_2: u32 = read_last_file.last_file;
        let last_file_record_2: FileRecord = archival_state
            .block_index_db
            .get(BlockIndexKey::File(expected_file_2))
            .await
            .unwrap()
            .as_file_record();
        assert_eq!(2, last_file_record_2.blocks_in_file_count);
        let expected_block_len_2 = bincode::serialize(&mock_block_2).unwrap().len();
        assert_eq!(
            expected_block_len_1 + expected_block_len_2,
            last_file_record_2.file_size as usize
        );
        assert_eq!(
            mock_block_1.kernel.header.height,
            last_file_record_2.min_block_height
        );
        assert_eq!(
            mock_block_2.kernel.header.height,
            last_file_record_2.max_block_height
        );

        // Verify that `BlockTipDigest` is updated correctly
        let tip_digest_2: Digest = archival_state
            .block_index_db
            .get(BlockIndexKey::BlockTipDigest)
            .await
            .unwrap()
            .as_tip_digest();
        assert_eq!(mock_block_2.hash(), tip_digest_2);

        // Verify that `Block` is stored correctly
        let actual_block_record_2: BlockRecord = archival_state
            .get_block_record(mock_block_2.hash())
            .await
            .unwrap();

        assert_eq!(
            mock_block_2.kernel.header,
            actual_block_record_2.block_header
        );
        assert_eq!(
            expected_block_len_2,
            actual_block_record_2.file_location.block_length
        );
        assert_eq!(
            expected_block_len_1 as u64, actual_block_record_2.file_location.offset,
            "Second block written to file must be offset by block 1's length"
        );
        assert_eq!(
            read_last_file_2.last_file,
            actual_block_record_2.file_location.file_index
        );

        // Test `get_latest_block_from_disk`
        let read_latest_block = archival_state.get_tip_from_disk().await?.unwrap();
        assert_eq!(mock_block_2, read_latest_block);

        // Test `get_block_from_block_record`
        let block_from_block_record = archival_state
            .get_block_from_block_record(actual_block_record_2)
            .await
            .unwrap();
        assert_eq!(mock_block_2, block_from_block_record);
        assert_eq!(mock_block_2.hash(), block_from_block_record.hash());

        // Test `get_block_header`
        let block_header_2 = archival_state
            .get_block_header(mock_block_2.hash())
            .await
            .unwrap();
        assert_eq!(mock_block_2.kernel.header, block_header_2);

        // Test `get_block_header`
        {
            let block_header_2_from_lock_method = archival_state
                .get_block_header(mock_block_2.hash())
                .await
                .unwrap();
            assert_eq!(mock_block_2.kernel.header, block_header_2_from_lock_method);

            let genesis_header_from_lock_method = archival_state
                .get_block_header(genesis.hash())
                .await
                .unwrap();
            assert_eq!(genesis.kernel.header, genesis_header_from_lock_method);
        }

        // Test `get_ancestor_block_digests`
        let ancestor_digests = archival_state
            .get_ancestor_block_digests(mock_block_2.hash(), 10)
            .await;
        assert_eq!(2, ancestor_digests.len());
        assert_eq!(mock_block_1.hash(), ancestor_digests[0]);
        assert_eq!(genesis.hash(), ancestor_digests[1]);

        Ok(())
    }

    mod find_canonical_block_with_puts {
        use neptune_consensus::block::test_helpers::invalid_empty_block_with_num_outputs;

        use super::*;
        use crate::tests::shared::blocks::block_with_num_puts;

        #[traced_test]
        #[test_strategy::proptest(async = "tokio", cases = 3)]
        async fn only_reports_on_canonical_blocks_with_outputs(
            #[strategy(collection::vec(arb::<AdditionRecord>(), 0usize..22))]
            addition_records_1a: Vec<AdditionRecord>,
        ) {
            let network = Network::Main;

            for maintain_utxo_index in [false, true] {
                let cli = Args {
                    utxo_index: maintain_utxo_index,
                    network,
                    ..Default::default()
                };

                let genesis = Block::genesis(network);
                let block1a =
                    block_with_puts(network, &genesis, addition_records_1a.clone(), vec![]).await;
                let block1b = invalid_empty_block(&genesis, network);
                let mut archival_state = make_test_archival_state(&cli).await;
                archival_state.set_new_tip(&block1a).await.unwrap();
                archival_state.set_new_tip(&block1b).await.unwrap();

                for ar in &addition_records_1a {
                    prop_assert!(
                        archival_state
                            .find_canonical_block_hash_with_output(*ar, None)
                            .await
                            .is_none(),
                        "No match when block is buried to deep and UTXO index is not maintained"
                    );
                }
            }
        }

        #[traced_test]
        #[test_strategy::proptest(async = "tokio", cases = 3)]
        async fn find_canonical_block_with_output_block1(
            #[strategy(collection::vec(arb::<AdditionRecord>(), 0usize..22))] addition_records: Vec<
                AdditionRecord,
            >,
        ) {
            let network = Network::Main;

            for maintain_utxo_index in [false, true] {
                let cli = Args {
                    utxo_index: maintain_utxo_index,
                    network,
                    ..Default::default()
                };
                let mut archival_state = make_test_archival_state(&cli).await;

                for ar in &addition_records {
                    prop_assert!(archival_state
                        .find_canonical_block_with_output(*ar, None)
                        .await
                        .is_none());
                }

                let block1 = block_with_puts(
                    network,
                    &Block::genesis(network),
                    addition_records.clone(),
                    vec![],
                )
                .await;
                archival_state.set_new_tip(&block1).await.unwrap();

                for ar in &addition_records {
                    let found_block = archival_state
                        .find_canonical_block_with_output(*ar, None)
                        .await
                        .unwrap();
                    prop_assert_eq!(block1.hash(), found_block.hash());
                }
            }
        }

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn utxo_origin_blocks_from_absolute_index_sets_genesis() {
            let network = Network::Main;
            let genesis = Block::genesis(network);
            let cli = Args {
                network,
                ..Default::default()
            };
            let mut alice = mock_genesis_global_state(0, WalletEntropy::devnet_wallet(), cli).await;
            let mut alice = alice.global_state_lock.lock_guard_mut().await;

            let devnet_absi = alice
                .wallet_state
                .wallet_db
                .monitored_utxos()
                .get_all()
                .await[0]
                .absolute_indices();

            let mut tip = genesis.clone();
            for _block_height in 0..5 {
                let res = alice
                    .chain
                    .archival_state()
                    .utxo_origin_blocks_from_absolute_index_sets(vec![devnet_absi])
                    .await
                    .unwrap();
                assert!(res
                    .iter()
                    .map(|(block_hash, _, _, _)| block_hash)
                    .any(|hash| *hash == genesis.hash()));

                tip = invalid_empty_block_with_num_outputs(&tip, network, 20);
                alice.set_new_tip(tip.clone()).await.unwrap();
            }
        }

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn canonical_block_with_input_block1() {
            let network = Network::Main;
            let genesis = Block::genesis(network);
            for maintain_utxo_index in [false, true] {
                let cli = Args {
                    utxo_index: maintain_utxo_index,
                    network,
                    ..Default::default()
                };
                let mut archival_state = make_test_archival_state(&cli).await;
                let block1a = block_with_num_puts(network, &genesis, 2, 3).await;

                let block1a_inputs = block1a
                    .body()
                    .transaction_kernel
                    .inputs
                    .iter()
                    .map(|x| x.absolute_indices);
                archival_state.set_new_tip(&block1a).await.unwrap();

                for input in block1a_inputs.clone() {
                    let found_block = archival_state
                        .find_canonical_block_with_input(input, None)
                        .await
                        .unwrap();
                    assert_eq!(block1a.hash(), found_block.hash());
                }

                // Ensure we only report on canonical blocks
                let block1b = invalid_empty_block(&genesis, network);
                archival_state.set_new_tip(&block1b).await.unwrap();
                for input in block1a_inputs.clone() {
                    assert!(archival_state
                        .find_canonical_block_with_input(input, Some(12))
                        .await
                        .is_none());
                }

                // Verify max search depth is respected if UTXO index is not
                // maintained. Note that block 1a becomes canonical again.
                let block2a = invalid_empty_block(&block1a, network);
                archival_state.set_new_tip(&block2a).await.unwrap();
                for input in block1a_inputs.clone() {
                    let res_search_depth_0 = archival_state
                        .find_canonical_block_with_input(input, Some(0))
                        .await;
                    if maintain_utxo_index {
                        assert!(res_search_depth_0.is_some());
                    } else {
                        assert!(res_search_depth_0.is_none());
                    }
                    let found_block = archival_state
                        .find_canonical_block_with_input(input, Some(1))
                        .await
                        .unwrap();
                    assert_eq!(block1a.hash(), found_block.hash());
                }
            }
        }
    }

    mod block_hash_witness {}

    /// Test of functions that require both UTXO index and other parts of the
    /// archival state
    mod utxo_index {
        use neptune_consensus::block::test_helpers::invalid_empty_block;

        use super::*;
        use crate::tests::shared::blocks::block_with_num_puts;

        #[apply(shared_tokio_runtime)]
        async fn only_canonical_addition_records_are_matched() {
            let network = Network::Main;
            let cli = Args {
                utxo_index: true,
                network,
                ..Default::default()
            };
            let mut archive = make_test_archival_state(&cli).await;

            let genesis = Block::genesis(network);
            let mut rng = rand::rng();

            let abandoned_output = AdditionRecord::new(rng.random());
            let block1_orphaned =
                block_with_puts(network, &genesis, vec![abandoned_output], vec![]).await;
            archive.set_new_tip(&block1_orphaned).await.unwrap();

            let canonical_output = AdditionRecord::new(rng.random());
            let block1_canonical =
                block_with_puts(network, &genesis, vec![canonical_output], vec![]).await;
            archive.set_new_tip(&block1_canonical).await.unwrap();

            let abandoned_output = HashSet::from([abandoned_output]);
            assert!(archive
                .addition_records_to_block_height(abandoned_output.clone())
                .await
                .unwrap()
                .is_empty());
            assert!(archive
                .canonical_block_heights_with_puts(HashSet::new(), abandoned_output)
                .await
                .unwrap()
                .is_empty());

            let canonical_output = HashSet::from([canonical_output]);
            let block_height_1 = HashSet::from([BlockHeight::from(1u64)]);
            assert_eq!(
                block_height_1,
                archive
                    .addition_records_to_block_height(canonical_output.clone())
                    .await
                    .unwrap()
            );
            assert_eq!(
                block_height_1,
                archive
                    .canonical_block_heights_with_puts(HashSet::new(), canonical_output)
                    .await
                    .unwrap()
            );
        }

        #[apply(shared_tokio_runtime)]
        async fn only_canonical_absolute_index_sets_are_matched() {
            let network = Network::Main;
            let cli = Args {
                utxo_index: true,
                network,
                ..Default::default()
            };
            let mut archive = make_test_archival_state(&cli).await;

            let genesis = Block::genesis(network);
            let abandoned_block1 = block_with_num_puts(network, &genesis, 4, 4).await;
            let canonical_block1 = block_with_num_puts(network, &genesis, 4, 4).await;

            archive.set_new_tip(&abandoned_block1).await.unwrap();
            archive.set_new_tip(&canonical_block1).await.unwrap();

            // Verify no inputs from abandoned block are matched.
            for abs_index_set in abandoned_block1
                .body()
                .transaction_kernel()
                .inputs
                .iter()
                .map(|x| x.absolute_indices)
            {
                let abs_index_set = HashSet::from([abs_index_set]);
                assert!(archive
                    .absolute_index_sets_to_block_heights(abs_index_set.clone())
                    .await
                    .unwrap()
                    .is_empty());

                assert!(archive
                    .canonical_block_heights_with_puts(abs_index_set, HashSet::new())
                    .await
                    .unwrap()
                    .is_empty());
            }

            // Verify that all inputs from canonical block 1 are matched.
            for abs_index_set in canonical_block1
                .body()
                .transaction_kernel()
                .inputs
                .iter()
                .map(|x| x.absolute_indices)
            {
                let abs_index_set = HashSet::from([abs_index_set]);
                let res = archive
                    .absolute_index_sets_to_block_heights(abs_index_set.clone())
                    .await
                    .unwrap();
                let expected: HashSet<BlockHeight> =
                    [BlockHeight::from(1u64)].into_iter().collect();
                assert_eq!(expected, res);

                assert_eq!(
                    expected,
                    archive
                        .canonical_block_heights_with_puts(abs_index_set, HashSet::new())
                        .await
                        .unwrap()
                );
            }
        }

        #[apply(shared_tokio_runtime)]
        async fn returns_multiple_block_heights_on_repeated_addition_records() {
            let network = Network::Main;
            let cli = Args {
                utxo_index: true,
                network,
                ..Default::default()
            };
            let mut archive = make_test_archival_state(&cli).await;
            let genesis = Block::genesis(network);
            let mut rng = rand::rng();

            let repeated_output = AdditionRecord::new(rng.random());
            let block1 = block_with_puts(
                network,
                &genesis,
                vec![
                    repeated_output,
                    repeated_output,
                    repeated_output,
                    repeated_output,
                ],
                vec![],
            )
            .await;
            archive.set_new_tip(&block1).await.unwrap();
            let block2 = block_with_puts(
                network,
                &block1,
                vec![repeated_output, repeated_output],
                vec![],
            )
            .await;
            archive.set_new_tip(&block2).await.unwrap();
            let block3 = invalid_empty_block(&block2, network);
            archive.set_new_tip(&block3).await.unwrap();
            let block4 = block_with_puts(network, &block3, vec![repeated_output], vec![]).await;
            archive.set_new_tip(&block4).await.unwrap();

            let expected: HashSet<_> = [
                BlockHeight::from(1u64),
                BlockHeight::from(2u64),
                BlockHeight::from(4u64),
            ]
            .into_iter()
            .collect();

            let repeated_output = HashSet::from([repeated_output]);
            assert_eq!(
                expected,
                archive
                    .addition_records_to_block_height(repeated_output.clone())
                    .await
                    .unwrap()
            );
            assert_eq!(
                expected,
                archive
                    .canonical_block_heights_with_puts(HashSet::new(), repeated_output)
                    .await
                    .unwrap()
            )
        }
    }

    mod recover {}

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn fork_path_finding_test() -> Result<()> {
        let mut rng = rand::rng();
        // Test behavior of fork-resolution functions such as `find_path` and checking if block
        // belongs to canonical chain.

        /// Assert that the `find_path` result agrees with the result from `get_ancestor_block_digests`
        async fn dag_walker_leash_prop(
            start: Digest,
            stop: Digest,
            archival_state: &ArchivalState,
        ) {
            let (mut backwards, luca, mut forwards) = archival_state.find_path(start, stop).await;

            if let Some(last_forward) = forwards.pop() {
                assert_eq!(
                    stop, last_forward,
                    "Last forward digest must be `stop` digest"
                );

                // Verify that 1st element has luca as parent
                let first_forward = if let Some(first) = forwards.first() {
                    *first
                } else {
                    last_forward
                };

                let first_forwards_block_header = archival_state
                    .get_block_header(first_forward)
                    .await
                    .unwrap();
                assert_eq!(
                    first_forwards_block_header.prev_block_digest, luca,
                    "Luca must be parent of 1st forwards element"
                );
            }

            if let Some(last_backwards) = backwards.last() {
                // Verify that `luca` matches ancestor of the last element of `backwards`
                let last_backwards_block_header = archival_state
                    .get_block_header(*last_backwards)
                    .await
                    .unwrap();
                assert_eq!(
                    luca, last_backwards_block_header.prev_block_digest,
                    "Luca must be parent of last backwards element"
                );

                // Verify that "first backwards" is `start`, and remove it, since the `get_ancestor_block_digests`
                // does not return the starting point
                let first_backwards = backwards.remove(0);
                assert_eq!(
                    start, first_backwards,
                    "First backwards must be `start` digest"
                );
            }

            let backwards_expected = archival_state
                .get_ancestor_block_digests(start.to_owned(), backwards.len())
                .await;
            assert_eq!(backwards_expected, backwards, "\n\nbackwards digests must match expected value. Got:\n {backwards:?}\n\n, Expected from helper function:\n {backwards_expected:?}\n");

            let mut forwards_expected = archival_state
                .get_ancestor_block_digests(stop.to_owned(), forwards.len())
                .await;
            forwards_expected.reverse();
            assert_eq!(forwards_expected, forwards, "\n\nforwards digests must match expected value. Got:\n {forwards:?}\n\n, Expected from helper function:\n{forwards_expected:?}\n");
        }

        let network = Network::Main;
        let mut archival_state =
            make_test_archival_state(&Args::default_with_network(network)).await;

        let genesis = *archival_state.genesis_block.clone();
        assert!(
            archival_state
                .block_belongs_to_canonical_chain(genesis.hash())
                .await,
            "Genesis block is always part of the canonical chain, tip"
        );

        // Insert a block that is descendant from genesis block and verify that it is canonical
        let wallet = WalletEntropy::new_random();
        let key = wallet.nth_generation_spending_key_for_tests(0);
        let (block1, _) = make_mock_block(&genesis.clone(), None, key, rng.random(), network).await;
        archival_state.set_new_tip(&block1).await.unwrap();
        assert!(
            archival_state
                .block_belongs_to_canonical_chain(genesis.hash())
                .await,
            "Genesis block is always part of the canonical chain, tip parent"
        );
        assert!(
            archival_state
                .block_belongs_to_canonical_chain(block1.hash())
                .await,
            "Tip block is always part of the canonical chain"
        );

        // Insert three more blocks and verify that all are part of the canonical chain
        let (mock_block_2_a, _) =
            make_mock_block(&block1.clone(), None, key, rng.random(), network).await;
        archival_state.set_new_tip(&mock_block_2_a).await.unwrap();
        let (mock_block_3_a, _) =
            make_mock_block(&mock_block_2_a.clone(), None, key, rng.random(), network).await;
        archival_state.set_new_tip(&mock_block_3_a).await.unwrap();
        let (mock_block_4_a, _) =
            make_mock_block(&mock_block_3_a.clone(), None, key, rng.random(), network).await;
        archival_state.set_new_tip(&mock_block_4_a).await.unwrap();
        for (i, block) in [
            genesis.clone(),
            block1.clone(),
            mock_block_2_a.clone(),
            mock_block_3_a.clone(),
            mock_block_4_a.clone(),
        ]
        .iter()
        .enumerate()
        {
            assert!(
                archival_state
                    .block_belongs_to_canonical_chain(block.hash())
                    .await,
                "block {} does not belong to canonical chain",
                i
            );
            dag_walker_leash_prop(block.hash(), mock_block_4_a.hash(), &archival_state).await;
            dag_walker_leash_prop(mock_block_4_a.hash(), block.hash(), &archival_state).await;
        }

        assert!(
            archival_state
                .block_belongs_to_canonical_chain(genesis.hash())
                .await,
            "Genesis block is always part of the canonical chain, block height is four"
        );

        // Make a tree and verify that the correct parts of the tree are identified as
        // belonging to the canonical chain
        let (mock_block_2_b, _) =
            make_mock_block(&block1.clone(), None, key, rng.random(), network).await;
        archival_state.set_new_tip(&mock_block_2_b).await.unwrap();
        let (mock_block_3_b, _) =
            make_mock_block(&mock_block_2_b.clone(), None, key, rng.random(), network).await;
        archival_state.set_new_tip(&mock_block_3_b).await.unwrap();
        let (mock_block_4_b, _) =
            make_mock_block(&mock_block_3_b.clone(), None, key, rng.random(), network).await;
        archival_state.set_new_tip(&mock_block_4_b).await.unwrap();
        let (mock_block_5_b, _) =
            make_mock_block(&mock_block_4_b.clone(), None, key, rng.random(), network).await;
        archival_state.set_new_tip(&mock_block_5_b).await.unwrap();
        for (i, block) in [
            genesis.clone(),
            block1.clone(),
            mock_block_2_b.clone(),
            mock_block_3_b.clone(),
            mock_block_4_b.clone(),
            mock_block_5_b.clone(),
        ]
        .iter()
        .enumerate()
        {
            assert!(
                archival_state
                    .block_belongs_to_canonical_chain(block.hash())
                    .await,
                "canonical chain {} is canonical",
                i
            );
            dag_walker_leash_prop(block.hash(), mock_block_5_b.hash(), &archival_state).await;
            dag_walker_leash_prop(mock_block_5_b.hash(), block.hash(), &archival_state).await;
        }

        for (i, block) in [
            mock_block_2_a.clone(),
            mock_block_3_a.clone(),
            mock_block_4_a.clone(),
        ]
        .iter()
        .enumerate()
        {
            assert!(
                !archival_state
                    .block_belongs_to_canonical_chain(block.hash())
                    .await,
                "Stale chain {} is not canonical",
                i
            );
        }

        // Make a complicated tree and verify that the function identifies the correct blocks as part
        // of the PoW family. In the below tree 6d is the tip as it has the highest accumulated PoW family value
        //                     /-3c<----4c<----5c<-----6c<---7c<---8c
        //                    /
        //                   /---3a<----4a<----5a
        //                  /
        //   gen<----1<----2a<---3d<----4d<----5d<-----6d (tip now)
        //            \            \
        //             \            \---4e<----5e
        //              \
        //               \
        //                \2b<---3b<----4b<----5b ((<--6b)) (added in test later, tip later)
        //
        // Note that in the later test, 6b becomes the tip.

        // Prior to this line, block 4a is tip.
        let (mock_block_3_c, _) =
            make_mock_block(&mock_block_2_a.clone(), None, key, rng.random(), network).await;
        archival_state.set_new_tip(&mock_block_3_c).await.unwrap();
        let (mock_block_4_c, _) =
            make_mock_block(&mock_block_3_c.clone(), None, key, rng.random(), network).await;
        archival_state.set_new_tip(&mock_block_4_c).await.unwrap();
        let (mock_block_5_c, _) =
            make_mock_block(&mock_block_4_c.clone(), None, key, rng.random(), network).await;
        archival_state.set_new_tip(&mock_block_5_c).await.unwrap();
        let (mock_block_6_c, _) =
            make_mock_block(&mock_block_5_c.clone(), None, key, rng.random(), network).await;
        archival_state.set_new_tip(&mock_block_6_c).await.unwrap();
        let (mock_block_7_c, _) =
            make_mock_block(&mock_block_6_c.clone(), None, key, rng.random(), network).await;
        archival_state.set_new_tip(&mock_block_7_c).await.unwrap();
        let (mock_block_8_c, _) =
            make_mock_block(&mock_block_7_c.clone(), None, key, rng.random(), network).await;
        archival_state.set_new_tip(&mock_block_8_c).await.unwrap();
        let (mock_block_5_a, _) =
            make_mock_block(&mock_block_4_a.clone(), None, key, rng.random(), network).await;
        archival_state.set_new_tip(&mock_block_5_a).await.unwrap();
        let (mock_block_3_d, _) =
            make_mock_block(&mock_block_2_a.clone(), None, key, rng.random(), network).await;
        archival_state.set_new_tip(&mock_block_3_d).await.unwrap();

        let (mock_block_4_e, _) =
            make_mock_block(&mock_block_3_d.clone(), None, key, rng.random(), network).await;
        archival_state.set_new_tip(&mock_block_4_e).await.unwrap();
        let (mock_block_5_e, _) =
            make_mock_block(&mock_block_4_e.clone(), None, key, rng.random(), network).await;
        archival_state.set_new_tip(&mock_block_5_e).await.unwrap();

        let (mock_block_4_d, _) =
            make_mock_block(&mock_block_3_d.clone(), None, key, rng.random(), network).await;
        archival_state.set_new_tip(&mock_block_4_d).await.unwrap();
        let (mock_block_5_d, _) =
            make_mock_block(&mock_block_4_d.clone(), None, key, rng.random(), network).await;
        archival_state.set_new_tip(&mock_block_5_d).await.unwrap();

        // This is the most canonical block in the known set
        let (mock_block_6_d, _) =
            make_mock_block(&mock_block_5_d.clone(), None, key, rng.random(), network).await;
        archival_state.set_new_tip(&mock_block_6_d).await.unwrap();

        for (i, block) in [
            genesis.clone(),
            block1.clone(),
            mock_block_2_a.clone(),
            mock_block_3_d.clone(),
            mock_block_4_d.clone(),
            mock_block_5_d.clone(),
            mock_block_6_d.clone(),
        ]
        .iter()
        .enumerate()
        {
            assert!(
                archival_state
                    .block_belongs_to_canonical_chain(block.hash())
                    .await,
                "canonical chain {} is canonical, complicated",
                i
            );
            dag_walker_leash_prop(mock_block_6_d.hash(), block.hash(), &archival_state).await;
            dag_walker_leash_prop(block.hash(), mock_block_6_d.hash(), &archival_state).await;
        }

        for (i, block) in [
            mock_block_2_b.clone(),
            mock_block_3_b.clone(),
            mock_block_4_b.clone(),
            mock_block_5_b.clone(),
            mock_block_3_c.clone(),
            mock_block_4_c.clone(),
            mock_block_5_c.clone(),
            mock_block_6_c.clone(),
            mock_block_7_c.clone(),
            mock_block_8_c.clone(),
            mock_block_3_a.clone(),
            mock_block_4_a.clone(),
            mock_block_5_a.clone(),
            mock_block_4_e.clone(),
            mock_block_5_e.clone(),
        ]
        .iter()
        .enumerate()
        {
            assert!(
                !archival_state
                    .block_belongs_to_canonical_chain(block.hash())
                    .await,
                "Stale chain {} is not canonical",
                i
            );
            dag_walker_leash_prop(mock_block_6_d.hash(), block.hash(), &archival_state).await;
            dag_walker_leash_prop(block.hash(), mock_block_6_d.hash(), &archival_state).await;
        }

        // Make a new block, 6b, canonical and verify that all checks work
        let (mock_block_6_b, _) =
            make_mock_block(&mock_block_5_b.clone(), None, key, rng.random(), network).await;
        archival_state.set_new_tip(&mock_block_6_b).await.unwrap();
        for (i, block) in [
            mock_block_3_c.clone(),
            mock_block_4_c.clone(),
            mock_block_5_c.clone(),
            mock_block_6_c.clone(),
            mock_block_7_c.clone(),
            mock_block_8_c.clone(),
            mock_block_2_a.clone(),
            mock_block_3_a.clone(),
            mock_block_4_a.clone(),
            mock_block_5_a.clone(),
            mock_block_4_e.clone(),
            mock_block_5_e.clone(),
            mock_block_3_d.clone(),
            mock_block_4_d.clone(),
            mock_block_5_d.clone(),
            mock_block_6_d.clone(),
        ]
        .iter()
        .enumerate()
        {
            assert!(
                !archival_state
                    .block_belongs_to_canonical_chain(block.hash())
                    .await,
                "Stale chain {} is not canonical",
                i
            );
            dag_walker_leash_prop(mock_block_6_d.hash(), block.hash(), &archival_state).await;
            dag_walker_leash_prop(block.hash(), mock_block_6_d.hash(), &archival_state).await;
        }

        for (i, block) in [
            &genesis,
            &block1,
            &mock_block_2_b,
            &mock_block_3_b,
            &mock_block_4_b,
            &mock_block_5_b,
            &mock_block_6_b.clone(),
        ]
        .into_iter()
        .enumerate()
        {
            assert!(
                archival_state
                    .block_belongs_to_canonical_chain(block.hash())
                    .await,
                "canonical chain {} is canonical, complicated",
                i
            );
            dag_walker_leash_prop(mock_block_6_b.hash(), block.hash(), &archival_state).await;
            dag_walker_leash_prop(block.hash(), mock_block_6_b.hash(), &archival_state).await;
        }

        // An explicit test of `find_path`
        //                     /-3c<----4c<----5c<-----6c<---7c<---8c
        //                    /
        //                   /---3a<----4a<----5a
        //                  /
        //   gen<----1<----2a<---3d<----4d<----5d<-----6d
        //            \            \
        //             \            \---4e<----5e
        //              \
        //               \
        //                \2b<---3b<----4b<----5b<---6b
        let (backwards, luca, forwards) = archival_state
            .find_path(mock_block_5_e.hash(), mock_block_6_b.hash())
            .await;
        assert_eq!(
            vec![
                mock_block_2_b.hash(),
                mock_block_3_b.hash(),
                mock_block_4_b.hash(),
                mock_block_5_b.hash(),
                mock_block_6_b.hash(),
            ],
            forwards,
            "find_path forwards return value must match expected value"
        );
        assert_eq!(
            vec![
                mock_block_5_e.hash(),
                mock_block_4_e.hash(),
                mock_block_3_d.hash(),
                mock_block_2_a.hash()
            ],
            backwards,
            "find_path backwards return value must match expected value"
        );
        assert_eq!(block1.hash(), luca, "Luca must be block 1");

        Ok(())
    }

    #[apply(shared_tokio_runtime)]
    async fn canonical_block_heights_with_puts_simple() {
        async fn assert_in_block1(
            archive: &ArchivalState,
            inputs: Vec<AbsoluteIndexSet>,
            outputs: Vec<AdditionRecord>,
        ) {
            assert_eq!(
                HashSet::from([BlockHeight::new(bfe!(1))]),
                archive
                    .canonical_block_heights_with_puts(
                        inputs.into_iter().collect(),
                        outputs.into_iter().collect()
                    )
                    .await
                    .unwrap()
            );
        }

        async fn assert_not_mined(
            archive: &ArchivalState,
            inputs: Vec<AbsoluteIndexSet>,
            outputs: Vec<AdditionRecord>,
        ) {
            assert!(archive
                .canonical_block_heights_with_puts(
                    inputs.into_iter().collect(),
                    outputs.into_iter().collect(),
                )
                .await
                .unwrap()
                .is_empty())
        }

        let network = Network::Main;
        let cli = Args {
            utxo_index: true,
            network,
            ..Default::default()
        };

        let genesis = Block::genesis(network);
        let mut archive = make_test_archival_state(&cli).await;
        let block1 = block_with_num_puts(network, &genesis, 4, 4).await;
        archive.set_new_tip(&block1).await.unwrap();

        let outputs = block1.all_addition_records().unwrap();
        let inputs = block1.all_absolute_index_sets();

        assert_in_block1(&archive, vec![], vec![outputs[0]]).await;
        assert_in_block1(&archive, vec![], vec![outputs[1]]).await;
        assert_in_block1(&archive, vec![], vec![outputs[0], outputs[1]]).await;
        assert_in_block1(&archive, vec![inputs[0]], vec![]).await;
        assert_in_block1(&archive, vec![inputs[0], inputs[1]], vec![]).await;
        assert_in_block1(&archive, vec![inputs[0]], vec![outputs[0]]).await;
        assert_in_block1(&archive, vec![inputs[0], inputs[2]], vec![outputs[0]]).await;
        assert_in_block1(
            &archive,
            vec![inputs[0], inputs[2]],
            vec![outputs[0], outputs[3]],
        )
        .await;
        assert_in_block1(
            &archive,
            vec![inputs[2], inputs[0], inputs[3]],
            vec![outputs[3], outputs[1], outputs[2]],
        )
        .await;
        assert_in_block1(
            &archive,
            inputs.clone(),
            vec![outputs[3], outputs[1], outputs[2]],
        )
        .await;
        assert_in_block1(&archive, inputs.clone(), vec![]).await;
        assert_in_block1(&archive, vec![], outputs.clone()).await;
        assert_in_block1(&archive, inputs.clone(), outputs.clone()).await;

        let unknown_output = AdditionRecord::new(Digest::default());
        assert_not_mined(&archive, vec![], vec![unknown_output]).await;
        assert_not_mined(&archive, vec![], vec![unknown_output, outputs[0]]).await;
        assert_not_mined(&archive, vec![], vec![outputs[0], unknown_output]).await;
        assert_not_mined(&archive, inputs.clone(), vec![outputs[0], unknown_output]).await;
        assert_not_mined(&archive, inputs.clone(), vec![unknown_output]).await;

        let unknown_input = AbsoluteIndexSet::empty_dummy();
        assert_not_mined(&archive, vec![unknown_input], vec![]).await;
        assert_not_mined(&archive, vec![unknown_input], vec![unknown_output]).await;
        assert_not_mined(&archive, vec![unknown_input], outputs.clone()).await;
        assert_not_mined(&archive, vec![unknown_input, inputs[0]], vec![]).await;
        assert_not_mined(&archive, vec![inputs[0], unknown_input], vec![]).await;
    }

    /// Verify that `get_mutator_set_update_to_tip` returns Some(ms_update), and
    /// that the returned MS update produces the current MSA tip.
    async fn positive_prop_ms_update_to_tip(
        past_msa: &MutatorSetAccumulator,
        archival_state: &mut ArchivalState,
        search_depth: usize,
    ) {
        let tip_msa = archival_state
            .archival_mutator_set
            .ams()
            .accumulator()
            .await;
        let mut new_msa = past_msa.to_owned();
        assert!(archival_state
            .get_mutator_set_update_to_tip(&new_msa, search_depth)
            .await
            .unwrap()
            .apply_to_accumulator(&mut new_msa)
            .is_ok());
        assert_eq!(tip_msa, new_msa);
    }

    mod rusty_utxo_index_tests {
        async fn test_utxo_index(network: Network) -> RustyUtxoIndex {
            let data_dir = crate::tests::shared::files::unit_test_data_directory(network).unwrap();
            RustyUtxoIndex::initialize(&data_dir).await.unwrap()
        }

        fn announcements_length_0_to_3() -> Vec<Announcement> {
            let length0 = Announcement {
                message: bfe_vec![],
            };
            let length1 = Announcement {
                message: bfe_vec![22],
            };
            let length2 = Announcement {
                message: bfe_vec![22, 55],
            };
            let length3 = Announcement {
                message: bfe_vec![22, 878, 668],
            };
            vec![length0, length1, length2, length3]
        }

        use std::collections::HashMap;
        use std::collections::HashSet;

        use macro_rules_attr::apply;
        use neptune_archive::archival_state::rusty_utxo_index::*;
        use neptune_consensus::block::test_helpers::invalid_empty_block_with_announcements;
        use neptune_consensus::block::Block;
        use neptune_consensus::transaction::announcement::Announcement;
        use neptune_mutator_set::addition_record::AdditionRecord;
        use neptune_primitives::block_height::BlockHeight;
        use neptune_primitives::network::Network;
        use neptune_wallet::address::generation_address::GenerationSpendingKey;
        use tasm_lib::prelude::Digest;
        use tasm_lib::triton_vm::prelude::BFieldElement;
        use tasm_lib::twenty_first::bfe_vec;

        use crate::tests::shared::blocks::block_with_num_puts;
        use crate::tests::shared::blocks::make_mock_block_with_inputs_and_outputs;
        use crate::tests::shared_tokio_runtime;

        #[apply(shared_tokio_runtime)]
        async fn index_set_by_block_unit_test() {
            let network = Network::Main;
            let genesis = Block::genesis(network);
            let block1 = block_with_num_puts(network, &genesis, 12, 11).await;
            let block2 = block_with_num_puts(network, &block1, 4, 55).await;

            let mut utxo_index = test_utxo_index(network).await;
            utxo_index.index_block(&block1).await;
            utxo_index.index_block(&block2).await;

            let block1_res = utxo_index.index_set_digests(block1.hash()).await.unwrap();
            assert_eq!(12, block1_res.len(), "index set list must have 12 entries");

            let block2_res = utxo_index.index_set_digests(block2.hash()).await.unwrap();
            assert_eq!(4, block2_res.len(), "index set list must have 4 entries");
        }

        #[apply(shared_tokio_runtime)]
        async fn block_by_addition_record_unit_test() {
            let network = Network::Main;
            let genesis = Block::genesis(network);
            let block1 = block_with_num_puts(network, &genesis, 12, 11).await;
            let block2 = block_with_num_puts(network, &block1, 4, 55).await;
            let blocks = [block1, block2];

            let mut utxo_index = test_utxo_index(network).await;
            for block in &blocks {
                utxo_index.index_block(block).await;
            }

            for block in blocks {
                let expected: HashSet<_> = [block.header().height].into_iter().collect();
                for ar in block.all_addition_records().unwrap() {
                    assert_eq!(expected, utxo_index.blocks_by_addition_record(ar).await);
                }
            }

            let unknown_addition_record = AdditionRecord::new(Digest::default());
            assert!(
                utxo_index
                    .blocks_by_addition_record(unknown_addition_record)
                    .await
                    .is_empty(),
                "Unknown addition record must return empty set"
            );
        }

        #[apply(shared_tokio_runtime)]
        async fn can_handle_repeated_addition_records() {
            let network = Network::Main;
            let genesis = Block::genesis(network);

            let an_addition_record = AdditionRecord::new(Digest::default());

            let inputs = vec![];
            let (block1_one_addition_record, _) = make_mock_block_with_inputs_and_outputs(
                &genesis,
                inputs.clone(),
                vec![an_addition_record],
                None,
                GenerationSpendingKey::derive_from_seed(Digest::default()),
                Digest::default(),
                network,
            )
            .await;
            let (block2_two_repeated_addition_records, _) =
                make_mock_block_with_inputs_and_outputs(
                    &block1_one_addition_record,
                    inputs,
                    vec![an_addition_record, an_addition_record],
                    None,
                    GenerationSpendingKey::derive_from_seed(Digest::default()),
                    Digest::default(),
                    network,
                )
                .await;
            let block3_other_addition_records =
                block_with_num_puts(network, &block2_two_repeated_addition_records, 10, 10).await;

            let blocks = [
                block1_one_addition_record,
                block2_two_repeated_addition_records,
                block3_other_addition_records,
            ];

            let mut utxo_index = test_utxo_index(network).await;
            for block in &blocks {
                utxo_index.index_block(block).await;
            }

            // Block 1 and 2 contain this addition record, block 3 does not
            let expected: HashSet<_> = [BlockHeight::from(1u64), BlockHeight::from(2u64)]
                .into_iter()
                .collect();
            assert_eq!(
                expected,
                utxo_index
                    .blocks_by_addition_record(an_addition_record)
                    .await
            );
        }

        #[apply(shared_tokio_runtime)]
        async fn block_by_index_set_unit_test() {
            let network = Network::Main;
            let genesis = Block::genesis(network);
            let block1 = block_with_num_puts(network, &genesis, 20, 2).await;
            let block2 = block_with_num_puts(network, &block1, 21, 3).await;

            let blocks = [block1, block2];

            let mut utxo_index = test_utxo_index(network).await;
            for block in &blocks {
                for input in &block.body().transaction_kernel().inputs {
                    assert!(
                        utxo_index
                            .block_by_index_set(&input.absolute_indices)
                            .await
                            .is_none(),
                        "Block by index set lookup must return none prior to indexing"
                    );
                }
            }

            for block in &blocks {
                utxo_index.index_block(block).await;
            }

            for block in &blocks {
                for input in &block.body().transaction_kernel().inputs {
                    assert_eq!(
                        block.header().height,
                        utxo_index
                            .block_by_index_set(&input.absolute_indices)
                            .await
                            .unwrap()
                    );
                }
            }
        }

        #[apply(shared_tokio_runtime)]
        async fn block_index_is_idempotent() {
            let network = Network::Main;
            let mut utxo_index = test_utxo_index(network).await;

            let genesis = Block::genesis(network);
            let block1 = block_with_num_puts(network, &genesis, 1, 0).await;
            let announcements = announcements_length_0_to_3();
            let block2 =
                invalid_empty_block_with_announcements(&block1, network, announcements.clone());

            utxo_index.index_block(&block1).await;
            utxo_index.index_block(&block2).await;

            let expected_announcement_flags = utxo_index.announcement_flags(block2.hash()).await;
            let expected_index_set_digests = utxo_index.index_set_digests(block1.hash()).await;
            let expected_blocks_by_flag = utxo_index
                .block_heights_by_announcements(&announcements)
                .await;
            let block2_ars: HashSet<_> = block2
                .body()
                .transaction_kernel()
                .outputs
                .iter()
                .copied()
                .collect();

            let mut expected_blocks_by_addition_records = HashMap::new();
            for ar in &block2_ars {
                expected_blocks_by_addition_records
                    .insert(*ar, utxo_index.blocks_by_addition_record(*ar).await);
            }

            utxo_index.index_block(&block1).await;
            utxo_index.index_block(&block2).await;

            assert_eq!(
                expected_index_set_digests,
                utxo_index.index_set_digests(block1.hash()).await
            );
            assert_eq!(
                expected_announcement_flags,
                utxo_index.announcement_flags(block2.hash()).await
            );
            assert_eq!(
                expected_blocks_by_flag,
                utxo_index
                    .block_heights_by_announcements(&announcements)
                    .await
            );

            let mut read_blocks_by_addition_records = HashMap::new();
            for ar in block2_ars {
                read_blocks_by_addition_records
                    .insert(ar, utxo_index.blocks_by_addition_record(ar).await);
            }
            assert_eq!(
                expected_blocks_by_addition_records,
                read_blocks_by_addition_records
            );

            assert_eq!(block2.hash(), utxo_index.sync_label().await);
        }
    }

    mod import_blocks_tests {}
}
