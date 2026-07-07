#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(super) mod tests {

    use anyhow::Result;
    use itertools::Itertools;
    use macro_rules_attr::apply;
    use neptune_archive::archival_state::ArchivalState;
    use neptune_consensus::block::block_transaction::BlockTransaction;
    use neptune_consensus::block::test_helpers::invalid_block_with_transaction;
    use neptune_consensus::block::Block;
    use neptune_consensus::consensus_rule_set::ConsensusRuleSet;
    use neptune_consensus::proof_abstractions::tasm::program::TritonVmProofJobOptions;
    use neptune_consensus::proof_abstractions::triton_vm_job_queue::TritonVmJobQueue;
    use neptune_consensus::proof_abstractions::tx_proving_capability::TxProvingCapability;
    use neptune_consensus::transaction::lock_script::LockScript;
    use neptune_consensus::transaction::utxo::Utxo;
    use neptune_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
    use neptune_database::storage::storage_vec::traits::*;
    use neptune_mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
    use neptune_primitives::block_height::BlockHeight;
    use neptune_primitives::data_directory::DataDirectory;
    use neptune_primitives::network::Network;
    use neptune_primitives::timestamp::Timestamp;
    use neptune_wallet::address::KeyType;
    use neptune_wallet::expected_utxo::UtxoNotifier;
    use neptune_wallet::mock_block::make_mock_block;
    use neptune_wallet::transaction_output::TxOutput;
    use neptune_wallet::transaction_output::TxOutputList;
    use neptune_wallet::wallet_entropy::WalletEntropy;
    use num_traits::Zero;
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::SeedableRng;
    use tasm_lib::prelude::Digest;
    use tracing_test::traced_test;

    use crate::application::config::cli_args::Args;
    use crate::application::loops::mine_loop::tests::make_coinbase_transaction_from_state_lock;
    use crate::state::transaction::tx_creation_config::TxCreationConfig;
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
        );
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
        let (block1, _) = make_mock_block(&genesis_block, None, alice_key, rng.random(), network);

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
                make_mock_block(&genesis_block, None, alice_key, rng.random(), network);
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

    mod find_canonical_block_with_puts {
        use neptune_consensus::block::test_helpers::invalid_empty_block_with_num_outputs;

        use super::*;

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
    }

    mod block_hash_witness {}

    /// Test of functions that require both UTXO index and other parts of the
    /// archival state
    mod recover {}

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

    mod import_blocks_tests {}
}
