pub mod address;
pub mod change_policy;
pub mod coin_with_possible_timelock;
pub(crate) mod expected_utxo;
pub(crate) mod incoming_utxo;
pub(crate) mod migrate_db;
pub(crate) mod monitored_utxo;
pub(crate) mod rusty_wallet_database;
pub(crate) mod scan_mode_configuration;
pub mod secret_key_material;
pub mod sent_transaction;
pub mod transaction_input;
pub mod transaction_output;
pub(crate) mod unlocked_utxo;
pub mod utxo_notification;
pub(crate) mod wallet_configuration;
pub(crate) mod wallet_db_tables;
pub mod wallet_entropy;
pub mod wallet_file;
pub(crate) mod wallet_state;
pub mod wallet_status;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use expected_utxo::ExpectedUtxo;
    use itertools::Itertools;
    use macro_rules_attr::apply;
    use num_traits::CheckedSub;
    use num_traits::Zero;
    use rand::random;
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::SeedableRng;
    use tasm_lib::prelude::Digest;
    use tasm_lib::prelude::Tip5;
    use tasm_lib::triton_vm::prelude::BFieldElement;
    use tasm_lib::triton_vm::prelude::XFieldElement;
    use tasm_lib::twenty_first::math::x_field_element::EXTENSION_DEGREE;
    use tracing_test::traced_test;
    use unlocked_utxo::UnlockedUtxo;

    use super::monitored_utxo::MonitoredUtxo;
    use super::wallet_state::WalletState;
    use super::*;
    use crate::api::export::Transaction;
    use crate::application::config::cli_args;
    use crate::application::config::network::Network;
    use crate::application::database::storage::storage_vec::traits::*;
    use crate::application::loops::mine_loop::tests::make_coinbase_transaction_from_state;
    use crate::application::triton_vm_job_queue::TritonVmJobPriority;
    use crate::application::triton_vm_job_queue::TritonVmJobQueue;
    use crate::protocol::consensus::block::block_height::BlockHeight;
    use crate::protocol::consensus::block::block_transaction::BlockTransaction;
    use crate::protocol::consensus::block::Block;
    use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
    use crate::protocol::consensus::transaction::lock_script::LockScript;
    use crate::protocol::consensus::transaction::utxo::Utxo;
    use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
    use crate::protocol::proof_abstractions::timestamp::Timestamp;
    use crate::state::transaction::tx_creation_config::TxCreationConfig;
    use crate::state::transaction::tx_proving_capability::TxProvingCapability;
    use crate::state::wallet::expected_utxo::UtxoNotifier;
    use crate::state::wallet::secret_key_material::SecretKeyMaterial;
    use crate::state::wallet::transaction_output::TxOutput;
    use crate::state::wallet::transaction_output::TxOutputList;
    use crate::state::wallet::wallet_entropy::WalletEntropy;
    use crate::state::GlobalStateLock;
    use crate::tests::shared::blocks::invalid_block_with_transaction;
    use crate::tests::shared::blocks::make_mock_block;
    use crate::tests::shared::globalstate::mock_genesis_global_state;
    use crate::tests::shared::mock_genesis_wallet_state;
    use crate::tests::shared::mock_tx::make_mock_block_transaction_with_mutator_set_hash;
    use crate::tests::shared_tokio_runtime;

    async fn get_monitored_utxos(wallet_state: &WalletState) -> Vec<MonitoredUtxo> {
        // note: we could just return a DbtVec here and avoid cloning...
        wallet_state.wallet_db.monitored_utxos().get_all().await
    }

    #[apply(shared_tokio_runtime)]
    async fn wallet_state_constructor_with_genesis_block_test() {
        // This test is designed to verify that the genesis block is applied
        // to the wallet state at initialization. For (practically) all networks.

        let mut rng = rand::rng();
        for network in [
            Network::Main,
            Network::TestnetMock,
            Network::RegTest,
            Network::Testnet(0),
            Network::Testnet(1),
            Network::Testnet(17),
        ] {
            let cli_args = cli_args::Args::default_with_network(network);
            let mut alice =
                mock_genesis_wallet_state(WalletEntropy::devnet_wallet(), &cli_args).await;
            let alice_wallet = get_monitored_utxos(&alice).await;
            assert_eq!(
                1,
                alice_wallet.len(),
                "Monitored UTXO list must contain premined UTXO at init, for premine-wallet"
            );

            let expected_utxo = Block::premine_utxos()[0].clone();
            assert_eq!(
                expected_utxo, alice_wallet[0].utxo,
                "Devnet wallet's monitored UTXO must match that from genesis block at initialization"
            );

            let bob_wallet = WalletEntropy::new_pseudorandom(rng.random());
            let bob_wallet = mock_genesis_wallet_state(bob_wallet, &cli_args).await;
            let bob_mutxos = get_monitored_utxos(&bob_wallet).await;
            assert!(
                bob_mutxos.is_empty(),
                "Monitored UTXO list must be empty at init if wallet is not premine-wallet"
            );

            // Add 12 blocks and verify that membership proofs are still valid
            let genesis_block = Block::genesis(network);
            let mut next_block = genesis_block.clone();
            let charlie_wallet = WalletEntropy::new_pseudorandom(rng.random());
            let charlie_key = charlie_wallet.nth_generation_spending_key_for_tests(0);
            for _ in 0..12 {
                let previous_block = next_block;
                let (nb, _) =
                    make_mock_block(&previous_block, None, charlie_key, rng.random(), network)
                        .await;
                next_block = nb;
                let maintain_mps = true;
                alice
                    .update_wallet_state_with_new_block(
                        &previous_block.mutator_set_accumulator_after().unwrap(),
                        &next_block,
                        maintain_mps,
                    )
                    .await
                    .unwrap();
            }

            let alice_mutxos = get_monitored_utxos(&alice).await;
            assert_eq!(
                1,
                alice_mutxos.len(),
                "monitored UTXOs must be 1 after applying N blocks not mined by wallet"
            );

            let genesis_block_utxo = alice_mutxos[0].utxo.clone();
            let ms_membership_proof = alice_mutxos[0]
                .get_membership_proof_for_block(next_block.hash())
                .unwrap();
            assert!(
                next_block
                    .mutator_set_accumulator_after()
                    .unwrap()
                    .verify(Tip5::hash(&genesis_block_utxo), &ms_membership_proof),
                "Membership proof must be valid after updating wallet state with generated blocks"
            );
        }
    }

    #[apply(shared_tokio_runtime)]
    async fn wallet_state_correctly_updates_monitored_and_expected_utxos() {
        let mut rng = rand::rng();
        let network = Network::RegTest;
        let cli_args = cli_args::Args::default_with_network(network);
        let alice_wallet = WalletEntropy::new_random();
        let mut alice_wallet = mock_genesis_wallet_state(alice_wallet.clone(), &cli_args).await;
        let bob_wallet = WalletEntropy::new_random();
        let bob_key = bob_wallet.nth_generation_spending_key_for_tests(0);

        assert!(
            get_monitored_utxos(&alice_wallet).await.is_empty(),
            "Monitored UTXO list must be empty at init"
        );

        let genesis_block = Block::genesis(network);
        let alice_key = alice_wallet
            .wallet_entropy
            .nth_generation_spending_key_for_tests(0);
        let (block_1, block1_composer_expected) =
            make_mock_block(&genesis_block, None, alice_key, rng.random(), network).await;

        alice_wallet
            .add_expected_utxos(block1_composer_expected.clone())
            .await;
        assert_eq!(
            2,
            alice_wallet.wallet_db.expected_utxos().len().await,
            "Expected UTXO list must have length 2 before block registration"
        );
        let maintain_mps = true;
        alice_wallet
            .update_wallet_state_with_new_block(
                &genesis_block.mutator_set_accumulator_after().unwrap(),
                &block_1,
                maintain_mps,
            )
            .await
            .unwrap();
        assert_eq!(
            2,
            alice_wallet.wallet_db.expected_utxos().len().await,
            "A: Expected UTXO list must still be 2 after receiving tx, due to potential reorganization."
        );

        let alice_expected_utxos = alice_wallet.wallet_db.expected_utxos().get_all().await;

        assert_eq!(2, alice_expected_utxos.len(), "B: Expected UTXO list must have length 2 after block registration, due to potential reorganizations");
        assert_eq!(
            block_1.hash(),
            alice_expected_utxos[0].mined_in_block.unwrap().0,
            "Expected UTXO must be registered as being mined"
        );
        let alice_mutxos_block1 = get_monitored_utxos(&alice_wallet).await;
        assert_eq!(
            2,
            alice_mutxos_block1.len(),
            "Monitored UTXO list be two after we mined a block"
        );

        // Ensure that the membership proofs are valid
        let items_and_msmps_block1 = block1_composer_expected
            .iter()
            .zip(alice_mutxos_block1.iter())
            .map(|(txo, mutxo)| {
                (
                    Tip5::hash(&txo.utxo),
                    mutxo
                        .get_membership_proof_for_block(block_1.hash())
                        .unwrap(),
                )
            });
        assert!(items_and_msmps_block1.clone().all(|(item, msmp)| block_1
            .mutator_set_accumulator_after()
            .unwrap()
            .verify(item, &msmp)));

        // Create new blocks, verify that the membership proofs are *not* valid
        // under this block as tip
        let (block_2, _) = make_mock_block(&block_1, None, bob_key, rng.random(), network).await;
        let (block_3, _) = make_mock_block(&block_2, None, bob_key, rng.random(), network).await;

        // TODO: Is this assertion correct? Do we need to check if an auth path
        // is empty?
        assert!(!items_and_msmps_block1.clone().all(|(item, msmp)| block_3
            .mutator_set_accumulator_after()
            .unwrap()
            .verify(item, &msmp)));

        // Verify that the membership proof is valid *after* running the updater
        alice_wallet
            .update_wallet_state_with_new_block(
                &block_1.mutator_set_accumulator_after().unwrap(),
                &block_2,
                maintain_mps,
            )
            .await
            .unwrap();
        alice_wallet
            .update_wallet_state_with_new_block(
                &block_2.mutator_set_accumulator_after().unwrap(),
                &block_3,
                maintain_mps,
            )
            .await
            .unwrap();

        let alice_mutxos_block3 = get_monitored_utxos(&alice_wallet).await;
        assert_eq!(2, alice_mutxos_block3.len(), "Still only two MUTXOs");

        let items_and_msmps_block3 = block1_composer_expected
            .iter()
            .zip(alice_mutxos_block3.iter())
            .map(|(txo, mutxo)| {
                (
                    Tip5::hash(&txo.utxo),
                    mutxo
                        .get_membership_proof_for_block(block_3.hash())
                        .unwrap(),
                )
            });
        assert!(items_and_msmps_block3.clone().all(|(item, msmp)| block_3
            .mutator_set_accumulator_after()
            .unwrap()
            .verify(item, &msmp)));
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn allocate_sufficient_input_funds_test() {
        // Scenario:
        // Alice is not coinbase recipient. She mines many blocks. It is tested
        // that the method [WalletState::allocate_sufficient_input_funds]
        // returns consistent results.
        // Produces blocks and transactions with invalid proofs, as this is not
        // a test of block validity logic.

        let network = Network::Main;
        let alice_wallet_secret = WalletEntropy::new_random();
        let cli_args = cli_args::Args::default_with_network(network);
        let mut alice = mock_genesis_global_state(1, alice_wallet_secret, cli_args).await;
        let alice_key = alice
            .lock_guard()
            .await
            .wallet_state
            .wallet_entropy
            .nth_generation_spending_key_for_tests(0);
        let genesis_block = Block::genesis(network);

        let mut rng = rand::rng();
        let (block_1, expected_utxos) =
            make_mock_block(&genesis_block, None, alice_key, rng.random(), network).await;
        let liquid_expected_utxo = &expected_utxos[0];
        assert!(
            liquid_expected_utxo.utxo.release_date().is_none(),
            "1st expected composer UTXO should not be timelocked"
        );
        assert!(
            expected_utxos[1].utxo.release_date().is_some(),
            "2nd expected composer UTXO should be timelocked"
        );
        let liquid_mining_reward = liquid_expected_utxo.utxo.get_native_currency_amount();
        let now = genesis_block.header().timestamp + Timestamp::months(10);

        let allocate_input_utxos = |alice_: GlobalStateLock, amount: NativeCurrencyAmount| async move {
            let (tip_digest, ms_acc) = alice_
                .lock(|alice_global_state| {
                    (
                        alice_global_state.chain.light_state().hash(),
                        alice_global_state
                            .chain
                            .light_state()
                            .mutator_set_accumulator_after()
                            .unwrap(),
                    )
                })
                .await;
            alice_
                .lock_guard()
                .await
                .wallet_state
                .allocate_sufficient_input_funds(amount, tip_digest, &ms_acc, now)
                .await
        };
        let num_utxos_in_allocation = |alice_: GlobalStateLock, amount: NativeCurrencyAmount| async move {
            allocate_input_utxos(alice_, amount).await.map(|x| x.len())
        };

        assert!(
            num_utxos_in_allocation(alice.clone(), NativeCurrencyAmount::coins(1),)
                .await
                .is_err(),
            "Cannot allocate anything when wallet is empty"
        );

        // Add block 1 to wallet state
        {
            let mut alice_mut = alice.lock_guard_mut().await;
            alice_mut
                .wallet_state
                .add_expected_utxos(expected_utxos)
                .await;
            alice_mut.set_new_tip(block_1.clone()).await.unwrap();
        }

        // Verify that the allocater returns a sane amount
        let one_coin = NativeCurrencyAmount::coins(1);
        assert_eq!(
            1,
            num_utxos_in_allocation(alice.clone(), one_coin)
                .await
                .unwrap(),
        );
        assert_eq!(
            1,
            num_utxos_in_allocation(
                alice.clone(),
                liquid_mining_reward.checked_sub(&one_coin).unwrap(),
            )
            .await
            .unwrap(),
        );
        assert_eq!(
            1,
            num_utxos_in_allocation(alice.clone(), liquid_mining_reward)
                .await
                .unwrap()
        );
        assert!(
            num_utxos_in_allocation(alice.clone(), liquid_mining_reward + one_coin)
                .await
                .is_err()
        );

        // Mine 21 more blocks and verify that 22 * `liquid_mining_reward` worth
        // of UTXOs can be allocated.
        let mut next_block = block_1.clone();
        {
            let mut alice = alice.lock_guard_mut().await;
            for _ in 0..21 {
                let previous_block = next_block;
                let (next_block_prime, expected) =
                    make_mock_block(&previous_block, None, alice_key, rng.random(), network).await;
                alice.wallet_state.add_expected_utxos(expected).await;
                alice.set_new_tip(next_block_prime.clone()).await.unwrap();
                next_block = next_block_prime;
            }
        }

        assert_eq!(
            5,
            num_utxos_in_allocation(alice.clone(), liquid_mining_reward.scalar_mul(5))
                .await
                .unwrap()
        );
        assert_eq!(
            6,
            num_utxos_in_allocation(alice.clone(), liquid_mining_reward.scalar_mul(5) + one_coin)
                .await
                .unwrap()
        );

        let expected_balance = liquid_mining_reward.scalar_mul(22);
        assert_eq!(
            22,
            num_utxos_in_allocation(alice.clone(), expected_balance)
                .await
                .unwrap()
        );

        // Cannot allocate more than we have: 22 * liquid mining reward
        assert!(
            num_utxos_in_allocation(alice.clone(), expected_balance + one_coin)
                .await
                .is_err()
        );

        // Make a block that spends an input, then verify that this is reflected by
        // the allocator.
        let tx_inputs_two_utxos = alice
            .lock_guard()
            .await
            .wallet_state
            .allocate_sufficient_input_funds(
                liquid_mining_reward.scalar_mul(2),
                next_block.hash(),
                &next_block.mutator_set_accumulator_after().unwrap(),
                now,
            )
            .await
            .unwrap();
        assert_eq!(
            2,
            tx_inputs_two_utxos.len(),
            "Must use two UTXOs when sending 2 x liquid mining reward"
        );

        // This block throws away four UTXOs.
        let msa_tip_previous = next_block.mutator_set_accumulator_after().unwrap().clone();
        let output_utxo = Utxo::new_native_currency(
            LockScript::anyone_can_spend().hash(),
            NativeCurrencyAmount::coins(200),
        );
        let tx_outputs: TxOutputList = vec![TxOutput::no_notification(
            output_utxo,
            random(),
            random(),
            false,
        )]
        .into();

        let removal_records = tx_inputs_two_utxos
            .iter()
            .map(|txi| txi.removal_record(&msa_tip_previous))
            .collect_vec();
        let addition_records = tx_outputs.addition_records();
        let tx = make_mock_block_transaction_with_mutator_set_hash(
            removal_records,
            addition_records,
            next_block.mutator_set_accumulator_after().unwrap().hash(),
        );

        let next_block =
            Block::block_template_invalid_proof(&next_block.clone(), tx, now, None, network);
        let final_block_height = Into::<BlockHeight>::into(23u64);
        assert_eq!(final_block_height, next_block.kernel.header.height);

        alice.set_new_tip(next_block.clone()).await.unwrap();

        // can make allocation of coins for entire liquid balance.
        let alice_balance = {
            let ags = alice.lock_guard().await;
            let wallet_status = ags
                .wallet_state
                .get_wallet_status(
                    next_block.hash(),
                    &next_block.mutator_set_accumulator_after().unwrap(),
                )
                .await;
            wallet_status.available_confirmed(next_block.header().timestamp)
        };
        assert!(
            alice_balance
                >= allocate_input_utxos(
                    alice.clone(),
                    alice_balance
                        .checked_sub(&NativeCurrencyAmount::coins(1))
                        .unwrap()
                )
                .await
                .unwrap()
                .into_iter()
                .map(|unlocked_utxo: UnlockedUtxo| unlocked_utxo.utxo.get_native_currency_amount())
                .sum::<NativeCurrencyAmount>()
        );

        // Cannot allocate more than we have liquid.
        assert!(allocate_input_utxos(
            alice.clone(),
            alice_balance + NativeCurrencyAmount::coins(1)
        )
        .await
        .is_err());
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn wallet_state_maintenence_multiple_inputs_outputs_enough_mps_test() {
        // Bob is premine receiver, Alice is not. They send coins back and forth
        // and the blockchain forks. The fork is shallower than the number of
        // membership proofs per MUTXO, so the fork can be tolerated without any
        // issues.

        let network = Network::Main;
        let cli_args = cli_args::Args {
            guesser_fraction: 0.0,
            number_of_mps_per_utxo: 20,
            network,
            ..Default::default()
        };
        let mut rng: StdRng = StdRng::seed_from_u64(456416);
        let alice_wallet_secret = WalletEntropy::new_pseudorandom(rng.random());
        let mut alice = mock_genesis_global_state(2, alice_wallet_secret, cli_args.clone()).await;
        let alice_key = alice
            .lock_guard()
            .await
            .wallet_state
            .wallet_entropy
            .nth_generation_spending_key_for_tests(0);
        let alice_address = alice_key.to_address();
        let genesis_block = Block::genesis(network);
        let bob_wallet = mock_genesis_wallet_state(WalletEntropy::devnet_wallet(), &cli_args)
            .await
            .wallet_entropy;
        let mut bob_global_lock =
            mock_genesis_global_state(2, bob_wallet.clone(), cli_args.clone()).await;
        let mut tx_initiator_internal = bob_global_lock.api().tx_initiator_internal();
        let in_seven_months = genesis_block.kernel.header.timestamp + Timestamp::months(7);

        let bobs_original_balance = bob_global_lock
            .lock_guard()
            .await
            .get_wallet_status_for_tip()
            .await
            .available_confirmed(in_seven_months);
        assert!(
            !bobs_original_balance.is_zero(),
            "Premine must have non-zero synced balance"
        );

        let bob_sender_randomness = bob_global_lock
            .lock_guard()
            .await
            .wallet_state
            .wallet_entropy
            .generate_sender_randomness(
                genesis_block.kernel.header.height,
                alice_address.receiver_postimage(),
            );

        let receiver_data_12_to_alice = TxOutput::offchain_native_currency(
            NativeCurrencyAmount::coins(12),
            bob_sender_randomness,
            alice_address.into(),
            false,
        );
        let receiver_data_1_to_alice = TxOutput::offchain_native_currency(
            NativeCurrencyAmount::coins(1),
            bob_sender_randomness,
            alice_address.into(),
            false,
        );

        let receiver_data_to_alice: TxOutputList =
            vec![receiver_data_12_to_alice, receiver_data_1_to_alice].into();
        let bob_change_key = bob_wallet.nth_generation_spending_key_for_tests(0).into();
        let config_1 = TxCreationConfig::default()
            .recover_change_on_chain(bob_change_key)
            .with_prover_capability(TxProvingCapability::SingleProof);
        let block_height = BlockHeight::genesis();
        let consensus_rule_set = ConsensusRuleSet::infer_from(network, block_height);
        let tx_1 = tx_initiator_internal
            .create_transaction(
                receiver_data_to_alice.clone(),
                NativeCurrencyAmount::coins(2),
                in_seven_months,
                config_1,
                consensus_rule_set,
            )
            .await
            .unwrap()
            .transaction;

        let block_1 = invalid_block_with_transaction(&genesis_block, tx_1.into());

        // Update wallet state with block_1
        assert!(
            get_monitored_utxos(&alice.lock_guard().await.wallet_state)
                .await
                .is_empty(),
            "List of monitored UTXOs must be empty prior to updating wallet state"
        );

        // Notification for Bob's change happens on-chain. No need to ask
        // wallet to expect change UTXO.
        bob_global_lock.set_new_tip(block_1.clone()).await.unwrap();

        assert_eq!(
            bobs_original_balance
                .checked_sub(&NativeCurrencyAmount::coins(15))
                .unwrap(),
            bob_global_lock
                .lock_guard()
                .await
                .get_wallet_status_for_tip()
                .await
                .available_confirmed(in_seven_months),
            "Preminer must have spent 15: 12 + 1 for sent, 2 for fees"
        );

        let expected_utxos_alice = alice
            .lock_guard()
            .await
            .wallet_state
            .extract_expected_utxos(receiver_data_to_alice.iter(), UtxoNotifier::Cli);
        alice
            .lock_guard_mut()
            .await
            .wallet_state
            .add_expected_utxos(expected_utxos_alice)
            .await;
        alice.set_new_tip(block_1.clone()).await.unwrap();

        // Verify that update added 2 UTXOs to list of monitored transactions,
        // from Bob's tx.
        let mut alice_monitored_utxos =
            get_monitored_utxos(&alice.lock_guard().await.wallet_state).await;
        assert_eq!(
            2,
            alice_monitored_utxos.len(),
            "List of monitored UTXOs have length 2 after updating wallet state"
        );

        // Verify that all monitored UTXOs have valid membership proofs
        for monitored_utxo in alice_monitored_utxos {
            assert!(
                block_1.mutator_set_accumulator_after().unwrap().verify(
                    Tip5::hash(&monitored_utxo.utxo),
                    &monitored_utxo
                        .get_membership_proof_for_block(block_1.hash())
                        .unwrap()
                ),
                "All membership proofs must be valid after block 1"
            )
        }

        // Alice mines
        let num_blocks_mined_by_alice = 4;
        // verify that all membership proofs are still valid
        let mut next_block = block_1.clone();
        for i in 0..num_blocks_mined_by_alice {
            let previous_block = next_block;
            let (block, expected) = make_mock_block(
                &previous_block,
                Some(in_seven_months + network.minimum_block_time() * i),
                alice_key,
                rng.random(),
                network,
            )
            .await;
            next_block = block;
            alice
                .lock_guard_mut()
                .await
                .wallet_state
                .add_expected_utxos(expected)
                .await;
            alice.set_new_tip(next_block.clone()).await.unwrap();
            bob_global_lock
                .set_new_tip(next_block.clone())
                .await
                .unwrap();
        }

        let first_block_after_spree = next_block;
        alice_monitored_utxos = get_monitored_utxos(&alice.lock_guard().await.wallet_state).await;
        let expected_num_expected_mutxos_alice = 2 + 2 * num_blocks_mined_by_alice;
        assert_eq!(
            expected_num_expected_mutxos_alice,
            alice_monitored_utxos.len(),
            "List of monitored UTXOs must be two-per-block mined plus two"
        );
        for monitored_utxo in alice_monitored_utxos {
            assert!(
                first_block_after_spree
                    .mutator_set_accumulator_after()
                    .unwrap()
                    .verify(
                        Tip5::hash(&monitored_utxo.utxo),
                        &monitored_utxo
                            .get_membership_proof_for_block(first_block_after_spree.hash())
                            .unwrap()
                    ),
                "All membership proofs must be valid after this block"
            )
        }

        // Sanity check
        assert_eq!(
            Into::<BlockHeight>::into(1u64 + u64::try_from(num_blocks_mined_by_alice).unwrap()),
            first_block_after_spree.kernel.header.height,
            "Block height must be {} after genesis and {} blocks being mined in Alice's spree",
            num_blocks_mined_by_alice + 1,
            num_blocks_mined_by_alice
        );

        // Check that `WalletStatus` is returned correctly
        let alice_wallet_status = alice
            .lock_guard()
            .await
            .wallet_state
            .get_wallet_status(
                first_block_after_spree.hash(),
                &first_block_after_spree
                    .mutator_set_accumulator_after()
                    .unwrap(),
            )
            .await;
        assert_eq!(
            expected_num_expected_mutxos_alice,
            alice_wallet_status.synced_unspent.len(),
            "Wallet must have {expected_num_expected_mutxos_alice} synced, unspent UTXOs",
        );
        assert!(
            alice_wallet_status.synced_spent.is_empty(),
            "Wallet must have 0 synced, spent UTXOs"
        );
        assert!(
            alice_wallet_status.unsynced.is_empty(),
            "Wallet must have 0 unsynced UTXOs"
        );

        // Bob mines a block, ignoring Alice's spree and forking instead
        let bob_key = bob_global_lock
            .lock_guard()
            .await
            .wallet_state
            .wallet_entropy
            .nth_generation_spending_key_for_tests(0);
        let (block_2_b, _) = make_mock_block(&block_1, None, bob_key, rng.random(), network).await;
        alice.set_new_tip(block_2_b.clone()).await.unwrap();
        bob_global_lock
            .set_new_tip(block_2_b.clone())
            .await
            .unwrap();
        let alice_monitored_utxos_at_2b: Vec<_> =
            get_monitored_utxos(&alice.lock_guard().await.wallet_state)
                .await
                .into_iter()
                .filter(|x| x.is_synced_to(block_2_b.hash()))
                .collect();
        assert_eq!(
            2,
            alice_monitored_utxos_at_2b.len(),
            "List of synced monitored UTXOs have length 2 after updating wallet state"
        );

        // Verify that all monitored UTXOs (with synced MPs) have valid membership proofs
        for monitored_utxo in &alice_monitored_utxos_at_2b {
            assert!(
                block_2_b.mutator_set_accumulator_after().unwrap().verify(
                    Tip5::hash(&monitored_utxo.utxo),
                    &monitored_utxo
                        .get_membership_proof_for_block(block_2_b.hash())
                        .unwrap()
                ),
                "All synced membership proofs must be valid after block 2b fork"
            )
        }

        // Fork back again to the long chain and verify that the membership proofs
        // all work again
        let (first_block_continuing_spree, _) = make_mock_block(
            &first_block_after_spree,
            None,
            bob_key,
            rng.random(),
            network,
        )
        .await;
        let maintain_mps = true;
        alice
            .lock_guard_mut()
            .await
            .wallet_state
            .update_wallet_state_with_new_block(
                &first_block_after_spree
                    .mutator_set_accumulator_after()
                    .unwrap(),
                &first_block_continuing_spree,
                maintain_mps,
            )
            .await
            .unwrap();
        let alice_monitored_utxos_after_continued_spree: Vec<_> =
            get_monitored_utxos(&alice.lock_guard().await.wallet_state)
                .await
                .into_iter()
                .filter(|monitored_utxo| {
                    monitored_utxo.is_synced_to(first_block_continuing_spree.hash())
                })
                .collect();
        assert_eq!(
            expected_num_expected_mutxos_alice,
            alice_monitored_utxos_after_continued_spree.len(),
            "List of monitored UTXOs have length {expected_num_expected_mutxos_alice} after returning to good fork",
        );

        // Verify that all monitored UTXOs have valid membership proofs
        for monitored_utxo in &alice_monitored_utxos_after_continued_spree {
            assert!(
                first_block_continuing_spree
                    .mutator_set_accumulator_after()
                    .unwrap()
                    .verify(
                        Tip5::hash(&monitored_utxo.utxo),
                        &monitored_utxo
                            .get_membership_proof_for_block(first_block_continuing_spree.hash())
                            .unwrap()
                    ),
                "All membership proofs must be valid after first block  of continued"
            );
        }

        // Fork back to the B-chain with `block_3b` which contains three outputs
        // for Alice, two composer UTXOs and one other UTXO.
        let receiver_data_1_to_alice_new = TxOutput::offchain_native_currency(
            NativeCurrencyAmount::coins(1),
            rng.random(),
            alice_address.into(),
            false,
        );

        let config_2b = TxCreationConfig::default()
            .recover_change_off_chain(bob_change_key)
            .with_prover_capability(TxProvingCapability::SingleProof);

        let block_height_2_b = block_2_b.header().height;
        let consensus_rule_set_2_b = ConsensusRuleSet::infer_from(network, block_height_2_b);
        let tx_from_bob: Transaction = tx_initiator_internal
            .create_transaction(
                vec![receiver_data_1_to_alice_new.clone()].into(),
                NativeCurrencyAmount::coins(4),
                block_2_b.header().timestamp + network.minimum_block_time(),
                config_2b,
                consensus_rule_set_2_b,
            )
            .await
            .unwrap()
            .transaction
            .into();

        let (coinbase_tx, expected_composer_utxos) = make_coinbase_transaction_from_state(
            &alice
                .global_state_lock
                .lock_guard()
                .await
                .chain
                .light_state()
                .clone(),
            &alice,
            block_2_b.header().timestamp + network.minimum_block_time(),
            TritonVmJobPriority::Normal.into(),
        )
        .await
        .unwrap();
        let merged_tx = BlockTransaction::merge(
            coinbase_tx.into(),
            tx_from_bob,
            Default::default(),
            TritonVmJobQueue::get_instance(),
            TritonVmJobPriority::default().into(),
            consensus_rule_set_2_b,
        )
        .await
        .unwrap();
        let timestamp = merged_tx.kernel.timestamp;
        let block_3_b = Block::compose(
            &block_2_b,
            merged_tx,
            timestamp,
            TritonVmJobQueue::get_instance(),
            TritonVmJobPriority::default().into(),
        )
        .await
        .unwrap();
        assert!(
            block_3_b.is_valid(&block_2_b, timestamp, network).await,
            "Block must be valid after accumulating txs"
        );
        let expected_utxos_for_alice_cb = expected_composer_utxos
            .into_iter()
            .map(|expected_utxo| {
                ExpectedUtxo::new(
                    expected_utxo.utxo,
                    expected_utxo.sender_randomness,
                    alice_key.receiver_preimage(),
                    UtxoNotifier::OwnMinerComposeBlock,
                )
            })
            .collect_vec();

        alice
            .lock_guard_mut()
            .await
            .wallet_state
            .add_expected_utxos(expected_utxos_for_alice_cb)
            .await;
        let expected_utxo_for_alice = ExpectedUtxo::new(
            receiver_data_1_to_alice_new.utxo(),
            receiver_data_1_to_alice_new.sender_randomness(),
            alice_key.receiver_preimage(),
            UtxoNotifier::Cli,
        );
        alice
            .lock_guard_mut()
            .await
            .wallet_state
            .add_expected_utxo(expected_utxo_for_alice)
            .await;
        alice
            .lock_guard_mut()
            .await
            .wallet_state
            .update_wallet_state_with_new_block(
                &block_2_b.mutator_set_accumulator_after().unwrap(),
                &block_3_b,
                maintain_mps,
            )
            .await
            .unwrap();

        let alice_monitored_utxos_3b: Vec<_> =
            get_monitored_utxos(&alice.lock_guard().await.wallet_state)
                .await
                .into_iter()
                .filter(|x| x.is_synced_to(block_3_b.hash()))
                .collect();
        assert_eq!(
            5,
            alice_monitored_utxos_3b.len(),
            "List of monitored and unspent UTXOs have length 5 after receiving two"
        );
        assert_eq!(
            0,
            alice_monitored_utxos_3b
                .iter()
                .filter(|x| x.spent_in_block.is_some())
                .count(),
            "Zero monitored UTXO must be marked as spent"
        );

        // Verify that all unspent monitored UTXOs have valid membership proofs
        for monitored_utxo in alice_monitored_utxos_3b {
            assert!(
                monitored_utxo.spent_in_block.is_some()
                    || block_3_b.mutator_set_accumulator_after().unwrap().verify(
                        Tip5::hash(&monitored_utxo.utxo),
                        &monitored_utxo
                            .get_membership_proof_for_block(block_3_b.hash())
                            .unwrap()
                    ),
                "All membership proofs of unspent UTXOs must be valid after block 3b"
            )
        }

        // Then fork back to A-chain
        let (second_block_continuing_spree, _) = make_mock_block(
            &first_block_continuing_spree,
            None,
            bob_key,
            rng.random(),
            network,
        )
        .await;
        alice
            .lock_guard_mut()
            .await
            .wallet_state
            .update_wallet_state_with_new_block(
                &first_block_continuing_spree
                    .mutator_set_accumulator_after()
                    .unwrap(),
                &second_block_continuing_spree,
                maintain_mps,
            )
            .await
            .unwrap();

        // Verify that we have two membership proofs of `forked_utxo`: one
        // matching abandoned block and one matching block_3b.
        let alice_monitored_utxos_after_second_block_after_spree: Vec<_> =
            get_monitored_utxos(&alice.lock_guard().await.wallet_state)
                .await
                .into_iter()
                .filter(|x| x.is_synced_to(second_block_continuing_spree.hash()))
                .collect();
        assert_eq!(
            expected_num_expected_mutxos_alice,
            alice_monitored_utxos_after_second_block_after_spree.len(),
            "List of monitored UTXOs must be as expected after returning to bad fork"
        );
        for monitored_utxo in &alice_monitored_utxos_after_second_block_after_spree {
            assert!(
                monitored_utxo.spent_in_block.is_some()
                    || second_block_continuing_spree
                        .mutator_set_accumulator_after()
                        .unwrap()
                        .verify(
                            Tip5::hash(&monitored_utxo.utxo),
                            &monitored_utxo
                                .get_membership_proof_for_block(
                                    second_block_continuing_spree.hash()
                                )
                                .unwrap()
                        ),
                "All membership proofs of unspent UTXOs must be valid after block on longest chain"
            )
        }
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn allow_consumption_of_genesis_output_test() {
        let network = Network::Main;
        let genesis_block = Block::genesis(network);
        let in_seven_months = genesis_block.kernel.header.timestamp + Timestamp::months(7);
        let bob = mock_genesis_global_state(
            42,
            WalletEntropy::devnet_wallet(),
            cli_args::Args {
                guesser_fraction: 0.0,
                network,
                ..Default::default()
            },
        )
        .await;

        let mut rng = StdRng::seed_from_u64(87255549301u64);

        let (cbtx, _cb_expected) = make_coinbase_transaction_from_state(
            &bob.global_state_lock
                .lock_guard()
                .await
                .chain
                .light_state()
                .clone(),
            &bob,
            in_seven_months,
            TritonVmJobPriority::Normal.into(),
        )
        .await
        .unwrap();
        let one_money: NativeCurrencyAmount = NativeCurrencyAmount::coins(1);
        let anyone_can_spend_utxo =
            Utxo::new_native_currency(LockScript::anyone_can_spend().hash(), one_money);
        let tx_output =
            TxOutput::no_notification(anyone_can_spend_utxo, rng.random(), rng.random(), false);
        let change_key = WalletEntropy::devnet_wallet().nth_symmetric_key_for_tests(0);
        let config = TxCreationConfig::default()
            .recover_change_off_chain(change_key.into())
            .with_prover_capability(TxProvingCapability::SingleProof);
        let block_height = BlockHeight::genesis();
        let consensus_rule_set = ConsensusRuleSet::infer_from(network, block_height);
        let sender_tx: Transaction = bob
            .api()
            .tx_initiator_internal()
            .create_transaction(
                vec![tx_output].into(),
                one_money,
                in_seven_months,
                config,
                consensus_rule_set,
            )
            .await
            .unwrap()
            .transaction
            .into();
        let tx_for_block = BlockTransaction::merge(
            cbtx.into(),
            sender_tx,
            Default::default(),
            TritonVmJobQueue::get_instance(),
            TritonVmJobPriority::default().into(),
            consensus_rule_set,
        )
        .await
        .unwrap();
        let block_1 = Block::compose(
            &genesis_block,
            tx_for_block,
            in_seven_months,
            TritonVmJobQueue::get_instance(),
            TritonVmJobPriority::default().into(),
        )
        .await
        .unwrap();

        // The entire block must be valid, i.e., have a valid block proof, and
        // be valid in other respects. We don't care about PoW, though.
        assert!(
            block_1
                .is_valid(&genesis_block, in_seven_months, network)
                .await
        );

        // 4 outputs: 2 coinbases, 1 for recipient of tx, 1 for change.
        assert_eq!(4, block_1.body().transaction_kernel.outputs.len());
    }

    #[apply(shared_tokio_runtime)]
    async fn basic_wallet_secret_functionality_test() {
        let random_wallet_secret = WalletEntropy::new_random();
        let spending_key = random_wallet_secret.nth_generation_spending_key_for_tests(0);
        let _address = spending_key.to_address();
        let _sender_randomness = random_wallet_secret
            .generate_sender_randomness(BFieldElement::new(10).into(), random());
    }

    proptest::proptest! {
        #[test]
        fn master_seed_is_not_sender_randomness(
            secret in proptest_arbitrary_interop::arb::<XFieldElement>()
        ) {
            let secret_as_digest = Digest::new(
                [
                    secret.coefficients.to_vec(),
                    vec![BFieldElement::new(0); Digest::LEN - EXTENSION_DEGREE],
                ]
                .concat()
                .try_into()
                .unwrap(),
            );
            let wallet = WalletEntropy::new(SecretKeyMaterial(secret));
            assert_ne!(
                wallet.generate_sender_randomness(BlockHeight::genesis(), random()),
                secret_as_digest
            );
        }
    }

    #[test]
    fn get_devnet_wallet_info() {
        // Helper function/test to print the public key associated with the authority signatures
        let devnet_wallet = WalletEntropy::devnet_wallet();
        let spending_key = devnet_wallet.nth_generation_spending_key_for_tests(0);
        let address = spending_key.to_address();
        println!(
            "_authority_wallet address: {}",
            address.to_bech32m(Network::Main).unwrap()
        );
        println!(
            "_authority_wallet spending_lock: {}",
            address.spending_lock()
        );
    }

    mod generation_key_derivation {
        use itertools::Itertools;

        use super::*;

        // This test derives a set of generation keys and compares the derived
        // set against a "known-good" hard-coded set that were generated from
        // the alphanet branch.
        //
        // The test will fail if the key format or derivation method ever changes.
        #[test]
        fn verify_derived_generation_keys() {
            let devnet_wallet = WalletEntropy::devnet_wallet();
            let indexes = worker::known_key_indexes();
            let known_keys = worker::known_keys();

            // verify indexes match
            assert_eq!(
                indexes.to_vec(),
                known_keys.iter().map(|(i, _)| *i).collect_vec()
            );

            for (index, key) in known_keys {
                assert_eq!(devnet_wallet.nth_generation_spending_key(index), key);
            }
        }

        // This test derives a set of generation addresses and compares the derived
        // set against a "known-good" hard-coded set that were generated from
        // the alphanet branch.
        //
        // Both sets use the bech32m encoding for Network::Main.
        //
        // The test will fail if the address format or derivation method ever changes.
        #[test]
        fn verify_derived_generation_addrs() {
            let network = Network::Main;
            let devnet_wallet = WalletEntropy::devnet_wallet();
            let indexes = worker::known_key_indexes();
            let known_addrs = worker::known_addrs();

            // verify indexes match
            assert_eq!(
                indexes.to_vec(),
                known_addrs.iter().map(|(i, _)| *i).collect_vec()
            );

            for (index, known_addr) in known_addrs {
                println!("index: {}", index);
                let derived_addr = devnet_wallet
                    .nth_generation_spending_key(index)
                    .to_address()
                    .to_bech32m(network)
                    .unwrap();

                assert_eq!(derived_addr, known_addr);
            }
        }

        // this is not really a test.  It just prints out json-serialized
        // spending keys.  The resulting serialized string is embedded in
        // json_serialized_known_keys.
        //
        // The test verify_derived_generation_keys() derives keys and compares
        // against the hard-coded keys.  Thus the test can detect if
        // key format or derivation ever changes.
        //
        // This fn is left here to:
        //  1. document how the hard-coded keys were generated
        //  2. in case we ever need to generate them again.
        #[test]
        fn print_json_serialized_generation_spending_keys() {
            let devnet_wallet = WalletEntropy::devnet_wallet();
            let indexes = worker::known_key_indexes();

            let addrs = indexes
                .into_iter()
                .map(|i| (i, devnet_wallet.nth_generation_spending_key(i)))
                .collect_vec();

            println!("{}", serde_json::to_string(&addrs).unwrap());
        }

        // this is not really a test.  It just prints out json-serialized
        // string containing pairs of (derivation_index, address) where
        // the address is bech32m-encoded for Network::Main.
        //
        // The resulting serialized string is embedded in
        // fn json_serialized_known_addrs().
        //
        // The test verify_derived_generation_addrs() derives addresses and compares
        // against the hard-coded addresses.  Thus the test can detect if
        // key format or encoding or derivation ever changes.
        //
        // This fn is left here to:
        //  1. document how the hard-coded addrs were generated
        //  2. in case we ever need to generate them again.
        #[test]
        fn print_json_serialized_generation_receiving_addrs() {
            let network = Network::Main;
            let devnet_wallet = WalletEntropy::devnet_wallet();
            let indexes = worker::known_key_indexes();

            let addrs = indexes
                .into_iter()
                .map(|i| {
                    (
                        i,
                        devnet_wallet
                            .nth_generation_spending_key(i)
                            .to_address()
                            .to_bech32m(network)
                            .unwrap(),
                    )
                })
                .collect_vec();

            println!("{}", serde_json::to_string(&addrs).unwrap());
        }

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn verify_premine_receipt_works_with_test_addresses() {
            let network = Network::Main;
            let cli = cli_args::Args::default_with_network(network);
            let genesis_block = Block::genesis(network);
            let seven_months_after_launch = genesis_block.header().timestamp + Timestamp::months(7);
            for seed_phrase in worker::test_seed_phrases() {
                let wallet_secret = WalletEntropy::from_phrase(&seed_phrase)
                    .expect("legacy seed phrase must still be valid");
                let premine_recipient =
                    mock_genesis_global_state(0, wallet_secret, cli.clone()).await;
                let gs = premine_recipient.global_state_lock.lock_guard().await;
                let wallet_status = gs
                    .wallet_state
                    .get_wallet_status(
                        genesis_block.hash(),
                        &genesis_block.mutator_set_accumulator_after().unwrap(),
                    )
                    .await;

                assert_eq!(
                    NativeCurrencyAmount::coins(1),
                    wallet_status.available_confirmed(seven_months_after_launch)
                );
            }
        }

        mod worker {
            use crate::state::wallet::address::generation_address;

            // provides the set of indexes to derive keys at
            pub fn known_key_indexes() -> [u64; 13] {
                [
                    0,
                    1,
                    2,
                    3,
                    8,
                    16,
                    256,
                    512,
                    1024,
                    2048,
                    4096,
                    u64::from(u16::MAX / 2),
                    u64::from(u16::MAX),
                ]
            }

            // returns a vec of hard-coded bech32m addrs that were generated from alphanet branch,
            // note: Network::Main
            pub fn known_addrs() -> Vec<(u64, String)> {
                serde_json::from_str(json_serialized_known_addrs()).unwrap()
            }

            // returns a json-serialized string of generation bech32m-encoded addrs generated from alphanet-v5 tag.
            // note: Network::Main
            pub fn json_serialized_known_addrs() -> &'static str {
                r#"
[[0,"nolgam16n494axmrtxsxhftn2sgvn4uggt6tag8skztcfc8a2yrrn5l69n8gk5f8eenhf0pelr0rt5wxk82z46juq9ndpzx4377hv2ngns06x5hcchvtmr8wxtpvvykujq6tszt2w4mhdwmssknyfpjx59f6ywyz9crc2s4md0dksv0ayklk5rx3duz7p2gjtmtlc3sgz07urxljtf77a9yrwn6qy300f2e36z6humz3rehvphpaddj7vd02ucuktw9ux476njx9hn3sv92ay6up50ef4n3zh2a6jvdfcgsp6ed5k2q8e4lfpmc3p9uyrej7scarvkefe6e2muup8tyn5a4fvfsy48e3rcpxncfkz9wk0j5wss98rv3zq50uddhafh77z93ulleysdm839emh8v69y053v4hvpffr3s5x3lxmshkrq0087lyppqaj5xn52fhu6tkjxg2cvlxuarh85c58vnyatuaytcnshux4tk2qwgmu8kk0s6u34xv643aq59yrsnsvu5wskzvkwzjjrhlzjnhs5z5xg8fyvanv5806cpzjea277950vpt2npf9qr7qd96rttst05fdcxk5j0ut4c7qfpa03tq5rrk6n94m0fzu2km9hc4lez47e0v9yeu0xt6jkpjsvwcrwu0gxnuq4j2qjmcnkvafsuteyayhqvtwm3ypqyknr6zx7zcusp9h29970073wzwywp8gx0t3yh4usw23gvlhauctsfye8g3n4tvfg2xuhgrfr86q5z9u9kkec39krmyvzpewah3c36em0zskkns49jl9q4zynj8rymgaethxsrmjmakj0epe42xctu744ktwp9ms7xh2gumzexfhmgkqpypusx5sv7ag03pstlhqpp3s8vptaeqt4p57ejjlxl3v2zqdvsnvvcjv5twrcgv8s5a5hp27v8vqltxmfz9hd5m2l7yf9ux9d6rehz26gz0fuymnmcpru3500y689wq6k45xacwzhvlxwh0gk84090yxmeng8vwjvs35xkhnew7dn5zxky8g63kyfwhnz2m6vjwl655gwv9wgxynjsyga2h98hqz63eej8lpn6g3u4tar4j4d9ul2es2s28sdg9p0d4mawt7gryc69mvzadteyzxadg5h44vcm94gmynn9860fqxp2wgcwrm9df5vy32ylekjdvgmlxq63x2r3su50d25r3w90cl34pmmexhdeqj7g3kqphagvf5yff92am8f83s49c6y5mc972frs4qmmjew4f260e0tpsruqyxcyqm07kn6jmc7ptkfk0ky3hd3cv8xrjarrru69zqyxstn8d4lzjf2qsuvlktmqu037dfvmws8ejksrp66dqvezyndfz4sr6rcqsaexl8dk3kfyks6g8hdnspehnqcqw4pj8675ql4zwwsq74l0q8nu8a2ww38nz9psdf0t9cszvxk4y755pgfverlg4ew2u742sfv9f0ftwvcmu96p54gfd52hcsg6y0nlzmrdm2yqd08dvcdug9nyl27mchu2puhkmxdwylyuf26fdmya3tm6886sjx0v7ms50f0vsuyhsrewemkgykskldlfaqgfncaz0y60y0yw50t9mlshfezyp2sksn7zgpleuhqmqj5g5dh4ytqnt676ufr3g9aquq6dx8qdkqs5t5ptektsqlrpda9l4slycsy7hz5gyn4dzv45008e0fplhwwxwuarsjace2cr8qnzc55e7uwgs32juxfefflsv5942z5y33p2cgjm983npmw02v82jn9ktrmvadhvcraaz9avp3hpx6vd07pcwk76wml26zr2ew6e4uyjv0455uadvrldq4hev7fh3menu7hk9mvgl7yaez8afn5ysa95uvf4gwg4metjx78js4ssdqj4z5rk20ue0tl9d5k3x9cuefjyxzc6uu9mduke8k4wuz8hfj5wqpv35dzhj3je7g7phrcahrd9u24n04r2g5akupq05trs3h2r924rh53we5p6a3cresh73e9jy5ptr34a3fnhxlhg8gwn0uz5ra27lw5j392zhmjype9qtwmgrhm6y7whqqwkukmwthq40t2hd4j8ld2mckv3fyy97wcyf8dzjqnnqmcwvw0l4uwtl6e9z77w3mrenasvtdre320jhzq4phskk3q5r27avt6fa3k0j0evd8sanpgq6wtk0gssa3tlhstev2fuwpcf87h20v3apfvuglqj6kf4ra85x7zwks5g5tklfkxwswjlgheccypj4832wfu76gggxwvm9vzy5sxttns983z7qqul48ndp0u9268gj2l4qvxzv0r2xvzwc3nanc6sazwwgjc5fy6fg5vezsq93yft3znpwjpm4hqzu4mh2he84ru88gq43hrk4xld6et72m23cts8mlv0c9wc0shjg9jt7u5jn9le095jm32nt7dm257j6de0ym06ah3rpljfwf23gyf2ms8g2dj8hvyc59u7aquj35ajqhvjw55vhn8r2gdap607puwzvwlrvts0mrtsnkqnjq5u84pc39pf9x4pxhv0aghxwmj5wkqx9ynlcwh99wggeh2wk20f79anchlhe645lfzed3u82cf76yza8vhaz2lh42umza4hwfpz20mvjw6thm0vnj3etxvdeu73mjemv4mw27dhwku0726446tklc7memzet7ppdj9x3jvrmsstspt23zjnx8dl9w8akw88hyhlhtglal2gejqf9ktnuhng9p6paasth3sc5x7yjhtpvxr2ma435lfr4jceu6pn0na7n5h37qwuahtac9cpxuley7dvy0sslkq4n0nz0dwj9660pwkymmdj5e8mjnk5r2d2v8qgp4ymz83306teu3ge5rgjlmx0wnz5vpx6rtmgfhk2rphntwgmxd4c4m5cxt4q4y2lz03j0chqrrvjqycwe5kyr0tnhg954wntsx2fzgjx9pma7hq9qtfzweawps7j3mrzxkeg8eh9ve247tnyu4lqmx2f5wx2ql4slfkx2vd4a53n95ymt4frmr89jp8fx59c9jqevwzqzl5fz08clkn5wzawac8qhywryldnwvsjt8tz6s7w5qa85sqzyj23ep58lw2rl0ev8hez534cj2qyw34f8mue8g38s75pa2nju478qq6ylatguat4dam0r8vpepmslm3da3t8nrwm7gjwe968u0ps5nksp3d9svfptudr9sacqvxjcspru2vwzk099uq0pt38clvr3ezmuyq5cjg0ajvn70x8s7qfla3j5w8nwgrrssqfskcxk62zd9k6ssv26vm3p2g5n3lnvhd3dpv87l9hv5w0mvm4hl705t7cfm9tuc7ayxz5jux3u33vvlc84p5ewe5ruzcl7h2gy8u0ehqd38jz5335tme458ndm983gmhfqmcg38uukkzv8p9wz40a6e6"],[1,"nolgam1ctmven8wlv2qsz8dag50t09mk8wzvtyal7knz0ds7tvufgxwdlkt0c24c7ykxddl87rzw7q0jk8h2rmechagfyjylqy6tyd6vlrtepr5z02609n4qmtuu0whx6qpqydj6rtnkdj7rkp5a98ssvat6f8x5773kespk4un5z6lna9p0uwksuyux9uhkl2rqx2p3vvq7wurmuknj93d8zzlnx9zpasrn5mp0ayhzrlhewx99g5u98wpj34ue3260jcmr56enkd4xkwvkelkgaxkcswrcs924l6ssjxfvsudlz4ymq2hvqvr28jgrk8kze0ymuzrs6w30ce3wdxter00nclt2tjkl4tljy0w9zruclrv2ayx0uc80h6k3ut5866ljg3uz6dug9nrq9yk7av9ykxevmwljsyhyf6wmrp953k2ykte5q5qnrupcu58sa44rfn2cq5fx64fnzauhzr99qlzcfvyg5m6xhdrmxjtwlgwcflkux0f655k4srvm7fg8lrcm2ffgnklapdqmq8nj4mrx48zydz7m4lh04k8dhylentafzhl5kgny5gh4rwunvc5thv8k2h9nryl40tcawn7dvhhxl0ah4y4gfgd45f9tjyw56hmkmkmqqpxajxmny3dq9zrrapvrkcvkdyhtmpyzeyuxvafsk0jj8sa5k0z02tygqaupeeyjkt056hzzetvgw959yfj69e70vuu33fda35dyjjms2s30jrfhdmjlkwsmy79atyjwq5caqc3yaz5q97stavw0a55an8zutfgl4m3ytjw60f2xhunpr5kcvmem0rvr6wray38z3w82qyn6mnqft63qvsvcv7k55zcmuu6peje7l7srn0m892flee0degce7sgxk4qt665scmnjrjtj5536ntw67ytgg3rsdldsxhfrys964cuzrvtl8nccpd9jkjw50t8p5nahfp7yfp5alpwpqtc9h2vqm9m75kd8mvh5enfk48v45j4k25h4svmytqt83l6prprhwx0ck00054nfzar4nkry5khjn4sungre96p0kmuughd9apk6mu4t42l5x9z22ujmdad82vm6tt2zlwzgxrcn8m2yfqxvxrxtl2zxgauylfrrad8fc25n7ak4jgxds8708jtxcxjdsqv8ac6j7agvy2ceyw7e8u2dwm2wnacgdat5ka67u42xz57jefc84jfxr7cdpq5g45zlmq4jnzwpqqzd3eh3p463d8u3lhyn9hk7zerv8zclaag6xmaudsuzfhu8k96psd02u8nkk02nzefydfrmved23hw0cr4rcemwp7vqc0yzqw8fl69mpgfjgv9ngg2zue3e9spalmah85j8tlapv3s32r384c4a7gzqpz85l4p6akh5fsa45k62luma2dflfw4k46h2jtt255rpadkk2flefz984a0p4209utlfr0cxk9m45pg50fea4v55g93rwyf4sgfh7l0hs33vtkh69aleqwv4w48ky0t8eg6lnj5ct7nw77gxc4rg8cl5xyl73xl9kzqmhhsla8f989tq0u2m24lf5899hf56e0qnttvk4755y848rz84mmklwg2tc5mr03wmuhph5yeapxkmdw27u6hf2r26kstp6udu6p0lqg6leveaujsx0wj5tp3yq2cay0j6anshxkfexp7dx8xuxrme0n5mqqs5prlxe4skfgpkwv29neqwdw5l4c4w52k9pgrwatg8ed7whgsjrwtwmgc0255vpr9uhshldldd2j4lkchkwfv6k0r0e7rkv9r4gv06m2h7frufte87lg5752zy6c4wjx7w488lyx3v43n208ulseywaqfaq7388qaal893wz9gh7pzrxglq86hhur46jxmpf3fe0wtjdayhtmz33md8ur7q3x4h82vlgdqsrecvlktdh2vge4vl0rwf6mq8qw2ph5j739sknucyupt6fxdsj3s8cfar9xay0uky00ahmxc38778w4p0ajzncl3wmg8mde95m547tjjk2p2q2auyl2vzgeczcpuz020jmy76edmhjnp3r757jw70xvztt666vlkx90m94hqx6r4sved4fkuczphqg8t785xvf77gdhqm08z6g2r9pxaag96cksv0e4q2ssmq4yze8c2jecwsvmna2yu4nguy9ez75pfw2l3vwuh648xg99agdp99gmzmx56jgtyn5zakly72kldzzpuvn64lm49sdkvjcr0eas0h8apk2e9sh2s2zatlyur5yfvwncuzfwm63tvdyjcna6tyc5hdhs70ss94hz03uds4tynzk3898kgcd2m5qa4ewtrwp7zq92c3q7jmfvdrk99gjc95z6t7q695v8lqlu2cyjhmt7fk0wnf6x72gj7fppyk4qtna8y53ejpf3txxmhlj9k3ayauyfvxn40dv5g5pwhqwy2djfpwer9uvj3yqmts2xpmu85f2x3gwftmymau0hxgau5njyvx8hgrrmqw7424f6lzpdnj7qy2qp9dep3h4kqcncm6kd29n2thmlfkv22uta903js53vyaddtvake3y8mp8r72ft9yhp7pmec37my4qccc5yjq2qc8036ysj52cgujrctlaqgt8rj8qjt6uy9hlupnm605ftlpv2kjl6sqd6cudwxm7cv94cyhjwp6tnrup7vk0yl6k75eq36mtvaw8xwln9j3m5prvmcw2r6v0jt4x2vyrfy4p2smflyzujdevwt3perzg6z0lakk52k79n0fdzg4vgdnd8k75hg6qwyvqqj7k7sphuc0tgqhwd0q98ql647mqp43kk9qmfrx3mpuwmvtfmc3ragm2an8u05c6mrvpjfknd889v5d0um2h0dgyke7n060sna53d5fxyf9uyal88dujhr76na7jnhux0cxqq55nlpltm2mu57xw6dmud2vns87w5gqykwkqu54js94p9rudf95h4zhkves6u7ytrcag72j88jvwm09p7t2ml9u66utjgjljjpgzcpc6lfa9pwvlthslprecwhkgc3jn46ypp2zyav69wvv56jvvarf5d7n5e8ern4n5sj462d58y73x38ugs3y9m5d0kfqhekc0t495tdd94g4pz8tjst37z2lk9ahgeulgs3nfxap3vhy35fhg22rduqsfd2dqq0p26p6malul3zmkmq42xxpq2kn24gaysy4gpscpnz07x45d8dajqensfrgjn8rwg050xqcxz59hsxsrmvpwxwefy57pw52rk4lkh4yz5f2n4ckj299pn3wgz909rxjrkw9e74dxh5x5372te95hpwh7zxer2tawsxdet9ehc70qshydkvdj9qnfguldte5t3d2nf7n8v6625d6unt4xe94y3g7rs8c7pfjv520ukwm98c3lqash2wdt62wp5xdk2m9hzj9gxh2y9mfw2yl2r26s"],[2,"nolgam16puwz3zvruau6jj6m28c35g067qzdrcw7ks0zmlgls8ktrz86qv2ya9g96nh9eqea9s92vvcu2jnjz36cmfrrfcc85vxvg5r780xulyte4tpt9vz7kmf2xhjn7tz6u56hc8rn7sr9mdvf6cpxnmsh4k4h4xfw6szvwjmaylm35gv7n2xp5axjylwe27vrz8n5uf0elrn3ag3d5p7p4lsf4krves5g7zy7w5fuendpty0cj56p82hk9l8gkndmq7l24yuphkvtnyxfh2cr2p0mvcjyjknjh4gx83c83xhwlu5udrmfny7epcf3ff6uaqfvuslxcn8p9kg56y6tv2hn4mshnplhuwyfzme2dm8p540up5vmjv4pagpze8wptvgj7vejdpwzq2y5cdsfrjn9kxjvhka2mdruc0mg9xllqaskc0wd89lr043avyqutca2hkyvxzqyue7k3yp5m379ys22nu46cdwull8k9h329c95mnjp4386l8sdsvj7kxsqkmtt6gzq0wqdj2jkswlhyjvjdy0mq09ef0wfnvuhcutvhv2jj4f9jdg5usuhc0ygnwt9jrxhtn3u3eyzra2rwlmxycsu6gwjceu3h6hs9sgflxd3undz0meyf67pswhjetdzxkjl6g0t7eahpuymr7x5uyt42a96swwkdrml2wqvwtmcfqadx8gm5nmxx9w2qnnt2k55t94q5vxnae6nhtks2ge6dvqyh0ddrs0dkjty7fu8cfhpxk0kprlfhpgyaxtv3f4k4a7nmlvqqrvvg6m4j6xcfep25zfg90lfp4dnlw9ft58suwl3utvtk8ktur53tdrc295w4adz92vvhrcqwfutc3wc75qu2dzq3utvpk0tskk8hharwt4c0l7jnvrytt5vfutc638339vzpcxt9jld6ptgvn6jjdt7hh9nxpn4pc39wy528hk77jdzen2xkyjz2lz7rm297rfk4q2qcqnr3y2gcwcrp6320gv3tu5tc2quxcrzpyv9x2mr9cklvvh7vv4axyaqpk2szsxw8r6fes2fdl9tqf2h9ns8ruae8207nkx9zz5zv65s5f29h5d5grjxlpt8rr8snxauyzql7wwa0sfwz2a7z047a0v8er9przhgwhpnhrwcznu0q8c6m402napg7hd3ymnqk4dch72lumaqptpfmafugxgl29q2a5s69nv8qygvan42ffd4z46z5249gjgsqs62r9vczhm2fz7ey7yrh7c43fqd4kfl3gt57lv0m9rajvxctadny3er4n3e4jh0rwh4kwk2g9r26hkvwm09cm7zhqwg9ddma84fugkgval3qxmzzfyem0cudx3nmm9m8d8nvfadfhycv5hmhnxcpnae3jrma5sl7nh4dmkqw36a8pmw359xfj5vf5w9y2us76q7yt5hxxt8vcdsku8pvctxx9mcmnra0xfyr3g943tv7xd7yd4um0d8z98munchz4yjersl0czrjclkegsz8u25kysq4qq3fwlyhfu44rmp08n2wc7sw4tlgu9waqptp73xlm4gpmk6wszu3ttdc6vfs67n2vpvjvd5ck404sanzv7fl4qrchegmqcdjn0n6e7lsyerfd9duf02ulhnuvr2w62p35402x7xdgqelnyz45eh3t2mzz4ndjvyplwvhqf0p044s2kj44svvrnwyx70capd5762deg3tc3wfjn7vtt5fkehurys27jujlc97zxg3xwz8uf5lqpt0frmcf3pau05sfar25sqfeyql9wscrv60ja0sxcw6efu4cat9zvx7zlrevlm0pwl89t9q7qn0uenat09tzv75k6rrlwt5nrdjmhfk6ysucmudpzsnj7xg246q5kmpz25p40ms8jykxzx60ju7xuf274sgq97xs0wuexyhaujypx7a6ptyatu96cte8um5yyzhumljrjmdut6p92ljxg0e4qd65s7w22kdwpdsetp9jpvkap2ky8hfq2vdp0smujszsecn27pdkzuj9zx6e8j5wzqnfz8gjllw9kg47j34uam0ukzekc7l0nhjqm20xl6m8c48p42wye5mlyplkz4tk5q4wwn3f230w9whqgj3v3nfc0kfdujhf6nacmchetwp0aze8yjg6hmc2mzka7uh8fsl79t8498y3t6f0866gtv6qwmdrhsmzg3y63022m08eyw0rq3jpp5hrsamftsenztvr0mp9942qhf9k34x82u6l9mke0w6pye6sxj0sduw6n9xw2vtnrs6rhzs2v5dp250snjgt0nnmawqw5zskrephfh6xw0q8euv0pjvlujakjsftddeh8rsckh04qj4n6c3ctet7dfla0nrjscaqfwpmaya36ejsd07ycfqemh658qa97ah54lj4yelredtgl3sw7k5p9src675y8qzf8l6den7c2rz7u0chjvty3luyjgdjjzyutv8efhgj80lxqat93nmf0ggeg9xxmawsutznasjtxy0tc6e4stfq09jr3ne04gm2dqvlawxk34583r6chymj6yq2huks2mh7m3s6agy5l6gq5v7xc572l6wg9feuudpkdsd576qr39axn592ufgyqa8peem76p7d3jyc34r7r009kmlx5rl3euwkewgs69zr7z85rprgzmgxmf4pcv0wervksujdgzv5jp0vzgmye283xc99dktzl60cql337v9r3qapcgjryqgdltuw3j53g64s3qyjmsum0f8nnayrv3dts3lx2a87ufmdwnsc02jh6zrygqh560gjc0z3yhn8wfjszrht8nja3r5aq4nnlsndpue4x0pxxdkrahgc8sn6arrjpv9gnhtvx95duapk6rv95sjujax2rsqmuhejlucxfcjppgla6ru044swp6e9z2vqak2wn8v7xu8g5acmed0ed4tp02fd0ra3qyppd4yucms7jlvgsj8uc9ma7g72qm7uwy7kguv7h4cjtuqs4agut3cyuajyuhqls3vqtxwecmcnswcj8uac33djeqfemczzc0mlhwve4kq7t0tggyl80huj4295yjjcp58vng3drtr0ulm359vn3d498c7jywltss3kx53cyvu45r4d82rdn8eanyd5c0vz2d0rw3k6r5w85q3ls27lhcrp0mqntgp3uhwt8qkd9tgq8r59ugsmkzvwgse8wpf5hsk3u5c6rtkqzn0rkgrjuhfhtyeh9ynkv0wnf2y7yanpdvsjcuskw5nvfgzclhcjmr5ezwxnenm3anmq3py0hp96ulu803e2pu5snrc9peshxrperj7rhfg57vtadxdhd6tl6q4nsnwe2uscqz8lypdvp9mexwdwn7ztppcvxlv4pfpktsceh9d72w50lsu0j6ryhcuum5fwsp85qvev9gg9rk4af2s29jn882mfvf3nhxshyk2k9kml2kwdus9j"],[3,"nolgam1tzxe9cmey3xlr9ddlcg2cadq70nzm9cmzgcjhrjc0p5raquecylxe6aw8wev5vhf3c3ut6rxal32r6ngn04aln3crylkfpzsx823xfz79jcekn2z0myryaar9dp64zzj2tsy4k8zdfuhptwgrfaj9t67za9dc96clgy3q8t9z9q6u7zdenx2dp2aqcqp3ngf5uswa20u8mcz2098negrjksu3hud66n4220v6ss7xg7hg9ld6s9xzg2zlmm30rnwt900et9ygfy6xeaqly29aegku7yyfx0gg809lnc3tvu4qq3apjsntrr2huxrc9lc7pyt3gagdpwds2u6dmrm2yhmj2tkrhx8upfr2g06e7879ckzdh0e7sv7q2h2w9kcdnyzx0j0aa03s6rnjlnpuan9vjae9qugqj53gqenc6upyh604y6asgds4722uyjyqxxfn2pn7awtptd8ptky77qpgc7frxvnwavkscgh3tkxtdq0y46wff954m0rcfwxjlhzkuh9868nnxq3xenx4ywkkwuznxqup4ur844zh6q2vmntc6620vvu7crad6lnsgkfxeljez9sx2tdc7hrykdxetckfv6j95v84zkm0adgaqmhp29lkk96mu9w9n8nun5zk2y3a5nk8pd9krx0pf83j4qckvtylrt35yvu3l6u7qtxr3rewl34cexdr27znqyaqd3y46uhlmhnclk3ahegqctxz3nzmm2dk4427mj8c05ugvwqtvhrmjq8vx5lvd6qwpt4gf0gae7mj9u84u3650xxuuq4hzdtdrnarppnkckhlw3ka0x7j0lj4yx4upny57gwmrs42vej406wgz8ndw4geqtla888texscwvrzp03d6xhfu0yu0w03eym2qdzv6x92r27uzz3833k7ugz2zx7dfs00fhnnmx2q0cvrgpmphrlvq49n80rsauy57s4pn9pr0vh2ht9y92zx0xqe3xlncxjqcnlepatyhnu08wxq3j9h5qyazdge530u3rt8ft3c25u4anexflfst03efhklrkhap706mx8sfakrxjweua639fv636j0h2n075ud6p3ulxvzs042g9lwxqhl544us9lk6r42fpt7dax8fdr3c2w9lnx7uhxw5cw25gj32d8hah305283txpm52g59afcymdn5dw5ctv69krmkj42sff52wa2jgaqlrl6nszd5jurzhhxp840jngcnaq7nq9jgc0n8uejcmmkpe43frmtt4cn2gaj9sa5k29k2mqj05vn96s3f6eqyhdl7rlwu3vpxx8x8edg989nl9j99gcuppu7gpkuecw2jahcpx9cz08jm0xqm48uqadkkrkjmlfddwnk8xh3hc9wt3evhzjhpjkzu2yc8k4grxuwegt0eljrjflx9wlhdsa6geufzmjnf0rzyln5flxz2v6qhp53ccj42wdj4uqh7y44s5pacw4ew2pxvfugq54rjjt6r8rl7f6jm9zgkw8sgamc29awhc4p6f4leu8509ymyc4hz8yady5pd7jlfnjfyp7336hrsae7zevfjqwj0qc7zne5eu3l7vvrgyq7gu9y05nmyry0ns3phtttlx4dlf3j3nmhcfzs3aux4ct6dax93her7pte36nvcswgn0kajrglgk8fkyrttdgw83w66kkx3gcsaq2mj84huaghrrklnt30c7yh0trgmshh0v7gk0esxcgx4xscl6da0cvsw6lxcdh2wuv5ty84xkpfrcuhse9gxp28tg0fhqq8tk5y4udqv60vv44gyln69q7kv025yc2rxjpmmfsx8e69cpzk3p9rfvuz9ujawyla3a7appgm93v3xq7v9qlrn00rn2renuv7zwyhkdsg9yhh9a3sz4gn7fhrv08lgnyeyq47jmqr3syff58az0m79428us0knxd7y6rtxv4t5lducvhmgxqraxy0hrk52h50cxfpv8dgdaq260kgur24k8d5nefuvf3r3jg50z86lp8mhhh4qg6lyt09dpfysjzmacvzpka46tcljgnt3wyrtlyj3qf4nu9n4xza77laxm9v4alc9sfs78pqr8aw0gf9v7lfdvgxspqyja4p67qvzz0zj90vpyq4qzvzafmkr4hvdlcvmdkc59k3lkdmfyuhslk0uq364wygf76nhuhnxutlpn6sfu62nrqnfsfu4amdmn7quz9amwemuefcgvwn6crqqmsg5ph6dqv5a5cn66n80glp55zugawps68we0fjt9phjc8zp2pa6u7wp78uugmwklnm9wgy6clqvqdkpq6vasnjh4qqv8ksulyl8a5ns8r7uu7qlagh0fslmm84malkdqsq0yza0sd7ds6a94uxmrdj2zr8u8m9zwrh5f6ct3y7636s4pd67anz92g3szaq0huru7ckxu6yfq8da0dvjjxnj99jw7ussf6mf3cp6s2yj86v5gjtnsmq65zzu69x9r5eh2lmmnwmdxy0z2pa0v77w8f462p87apza8djcuw49g4chnmlfg2j6n0zsk5yw30f77y60ujhmg5x40yagh98l2tg208q7xdp67wawvfvwr0tqqcd9pwtpmfqh5fke83ehwcnu706wu4n4qmpegkf3se48zxygwzhyh9mpmucjqa4zcztfwzazhd8uhd7t90szkjpxhgu03xcyul30k42szgzwrf44ydksdrtxu90z5sc498lc0sgjhr7gwquq4w5s2kn8cx3xvfu936x6x92mdnj3vvz23dpzn3dzmqsavt8ymdr5yjd35gvm2tv8mqv6z754pfd2txr7kvrjfsljyfrx3xwef2l9ysq3njcydku5gljdtgmt3rh5qvnv63ll7vtmtqf44p0ft38jwam280g973kht6myfn4rms9vjg92lheqr7x7g2fqw5zev849u787c4ddvuapypv5r7x7455auep99cw2jh82u66k086cujkl5q5yax8rw3fjrzywr20ftth37le43xnmt8xhc07fvz2ufunn2nqyu46xwtypm4hlsnzxxhnxxtsw5ngddx5xcshhz9056fv279razejr29ttetuxyzrhcfuursecm9eumadd7je4c3vycqxzaclnslhf9rzndl8dddddw8xjm4ahyl9w8pvaekqr8p7urfcyzz2pudh2md78pc9p5jl90hz279l5tf9kc0pdzmnqqrx8p9prywvkvkve9rscseh4k6nl7wlxmcr34fn4ahmmwtstt3taqx8qhgdhv74xhap5zcwdycv6gvxlkf6354c88gvxauqpqgsa4dzj2ustqv8smuw69aw6a4rh9t2vf6uy786f3f85u4zkx6ufk6gvs45zcsm5qr92st2v2a4yutzcjckxc45qwtmprk5gjf3ffsqx6c7j96hxfmqnn076nvc25x9suz46np0tjp8mxpq4wqjqw"],[8,"nolgam16ypmlrghfdtfut2gm0j9x8u06dx73438rthdkm370jxru46hv6fp9ary7q0ry7rcgfpn7mf3wuznxhj5k4x3f3uuzc7myh0g2h2mtwqu06nk7f376ek9metdlyqcydaxumjgs29xfx68ld5aa6l54dtxadx8wwr9vd97wkq8g0ystf232d0kznj80hkq3n5xat97x3grn8enzlcw9w0k0qmmkuvnts7282p8sfn49dd45583gehtugjvq8zzjdza2qju67l2c4awml9jfxlhygvp2zfea5cza02dlpkkc0zsxnw2c3t53anmeav0tyeqq63r937lznxnl6vjsjcqpuy09zx84n46qhnewwmrtu742yunavysc0ywyuvvv2un2kkmlnay5vr9f7n78e0etsz99g5fkzzw4yj332m0eusr7khna9npp50n0ercx6n5t4n4kv6t54xy5pkanjuxx8uft0l9p8ttd0yuapx72rlt7cquuppx024utjuxd2t08nyve5cv8k508ghk0dzuynpuy09n4xqtnm6u3jfya7tn3l6q6je0wwhlct0jp3xfhkmnqph5kg2rp5uunuta68qanq65645cc9znxtzyluagggg33h6mcfkszvvnsk8w4pvzx6k0sz9gm46f4lrrxd6wxwgqewdu25uag9dq08wvmfd8uzfphxuqjxgg0c7zdek7ylx94yz7daesfj6x5yqzy9m9sslyt2cczhmkf7pc2rae0k6xrl76rt6tqja04fp5kyurkmertk5u385xrwnhpvj36s063xt4ta68hulv6htnjc6sx7ewvlrkws9a3hp7mcudydf0ktp0tp0umxrg5ayyk8fg5lavpxm0npvf5rjwf68gyu69pt8h4q7vwhtemve28waf5jhuxxtq5jjs73exy8f3ujmhpg3hf588t2ev6yz4apw7j0a3wlw4pgtfpgxfzp5wgqxse2a6dqd8ze7dugxpnyyprrtpw6gzetefq43wp243umn4ruh5fqv2lkpq3j9q6r33aglx8lr9dhnh7eaz8yahy6k8q6sykdlzz986jng9wxz40jxce0yf4jnuhw2ln5s5m5y972gds0w85j5m00nqwdugu33u77xw2snjmntwedldk46adkvmxeeat9ku5xqx3glql3emmj6ku9nsxu42rsv4c58gemvcexr2jarvum76e5crs2ychk5rppmsg0g84a8smvgxm8n65et502uwyjk7632epd04rwcejd5qfs495grgnsf3kmyek44hhen4ffr3sw4th70qjhu3yn5mqwluqc4dlqhdgx0l3yzdu3hk6jctfj3gmxfx2d9ah6gk86a2x7kdjwullq85p5xr2r9jgzwm3hfa8kp4y5j9d845ka85f58d0ymzethxrmf32r2mujzht8pt6ck78n4dj4msdlxynqnjadqjne6rtzw32eksrs38gxy24a553sddvsfy34e6d7kcjtvq9jpazc5z0wpl5sfxn95ua4psh0h0dks6asxjp2sr9vgz8yglnrpfq0fxme2qz8wytl508fmvrqkkw02nt94drzwmu867hxjdhg5kg33sdqvqt6287q7ml7085nqgmqkytuuhd59hz2szaptr099slzg7rys5uz62kgg6c3xa899f9h2f8l7080vjyz4462jmj2sxklz48sm7kj4ylt3800m6pmkuaqprsjqy2sr04lull6u3ng56u9t92qj4texf4u5r2fsd4tgy9ju263ft6y55dexzr8wwpv3g4gassk2avqm2rw0j5uv2alwxhwh04u333s5a98swdkxw2hv6rveuuzyqc4gq4w8sf8aa8euhxqh6xrm803p2au5vjcr5m024a79ma46z4x3qq2gfqhravnxqmdf7phsk9e94a7cpqwe5qp4tpgu322lddz6dp7lk5a9v6qwtzdflmhtj4fgpxdgkg80uws29zernuvl5vqk4auxk0ka9yh0s5pukg5ewly2dhu3hfrypdkhgu3lm9m4l7p5hfpa5hswh40sj4f44r87rk2wg7nduqxx6pu970eyhkxx3tvj94pw5tuq557zku8900n7vrkfu2m9k88ceq3t7cuclny6ckgqud0rgsrhar296qpulfh23gc2eajhyj958a34rg8tnfj6k25q0q6w02927hyvnarc4tmq5zalmt7ut86tldqge0f2lrx6vpacqr9yp5vu887p98nwpwl2ht9t32v2wuc5ylxvfwfuqw4t0uw84f850jgnhgz7uknf7m69pryqmm6jsfd5lk8up5yuc92s3cxlt6cutm0jhe26lvyz6ylcqzt7l9uu6zlhk5nzesmyvm3pncjgxfp6cm2xsch9uwyth9amrp2w838fguj9umy2a95hunvdy9dczkwa99aehug24ez3jq4jxt03w5j08k489mc87h0dq5enlk2f63w8qkws9s40yznsvj9m7z6lc4c2wkmddndryut8hy0xhjnnvjhghegz26pcfpyht8eygjw0nx23q6h5uhw20lglk6g3nln3djmcpqphtatax4yypzp8xgrk2g6l08wyg2pugq4333vmvmmecjfamqxzrx38xgs3p359rgazmt70csc49jl2qxenrefn5ds4kyvrmppzmewyga59kjq5ccr4v0r6l7rh3w082tx96jg7pl8vpdnafdajn9hshstxvu23n607p7x4yp9ak7lmq5x8rcd8js2tafes4lhqcjcptxnfhe6hyuzrsggz52wkvc3tpf3sznk0szsu0w5z6agkcugpre5uz3ad2e349cyf2mp26zp96fgt723danhqs09dfplfpfxa32mdm5rlk3r4e6ge3fffddv7t05tzcpazm5s8gjncughj0hkdnpjzks5fmfgs8znp3gy00c84f9q8cjmzjgtq8u9qpsyys9c6w02jcdqxnr2l8lvrswa0k2wzf9dqrwdzz3xjqw0n2tjn0h0rv7egwh6truf68xvnl3hlzspvnfglkgrs4ctndv64gccj9ta5qgr3fr030yuw90jrq88cn7wmhmykvttsdsrqh3a847ff8mw0tet5qkaepx5sxepe70lhr4j6cdexugaqstzgpmjcj6tfftplrl6s42gjvyyw50cpu69tq089j0x6nj08xkrc9ztsga55wwgal95dewgkc8lf5daqnhrp2z58rmff3f5fu6cerg08auvh593m005wxcm8qcq2fdez6nc00tadrsq99u2ccfzsqswgm6tp4enc2gnl4hc8kqpy85d60gflv2k4vcf68xyj8wcv0x8588k6qmc9gjqkvcn7mwqkwtvhqa722psdrsvcp0c07wxnhf0k2wwdm8s3f698kqt77em0sua8sevgpvfwwu7e92v3k2m5uzud2h0mgp998t0g5fs303cn68yzkhq87nu"],[16,"nolgam19phze7nqq74s3yjzm5ajmr47tmrc8yafex86fzy7f088rq6uafnq06lmeyx8p70na07dx9wm6p3utmlpjq97cyya3guxg0tvxmtwhz5at9hytyw8ysmdkwal9y3grf7phd20heu73ac0fawc8c04d0yzxpm623ekq6t0qea78e37ea6582uvtrenw7jh8jzul6ejhmeqxpf5xr6vpqu3s72qumq3cpax35wzhunjp4ftxe9ahw0yzjyjm74jp5rf693ftfugffw7pt2jh2dqd3ggv3hvq2g0urr0czj7t38pxuml30uds23wqeq3w8weht9rz8ktejetdx4zce3kaefgxzd7tmkyafq0nku62u2yrf69uzccnjcc0ydkxdy2cvrpvwhesg5678ka3dr47flg2w4g9d54v5y74ujtg9uyq9arhhc07meljec76qgsrdzc99pq4thas0cp79g3ww40dsx9xll06lfvr682nn39zyr3fzkvqaumvazz7thhzcjd8m74tgezj7nk80xj0a7cp7vggggjapxhm8dnsahpddvmsr30xrevn5zywz3v0xvhr8rjydg7y2nt8x3jraq8medgyxtru3htu8e4g87vn3jurk67p0w45n74qlau6qxlxekk4wdj47rt6thq790e6tszqpn3v7rdz4rh9gkjhsf3j9uz966ufxx7zamwp8ryzvw794sqrt0sza9sy65vr6ev9nn7apajcyjhzhqev50scwjhm0n5lemau30ac0vwnje9ktn5jn2m209jxlg2kyax8addqgyq00l83yme0rud90d7edps7kj90we40qwpuhny9kp9hn7gtvghcyx8lpg5tqe8yyj87qmte3l0f0rcml23u4tcqtdt4mhumdhcetk60dnf43jjgjvc70j4psl0xhdw4wrrtysk8t9rkxwt7jtyggge3w2dqxed70cms0fnqgf3h58wu25d4dn8xdaeyequ6n2e0xg0ffgu74amdhl98pqpqaxk3kkt7ujyw7a00qxla5lnr3gfxl93ad0tfcl20ut8cyl5s5ghuje57v662nxld0ljmdhyvw4kjrpjr9shzt8m37099ug59u3r7qt74s8vredcll9r5jdsyjqdjhgr799nsf8386ld7ak9x4hxkqwxy9qwu3wpxqtsu9lvv2muczsh8tkd4xuuwajt55vavxpauycl839kvl645kjx8thkf5lmvrtlajwnwqc6tz8sz8nz5n8msm72yf8rqxd2029a6dpflp6qr8gln44xu7jrtkr4pfwk8h064n8qhakczl064rm59a5pty0nsgd7lqxsj8ph0mnmrl6pfpa0dtf64ezulh6pvae4mx38d6n6ks4q3pnslazd4675f00kvzwanvg0qzgqp8jyrelwsyueg0g2enhhffhpdhl829efgua9099vzw680s4xuy4fgyfwq3caac4ys9prtug3rvfevxd8gfuap4pcpv968uzn8h6525ljg4pw7fc97tpyuteracfltx2dd725upzz5gyxuewxcydaeguu5rw3szxwdnul3rt27nvqjwxymy8ksf0esh3d9cmdt2ch4y87fqwdzujz9k9jq0mwk0lq52gtrg4ddgchqfv3h2lshhzc5g99zpjjnqmql8crzgtwherlu2caf6dh303etpn9a2c3k2zkv2gtfhps3lf24087ws9zpqnanhdecnkcw4797dfe3rmaaf639qqzsdy9mf26ar05c7zashuccy35r3n6hanl352x0deca3dsxdd9f38xxc390dw9rfx3gufv7c4ty5ht5756jc2zwmmxe9u48wgnrvzre3u0gz2ngj36pmg8wm8s0j5rk5qxvvndwr34j6plxhpe87gkzq67xu5mtr42cxtqeg33a43un7me8s7zendd62h3mxjuzsffnuhjdgzvpy76rhf5m05dnmrkvu7rj8w68j8kdcnh5q6lqgqrx8gqrw4mrlpjz2vdz6ez3rj4y5e0xdhts4pqed8nyvdcs0pmg3nkys5t6ym80ujaf7pqd33cnw4nz8x5q8w06v7xg68mgdq5r9da8tn4fywyqg4rlg0345u2t7qh58azcv7pa075zdrc2maqgmyc55j45ehjv375wekqrnv8rqdthuxzrnleryyaql3vhrwdup3e680jvffgk0ex7w2n76kranwwhpk9pxkaatkk55wfwn069j8endfksy3ammmar55jkn2nzj5kwua2e79ldlza4a5vhkdsjychg2c7x6qerkalq8juldh9yldagtgwpx6u7s4f2hrppl80r26se8ulymreswtztf4rqd73xqf78wm6f0ky5nwhk5n86jkdyvv6ezsx0rnxer87st8vwgagaz677wt593j0vegpherfdcyl4uvhfw5mdm86645rr435328lzvx8eshrjs0vkr0pxyxp3kt0r59qhxyx3n43zgm7s6lyrf4jc9x96llgr4t4whd09nu7yswslzcls8n9sfm8q44gvl8g2qad8s8g6xdyrtrme45y44x72f0dzjedc42thm0qrwc9wxa6lsm7t9nz47dafhm45430d9n8ve8fq3age5lcgk2uctzyntkqutd0rrhhec7vdzyh3k83pddxt0tass05r02pg0rp2960pj0rl6me2zvxlax5axc49rxl2p3mqvwe4a7ts995mtxypqgsdy6cgguath0cv5jh2mddpje64ggnh0akrffykgd93c7kj5lm32fjspmutzwj64ck57qk94wj8nllnutf7g5mlc9c4guu7k95lwz6zkzq3fq8zmfgejpyrzchd6s6v5f3pw07dy7x6pu6x44mdk6p4ym7e4q08w69xjskjwxkt6p8sr45avjxcuwvwuxtanp7madfnda7c76cgdrqwjrmpzh5vn2yd4qsxw26u4d5mua6h6z0ksy6jw5tllqqpwddyets4m3ea7gsm5vmr3tq4lr2ep8h9vnnn6x69gqukzg0ejxzurguwah6zjp0vqnvn23ga8p6wvwt5ugsgpx5qh0jw7wyheaqr6w9tgxsqhcyfc8js0yah8zpd2d28v7q55uenxxdgug58um3rd9uj43zsn8kanj2hzcgka5nx6ejndqwps0hpghkugng3sxq05243q7zz695e6j4f35jy32yh4skh8v39ls267cp94tcwyx0cmzh95r7r2auzpac98u4ktwrxg4f9a8vpzsjatcsnhnnqf88j7kqaqlxfns260le9qurm8p5z6wvx3rpg4xa73xnhm0v4yjz3x632vere005u5syhkljdre9960dd9humjm2edz8dpc0g0cdt9ljj7u3dtzqyx4t9h0vx4mqshykzkf8m3rr3ynmy9vmply8drucdjhsly3n2xgu4zwr433hpwjvtjcwn4msm4t9amnf7r9vsyx"],[256,"nolgam1qnpl0flsnmtr7gshld0mrvpq2fwfv4vdka8uhqgt32pd5evxhgmfhnvgtfv8xnktjp03yn9z4avtx5pf6dyglkr7h52ssjrrnsq94eful4pxkwj9y7e3mvzcg3aepuwdp7fu8yznp05ua292tq87m3xn97c33pamf89efnqtud0z30uhlxx0q03jvyh7fxr5ydt3lh5l90l59gvj2yp30gcmen6dzsxwtxqxc903yfyn63g2n8shq9hf5py0lftd5vj0txmt65c25pyde474u4y3hh9l3kusv9azl3q5gp5ks2w2czvgnlw7rj7t7mc9vufsqtd6kx6knrp9t9jcleanht0egtwpp97xtjhnnxsqxfm2wrhx36663tuch8avu4c9putq7vqn8se8r9xmu08lwzwe3ktgn4np4vk80ndsfpt8pwnnl37r9kkfw5uwm8zu68ac2n498ra577tuksqc68hk9dkh4dauqkxnk02cxu3g89z3a06qkf88hyku0rtle40r5fzujxrxtrr0c34lfkqpuaxwqe7x09wtj0mrt9hh6velv2tttqlq7wt5hp3txyhyvysw6ntrxcq4vv64jwfs5xz7v92xzwehmyara40knc0sxslamdwq0226355rf32sv5e39eqjs9hzmgf5erk2av68eu4k9lr0kwqlksdscssq8unaddz8smj67s5esy3h9jjm58wraupjzy83c2mrrfuyl3ucadgaehekm7khvrq2q6cfnu9mxdmemltl7ru88wyuymf505e52ccdcmc5efg6nmfxy8scj4esh09vfzydw9lpjvthgxds7v57kmrznqr28guzeh0pxdduq744cnrc58myeay4pfz8kdmw78r3h8l3efqemyhj7awk46qllsw9s6h3pe2vex4jd25nekw0sp5nwv4ahgu5d3qcegtv27j80lcxwerdkjfvnhp5v4vm4qymggt3jarmu2h5w9naw97h8cyyc3lqw6mcfgssm8skszmddstgavkcjnqkkyharqkaygvdmfy873wu6c0m6uqzcf4fqumsq06z7vuw8ped3hhax6c4tqza37mmjjz509nf5x9uj4y07jjex652reppwnt7uupr5lrvl6slc25hhkt2shg5r4awtq78x2w3j8wyq404s9hswpwwwuhgq7n647xw5z7smww2p5rlsq3u00ctu6tsu8sv9axft3eull47cneyen67ng5azqg2ddvrh0957mgfxe8q72tnyrt4nxm4y6qeg2a400v6hwmcdcq53p8xdgt45xqsgy779j4vd2ttvemd4ujnmyqls0puv22rmj0trhmyv4cvg2tglru2m6lhzzsdhjycn47mrr2zdymwhahjfst2eqhp9zmhfuksq4xuem2hgswjghffwr8hdq0ytlel2duc6sucg9fm5y92x22j6htxyjltpc6vszw6nhqfk5jthvqnjcup606cksd5g3h0lrqwsest5dlkel3cz2j3ynar28aknzlzw2awzltpdks5gfuufenwvfyv5k7ywep4dc5rxn03mw08kdwp9gllm6ada3uy4ap522p59am9c5hpt3nwmzhk2t3u0geja7wnptf5ukrukldl08gk9rp4yk2c9aumdnexn694n3cy06vpxh39ru65rjr89wuu4wvnd92akv3de7kdg7g6443cnhrcp9nq9x0g3rfnw6l94kqlcklwkqqvp27v00nm4qjdg82n26zvrhtyw4ms36h2xfahrgmks4eael53c2sh4fj3szewk0kdj3l9nvhtrc86njxt3az5anvfzxnfr88q7cljhfx5jwpd7cgysw0ryvpwsr3c39kus6ded0r8sw95hf6nl0z9r28vcn7rj7w8qgyuj7c4cf4yufkftqjx6hwffxfudmmcjkle88ymf9kpz3hyufses2a4a7fwprn9lqgshu2pn3p4vlczf2rh9rvsw6la72zd2k7a4jrwkxldeqdd3w6ua3yr2v0nj0s2zufsp8a48n2q2kexxvs52w0a90s3fa78wt2tctflfcr4xmprnfqck4uvdu4rfm7f7lewhldy2sjdmdepqzyz4m798sge0wfyclju9xewq6mqmpadusrcukeevya7fse03luqr0cssu2spwfkvmjhepgnxucw6825dxh23jy4plx4v8rsdudztkn9du93j7qyw9clzpuuyjzeekjumknuy8ckx6dxaa205nmydcqgx2wzkwflg4z47zkl7ermacas77jvs75zlgm34wtdystrslgcuw9jrafsua5cye9fp8djg0yunejqep32yjqf4520y38ylfmvhrs0m0v8kjl6tcwuyl070xallnzeu0hscn938462837hmxr50539f48u8v0tmnwjgdu5ahn48zyalpda0wg0dsq9le72ttrla83uc3cdtdz05w4v65ete35ppeurr6523zqgazu269hjrnm3yzusy8y5t2tyjy2wrl9qe22gd9ltjm7s2dt7ymhaw96k8498se3nzcjdf0aws2gf9zrymjtfg66fgzmmrkk3d4h6hmx5wmf2z3xwapz9z2v2kenpc8ms0zlednhwrph3fezwjcy890nul0ejer2hg98gew3jnu5ecjp3zt0ngn4ll63gpevr9h8a82s764hqxgr47rlh4y8y8ne27jgsuev4w95679w4kfzqrmuwrfaqhq3fu02r6n6wp30lz0wmxffwr92eht0tqf9lt77wlwhjz6s86lyjs8e02ghwq2p9t509f443zt0pzmhtyqgymqc8z9cu3glmp449qw26vlvt5rtnfrgjzpf7dyqfqz58zgyyr2n5xa652s4t7w63p6ayxrhmd0hau6vsczd5qf0zlee5g7l7etqs7faesp4nac6wchnzs2a0pgjm4ee6njt2wqyjjgpz83ma8cq23n2r7jcquy7a5n0dh3ljqtz6ls3u8xlny55vz82qevdtntvhgyp3y95np2gga25jkcd7zfhgl3z0q4sghfae42zy63yqdhwp2yjyrknegjtxkkr3z5temuwj689826p267drkzz6dynn8yw5jm8a4ml0058a3p84fpf8q0ljsl8etqf40jqmuwng8709q4sts2c5q4zpk6trtxtck3wlusyzggu6wlazheufuzvdrkcj0rtv3y06l8s3e4fcvzmxcx8w9q5kw8p9m60pqh4jalputnklhmfgpslagwazaeszdajj9juv9xd5df8uf3s8p830wj2smy0u4zs5z52p3tdmus0l4yk7fqj7xnstax56rxrf8qgu3j7dlan3q929sk69m2f0md90sxqf06kv6le5cflg67zu46wxlqq75gycqu3lyt5a5xjlr62kvlcmaz2rlysr4sz58stv4lmkwfjfdau2mnmd2hwrgz7dqfnfmuc97llhyfrgjze"],[512,"nolgam1ulnvnx365d6pdcuqy89rqz9sgkkfk7svxent666eze88az2mfndd3hpj90ndhupvfcycj95uzsrw7gl3mwp2et6gvww0m7ffls9fvak4ssccqzdldyp4jltwqhfl5eaczy8dshqx89044wp08f70688yyy0gxu54ksz4f46sdcxdf6lzu748xueh0xrkmf3qvvrg9nkz3xdvgscezzckv7d724yl3aatspy3hzpzjdpymj6vgphh9n5tt386hsga3lz4ev7a3rv66whkzk3vgdxdy7sxutxgaruncu4u74k4c5lxxcjyw9g2whu47ch320md3d8u52d08w2a7pjqjkgprxta7mk7996ymnd4d29qwjy877fr3q5hdzn8ypwwxe82erpvz294d8l3h760pk729ycj5224uh2rzmyyjk820s09kw0fphxgjqhw3gzypp6ahcwutpdswua7pxgy5gapw77vzymqj55p8k0jqx5pvxwegdauk335kgxva9n2k8t0dune6uvayteq26tyn5773emdhhpt7njanjgcanms7hf7z9mphcghw3lzffgt92zcyxyxr2dycf6yrudn62pdv6yulue8las8dd2v00p3f6hzc920dg3je87pvwp5u54rcnr63777eq4cxqevntucjjath8qpfl4vqu3zps7d7mh7dfpclcxp62gwtw43vny57kndv67kl0adejzcdhdes2s6aptn9kj56y4yv3072uc8qlgn9gk0yf539xgrm4zsw0savys6vy6r8al5vm2d7jzaxywuvl2gdzycykrmc3xmrzwwq7vh4dvxd20vjfg3dhsvedd85pqydjtydzw94lxclfea9vale63qdhh5dwm2y8jzv9csymq07t5gde4qlzjmn3jz4un2g5pytmhkhmplwldumrq8sehpqspl622yd0atfwly2uv69rfecr9lasyydxm9d8zzt9zsnzeu696zakwa8hvmhuv0xmf6ws4mnwzueacqlkzy4zgxzh3ucm3lnlvhlxvff8neqnxmjeyujzt9fsxqr0vcs6384t3mve8spw9lx7yk87utmwcr4qp5rpluhx8atmhgqny6uzclx3lk6dy8yva2t65uh67mfvy865hhmkdwmlrl378vqrlsa6acg5n0uj4vwzyezvwt56w79hc56x2vuz0grsumwxwcyuujk7x4fzw9x7z2awrrmvq5h7lu2y9j3hvffvyrv09avzq42hfez3l0seygxhfs6ar0cn3f2q4wqjr4s7yhrp4c2cnnrr35q9a45t9zm6cntarcfagauztzxmsdwpw48d53k3rgzt4kflz50rccjalk02kxwu507eyzhrzm5vu95lgc68xvv2c66qmjzac9ctz0vr720h8f8j3lnucvhqagx7z7wqsve0yn2764rzewcexq2q7zwykj0l8ul9yftz294nzna4xk7jsquyzkd49gx3ydqv9dzuax3squ8pljtna80kjhcj0vu638w3a0nud7a0taaz5p0tvk86xpqszelr4x5knt7vytv4m2yvg3gj0n2w7ehgsm84k8n7e52czrw4ckj6wklwuycthe24fuc9jvnaupcvk85dwc5dh84cghvhusnmld728cjw2dezr570vqc7jknzvshahdldq6wfevzpkk9xvjwlhnzt5hn7u5f8z2u8d2cnmyr8ahl2murfrt6y93j0huk5e57ywh76w3r9x445x33ppe6vy9fplnju2g0hnulf2xltyf486xjvplfcqc2lve2hyh43e8llla6qhpmpavj0cgqrpt5gh3gxunczhh7jys9v7ecqlkrkcekjp9xlfa702g2axcthrhkldrfgmuzrgdacawe3wzf973whamemt5wtx27uznhqhxdways2e3xgxpwqcc80395zhf0l5p6lcu7g2t3f47kknaavp97262rc9a6tzawrftjlpzyc4s845apd8m0qdh6d9760xy9urt5rz6v5a4x9j057r2ykunzuuze6u8c60scdsy06wwud3l6dc54ka0agqjms9uhnyf567eel0zqugqpp69f98tcf28crvl6jtmyf69aqhvl2f9scydyhfjvtq7gej5hseg4ctqhwpduhl2upnkwqh5aahtj3cgzrdlu6nayjsxvgle2ljvfzgrn9u04slnxm7ee6xglqpehjssvskjx706e5h9wejq4f76yv7m43llwstpjrfn8vy07hjjr9lare6fjtww2kzgjgdnxr5slfzm67frfyp82g77rsc7cv9q2snzdcvfwqxy02207esrmcvxs25lx6nrd2d3g38vej0kfc7rrclhkxqcvwzt6dg89642yjcthc69r7ljsj4d4v64hlczrhwlnejrsswn9mv4pu9xwzuzs7xee5vvjkmt327ujtaa2u2yk00r3mmawtnl0clpltwztlyym75r4hmc6egef0uvsst5jn6pasnk2rvhx9v6d8upxvul903f4nefmnwwlj669w5w5fn4a306fvgxckdtyxwjhnahc3urvl8sg7djhdu3gjl08dj3vzhke4x2e070ndfn967qtxn29thqz5yys5e3ujsrczw90k4rmm7knnvkeqlj9v4myty9qnp630zsk5vpcpsvl8l95h04ceknxhy9xmce287hnxyjymnqrdynkejyl876epyv5fwmz9xthg9rf80ygxzujncy9a7nzt94rjr4rpnn7aacv5hcxut8e5rg347n5urapg6c0w6sfszehetpszng4p0uj4kl0jglmqm43vfd7zuseml0csxck80rsx709gj9zzh5nflz9nxc3ezedyexcm93h2pl4p8k9vn3whra3a7tq6ft0x9grav72d4pdc0pawlz42meka03x80p8rtgn8yutqsckap9n9p22zkxsrkudtgu7gymws00dqjrms62dpveu2jantvmkkyxl2zcmaa50xx0dgsqlmhsztyj7dnm9wz56tyvl0x4qg3stqw4yuczvxq432zzt26x8c0nkj55pjvmj2j8kqruvv00hq9kyhumap00nmeqr9xg3g6gupeqemj78xf2j44q4xvjyhzvfcv74r7v4n0sfcev50ym3clhqqxgrh6rkdw9u6fzctv4r50zxmgye4ct9ajzqdjvxlu4rn6tdj48cwnmzz2edpfe7pe6q8gv58e72gt2yn7jy8etwkw0yu2dm47rmxhf9q424uzvknw9836hddr5nxkq0ykkjg72clptfz9udlrprx0g9tazj93gl6264pusdd3vtx43hc69te86vjzc8s0f990jmkgty70e0tllszn4k2x5uu903vagqqzj00jew60aymrg0v48s6xg9u7vzz9phgje8aemsl3xg3tw73ls05car03e30rlxm4p3gw8ucvsngaahntplyp308enzj0gvk8kt9e"],[1024,"nolgam1vtxnrhcwje6zm8lu3vw8zsp9tcjhr5svx8h8vrztn6xuxvycwttupuk4e7lehmmt3e3frwhg52e6asq36cjnvncg0tyl0pep8lm9chw0daw22nl6fz856pg6vglr0dp374g6yxcrsvxt4sc0wz47gzlec3rha6zn23e4n7v4kxygvx0l8qyav8r3qg5wfhneaux8pweq8hmk07ds5329tgfym6f77ptlzk32jfm880r63x8gu32dafrvrfhvskym6vfuffvzghfyh3rnmvd5y08vmy990mdeszu26vpznuuumklrewvmfrktplkev88mqjvg3lzxjq9c5xejrk7th750trl83wavwf0fck7effuclalqenfcsv8yrsut6f6pg55amplw89dlvexrgyrpd3s0mq8rpryputhpqn8gk9x3h4dc7ft97yp3z8edhjazymfvzytl4trp5y9nnwmm2h3jq337yfznnrcnr9r7qyp5sp5mu7hsxlyxslnae3wnnzwq3h0v8zprd5cjm67alh2g9zm9wsw8dz2fuzlv2rfj4mddz670m0slda636c3srew4fchtg0cpgldp4pu7228tdeyu9uh2rnmpd8gqpxsjtwg3z2qrxhkcjxsuy4g4vfdusx07cy84e9l7zayhw5ddwkklssy4xxdxshehqjrd0v225y2y0vpqjmzemdgrmc8larf4aknpe0hkdv7272y2s95z9ud64we760ltvm79ndwguqrgweyf4h7w465kxaufmyknhtmq3qgg28csapjzku83j9aan0rxzvkn5ac2zf6z9k4czj2n8s7fdvfg6w5ptq8dtdlq24lnlddsumyxhec8c8xjvezx8wj05r3djpnck56yf7ma8kwr0r9s2qavfmq9lxy68c6sj608vl6n3jf9s5n5jva776vnkmyvvrrk9rtdn3axcekkuauh7kyxgrua6vgst044wm3hx503eq0f9yggvtvgj63r5mldzxkejtspup4m2egx7tkn0uk7zdeuv0ktuz0m8nsv5m8d7qkxfjvdau4hc9c5yduzsfxzac0f2u0u27fjt4la300vyxedgjmfrhr2uzty69ver93d9ettxdmtrlp9csqlrd9ckny2n3g870rn0xzn8pphjehvr4353xzj4lfypgxt36phdyv2h96p05ckeug8ahcq3qvme7mw8xe55d0zlm9r8yd3y3xsg4g006ch32arz85zvgw0gahuvq2g5npcszmd7x8ypxatqxnxegkgfe2v94f2qq089efrtrr8c5v44y45llytu89uylzm955a4jhmffchujm6e3spl8ftsv25t754rfpjl3uxqvwdu32acxsn6vdjwd9jswgnx0qqls8060q8zekc78qm7wxxnpmk39uuppg3wfzqw55aq3k6dxmc2jzdav70j5czkysjpzar3twherdpftvkceh75jmlsakdcvkw8vmjf3xmtugfqelf63xt6dd6wwa2ce7xkl3ettzuhywvy2p05tdne9cxxyws4y37wxlpuqp63p68zgxjyx5q080qfnj6aa3mqzqy8q24345fmpps9py89d30un4d6kxsmrztu7ah38xk8paavhnmlj6tprsf5zqr7z5mg687ax9q2tac89pts9eatm2wv5q60enz0h9yk2gx0xxu3d579e2plwza4u082j72yd726vm6yk7kfctz5nf6w67dyqa2hvgkk9dy6yppn97vz42gkq0tu69hwv7hrpfxwrtef9948ewxg90qdtvuk00nu3hy6hmgr445m8j9ke3kzqu27zdkhzzdr5psk7gcaz04nuj4lqmq685f09djl6h3gu5r80car6j3qq08dfj2vjj0kfx7jxqgl32wwws3s4fsvsw6t20p57p5e0xnd7guxpk66sx76pvltq0398meshvq2wqd5dx8w72g7m2hwyy4zjgsep7mrtdvamqqpcvkxfyek7l839mxfd3shl9ua84390z0crzmrzd9g5pm4knk7hrfygk07zvsqm8qjerjshc2656ntczzdereqj65hznhkyyux92r77q53qf647kdyjn3pzl9xfdq2hcw0wryjsysz3amgkk3tdu335kyngvev5hu7a8u24wpnzqr838tyqqk459tm42vql6cmlj6en84vjuqu9ukdpxv0dzlupf4dkax94fvjkdh7l623w8k7nj2qpmctcufwgxushz4a94848qpct9zvmt7nwmp87c94xavc7gn4ud2jghllcumaye0pk8n9ywrhgydz0rl35nls7z3y95p0pg4pffd0yu4w2wucjp53hkq7gersl4d2h7upqj5dm2ggqhrakqvs35k9ejc2scrdgn65mk3pulg9vhtu5q5h74l25qee2skjsscuqym3xpts2q3vpt9wvffm9qrkq7s5r95ahd08hy8ktg338rjgu6wcwstr3jynu59h5vgshm6m6xdaadn3peqrgtywn824r3ja0zxvm799uha3j07nnz7chr7km6z9r6mqs3mph46uaz852h633979qm7kwn0js88eysmk7krfv7w8rygyy9e7xxhp68nkttw7x868hrypq96t72ajqytnkrsfjgwtamcnmuews8jlgmypqmm3lywlzf6krmsr5waqh03tqw5e04v7hyku2gkclefade7uknexxe6se5a59798j8a5p39d2jyc0kx40mp3u6djcy4tx9njys9e9nrcy2eannk4nxg36d6rdfffqv97ves7422yff456smv0jhv0g5gdnapp3s89s5d4trsh5cvr0960aky5kxjppv2md35ee9c62m5e9q6s56ep8szpgu2u3d83mk8avf0lrmac6gpd6adsuk74gkdzs3ph8wu4uqwvc6d766ee5qx32lr5enwpc8cgxev2rs03dxw7p9cmjzw0u3d290glrewafgd2rpmfzcygdhvqs6j7s0dztvtu37pqwkf2rm38mefjgmwgp2lu08gcv3csgzw6mppu5ne2j3wpjgtg4ak0hv8328wt54x093hvm8ewszlpva62f09zqq0hmydkpvksp798p5gujq8zgf4s75z4ukpmx82djytp7hm8dzrcrd4ft5dfmf4ams9udsw2uryfc8va2mzm55ftkrp0kspjd4ks5lfhg205pge7ng8x4cggct32yhcfju6t7m0v7c80c2ug7medm3874gexelvftvwhmzmfcacmqmjnswrgu5duwspm4e75sna357t5t2yqxkckcpyhxvslnnj3flp53ppfezz8t9xr63d6hm3rk6rm3vt4wduglsx63270muuycdrc6sds0m0uqs2jr7fddmyxfat9t7gs2ytk4fw3zvth8gzd7u360uy7wmjh4aprnftheuv3sdarzcmhcfgdwp248tg5cwh658x5lprn70yk4958y"],[2048,"nolgam15ghkqlqh654udkqw3xcr48tk804gcg26x62w8yvfj8jnet4n4254an9e5mzjvkhd4a0rrese6gs3cf2f3qhzyrugjxgst4ng2t3hf9p3ksf5j8d2pltwe0feqt5kthz3pa7kdt24he8974ad7nqrm6lj3yefxpg7vkf0hp6jfphhvnedmrx4tu3j8qkvmmzra2rgaz9mua40yqzsy89qgkkp724gkdw3568h4mar0kehv9tgptyvkqtwyxkdux863zmc6u26u9d6wh5zz5n0m34vr6ak78k2ls9h698vde2ghxn5cjmrste84fh8v8fsnzwz30z555hz8kquvd9awv7ja2e07dqcshd74dcfp9ulyrc8g50zxt0a7ftp3txacu3emz6csv0apzmvazm8uh3j59mgphcxmgshl32af2e5ygzwgnqzcdwvr669dz9qs5k8at6qssvz7jrqw7l4e4puk3t74rcxt7ke7k9ufjx7vg3zgm6jzjr8hlhkazss0wvpajx6zv7jspexze76chr60c38ntc25w3nal3nhsm9agw6p5xj9vsqsp90elrt62lh6frejz5nucu4fhxww3rsktrjlkl6ehh2xjklcnr2n47x0leayf5t9mf3fcvlxfgc4amwfspv2a8cvs3capcqmaeclmt56uu3z8w5cu8z9xsne6y9ddlvcym6p83gcta2hmew696nl07r2gp9rnpdap8z80lhxgctndjlklpnthwz56c4v0ju440yfw5a9k6eu44gfmpv8klmqmhd8ntruayz0v5gldn9vdwx3ke2kws89mdnl7tal3qstxzc208ztsd3dq0dlzrxezy99ctx6vdqucwa3qr3w9946lrnz32zzndyk9qn449fvlz3u75fcq50c37fcpexm6duhz456yp0ukulhr88dt84gr404p3mjduczpesk4j6sgthajpt0egtvsnwdgc07yqtwh5gm42x98pxhvekpcuyy2sh3j0detkrvz0f2v4auz5r5axll46e3wc4wgtezk80596lxan3wseuuxm65yr9a7cnyvg9wl95z9xf0a99yqc5s0xzeem745phfs8mq2ccuh4005pskhg5xayqd0zqayuwn8t92snn63jh6urm5gfesdla5l2r94zf0gcxhpalqjcu72e3szywvqnk6x84l4uj6hy0ft2scprpuc4u9840wc3k44qhw45h47q46yzxvjadeqx5g3zn47zpnm0yge5gx2ranptc4hcggf0fyd2kszxyhvujdscp50vagxsrdcdek3psdpatlqca8x6pl5re3cr3yxvst52uamfyrdguq5nm9y2ffdde00u2z8hpqlftp80kpy26v36q79s4el0z5y60zl9af76s3e834lyp4e0e38je4jav0zsznkfj6uucju778sns5083e5v50qp8ulntvaxhucmywaxvr4nzmzdqv03z9yufkwh9engqgfux7y3ljfymwn9v2wpaaearcqdkfckvrhjcd708qcax2p6ulxc6kwdde440k0shrql2mh73ta30m0dxvg0j8svre4eh0pmhv0hnq04rfrlx6r83ufq3htnk95l6whm95t046w3ayt7e9m2vd79vhckx5jl5afzrx97rhjdhfudrkn4fuxe92tgqccuqykcys30zp9vdnwwkztwhe2w6rscr2samg2wujzgwe35hjst29nv5eq6qqrrn5vc3wye9j73hfy0vfcspd0rttalsdtmgmycu3yvya82kfhk3tmkddnqy5kh5ucfu07ju8s026gtug5m4pspevssvp7e9pyq69wl4lkkvuke800cmt4jtaejcpx8lyghprg2sk7p3v7rwrtzy2ctdfa7lr499gxm9nxdkwapw6t7qmf2hl9c7j5c26tjuuzgvelwc44xgye4t4w79ett2ceh5tnzv32e3pxnwexelx3ktera4fmrsp4sa4655e2zw4erxvjjzjlvqpwl8kth8hl256vvgftm4vj86cvku4vp2c3jp3dnh6ekst7xjzsjec8qd36ruahx77q4hdp9tz2upkjs467ta5s6tl2tp7fkp96p22673yscwz9lktwy44e2su7cr8pq3dmfrgmv2g56f0nd4d78pvgx8wa44ckgmmd3ccevgdrwvwe0wxptld3jkknsdalw3spwk2ckds64mmpx7y8vzrrjh2t5tdr6kkdtdfsgvp7dk9pk58r7yc2vypzjps946223u9yjfujscau86hdl8x7j33gr97cpkesxg397deeqnvlhm5hqfw85k4y90gda9lv0puhdrx4wl7ajuqfxpmh8sckefsj7ax5u9nn67jz02xpxr66w7yvcxpz3fjd6e3uzs5kyjw08ycux2zdvcwtnvntlsuu67at3rl0n2hsyr2c2hk2345v60hknp5s7u5l4pl4n6dcfya2pdx8xcftxarpan3hw6hsfdepq6vday0mfy383r67g6qhv6wuvhpmvuvkv85xevgwaxlpjxkqltsyudlkh9y9wvwva4gkv96kl2zke8x30h3jj3rwzr8kpk3pgzrgcpk6awe9n5gmx5k4d782agd3355mvcekvkzhh8x6n5qvewgpn27ae4ku6agl4l0v9wx5cncz0xhfa2ec5jqn7x7l4mqx0yc4x2f9jecwqdvruk5hjsgzx48a2xxg7jg9zejhpatt4c639y6qys6rmylzkc3akadw8x4xxt5ugwskk43dwfuph2dmdxgw5eq2h4kfdxa9vvkys72f2puut3fqgqpnsxxfnll93zyez9gwp0hn77w9p5f202hr5gr9x9wycjr3cw3sce0ak67f3evvkzenaq4kvsjj5sn7amm0xpxnu4w4eyct8a34m9tghxxj9j604lwsj0gtt95t5pw3746jjg2tzwelj5s3ldj42l8v90ftp99726are39rnhjnp27txk8dvvdzh7a4hlhnaas87a8959vhrzztakszhl25f83cn2yldlexqfkjeatqjtaldjke8y6yw43ut4dnsdgk4w53g5ca2py7suvg693s43zqrnkcc7kgg4fc9ks0ftaee5gse9z3vauymw76q6lu7rh64jak40rtxdl0m0qv2ay7n9ztmnv040428svkjxj2h3ugcwld58g8spw2zu2t5t7pkp6fcuupr4rzlu9spvjq0xd65gnqucf9k0f89v7nlk28fxkw8m9xu60d5xgh2qaf4x997py9y6q9d9wjmu99wldxs9gsj5ykw37jywg0y6ax68l0fw2q86ku3muj7508ypsdmuuj5zjnk8yhdgmdzuf06vcsx0svtvks997wvvw5vwrs352w7unppdphj8tsj29m0v3zn3lkggjd0ma79xq9qn08jsmyqapdysnk952pde6g09t79r4t7ptaxlhu92yv5gmlctqjgh7y0"],[4096,"nolgam16697p5c462kpyhf3p2mc8ur74r9uh38lwqsyyxfz7exv5khtfaahpcc4gwaq0vku63xj45k3mg3uujmr6yl5p0pnsf2yw45xumh2r83rl7w2lj38eymadv8gqv8fuyr85q7yeservyrk7epshqjrrxw9ezy9gwmnqlxwq8araaanfa256k5yvlqeccdw0h5r6t46rgcwgk0505cwxa07ctsxe0vhqc9ua85d8fuwa23k9cxt740cfhnwx6qrpnnmarvphnfhm3jt49wfyetx02zaav3j3tfgghahgwapq8h0jvgck8sjm5gn6zfxal7rt7ls79u68tx4zrnkr3ycuutrzrcef5wusyhvuj544nl096r76krvlftf2tf9rxcr5mytx42eq96k93nnsa2tyf67j9d86c0z7mn8e3aswtnd5tdx0z6x2x57jxt5nu5dg66w406uwn27l80hmcq44nq4u82dzm9g3dgynl2uf3468s8n4gj0h4lu6q0wn07cdacaslplzvcpccnmdt4lv9rjz5g65he5arjnxvrtwlvlyehtlcptu7vvnqyef59m3dnjh9v2ss7uqkexvxjhxs28tcs406axu9k2jlljhhqmc26pwt9z6j6ht72m587nle5y0pwsnz4ezvzmuwttmje7yssdnyax98nx2jq8d3nrrh75xesjkdpqp5qq87ygefczqgc8yywtn0zn7v9q7r8zvpsdgdvzdrk7wmnaqhpmz46cg0l2eruw3pn7m6f4etgsramq7gulf55w0e6qff759cymg5s2rzljvhrqu287dh4cgpqz4d5m03huzfl6zjj4sgd7suq2y62t424jkw8px5utlu275rlm5fkywd5s4tdz3xtga3mmhhjqu4l7e0mvvm86l07scr5e33qcf8gj423ld67lgmqadaeh63qfw2f5ng79eaesvy59wc8qgt63laf0h6l5jf40ucp78u0km445g4ew6vz0s0twh000wuk4gysxh89np0zaxrzxwxaglaj7yevftf0cj7rrrqdpktxrkz5hszga7l7yl5hc944qc30lctql8qttelyhmkj0zaqgns59xhjxwuahukxjr0rvhdj45p7dulw32c9v5ady0kg09d370j4utc5y6vh5g8zzs72l7a9rewzg2kx6rf079e9ys2d38e2eqk49f807p6lqun4xuq2emu8599xr0hdmx7avf3kza6uagzct5frv8v85rl2w78nrakfpnr5wdgetunyk8t33g7wnr3g7ag6ms6xnzprcx6f8grzqw0g5ppz9rvphgw7g4600yr7xnkdhmstmlrhrssv2vs3gfv962dnzdwewpas66vt32usmsn97cen2pamhynpqmdpg7f79dfuk9v2z4g4jxepl6m0rcl75tu3dtl4h7f9amctdg7n5ne3ky9fmdqxrn39v2z9tmn0sjhkp48q6q70dxgxzgumc5887kmwukpgrkn09vuqvwvw6yg5x9tgvjy8gfxf00c4ujgfmfw28jxnvgvwceec94q5c6gnl37zsnklegdwn7n9csr49psrlgrrfcre8qadrqc9h89s8qjrgakrrtuy3xuv2fpdvnsty2tuvrldxgjphng7px8ag88yyett3ym2ldna48hy9jp5p8hp7lzkd9wv3ul5mxf2ajyn0eul5theqyf528g40lu53x4l05ghsd8ka3xth43y60haa85tcakv275grwrdxs837nhwhp3j3stj3xu72pxj3eq3l3dgs892jsetq0m3vxcqymqzh8am890s2es3yc28ttsyjv0hfm62vrr0qk6k9mr0h4tnumultg8zxjx9m4n6uh9g27mglpad7n2j9d0f7rs8z5dft40s5zlkwrq26rnvt94f6gqs22zkdphzzj0ju944veftj3kpwaxdhrhaaqw8y3guur76xe9r302865cpkgr0cham554vpcjc7907dvr2jtyh66axasjdp2clcz2yd9f83zyh25m9jv0x2jmnnhaaqpt5l6qhsxc6e23lhevuzmmxz5hgn5pr5e4j45kwdzuuek3l89e5lra4wprx9zjmmf5h5t2h7ty2knva2cqn8pc8k692gmrg43nj4u6wzvln4lru0hnzg7z9jrm0gul3p7er7vq2qpkp36e887r59za53np48dnszf62qyxgdl8fl6vsapqzxmxx7nkswzs8un3dy5wzs3vqj94a2j2gx2gpkmuxk6yuxrj76cttk3fv0uew0g7wmyvc8y0f7pfc6a7x9yh6wn0l75smf62l5lg683x3g0uw5tah9c9r8qtr4cse8az20cvqv44wzl0ns4h88fx65gkxp35qpcuv6m4pyyskzmp3w6heq26e9ruvlatht8qr9gp8usxdpngvqdf8xccglwm3suw9zhjkdpjnyvw4x8lug3tq6vwel4xth68ue2ex3w6jeuux75q9cprt4ex9gevvjawnsq9096nxtydr7leyv06c2ckr7udp8zderymh2tg5gj9r9k5l2fyld4wl8flwje2zctfwzalg56drhpnrvh5quf7kpfdvxysp920r7dt7wkztdkj9cwwav6w52re87ywmt3hpvnu2r62l75tduh0wjylp95d0vcgq9grx4gm4nc53vkjsmvcrua4vk045a9h9dcz6r6g86apg2sf8qfxrkzld02nal7h7gq88ulctsp4cfqtmgwzzqt0n5zckqtc3s27werhml64d3u34jmt6tnqjm7s4hnn799fdp9wpwzmaqxa74kngvxy7u4humr3l50gr9zny5wcw2cl0pk0er3wugspzjvmsv2k2dyhg5duvmfgksg6pdy8h9nuh82zwp2pfmslntary7e4uqws0vme5uf2fd5ruwjk0ay6ste09dhp92604mtn2lk8mvk2jdt79gvv8az3gds6gxy095v57pd9vmjtlh6f4t7capmhqf9ershyzg9dzf9wftvuk3jkkc3fh4pf2z9rjfah9ece6rpqwpnn2uxdtd7nmdckjstarf3ftx7fn028jdcrj8m6qgrmufzdkdjup3npq3g3g8vu7gyedm69fn3tmyphxly4wu6af9mxhr5mv8yc8ekqlcp9mamnkusr96cm59ew3lcnvarlk0f3ns6vsqudgputfmru6j79re2e3h2szk9ecf85dc8n7tptt3zqlq4d2ugd0xsydurg73nrwp3j2qxa9g969xr9qaags8cjvqg8ur0f2zyq5ftn5vsjh3lfaqvx9zqn3hnwzwpr6304fzd94v55nqjzwkhxg6n686t9tsdzn2wfe6sfy6l2q6zeevvtyj8sfggdnjgqugycwtg24arnmdttssnaqep6nzw5h55xurhavurgdpzkjkc5js9zchwwgs2ls4qvkd7thpv20kqcxzwzfk9qc96hkrtags2atev55"],[32767,"nolgam12r24kxyf02qnf863xl49ex98q4emq2rf9thng5gxx0kxtv5782lnmg5m47fx3fk885hte30a7efxzly98tatejcl3t2w6clztmtz43l6xamd6eq6d5uyaurshqpy0awhph3wshxer6knxw6ygvkngtdz28va2qmedmwxd89np2xjj0vul8snwld932ucnkcwkya5yftr32mdhvn8x85wmne0a7w8ytssn40pgftp820y266ukf6t7qrm0nts54lxn8u2lm64clqzv6sxz3vfjdrhgrfumpm6af994jqkfw4z65gmkrwwemvql2yffgex9ammezqd0k7velgusmraszrjegqfxxd9vssks6ev5l2ty470y5aw64eckye0frvezghzvn7ws2n9sdnthd3hqas6gwg54us008lthlhvjkqrmws2zzgpmdlh3rurmgwhlglkmdldq7009laum7dyfajz7s0urgr9z7kkqgyeutn7qdmgz03jnrmz75nz233enlm70lh8yc9j940ffd2myd4a4fapc8ma57hqnc6rcvn7s9fw72aks782d55uclxjpw4ymx8mrgs4zkxvgazgpy7a8fwvmjurvyn6xssfqc5z9r3aye0xvj3qwkgxucllntecjzzvsq59fn2f2f3ph7mkjhy6hskhq3rrg5jlsm4r4sdy9t9x4ay7t8x98ltjq4zu2dhg3xsqmrsnh2wlrdvp2849h5rjszghtfx6564an34975qcaz4j430fkzxtsv7f6jhhf5jgaem2wkrf7mp7hetys0jdxfw5yzac0umsu0jqxswq0ezavs8kd6dhd0wu3ldtc0anfj6g6p27mcz4xrr4cj58xvzct0tegf7l5lh25wy7fr79h6c9u0mc40ul39vx24h2c2k0ndw0axje9fspzwsswypv3x09j3ykf3qnf0agcdyxz3dv5sg3uje4ph58h0sq5nwprlkydy22vqv73tl2zvp7zgjmj67k5lsw0urmw3rtn7j5nwhq7gyvtfwvzp8fh2397jzvnuf2g6y86ku74ev4pte49pvsqf5kyw7h9sj34xnfp4mmvpx8wsxtmf6ryteg9ympklrq7302sm80u35kgt6kc43nwxtdkjj5m5glevur45yqkcrfhm0hmzchnr3fes9he3tks4tp594ef320mmk9n9ye98q784v6wj2zjf8lp2fz3cg9x64gx0rch3f6qda4ulj8f8mr83y6yua6m60jczhkjz98ssfe66hpgw40nrqe0mn8wpdxzvpk9nwgsr8kamkhfa2xt0se4yxxlj9x0exzvq79f5m0msfsam2nyc4wx7u3w9hjuq4ht8f5c79evc89jt82wpfkys3kcdw0e9qepvfgu2lxauhd34k7ch0ey0dqxvcgkyy2tlkc0ha8sm0vuwnv6nhamz7xv2ff08h7t76q82y4p7fm4m9s6nswk3h4ferlpdlcrs3d37lc98p7m6uxgah79t5rxznfhmx0yus7jqtqm334vzh8y25jgggzl5vssc73f0gxjgnqnzh2xqtq0f0wav9e0r0gsl0rqtceh0n9wlqxpza08vlls96el8axmx77pvzhav34mfkvnwgd6grzy96fmzjkcyc60uy7afla9lvj96cvrfendczhsd2jqay8lg7yzele3qtcs0ecmuatm6qkehqam2dcyfssaacsfkywd6detgt78lrl2hp2qa0xjlm9ml4prlwvcnshgr376pcdrp623k0rpgxu8pnql2rx8ncpmkgx0f2q8epvuv4fpwk9xxhxsjwxaaa592k6wq00fv32c3sx0gdwj40cjx5fd3dm99wvl3nate0880l56eddp626hmdltdc57afprdqf9vh6mjrta8vmqwg8r266lt39zjjhj4clxg633hx3ylutysc00vr2jw5ww4gge99k47le8cccttv2yve05u8dy3k0znj9flvsysvzhweu9cnl66k5n7vzeszx59ttf698fmv392uh8dlajg3l36eu822235xmpvaumns526u89qhl9anmlferuk4vrtdp2xucjzgd42n5vydq4szsgv5tqcuw28jwvg9c5lydvp9r8h8xg4tftymty3zmtfaey80n38s7d6gvgfjzv5ahy4mfd3lxua4e4uuntd49svrcvpc6pgj2fp683nl7ukq2pzlrr7hvywscfqpd2evy2ppcmp6lkcq500gfttz9v66nh07wfs76m4a5lpwds3tq2zpyepakaqaqk5mjywhlc3t0v28hzwht2r09szc9gu5nrp6xg9zjd5z3xdp9mxv6a7jq9r3svsgh4gualfukdqw8qn32jf3rdapms2eazhpgscgzw5va6uqwnr98ydxqeqn3t8e3ap5demts4tf9zt2zhcv5lzxzpta2mvfu7j9zlwl2e4t6930jclecyrs2kcpmljl9qmd7jf70p7z0ffcy6ej93kwz3uaj2lpfc59mmhsr9gv6tn9c2andxfxw62m8ypjvmvyysx6cnm3djsttwfesyjzcxtw6f2fc6wqp3hyg6gf54f0g39r3kcgy6u8r8aamj7sjg0u06smqvhhqkjkfms784lcm3gqtzkrudgx7xxw0xqmekyd2krldcls2clc7ckqvrumfp98sc835d0rv28dm7edhpg4q0uymzs4ze30a9m28cq5l6r5rmxfccz6rx3l8e4zq2mm5gua8hwu3sc9eagpqswhsrk3jmyyfpp8sh07ldzmt6thgg4xe0gr7sunngxs9t53a6xtqvl0sk9eh78euy8fupc3ask4pl6yq8zldmcqgm0lhzcz36ku8uc3p04lkzxn69eh5rwchu0wxg2cumecvhevsmwa9ngugk9r7dljp0dt9nsee4hq3sz03audss5rwtn0lhzvws33dj6k220svwxd47yn0ytr44qptzwq6ll5syw4wv6xm7vngcemtpmcq4seu3jdfednm5y2tzfqdf5y4q20lespfxta0y9k3jt75k2u8tp04qltskrkwhykrj6z85md8kgaz3r322rrejztuzj63tmh383v7wlux5387t3ka6s87te9a2t3fyfcxw8z8ra2u9wssv8tq7dfsw5zpav4vm9dn7mt345yf0c9rlxr9r3jutc3kxkhyx08a42pc7dhdryjsea0hu50mrzzyzhlpn247p2vdgcpssdyevn0te7g9lh8av4j2zvw5hh6hhndutkz9y0thpt75csuqzd7puh2gcjxrs062v249q0vdg9lfzns8vd8ecgt7a03hnkh3f0xjvtrt73fy47gpf72vayjpawpfxhazgh50kn3pj07xeql2vu408jy3mu2szz928ska04x43dhj585v2qrxp2vrs0ayt9hvnqrjdn8n87r90tsk985y88ycuxkmj9zkgjqkld47nq73geslgztlwl4"],[65535,"nolgam14e9pwpz9ps4gsl5h37hfu527sfjkt5tcdx09sta4yafvj5ky7y4w96kj5k3rq9hrne940dtrpqd48vhj935vxx85h7p4tsx92hz4cgzqfx9wrvlanzu4fqhpqmk0lw4pd4nuea7uuhuuwh39s3ah52rp5j2tz6a85lw9j3z0tsgehk59trxhuw9dt822hez0p3qu3h3q432u4cj2pgeth3qcc9rpycjgzfg85g74cwj972zm9npxu2ccd9ueuqu6z7asfg6qy5pyeu58u6nkmj25d7mxfqn60stacfvu5pxszm2dcqp95t64sslgp0k4ec0vkshw2fpsmj7a7k52jp84spmzmnl2nsk46mcw20nukaghw0m44r60apmtrptctxuce08h58j78qlvnx0td36vycknz38shga44pgffpa3hs20n34rtdlpyh5cepqjq3q70vf3q7mhtsxmyszvnc5ca6xzt2c9ejnuvhv24y2mf37t7x6f5nt5glfhqcx42nac3qhd2suxyr95e4mfqtsqhvj7dsjh7nedvcczy0u6fp90td0nt556gaz4x0whyq3lhqusgccqy2nfjq74ka9w73vw0q6amw69r0860nxf4z7vduzkn444qjmdwayqzrc82l6huzzhzy84kumzntvsdyc0yeyzvz4mcds20ujry6lud0wgeqfajehrz7zd3aqjgvqu6jrtgpslw5n27qpskshvglgmh8djahry0stej68z0vkeygu3vzsxc24w3r5qu7m9thele9xwqfk568l3t7njpgrz37rd0ymsvpanjyu84x9ynm58anj7unzkk0rlnr32akcgdr98md24gg9txaxt2xrerthxf7w6z6ltp8rzvxqfdpaa29t2s9rdffrx4gt20rsunk4cjyl05l3k49s2yntp2hd2gsym5zl84qdqcfk7zfg9elpt6vwxplwzzgtvnl326s8vca5ls950mctvk5vy3d0wqhu4dv2kmqxu9tnmfnxc4asfsawqr9nrm974heezd6t7cde525fxlfsjyt8xwx3vpvvp3kdnlhglgqajv0v2yw73tek2rs2prdasjkxf7gsn9ulms45kd39swpkvup7sue7jjr79y0cnlqvhrz3tnrk8xjsr4gwet9d888lu0w3mamdg75lkn9d6npsvyl49uc2r4fln7hgtq8gwqgk66j8za5yg55k3prjzjcqvmdwhk4fvfsnrmhj0k97leecuy3uw39awe8vyg8tt33krpmzq285d7jzsnntxj2n09ghq46pm52rgdtythamzhudxhm2tsez40juv0lz8r3wev5w704dekxat7wxdgrhjha8xm9wdaply57ljssr0mk0vs03h2r2q9naw75vzrj5h65jml3vd7pt3kdk7qtt28vmyksc3hu5dpgahdpp2v05cl423axgseykcw7yclulw7m7ardkxemaggss0fn7rzk92uac5qdwd7hmjt33vpjra0yzq5vtf6p2akrh0fk7kcjed76xsf6425uv6zx6l4xrg3qnwp5xlmat8ajptlz206j6wj47d0xlwegkk6v6z43yf2jyrhure3x00j20r6qh328aahqshf2q8dwrpfu4l79g4dtq53ngzpd2qemrvv05rvnxkhzrlsmfpvzr9ysj78v6sanmcve5sdaj9uqgfa9gen3gxwg3jt232ynftq5l5yt45g3ahesxxv50rv4meh9f3l0nfswwcmzf87nq56l7tl375whd00ap7mmnxmuthq6j7l0hjsztur3xfyn2z4cmqj62998dpggdmm4ehhxphewuspx807gk60q0g2ll6gfnujy5kw35y4v70672fle67pf4nl5qvw6frjq9la6chgswy69jm92gyt7meh7ed05aee6qjzju7fl6z9xq5rym9h9eqy72zaqd8hv5mgzecym0rw04rj8jfeav5prayaqcjq6m2h6m6hxl53t78dvtv4n6gvu732yfhn7q2mrz4sdwnvtegaj4wp8c4ccu9u8344lfz7m5kts7fe458a2xwha8fu4pxrclf90m8w7u5kdfa9fhf4augd3n4s340q5trvnwr87uk36q6pgllzs569gyyf2g3fzpjmmuzy7v55a8v3sh4tzz9nu3xgfe9rq7pwqdq3gr22uvrpd7nfhklsmxp6kzn2ujx6td6uchc4yj2ulkx8t4hmj9vh7gxyw2srsn7tuyu8xkvh7z69sd5kmydzgcfu9qqrj3u7wyh0znmrrgp50lzyrmpvnhz4hs8al7zpx7z7hmfdannyq0sz2qkrsqsv9ezyqlu4vt07zcmqmu03pmuzyta9n7w8uhxcs2d5xwepdjhrswkk3c0fyza8epk5sxsskaujgzjjdt0smtj9pr4txkfa9ym576ltmz8kehnlp0v6v4dtcea3jf3rtj69uydqxjexehq5kpu594767vnpa6r7rqnukklt20lp33ps9j5x965qry0tl3n4ftfgvufwvv4qh0chdeaju0ry2s2qtk8avntten4hjgfwte2g30fg4xufmc45zndqht7cp7ynjtc9pvumnaee2mpyjgtjfm0kupus0suypyfehzf4au7udq5f7dsxsupqxcpfz2f529jcz6gml388jepn4mvg5sekvhnfz32q5s70kvuszfp7jgmme57ragumfsp8ec5jsafpdul23yk97gjd4aulc7z40ah4ye53gd0vjfwcw5ryn62phkgdhxkw3rmxwc4ek54u0vqce8hs2zlrh8r5m5878qjupnzz2438eu7f3gyt2nq8smsj7xxnedz3nfpwh8rrw0gx0enwgd4je429mjva5zm2fujfq8gk84vcqcxgd0gyvpzr6xwcdnu6dea4p8j7az9enyualn9s9pzf03cyh70xpwmfenecezasge8mtj4885d7t58s3m5gwakvu864pe87a50zss9cdw30x200zcujh8lgl6gaqvqer350y3wll4qe2rjhdw045vq759usw7arvm8trjhmcvy59z33m7dz80qr5hut7fmqx37kszzsjx4r8vvq4sln0pxvfjj73uh6ynqzvh98s35gd9r5apxq2e728efs3hp56eeruxcpsj427jgx3p8txvw3gzlvueqwfzwrhwkhukulskrh5a6cv3g82gx4wvledpsshrh5u3y2h8lc4juce48ms8kx7f6y48nqln59tqvv5tdwk7zcrsswc2zra4lfnauskug0zmncfp0vpayekr2evdp3p6ksesv3esjaamm3jghg4faekxakn2rwqpweq47meu6c20w8vkq88kc953xz6spg5yhqsk7x2650cz0ezlshsra206aemwl6rydmnuw2xnvlmr3u9097tr4ulhht2r9zqlfvpuh3wu2lx0pupwwgf0udms090kv506xjwl4vxu6c4h"]]
"#
            }

            // returns a vec of hard-coded keys that were generated from alphanet branch.
            pub fn known_keys() -> Vec<(u64, generation_address::GenerationSpendingKey)> {
                serde_json::from_str(json_serialized_known_keys()).unwrap()
            }

            // returns a json-serialized string of generation spending keys generated from betanet tag.
            pub fn json_serialized_known_keys() -> &'static str {
                r#"
[[0,{"seed":"085de9d8ff01b393be81f8f76cc6b153b7b0c20e1097909390e0877fb0d38fe1cb3518c189ecc220"}],[1,{"seed":"3b538bb459132b1f2526ad3172226080699560c05a762d89fd6d73336edb3fb5a0d5c9e36b092fa1"}],[2,{"seed":"287365585508989266466c47b04875fac951a93d6d794ba4de91cfa892db92a3e52bf8e91b85f30d"}],[3,{"seed":"47bdfbbe9803d28101356a9db943a1c5081e15cdea333a27c814c9fc62d274565f08fc1fb57bb2f4"}],[8,{"seed":"e7718293681c2a25f83ec4fcf2adc6c6df9cc67146abca5dfaa129e3c9af3d5d0ff0f7c55e3282b8"}],[16,{"seed":"cdf0082897ce71d4e20eef2f953dfa092cf0a3c015e79af51a262889849f44c23e6ed23fd41d95f9"}],[256,{"seed":"7deebf6aac8a267a50b2c09844f203f1a14117c929c41c4161af663281ea8e102eae65fa0aab9756"}],[512,{"seed":"0ed702bb8d3c3e4801088a6e47158f8fe747ddd0b5d197809b8fb1578e39127ed5a976e26bc4beeb"}],[1024,{"seed":"2eb0d1060c2485c9c8e560954889e8abc64ea3dafeaa2f0a997befda9d5ed932cf5224fad779bc8c"}],[2048,{"seed":"1199406fb70219a94dfccd3e08663d6d4b086034e9d4125760222c16b5ae9e7557e1bd2d22236fea"}],[4096,{"seed":"680a341df644f26ba0188f90f95333987b84dc988cce1dcb3db32a60453b98d3300476177e961646"}],[32767,{"seed":"2f5502fe93db525e75a35ca2315b6c253ea03d324d1dab4bacece8f0c518acfaee137c5b3699c682"}],[65535,{"seed":"12633efc8a1779f3a4da5980812b720dc77ac2dec93bd281589ca7f44bfa2d76c945af5226d0fbc3"}]]
"#
            }

            pub(crate) fn test_seed_phrases() -> Vec<[String; 18]> {
                vec![
                    // alphanet v0.5.0
                    [
                        "north", "marble", "choice", "wedding", "leader", "sibling", "switch",
                        "vocal", "route", "element", "elevator", "grape", "duck", "pyramid",
                        "record", "almost", "bronze", "license",
                    ]
                    .map(|s| s.to_string()),
                    // betanet v0.10.0
                    [
                        "among", "inquiry", "crew", "between", "salad", "brass", "point",
                        "swallow", "impulse", "enrich", "cabbage", "hope", "lunch", "vacuum",
                        "message", "apart", "screen", "robust",
                    ]
                    // nth-receiving-address (3rd invocation)
                    .map(|s| s.to_string()),
                    [
                        "cherry", "stove", "sick", "veteran", "sketch", "mix", "faint", "virus",
                        "dutch", "ghost", "celery", "consider", "glory", "february", "shove",
                        "shallow", "key", "bundle",
                    ]
                    .map(|s| s.to_string()),
                ]
            }
        }
    }
}
