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
    use tasm_lib::triton_vm::prelude::BFieldElement;
    use tracing_test::traced_test;
    use unlocked_utxo::UnlockedUtxo;

    use super::monitored_utxo::MonitoredUtxo;
    use super::wallet_state::WalletState;
    use super::*;
    use crate::api::export::Transaction;
    use crate::config_models::cli_args;
    use crate::config_models::network::Network;
    use crate::database::storage::storage_vec::traits::*;
    use crate::mine_loop::tests::make_coinbase_transaction_from_state;
    use crate::models::blockchain::block::block_height::BlockHeight;
    use crate::models::blockchain::block::block_transaction::BlockTransaction;
    use crate::models::blockchain::block::Block;
    use crate::models::blockchain::consensus_rule_set::ConsensusRuleSet;
    use crate::models::blockchain::shared::Hash;
    use crate::models::blockchain::transaction::lock_script::LockScript;
    use crate::models::blockchain::transaction::utxo::Utxo;
    use crate::models::blockchain::type_scripts::native_currency_amount::NativeCurrencyAmount;
    use crate::models::proof_abstractions::timestamp::Timestamp;
    use crate::models::state::tx_creation_config::TxCreationConfig;
    use crate::models::state::tx_proving_capability::TxProvingCapability;
    use crate::models::state::wallet::expected_utxo::UtxoNotifier;
    use crate::models::state::wallet::secret_key_material::{BField32Bytes, SecretKeyMaterial};
    use crate::models::state::wallet::transaction_output::TxOutput;
    use crate::models::state::wallet::transaction_output::TxOutputList;
    use crate::models::state::wallet::wallet_entropy::WalletEntropy;
    use crate::models::state::GlobalStateLock;
    use crate::tests::shared::blocks::invalid_block_with_transaction;
    use crate::tests::shared::blocks::make_mock_block;
    use crate::tests::shared::globalstate::mock_genesis_global_state;
    use crate::tests::shared::mock_genesis_wallet_state;
    use crate::tests::shared::mock_tx::make_mock_block_transaction_with_mutator_set_hash;
    use crate::tests::shared_tokio_runtime;
    use crate::triton_vm_job_queue::TritonVmJobPriority;
    use crate::triton_vm_job_queue::TritonVmJobQueue;

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
                alice
                    .update_wallet_state_with_new_block(
                        &previous_block.mutator_set_accumulator_after().unwrap(),
                        &next_block,
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
                    .verify(Hash::hash(&genesis_block_utxo), &ms_membership_proof),
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
        alice_wallet
            .update_wallet_state_with_new_block(
                &genesis_block.mutator_set_accumulator_after().unwrap(),
                &block_1,
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
                    Hash::hash(&txo.utxo),
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
            )
            .await
            .unwrap();
        alice_wallet
            .update_wallet_state_with_new_block(
                &block_2.mutator_set_accumulator_after().unwrap(),
                &block_3,
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
                    Hash::hash(&txo.utxo),
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
            ags.wallet_state
                .confirmed_available_balance(&wallet_status, next_block.header().timestamp)
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
            .synced_unspent_available_amount(in_seven_months);
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
                .synced_unspent_available_amount(in_seven_months),
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
                    Hash::hash(&monitored_utxo.utxo),
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
                        Hash::hash(&monitored_utxo.utxo),
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
                    Hash::hash(&monitored_utxo.utxo),
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
        alice
            .lock_guard_mut()
            .await
            .wallet_state
            .update_wallet_state_with_new_block(
                &first_block_after_spree
                    .mutator_set_accumulator_after()
                    .unwrap(),
                &first_block_continuing_spree,
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
                        Hash::hash(&monitored_utxo.utxo),
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
                        Hash::hash(&monitored_utxo.utxo),
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
                            Hash::hash(&monitored_utxo.utxo),
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
            secret in proptest_arbitrary_interop::arb::<BField32Bytes>()
        ) {
            let secret_as_digest = Digest::new(
                [
                    secret.0.to_vec(),
                    vec![BFieldElement::new(0); Digest::LEN - 4],
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
                // dbg!(wallet_secret.nth_generation_spending_key(0).to_address().to_bech32m(Network::Main).unwrap());
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
                    gs.wallet_state
                        .confirmed_available_balance(&wallet_status, seven_months_after_launch)
                );
            }
        }

        mod worker {
            use crate::models::state::wallet::address::generation_address;

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
[[0,"nolgam1xfexkzaxy3ekte80xjqzhklg7xr6gdr7v5v5f5te5jwzx6gd3dsn6y5ef3nwvslw9zyq90987z26u9lz4awsrwj3j06q5ymryr3093rhvzdjwkl6nhzk0zp8aj497kfewagfzrevemwnwuqj9vaxm940kueg8sewm4d4ahrx6w9jar96phnrdtk6a7yea2k5lqce4qg4098xvhjhhrxj3mhhusmaqmlylhl63wr8qawaxwusgsrqtk9f0ege4sgfme7zmmu5pgy7q3v2272rq0cjlyfu40hqtjphc22vwrmyn9vsmdutr3n007rfgr2xsmhdekepjpdrkd0a3463j7qdlf66pfakufcav7aeael7u4xywvq07fqay4ft45kvgshh3an8fv2y3juqse3avfshqmvtetu43zckm5fmc6jgdutthuvwj3tscfwyyt95lpqxa3ldjk8dlcwlt4cdahylz323nu22xtp8ets5jy9pszg3pj935v5v0xuts8fxhjxq8r2d0sy374z4vu6k264l0has4hsc0zn0qwyuwe7z8jzrdkst46znmugr8spdc9f04gg2tcrpjfm3genu3sprpgcrhxyux29xd0tuzahd6uflsjuy3uet6qg06mjwptvvhz6u48n7sgah4nvtj0lh7twr8evejhq50ruz669km8t65h85sq8phzpasrdy5jltj0zwxgshvgd0j360cncrfsgm3t20pk8gsgryrn66nt7dp6w4sfakj8du3tmkl9mwpudz6yq7acx2agrapldm6lqvwtp2q5kesc69e8x823e0allhjqxawar7fuyahlnvhvnmlq2khsg3nmr2el5gxzg274vpkpndsmqht9t6az4d4skt6ykq22zz8rruvrh3q0zp90x63kr7rqlwrq98a337tvt8ytpsc2s69rglcfn0pwkq44eyklaewkd66a2ra5fwnwz737qllx3zyc05jq8zetu580ra2rzwun4llh6p6mzy8j9stwhmnxvgwdqpgzrrxqjcywv4u0j3teey8qdh39669jerfxh5746r0g9vfzppc0237nnkwpxusy0us8as4ft97zz2ahsavrra2hpgu07sq2g6eyyameez3d0e2zkdtzqnzsm5rju44hjf5l4d7z658t3cspvv4e32j5vc3qtf0sta7dhhn99sfc0a4el4f6ltek25d68qhz3vent5qkjfturudkyflwrtyymx2s7hlh8aegja0quqsj4zyufpev2zn5yg862wapl7jqztegstw4ar3tlrvzkjwz4fdk9a3peflr24fc5x0m3cxd9zzv9z35xez2905d09dqfl2p3z794s2qnaz2dcehlellz2c5qzql8pw2padsuz6d62z5mksya39fz98zanc99curw7gu47efay2crfa8psk23dyeef4vcujmphp7qfecfs22fl5mypg02kqmqfcpg8drmz5sp40tturtfef2h02l7e86dkk85n540h426eqw720vhw7pmeev4286vyp77ew8nxufc9hltrq8xhgx0px8gppuzk6gwd5ylqhtd8q29wk2pewlfmjrk22dxler86xevz93qh94zhmaekq5xd7uaz0yma48ptuuyqa6uy5nma58mn8t2zyd2t7a03rqqpywtgu4qytze7y6n8esr78dlm9z94qf9r5slzsnjhxrgk9wd7rmshapnvnrjvyz3d9037x4l2k7y3nyqhwalj4mrvvfqk9w4fyy42ct3eqkm4u0t80wtxqpdt4ltwty9zpc2km3jakucgkpvxgr2jhssn2zpvmqt5n2tv4f7c3uuxeuzlshudp90lv0vf954t3v3dde0x7flalf464jdeae433pyzen3vwmnskn9xcuvts0fuaw7qdc4ysgu9vg26qyp9qwz3tx72zxcltg6d3mn9fdytv645ea6h6culwd9phcsf0efq2kcp3p98dzarf9zrze4rsyrrmz30sezr06awh5n3njtxu3au3sqcgu8q9k9fzda5x5v9ljgjyflg0ly3qndgg0vrr6e7yzuepdf4y6npwyh7marlkvkq7gkkz9gamtu8lryxflauxs3vv6mm68ckg6ltu00hjks7lsnturwd3e9nn7grd3qjpmnkzuk2e7mmggmcvv5k28ezx7xjvrct43hslh7uduszjulqag7eptlq5p2y6y7e74qde0mgkackyrnwl3t8ynu6yx52xg6alxtzatmfnsxfjqn03ntnes0xcajp8kd3ejph9fr8mlnwmugkx56xy95g2kuuqpkj3ly5klp4n7rmwejak4tsn0cs44x2c5sz5hrdrna57yjgjrg3ktdc26dk5fl4lhrm7gjjfyvtpsl7jczxfylg5pnwu4yhdjr3vk4x72taehaut4f0xn4sxxgkuwp7r8su7n2rzym35apdqtym9ahr7nxrnraut33r9yk53lgrvakket4eat3q9lrt9t0dtyag00qkph3g3px4n7adyts4ve26tl0js3ujwwu99dms62ygqfmhr9rweql85a6rf60xalt7fjd0ye05qe5hk9x4nqgw4372s5hzqdf0z6l6egnzswcq990njalwmhuqrz4vqt6jf5tcydh6vm34lrrecc3ce94snl580hfxad5r7975qvx8694uzyg6qhzkkpu4phtycyafnmgv837xtp6jl3lqxj4enasmhd0w8dlre782msyzh0y4fcczdj3mvpxt2m9k3zkn8afj08djjn7wt3rqeee4aq5u5axvl234d4tyukq7622vyw476al9xnlnwnkjelxzrh7arpw8dayz3sygdv7j2jwwv7ujyj2kpwtartmkcp6dxj0dq8eqnr4huu2p9ydw6tx4f2uvtte7lr3syl76r8qxaxqwe05m50atecgqjmxuv6cc79mprfhchl4nugpgzhmaq0tdl9a37t4f2les4fvtxqch8r35f7j3q8kvxfkytpgrdpmpg2tqrj9j5kwxwlyh22em852sntyup6p26pf2jvdlpc4jhrxj63eguvenyft4wc58z52qvl2z24s7nfjq90v4d9guquzq68fap225g5j27qehhz3pns9thgzjyh2prgcvhk083yn9cnhpc3xs75gtucpjnmg5gcae4vcxk7n3kg4ty9mhlc6npgwhg5s54mwc3z09wspv3xtj737tuv2tzlt3yfcsra3gdhuq7waexesqhe787wjtgy3lzuazgeh8vvhr7sal0s9da48qzjgqslqswkmgn8w9qs4949vdwcht2wylsnrs3ewpls7huujdua7gnrjedmh3jtcjclqszcvfvltccgv9vc37wxk6c2jqw6tf9mxmrxm02mzngs9t4j4v299lgr6ylma58h66jtg6h20nej8n3yjmy9ja20py2w3985wel0t94nu3u77g7rwqupx"],[1,"nolgam1hz88205w3zmszrsx8cdh8zhahv03sh73z8n7glagm8e63ja0cx037z87ur3rhgtr8fnwyu6tqmgsl39hmcmn75a60td4s995g2mh8zscm3a5eyjmusg75vjrx4u68xuqrjhpcs3y2wdf06yhr7euw5ew4lglhrnkuewr2nxl32dczk9lf2ap9msz563n2nz46zs3dfru7s3y4wgyklaq7d8999u4kd90mszg28uhuujdn05vqcxp9d3wkg768v8m4vd88dqarfs0gnr0vr72l2dntu5cp7gw3p4us85ppnd7f0wt0hsjj2yay3ke5ms2evzjvz9r000vr3q4n7a3pgk6lt5u9n2qeaacaf5hl7pje9c02ru4nn4nl8wku760ax25le9uh52fu5e8yr9pwpnz6xfp38vhkqvwac5x4sxkyl94se5n4lscfx65rxptmss7mntx692qkkzk9gez5e4fye6ps280w8wx7sq2lc5cyepaxvkfhrjv2p7vegnx340pzuqcdum9ys9ush22r8fae6fqx020txjm45gps69nnufg0p8x0yjleeqm3mfap4l460q4y2hfgmp59whnd060fhgvfg7pm7zeg0t7aqw3d373cjlwruqv2y85v6gx2wdt9qx4lxajk59kejr3f38x0srhx22qg0g6sv9dql24kd8lq6w5nghjjrtemfkyzwfdggh4w0u7jqk9yct34u6f8hm9qhhynrqgslr05sqw2wqfth6tsdl3f90wemmv4pfggfvz4tl2sxpakxnyly6uh6jqfu9srd4nlh24aq4w3dd7e65p80l8vm8jmtzggjxzj75rwfhgv3mwdduhljlx58u9g4xqvgtpju9k6cegsena49znhm88v93cehdyf79zuj7anvsepjuv7hnmkxle3y5h58g9lryh2jw08ghwu8ecxkykl578apaypxnfvawx3pz4u4rk0w8lwhve60jurza3vcdpkr27skl2msjka7ruald60ef89m38nmsx6v6grwjen0ft3s68qy3vhmdcvytau4q83tanw8mf2y39hsv29msz5u5gjx6dr5f3xvlkug859ewzq504s099naymferqults5s9q6v7339g39pa2mz84wegeu3tamel6r028uh5a7p5x5x9yrt9xzr4nt3lhuyuc363e7fzk6q2ddrm396kr4kdtfdvuxnmxt3nhte8gph4sze90rnx3qys8xunduddx0zlpa77serfd9j5ew8485x65fgy5tc4zagn6jq23mlj4cku56alt0m9nly4wym0frkzrwtukdusnkpr77ltnfuhdas25dm323ml8kcedcdf2awe4azp868chckgt0ulk6lt0lp67a9xtzsxpwu8776gurwh8nkeqsag40xk4489j7ee7xa7t0pn2k6f7ne8nenc4xvy37wdqzkypmhavhcqyjzk52g2d3es3ansu08rv7m4qs0nan3csyc356f0ftr93ll9ml24tel5np3afyattqrjdnfpuzzqe720z48hsy8wjlsqjg5ypppsfe3s29smwc4etz5vqu6xnyfxhz8mq058mmmnu02m5hr0rf8kwv0zgcjetmzngqqpru8xwx3tlspsu2xg46ey8lgwz39zxnuuvth3dpqkare3srtk3rf0tdjc7620jt5wakyj28jsdfy8mvl0ta2c9herq9z4v03zcnz7mvns5n3sk332lh0ugvfm8tq67zcmrrctxhhefyquzc7yud3tq8rj3rcnaex7enu70tzfv7z5qgsa7lwup9klennvwtl0h490t82e4t0q0vmxjzrf5kmcurvshzv0lymzlehjyv3up59u0esdwctjgaupttnklrxyc4fkxaxxzxgckww9tcn3nza0urt0anve56p97rjqdxfyqr6sk6n2ram8llujjd0qpznaqa8r20h0z4p476wefa4jnsg7xpzt3elxd5l89ydcp5f24368tm8np9f8z8sy3wtkx0tx5926kydm2lefuy2u84vy2v6sv492svdaymewfpmdasn2s3ja4xkw8qwjfu4vlvsnev5j5l2dq0thdtnd9twpma82jv703zt8acs4605jm8e4pa4pfltkfd4d2sy3a7gzyrhm2glacy54rmksjzeeujzdkg2996hejeu3zs82a2q8fau2utdnd9pm2uw7fclfhrcr49fl3jl2e7qk58lnsw8vs2h5cjux2uvqjh69qemtdhrnqxttdnsdfpp2kczgvzhajylqqfk5k88ddf8lu0gu4v8hztwmmgwjlaraltsvkszrx520lyd6wnfezsxt2fryk8sepnz6xkm95japkx643lzvkjkdcp0fqjdmmeffy892z6smzsklhuttx3l928n3skk43qhsyhk0kqlkhneh7c6dcyrmwkqvw93t43eezmvymg6dgn072acppqtdmwjlythk2t0ctfd0xlcnnncm0culgm9r59wezs8r8uqe2ygtglaspvlq6kf0sktf6n2ktpqd896t72n7ku5rlxnz0fc6y3e0rra38amret8eqag2wyfx25rn4sgfr69h9asumrqfhr973c0x49tzt0j7eas8q4gch4pjqr0ehcfjv5pnh5lwkjkpfulmfmrrrgnxv2vzalx4hqu6jm343zkrnrmazynwlmq02464y6dzwr5ympuhwfjaawy5szjn426mlq4tx4a2f3cj2ma2g5kfrenwqvrf7sjfvas80kg0mh6mzs983uc8ydrg63nglavmp0dhlpftyst6cvr6hk3ywrksqmdcdkmz0qy4h7mzfglxt2ga655yew25v0xvkga6k7g00em3y983gp6mkarcn6fsz9enxukgdr6h3ngcth7gqf6800dd0upv967dg89f6vvkacrsug69jylrsz3pf4dm22uk504prhsqr3vg8qpk45aseqhlpvc6fly4u9xrc7frwj5tyd9hj2ee2k8n93jgxpa9e42y6n9820px7kg5dw3dajdps35njncj60pavuuhatyk6p7nkun889uz4xp3ktgqt4vwhgezy9suk4l76cymrv0fn34t6q63jl29hf8jfyyjus3850xrpdwwlezyqjwxy7v62gcyy9q0j2gxju57ktgx9yhtwtld2tmwx0z4t3372hwzjrlcgfr3fk3fg063ftfsuqfe5juwp05tsaeepy2vafu30m0hd8ek2j20jjny0hat92sznpa5h7lj587nsryjz7ntu4yzva8waec0kz7y75swvse9fsgw25v4gkpvf7nz05r30sfcja42aycau6zw49snfv2wttr8q2dwegzhl9gdkf42wv49s7c5gqzldmu4fdvc2tsvqttlppdq5clqslt68jkypwfjgturx0mumt0k48evj7muxudwenhnhv2p0xztywgjj4yme9c2xq7sq5fphdpm"],[2,"nolgam1c6emn68jx82xtyk2dkumslsmv5tgjtjnf4k6egzljfpsars09v8z67mp043kg67tdk9f26lrsfq2q9avl6e9eeqaqtl2y3adf6vaf09jyk6fxwp72w92tj48tjnu6djhfns3uwjl25ylt9pqpmz7kygmtt6q0w27gl2rx7r8gvnny86k0n0am7vkjdgyjn9lk3cg66d9vv43d487wu6wsl90a0u5fu6sawlx5jxmsmsdah5gdx6mu5r9rxd40k2xjwfh3fyqk8rfrwzc45mzwgjvmckssd875dm3w378z7u5cclu9s57ykwcxk9fpzga2mnhgp8hl4r60r2ypp38qestfv2z48x0gswykg72kqx0p3f2n7vgcvnjacwlhd7q39ej3lf2zr58exqyl69a8e3h32gvuhl6x73d9evfnchg5cd836ma7dk6w9vnk5rszcup3gzv97s90vfx07w4jty2sewtpuesvqez62x2esyesa9rmpt948sslqzmu64lpzwql9npvf7p08fwhxcled9c87q2xljk6z635q4h8tfhdnduduhg4avedsevfurfucr5mxhym9ggp93juxcpdh6zhxunjr3dyaxdm6de44pnlyl4k3qll96zenf5t2dseh6aqtrkn9duylz2gx2ns446u3zg679wahsrwjap852dwz78pv9kczd06qwskwnn7w69ntmphjg2mlr8knzcmtg9ypqa57eqp52tq94ugu89tqwhyes0sm7y6w3flmm0h3f66c8v6lllc60yr4cfr6d3sc9st2m6n607sx65kk026jqeg8uwakznr82ef059h09ve8sk504sfdsnjxgnfdmyq6njcg4xlflprkxu78myq0yqtj77086nqgmjrvfnh4ew8ctw229rlpx66q98x5qsrxla2hyw59jdwqn2n2ch5a9jhq9d8cmawcs88e4w3ya6wplavr6stp43yhm4uzu0ss38ekfmhlyqazhz0hcu2ndtvm4lmazhpacu7tp3c52ws8zec4t9at0rq0dy77jq8dl9xkytumctktyvztq5fkenr8f8jzkgegyfkre340emp8jve0r8lpgwmk40d75vzwj7jf7qqy8lgyurdyjjx6m6g0wwqfgw44tm9t2k6qqh3tl6n97kac4gq3cpkykjd7q9q8a84gs6r8hxh7585p9cwg3lxqfh0r77c0ykp2w8yzc09h97vp6rd087j89uud20rqynvw5zy7y88pa5ngtjhydef860f9703y4yrgk2pxq9h7m0hparaq7p74zef3uf4mrjsazalz97qn0csudt5cn8qzhklwq0966svc52dq3qqyzshe2h7wm7kexmyj8far56w6s07naf8hl0tusd478dknsahg79sdyw8mzzn4upwmj85g06j68z27gx0ds7kk8484jgsfckkcm9l8m27357rt7t2ydvfelh2hca5wlvvz5ewgsmy73uqs6zrjkn43qg36pkd23qvw0d4deevafvk6jv75empdjfgh8gq44wfz5k05qzxk68ljz6czprfr40thc4fjdctwgrqrcvgufqqgqmzzsnt2crffc853tw3vurlwwnfxyklfx7jtvkdf69gxugykurvdwnvv8c39xmvzd044q5nlprs0kewgwrm3vn2xs6zfa0tf3mtvkxnmnd64fcl7dm5tg66h0anr6ppekua354lpdqezvlvfn7u90rv42p6wgjntdkwnm8vwquja8q9ltmdud3jldexe72egu0a53uh9lekvayvvlf72kmpfkh9kr3hv8dgvhfe4c3wyr95c8wvqsh2ghkdj22tf5lv5ua8pauvlka4jqht0s3zc0sfqd3e0d5cq62f342w0flxaxzu6qk74827r73s35vhv3w8wg4ghf9c0z7t9nycmxpmda99qsm7hfmevwxlpra5ep2skm6hvadhapznlwtgwtfeleag8dkcrpv4lzgcvhpx7kdzq30ng44ch6t82jjjf4ny2f5dmaltvqp8ktzlj4fs589wekl53jkvnqzltv2cvm2nd582s343f6qtfmwhy2xsdzh27l2mjzhsyfwy3uf3s9w0qatyv5qwvrx2e90sj62adus4sc6t8zk37wgj6f3cwcxyw745mkmmstmpn8h6fj2y7dkz6pa9fl3zvd030r6lhmu2fxgf304pzytnl3van82z8j24tvkgc7jp4px2k9qq0q9lj9clerhjuf3a7ye342prcnlc8p432365x4673wjvjhae3utt5e0pfeflt00vmau7mrav9j2ucr4j6htslgyrtf0tvrcjlmluva0lhx80c2d3s7g90pxvwlmg9gm9phy8cn8gp3299emk9cxn7tm5z4rg090kx8tdu3yjru8tvl3d0uy0tka63vt95jtujdnqh2sawe5jqzue5pscmu897hvnrq7chmnuc7hdyeafxamyas9hwymhngt25xq2hnw55wrwhjc7scgsw3sa8ty3jwh20awr7lm8f0d6g3570nqp3f2dyj3zyclqy8nafeqr6u723w5wcznvy30a0jp9hytc5cl7z0ktp7ug5sqylnfyh69t5406py2e4qf9r3eycnag82c5psqrsnf8pyvk08ggpfc9wqcmxahtta5ctchyq7s3t3fec95y84q7644c9hh88h7x54za3rq8wdahm733xzukwfp55mp6xdeed9vc2yhgda6v299qf8xrvju0nh0438kuefd2kmn96dkldz9v35tdtcm5acttzfvarsqast0nk8ah8stk9er2zanu96r2kll6am7c422cts9l67yy286ram29qnku6nzrr3jyrz5qhgfle4jkhmhq2vskexl4vq4zsgxqqwv224thag8g45kzyp4lt7jyrw0vda83n5dc93mkks393jmuu2jgdy7ugcqnnvl9pewa44sf74jmmzcuwnc7ukpw8vug2q4yd2znanjers407f8egv47xgm99h6xj0znzw5uu42csxwulsd92jr75dmreh3fr4my70d3swrqft579fszcrtlk7exes7tc5fk3pa7hjfmd7xwfdeps863emcjwvxqajdmffescf7jx9x5cgfvvdjze3acsxwk7nd55rv37j44a6et5nuzc5c3y4mytjl3savyl0yjphgj0m5mxg06k5ryk7t90a4z6x93ruznnwf8t9hyc63caa5c05u8euklazq9sfenvv8pld0jy87udt50qvtg374htcps7w2d93tl6yr3x0sla5hy93rf78l2v36xmxfa7d72qcdwpxmze6xpcgqwfmk6d4y7dsuaxlaqt0l3apkj0q6mz5qhcehfuq06gw9dl5yau368vw5t2c6d0rspqkvwy27hdzfmxegfnjdg2cj2xgcyg8sjlrg5z49c8hwxpcgcfmvh56dyjcwsp67w3zwxncp7yk"],[3,"nolgam145g56gep45nml6k06qc2j5mjdpc9rpn5rxrhr7l6ax8psah5at07qq0q2w34qsl2alz2dy3rph89rplkp5fqaydnkm7xzvz36q35sgjg4ahyhu95tpp2ph835pj26wrkpu6xqpmfmnkay3fcmhgr6d47g6l7n7tgrucq6zew6ezu7a6wn9pzv0j2qhgrngkfrq36tp6txmta86wvqqead3xl6cv54dm2f589gr4gwavza224ktp7fn7j54nvnm642rnz6y48kukf0y4pv8wdlwks5xzesh0frdt4c6exyq8yvvakex8g6jdpf9w0jd746q0njejumfu7dnly3l3kgde3u27f9y265a6u88dz3uruvufz2hk0343u46zyyf92s8quj06puzymr7caufrpq7m2tr2lc82dlzumawntks58z05eq2eh05vyfwy3xvtmtfylu4uyshf34c388agjjkly0gfapwp5qlafyg2hqx2787zwnrt9z24wnrzp8egttt5q0kyk9sd260jyukkqau8u45a8lx2dmq4975972d0fqsn2s2f0spxu2qylyzmc3qz4vhvslxcraqt2e6zh70h56g07szd4ahccpnspvz65qjlx5t7ff67n4af7zhf8v96xta5g9pa8fx4a9jh09md7wgp4ft5qrmn9jg2n0enpupuqdavjlcejaaje47a2satjg8l85rfsrxh0leu4prllh8e9gzjrcq65y3a3punamwkky268fv39h6tx8dqdrlkewuufzaw4lee7kz9unya48a9wnrtmyvctc0r30nxah07k9darrn2088exjsgyl0ugz4tync2tkft48p2jmatwn0gvace42exnwhv5rg60e302qs8k82zfj3n4q4lclvxy7wrs5ewrehqsydm65khwjr9v40msegfr43nscy3tepnwrffvufuegqx3esu930upxlnsz9nhupch879nhefjgakejedawtqzt0zytat3n023rr0fqf0tf3skrhft5w8hjvvs6z5xzu4d0rdy5x30y7ls0syffc4rkawkw083jg7rad589nls6e0ulszrgrmcvyj3ekw627vwvq2kmcl54drgtx0fd8gcq3t3d8uyze0xx8expkf76tsnc02vcdpm0pl8lsscyhy9c495qf9ewmc28ur28r0c7x069c9zcpyuq8yvsjdhagxf6h4j5zxvzrpup8vdh5pdyncf8msryunetkj99z4a7d7z7dkhg0xel2gemdxpddqd4pahe2jtew2kczhh8e9mjju9guy0smmxq0qkqs7f2vy4hujdfazz6zz9l8kemk02xhnu4cw3w8hqz2ualll9qnsx6legm2djrppelejcqteju58klhuxw6azlkyyj4d5res6dru7nf4ek422pldx8nv77nf300uwyduqzhvcra78qewwjw44zmke80ekcueuwqrw4swvjyswy4y96ln8dyugvstx24rv3n2rt3papv228g03q7dups6qutguascwvyl2hmy2fjne80ferhvfpa6dfp36p5qdjulw33kx6fqekqtg3dque5we6w9ntyvhk7azvg7kqgmd85g2u8ujnxjhre5du7jmzpy4mndkwtaehjxj08yq9rrclsdtxglwer2dtyq27hd32twfl4vt2s27pzd3jn4hkdacsgwzxx8d95x6ek6cq90pefmjn40jpx6nsgppcm9486e3g9njpqjhpkeakj9rk55gcc02hlft938h8sqh480xkrljdvqn23d0r95levael0yxqvyfn323tcw03ygwq6gn4ljkk9wsxudrcpvkf4z05zhlewaqmeefkcm3n63cqxnwwdz97pulrwxs2jaw52n609wvytk0ckdcjzg8g3vfzsyushz8zj3tf5j27vp2ch2ywztu7c3mt3ewjvwfljrhlakxmmjt5n338a4fgmd4plv07za73cn4cwmw9sq66ecc7hk2sw925rwusx3rs78rmy2remtuhxpevzt57tlp0yrp8hrx4nxpu3708hrnhydmr84szr6ta0qt3nunmt4zfzhr7wxwhkt8y325f4tpwc7tcqz5nt776ty6dl3h0tpgj2lrpurqj5gzsg0smuf23nes9n7rpgh6vrdn0jwa85dlzmqhtzgrc4nm6e4lzjasdk9gthlnx63actw07p45rrt8lpsnwajferedmu4fnwwku2ja2fdcwgmqxy3q2ju58hfcuzrmpkrwynu84af7ddzducx3c5frhfsyzl2xcrfr49mgfcwzpa7qkl6rz3ghx3rf8yp4qhytyh9pytexcf4t9gxcdpq684808qsvuktxjup9mrnpz6qp2sfv9w0207x0cp9zc2n6248x24wgwutqy6m58eqeenze8lf4ya65gtmdsf7utx99ay45dlv3689vfrg92j3zw5pluphz8vqkhn02jm3dnqrzgph88m87u545jvk8yu4nmngsn89zw9yz6zg9y6q7q8lzvggmh4vlwxlhwe3x76fc9zegzuw3pxz4xk6j46k4dq8hmhm04a59w7rf4l4alslyf9mq04ua35cd45ejvzvkc5q5vc48n4z98xdnnhzsu5246m2d7zgfpdnm36h5ms3d4782cj27r8rqwy6au62z7x2qcw7he0lnu0zma70wr6ytnr6fd9zyfgmvd443xerr5j2u4hchu8qz966y3vcselkmmac42swmc9vyfvqetq046pqpmqmxaw2lyde4e7tk9ru3tr9q78y2p7sr2kg2kcdfa6ngl6zacsk9kuwgg4tlj9yyy2hpvxzec3tfysj8mv04cvdfpe0wa7330mpjxatzsel92gete3kh65uq5d2vpg32fuw524c54ketlxlyvqe9vma5cqj48mx3jctxa6qv47q60t0mv28zs829567qzw3mukgwm2n5cvqn2s4k06f4wrzrmptyjdy3y8wnfkfnret0yg6pkdwj9fwe0x2xjkcc90hcu2r4v4ec86gquklwqnvxfht4p0pz9l4gja6gf0chgpry3c7nl5zr3acnxfn0yzkg7drfedsc6amsxha2dw2yly9v8vjjuqsw2u3ldlp2ptmp9h9djsq62u4rgh3fkexu3xrnuat3gqadxgr6q2tfsmapw603s6r7tgr7tmf9fw45yavn8m77xa6z0q9rq8rtl8sujpam9mp40pmh3v4au3sxd6dfp2tj5a7yukwanut8fk8pyff3253v2kh92qlrntx6rlup57ukg2ag4umgksmyhrxmweyyze2crf9n6w8y7dktly73xwysff5n2lqgs3q5a2kyt409hzygat5uj5jje3jw3egts8pgdwru9gu8y834a2dxmy24fd5gpyaqhld9327tsp57wq5eyucrs9ayk68v6c2muq9umn4je5j2rqg0lus7z4wlfgq2kem64z9"],[8,"nolgam1kx5pm2nz860ef978qrv7tt2hn9dfsxs0fgfywe88c57thfmc9p06zmu0ty9wag8n5s8d5g3w2k4g736hgy6u9le0ph54sxvk4wzvv9wytzhxva02rsmnlk69j64kd7c3fdkx8q0ncctpt77rajcmk8rwu9szzs9cw7w4u2zvl4xcmha3xjv5l0jdxcjtdc39u0cvn6z9hxzwvu059e839mj69l0ydwf0a027qtxr900zw0gspd4fkx2tgu6zfywt8243k5q6l59m2sgl964l6w7jd5pn43n48fyasvw0s5826ey73a60r90w2vwgyydzzadvfyt4va3kysnxjlyk7vfgxzsv9mpc6gypy7cjr4f64jghdwmke3jqn965n093cg285d9d8hntawx2lj0akfw44hjp25zam0v27fxz86khmhfjj4ayk03ej0rkwuff8lmc8033czhzep4xl4t2knc5ddzaeu24tltr2x9da50y54527ucpxq5xlwkdfcvmsa2nwhahluld4sllxhffzk2d5un69lnazgzsxkcwp5fvmmez6r3cyv0g3g3uze2vw09ssyw6hcyzvtdazzfsayu7qw2kh94cyqkdq8duqwr2a3g2pr7ec90rtejjcdvt88ggewgv7h6he2zuw97dgq46p29e9g78yzs4vulmm2gu73khte6fsukq7jqpatp3mjpj68n25jpf7pqehs969gu0fs0wsqhe360hppwh4a5jhmllt6x7n2awn720cntl7krsstlnt794mx0p85ktlfs5ncnu3vupuaerw3p62hakhq6jzkjkrzdx08xjyxctaf48l0wgldgmtpk9w7t702nf660vvpe487ch0exdxvgse5pv2hxps3r9wmqg5du64gtku2eqyumqvrm36lxdl73rcyjqpy8uqf3xyphlw8n29qls5aq2ewwm6u33562yypy43nmlhj9a8ay5tjyslv9dz45ng06t0uh948msgcrz7e537ey78glc5dnsy5exa93gq8f9dymfuq3254h6nv7dmt6wxm5f0a69p73sexj5xd33nkn8fcmg0t5peevyazhx4vraxzqfuncayllg6trhce6twxgmlhur4tunm8zeqp99v8nurhc7s2upzls5l2vgkt2ffgkqn9x7qxnqeg0vjy8thahvwj7hes8dd3zkmcmlryraf7axsfhwwtk6208a30k6g2k7hkcnr4dl3w3su6zrgq36tz2qq5x6wqjctypqn9trpftghfkpzqjs4d259pvx8v8zhp3f58hmlt90302dwmezl2s7cwgw4gumsljmx0cphx2pup8q4xgvcwsk5p9g5qhjcda72v56c2h297tr7qcjx7euxf7k6a0d6yt3xgrj4x2glu0xkq79z3jjjt72lqmh83s2rv27xrgcsa0ahezx4azcgufextsvhrpdkf6tewszswh2hpgr2scha9eet7qpp8wnzz4qyd2k9z3qj4fuqq4l37jzjeejfy7hprlk3azj4v4n38wwal5c3wyz72jtetluehqlg4xyw5vzu9jzlhas9mt9p4rd87rt6ghrfayaklurx6zcqfen895sseqr0rrefm6j6y7grhtldd8nlwkcuvjm4dymuwq4zyztk2j6ar6587rqgywveg73z7kwa8v3j3jl7vsrf8u2zsgphluw2ruf6dc43uke9f39kdepla6gdy5sllzq2a3rxz56xcrq7q2f69zvvlr3nl34uk7f5umx60l6ax7jz46vvxapwhxu0836f5nf6jwjq8gv7hqsx7q3zcfdnf73ethsjrak5q6hn2cr9u73aqkt039ts88e9dgz77ggpk5umacpvh7yvsmewh7555l9s80q0xp2tjq2fvrtems2cq4vhqxagh2gh4vz5dawmdrluz3sjqdy3arn498xaelta5sqj439t8des57kj422r0eqh00p22wgqwys4g6pwayl8329g282mhrr9ec6gkzjqph29kd0h926ekzzg2l9x3yp4uxhaqaudlefetzepx4r8mcr9wn62ep72fp5gmdvmrpxkyxfu5wcqqd3ld05wjacft4tjmfjvy0jqpez2r9flh2hrc3qna8j3ptnveu997lwc6l88jreh4kc9jk7hhghfh8ynqytu8yjax7p9a55c863equayklz53shhnxn3x5stclc3hqsv6quv45e54hnq663wu9meu53c28xurfgmemez5shlzvtpnw8aw207sf583r7g8twcy4rsztjg9yxgamrt965pzx7qt9lmz79utp20y26erxgwk7a32ty558dm2d4necynfkueuj4ud5ejzy6qs8a2kaxxtatcr74fennnxjphrq2s72amhyg4szpyvtjengmwc04n3yca5gea2xca49g58xk9mud8uj799fzdqgqrm08puwcy28z6jnw9stwyrwswwxrujwj77ry0crpfcgc458gwaw069sjrpfjq6pceja2wz02pq8hqqk8mns2z50ra0xenvn070xg7z89fchqd9n8lqj8px5qwkgd2kwg48jeqllfzmvxc3724465slrs0utuuqq8c3vgt3r68jjh55dcmjlapq0unesqe457slkamv2rgkl7pvr4rzxt3e8m6hrddcntj466x3rhl9g6kn8uuwp5pquyv4350d4ewjnvzz4d5fafk2gzus3ugkvjte3tdmyg5qsdlhhumj9eayrm0q95czzx677ke0j7wsa4306jddqza3zrd30mmhwc2zs7vf77en2tj8xzpmmv8dvfnffmtux2j0x992lphwe0nuqg6zyfmz9warmk3zfadafcnr4lrek76v7nscupapju0p8f30hhdkf0dcyazzc8paq99s0t29zwqmyxwrfrufuxhpaaswffp5t9mlue8qtrjra7ukudtk0fdgcdxa8g4p3p0jy39ydptceznamvtvpd7m0z039rxf5v8g3kr0gh59earqx65p3ll5u6g35kyj94sc4chawxttdzfj3jhj0lnv2dgl93sn2pg9efwv6tfsr9ppweganlzlp50w70aktpfk4fxx6wd8ns83pdda3zyfqadyhcpfjwxmrmejj537cnstszhj3q2zascnys5m39qy3f3afhh7wlg5ug8nseq8au9g74exes6fgp2zvkllagzt3crqmlhk94gapennpujf3e4333jfsca4kwndeyeccccyuttkqtjp8a9k6fheg6nydqyd4psu780xj2tgfyavvnmxe6tzwrnq6wf2w8ed0k9x7tvrp85xtkm3sx5vgjrh6zjf7ahfdm0mdwxrsxeqfhpaqptcp8ctfaucdlfjhlf4svmdl83qq6adntrvl8qk74f5pdch9fqm3ryjn04emrrt4guskwvj0ep3cdxgytz4q04z57u7pfncphtplnzcyrm63gz009q4g"],[16,"nolgam1ua5g9skmm5d4dgtpk0vzuj4xw7k3ye2x07fwqnsfp0mvt6f8gnmhr879jmh9tq3pdz3xvfzdg9hlg7mtl9jflw4kwqya4676r4cevsfrw4egr4k97kfy8n4jwalkjhlxyx007hxw2q9t5k4ql7ykvtz3583rsxxwhd7x05rauvzmlzs9mxhv6fst5xt5nvgc9s4yy676xlf7c4vd7977zlpepayayvq6ehtk8qp7prc6a2jjxtl282n94qj5ge709ervmf35260r93xcfxcff7eqyc2c4ntvjj76gj8ptchxkezltdc3l7mu5vqnjeqqtqntw7j97pv2w0za3e3es3ufy6m3sl9qwg2eu2gnnpkz9lakes4dwqlzhae88qethtsdtfnkp3uvmpd2uug2r3f9uuwqv0eu0at6mzgyzxg22p956vc786ujs03l6gk2lnkmx0ktfummwf9xa4k0vcku5cglx2ahxjwhtdyj7vvmevacy49kfjehf7y9dnj0czpf4ae83l54kzvnlsatvpcqxugmurke20lzerq26vej8f22d88nupmlh4wzwhptptmpr4wz259nj4tmcfmrau7yp72x72a29eutexvwx2khtygscpukzmdpe99rx8h2ze59dfwaq6d68ynvzkcjltk7zz8y9eh0ulhlxy2gxueg7pr35xv5yakkf066xnf4nzzxq6x08tlrlhp6eapquekqfyq68d9nazg2jr6a2ge8086jm3neeajjzdfwkztwgxd37hrwah325mhpsh78ysudqxw57r8y8yqqqfqqxvq0alx09xy94h5ukx6ecuzjf7z4fepnhpuwt4l5asz6az7a6q0r8fw03jf35985kz3w4ny2734uhxlly4shv2usex67rfrl3hzerqugs0syvmtuw2hf9hru8ed624xpy4nk802vmwa9n9whks7jg3hka7x9v8enc74gtc6xj4vjjr0zt0dlr4mjufhd3lsdm0c20wmwnrurrax2l8q0q3f98guf2nls7myr0rkjn9mswd0fjrxa7afg8zhwrhterejm592s0qsml3mynwjqfjdnpx6zfmhlz4wyul2q8txa3jyr9ekudds3c8qkasqhn7cfyg7sr8rcys0jcgtdh62rreyzlk970gzaqplkfax0jdf9dar5v55m3l6fweqgx3lhlu5em3ae9m0202zh9k22s5vhl5qyvhkgsxxxcvn4wv6nnn4x8gr28qgmwk45q27rldkaqvphl3cmaql0mr57kvtpmd2re08nccx4thmunzs2lzhx39940ly20q3eslw9egm69kjdmz3w466u7s4avra786u9yqa6jlwjyesytyf35nm2sz2n03huur4y69jkdljrjm4ne6nphksxj2yccs5tg7m92t42hgy8w8cu08rt7q6tarpdhj3g24kc70zjyxpmhc9wj3k7dsestk94mn7aaysxw4l8rv24qxglj4l7fukty6t64r9dyzc0nn5hq4spqzayq80h2f2cyu2dqc2lj6shj6pzmd2kpugv4hpccsy0vw5smnjyhnnqnq0wr74l56u0srkfmrh6d387kym25qpv4u4e8g39cw0x47wlaxgks9zrlg85wsszmdr0rglww2x3r6mcyl83zxl9l47f6jdyakalftcals8apjya6370t5tsdef807zdza58vdzwakkeulhh55kyx3f6tl53yrzuz3ars7k6dv402ft0fh6eanqkspmkq5zg034zhakwefjm52hpqlp67ctmdmzg3q64676uz2v9qyfv245ra07m93gu8zldwt7l8r4r7uml6v69fy5w6zhlh3zwtp8wjz9fppzjnmmkg7vn48qxkescvcn2t47tc2rr9te68ptsca4y8v0ud0yaha332fj028ujqfehh5t8q5m038cuys7mp4nxv5hnjdkanrplfwws3nwsy34gma9seze2t29dryqm85yhu3yll5mu7zcup975ak5s5lm40k8209gsh5ytzd0ch0qtkdl2uml5glvv8u8gpdx48gsp9cxqh2ca03vf50kq5y4gd9np54lgtfd7x7twu7gam6uu6n56cyyjeujme38wmjd30xcv02lxg708dleckpyxhlravc9dd3cecd78xyaj30h9auc7h9szqadxfjmp4ecx8l0pmse033fxs2w78e46a2jghlyvrmv0hax75sfyynl9u3y86hxn3vp37npgzzn0qqyu766kv8l49nenwpv0hvjqqh5cvgn9mkkfy57zqttmtsff4lueqg2z4l0ksdmj2wmequzsvc55q0nwlmczvp7hrljgx7s05uvuhrdshrllmvuut8r4pdw9rpgyp7fnxgs0kfu5dsf2vjlfwet33duh4jd4hlhj5hwtrspauvh0hydsmsn9genwwtrne3naynpljktdg4j87ptuwemdsh9lkh6d8yzzjegvphte5rgwdqxyvfxmkztwvl49twx0y92rmd424v2kxr3lldvlry9wyx6ajza59sypx6ea9tjsurv6q9ttuppr0qp5d0dct442zr87kex5a06u9k9zx0wp533lk9zw75vshvc5upz53uaqfeme6f0r4rjpwryaxuffm8nlwafzqne330w3rqgcgtqrhd27kpw00rxuw37d5clq2eqhl2lzrtue5d00cwevyaqtfvuf8esn4xet9pnnepdejfj7mnnvh5qd6l572wm0377c6pyhn6cmr0yl9jet0zssvyqjqwmx2m84a6aw8uff9rzsl9dvkkf072sayfkkgad83mxkk9nzd7cu4zajar8hfu3nypajjf6pxn52nvsk9s30xhn6fxj9cv0ek94ffrhg4r53ql4p935se9fumpk6clfrd4kuxyvg9akx26sptnhlt4wjuup3xpjm2n59plam2vkukvh3yk7d0556ktufd07uf8yt40femz5wx0724kg6pcfxm483u3n4s59mx8r3wkfvxh3zzth6d64cg2eujtegy3k9fnq4zk3dqqfktzxqzym6yvw80jac9gfu8zuucgmej742uu8997045dazu7jwkxmh9guc9gt6u53vcnhrhwgfvz56ke3mfa3ytzsla5ejztvyxdl7n8awk75gu5nrdvhz3cyat2d47h4mdu25fyz95ncqcpnjfvr3num4zjm57wsp6e2l7pp3qhpz25e2mh8vexk2d9kwqf649zl0ja26ph0pg4vtez4uxlx46zlep7qmw3wejv2jnup04x67wd5x7d904vmq2gjj936uqcd8ywj4shzjvaj53n6tcpheuxlh7wd299j04dwkff7qsz439weaa9tvzt2zl82k0pz4stwrwmgc3kg2akhksgpcy3ertn30rufv7p9w3ed3wypczzg9h47s0htxfk3p67wp8zjzsmr4erw46eyc32kuy7km69gqng9"],[256,"nolgam1szfq5d9k934nnwh0hdkl69vndu4g4cpkss6krxalt6yqc76cf5zfaeczxphxggjgxj4lea3vphun4guxmcy2g4ukq8sndn4jzdrds5mny393gp9pqyr54upct7zfp4wuu96ea90rzwwurv0yf5a5g0fjmzzse9pwtew4q3men4rxsyn587v4vlmtgkld7l0tckqj2l9qrtzur7d88tx3er9ac4prrantagleayux90h75r4sw8vfunxu9d7s224qjm6jz3j3fnjj4562kfttlgygsk3a4vf98wwhcxkd7gp6pun2j9rmphg60x9jcm26wagnryzalufsxhve7ffanfxvj68dwug7s7mcna5jwpvklyn3mq6ahejmp5vsm4uyf9f9h56ywdaq5d7uglcgwp3d4fe5amg874p3ea58ka97x6re5wn5ghanq2rsv35mfv37ntx7nf2r7tkvphc473nnqanhxxdxcw6qfyzjwv6euk9au3xafp7m39rz75sh5nxs45t6k0w2q28wjwwehvatajdufnc0ral480d5eln7sayqwewu0sdegt8sf2ar5mqe3x6q8tg32743y0w400jqpn4x7jw7utawnelkgaduaexap89snnvlp2j6dgm7y8f5q8trhv3tp8r0rwasqf34qlu6u56shm4mpx7977sdund3gmy079sxn26992y8pl52a6pks6d7n99wgcjphp5mrr6rzk4yu404gxs9gfvyedetkcugxjx7lry7semc4pyfl9802xthdlw2qsrl4hjuz26tjj2xesamc0qewllmv4wk9vzgq82t9ctxw6cr2ahwhkw5sryaz58lt6lzj545pgmq87zkuqx0q4txf7zmd4sglm9zaxlkmptvam4r6l3clp4jtkarm5lldekh8vtadxnsyz4tmae2ytsadwjctu5phklk2ujp56cdzr0fyxh5gf6uce9p9ew09404m64n0nge5nuvs8rlp9cgrjam0zx6qejwdv7l6w8tepk32s52twssucdd70uhkajautj4rda075hs9z2vw9tdkvutktugmqxwdehhhps6kkfwtn68p8a9yn0lv50cvlaeyng8erudemvye997xat4s4vd5rfcwnhryxtsnp2j42rc5enunej8fep2tv2wjlgl9gwsg9fvleazemg2tftvf6939clxdnanrsajuqlev5nl5m6q8szllt2x4clpjtgpjm8j78596y6udkyuyr5x3n77g9g78amsuu4hkgw6slklqsf0azms09vf662hkcmhjc350derssss7qupg4z5f6mawe83m64r4m62an85ene8sqg8nlq6d72snflduswc0ruklc33wpej49d7j79mw69r9ws9ykhaayausmuk70c649vvnctj0rjmngwzzyufa928h4vran687xm75q4m7jf7s9crryd63hfrcc955dkuw0nlf2hhlhyauq37qn7caquutazat97qws7ga4fxwnhgepdsemazc53x6d32yyka822jc5ufur4h5z2fh5t2zw6kxx7uwkuuvnzweeppaf4r333qv4s4unw58tze8c88z7ve4ne65nag3w35d9ur092q3yg4jjjd8lg3lkwkkxev8cgje4tedt7kayzmtpksematt3s8ackzxrjn8vfefklpvsfhetm7c6m3c079dwt93nee43ehrnx5c4esjeuqdwpl93dalatqpfyjkaqc59ewtdhvg5qjxd4p45mlxkkh6h6fjlxqfkc7ld7723u8jjquscggdph6hvq0g29s6hxxncyv9mrxd40p3sa748fj7gxyutkkr77ee0wtg7ulayzmcn95uq66qxk87g8qw9n7ugtmfhqhad33aeh7re764m8umtk7xvkv89g88cj9l05dsvy3nqgea8vlg2ckt8667szw452yhzmgy00lekdftec8fanu0st07txxyfsskurlt4u0djumszzfsal7sc5zacuv6n76klz5lcqzrffzahnfxfnljjr9nxczrdnfdth4klqkaujccvhxa8velz7pv0rxzqltylkxsywk5s4nq42g06n6eh6gwdpfsrrk8035jkxhqqmmqj3jwrdgfyrge0smhdkvp2euch0yexedkp7gzl375xsthyv0ey74fdz24kd5p4nnmxv3t2u7yv3jw9p9ng4vuz0yah9g4sqc07kms2vafn8ht0a9sra8vguz8v9tnzz9u9kvgs22wnngtqhter7z9ce30qmecglrvz8sjqwx6p2wmrc4ncl4h9rwzrn00a8f4ate828k6vrj4dyxncr3yf2wvk6cng53jn8w5sm4mnlxsukrfjge80dfg3un4sa58ghcfugf39g7ztradd985ejtlnurjg0pr2thjk7vn932cnjalsu5fhvf47uz377dwqrggt5e69kywjhy5493uvrmeal2elkum83gcqryxuajd8mrpwun5q5sshxqvgkdxvukxv3wtc85n92ylqgp47d4wmlw9qakrqazj3wuvr0xzjupwnatvd0zuhav5kuutdh3nsgh4sm5garajt204g4uumsv99yqn9nr4x5l260dwvhreaqhe6h83d6ffr8efqncrp9sj7jh0z62aehmxyvzkdfjdtjvm8dqr9r6h3vyfydveqh3rumd9cum9afn2c400ycl8w2mqw3d6006ze5he7pzkmfpy3vyrgeajt6r0s92hjfq8txz34d50tj4kwfuep2rjgcuyrx80xn6jy3u7ppnnux2tfus3mf7gc0ynzapa07v3rk2k4c0vsclmxupaj4t9tp7ckdf5amvcdevqx0kaqh753cs2dhegq5zc24v9a2gzsypusjy4c8wyvgzzv2mj6a9r3g9wmst0kywf40x5nt8wlc0xqydkjef45gdqzgajwtrw2et0yg65wqn8rnfd2qgfga4fgmxu6999yxxwdyqg0e56evd2pyvrkjphgt4830cxng43kvfqy9l34jqa5jjyyfefzg7gty7hnkcdc3um9frqna8z8nv7wzu4qm8dmnn3ajgnyecktgnm3rn7dpz0e20p8n7kc4e2n5m8vnsn6fmy5gnnt45dvzw3zr86p8jl6vpnvl840c8s6thrr30zuqrg8a6nyc4nfh56j7yvhh9cgld0pypffdzlrppfg75060xr53p8gfcmnn2fmp8vqtzf8ymqlvugkrzr20wpygzrf47n0xaujdk5ccmgulgf6a2la2f5w9u0l4hz6qehmjs9hlu4u5xmcm56vfkgway0zjykmxdtrh8e8hvs9cl3xn433l403klry73svs3g67ga5edc2vzhmjyhgqdq2llly5q7ft8gm6yfadnhszlumegjnlx2yj077ee84plrq2w2qvs0plhje6zz6rp36z9j3m4jtfff9qf5h0ua6jqc77tek065d480av"],[512,"nolgam1uvqfdlcfxv9eu4uu5qaawh9ggkg40g0pkvnrgyd5hymt2qyqpj8qwzxkxwtmef3ylxyde82s944zkh7t2d3ff2kas5yf86xqslux8n5gye7x46g07kxhatctuvklmr9e5pqeascmw3nyucr5rrmmz6hlkf3p5zzujltssl0xq65yujx9avq9w227jm0lss6aw2ztydznygw5m46f5mf5r8s20hvd54pk60wr3fenjpprehzywq6muzl9t55c2xe3fnracnemp45fpe9w2kdm3c9th7uz6l3ayelx287mg7d7lyt8g55mcxnkl29yw3lxxg6rwnepl5w747w9pwkefzfl2a8257crrce5lv70wjnnnkvnuvfcuqxq4en7ah74f4mxun4n0hr37lsqpuymc4x6rfaa5h82jjsxz7vqyctc0sfh5knuq8v005ugn3wkfdqsnv5gn9kywu9fzwcjc2dm58nxp63z8vglzxn9jyhwh73rdmat58g0vtyulhwmmgne4y37a9t2jx4e73xpwzdg577fyvhf7up8tl2tdwg2ld0jg8ephg5p44tzl25lgtq59ju5e5zl6ura42v72es455qzhdxy75wm5m3xq2v06ujk6zu0ay7sasa9t6pzxr45pv27k4wnch43m33ge5t4dyerrkjz7upkdr55qq5ecsn6qcplajrz34z6a27dhdzkjvsaxsf76kly3cdtes8gjphzccz8qa80kath9yzk0f3anr80kex2lg5af6ks98c09wpsrgpplxcluz465kmqtuvq2x0xjfdjf47vht5unvvq36w4y8jvmf4p4ths74ev42wyvz2je64tlpz28snqf67m87xwzhdudqstam9plu22xgtg4f4jr0kz79eugzyk98h7rslh392ykrg7exuls4llwunjnxtkl57qge2820y08hjtfj8dxln6x50m56kgyj9m909rws84a6yw06980y573sttkplc6hkrucx44pxyvt30zj59mqedluf5qmv3694frh8n4h4tkzxvq5006y7jehtl05v9zqcn8cczty66nk06vmtpkp0ygte7cvuus4l24sy8853gqj4ntakjr8ur0dwk89sp2uf27qtuyq2yae9mtcql0sma8jp5hmhcw4kv2scyhm20ppmx6pewhfjq79avj08zm4eascz4fcgpe70d052jct6zd2qjf0ej7lgh87js87wafepdted7ds5vkh0rdag5x0tzk446nu6r8fcddnpm43eqrtmklcr9w2q309p7xcgms08df0tvv9p3pdjeljmy5yqcw3x386ffhkjhh7f9a0h7ldh2rhgj52a2kqxq9wnzhn6tflpuvdwpxeuw4jkttpjg7t0ajt376fc5glmmnnuqza3mxe5lx6cdyvgrstqdm4ww5qr5ufy9au2mtxdg6h5qej8qxqx2hdm95xark02sz4067cnjd598s27hp2p99ydfzep5884t6k0wslc8f6hdjr7m4tslufz8tkpcgzv73q2lee373jr90lwhx5p9dz0ccq59wxyp8c0n9r3h9edul5s3lmtlre7hr5nv2zqnnn70f0qrv7v62xwj77v6t0fd2jelucunsrqwvz3lkzlzw4p3z70gc05uhwgr7wr3rsywtwqc8payunzj2yza4y28tmmwuanmacgsf9dv6h9xfleam8pr3lske56dhkmq8rard0ls6zmp0y075g2ck94du45g6d30udau0rjeg5n5t3kqw3ujazqrvry8sgq6dpm6chlk9xvuqn8nxmn4w77lf8x588hnr0gc4fa8j2paa2vfgrc4w27435ywx25ml8jqhz883zlpchprrrq2yacs2n653flm08se2r8cq7j72gtek5wvajq0490g85gd0xdttn4ge8jmcv2z7rfzs8ktlphcatuej4efs6kf5pf0hjd757x76k289hk7p0pz6y33l6j3qmnxjjc9dr6j8tx4awqtx069mdxrwudlm7vvwwdfxe6edkttzgzd0dje5cuw8vgtycgw7yut03f6rtuvku35fzru8mvjqz5r2dvyj62lxeukz3uk7fxevrmdc3tjv53j3872yay6mnzkxnx4exk52xnrnleskd2a0t85fdqj86h09qlv4gmq2q26wwkyyfd66j44u0wwuacjqeafnthehjzh9n32mmuhzm7hhmaa7eelvdzqg9ndzhe9hahgpcpaer0k23xe6l0p925ym5s6ym6g4c7aat6p8vwa8k2pcfusf79xx7x5tdk9u5fc4638097ngekte4qmcpz43mdtg30p33zxxakvnwkg8d3t930qu9u9tsgfaylsf0407nw7fdk9c5tclk8en08lpr4hd64nfk8lw7peu05a4p35q2ynt4hg4xew63vn6y8rkk4gzun6w6ttr67u8sxft7a49dqy7nkrxpqdsxl3y7sr08fhuzxzlnu7swzr9v0sy62j5qx0xrllwftpx5fmrpfwdaxs2p5guwg9lj7rzp5kenygsqc83amxajhjc72w57lu0qkr2h8p9q04mg7e4q883p4demjm2mvj30xq3l8cz8qq5wajxw2llv8ghr2cw484hhfhjf5ktcvyxg59rnmarsrxxw9pqnqxjpreygaykln0gzgu029qjwt2nzmvpgydmlwf2xghq4cxxa8knuucv0l9ymkjhlycxrtyxxwll2dfggyd5hef92m6thsuvzrn9c05lmt5up4epjq4vkymf92sylmljyvewzn5u7ret4qqd2d9q9mvkvtua02j7slsw95pt6alpx86ex7hzh92xlandy5ycdquxqcg9rwmwqxwds8njzhzaxafkgdcrx9a8exfxg6ec6laur7fespz7wywkla2f4luc77pasj2nfwsqv4n3knyy2jt37a3uawsvax23djeeulzs54s8pf0kh5wyyd02tqxy2q8harz4new9atjzz7vj63vpcmafdd2lgj84ku8566ppy750qqcwfl7gs9x3aecs7my5pw0m3m269aljndrwsmee6e23x4luzpgrt92fwkt4488zp8lf6spv7tjmz6trfdqweedt7kc8jp767r42sua7nn5ckkyst0xsdtjqu0t2j0re4nlju4a5mnc3t69t9s623yd8qk7td36m9tgq42gz8s28unwxahm3ag5g3t9m2up7397wurk922l69cgd9r6tya5av96gpd5d2ftsncm4acns38k9g604h2qg43f55hep63lymtvg3dk3nlkys5e9rpr6gk07xt9ux9l2x2g7zt0hmj6fzecykumem78u2a2q5t8crhuz2ma3ageln23vswht7xyze68d5gveylrthclvx76rcmlh0prhe2tl942jc0uegq3am020k9aduvlfzqrsselzh8fdw72k8e3pdk4kmwkrk0wt5c7jckd5fd"],[1024,"nolgam15tmmmxyrvzmy3ryn6tm674lz8v0dsltnglyu5c3e69e0n6flmvpr2rw92a2lyxzu786h2hhkl0hvdv4n3kh7c4eawhjvzhxr2y44u686tn3whv7g0f73reem7qs9h5vfukjwchg8s6vnqp2majrz9emhz08rnesywvvq4h2jarc47v33fy30a5699mx4led8r6p7qnsvckek29a9tghs0letjjt6jh0ty8np5fp95vd7qhd8sprp3l8az04gsdf8tk7qaej4d5xzyra3pphz8jp2kpnxhetny9y5wr7fcrq96znsrf9skh2mzuyc0jrgckwdem8glffd74sfwcvsqcwavpkd4pxh4adhqyl206qugj883trc64as8m6r02a53lg6x0u25rc2kk0d83lmc6e46wn6tmql92rs6th7th4nms8230hpf0k5643v3wn6dctam68ayah6eh3nt3dpcudyne3nhf3gs792ync5wjevf0nke9v92u4qgyr4ddhl33cqmv5rk8psc8c9taw0mf8fjd92t8qmt2m8x0t94flw3yrmnelyas7kngwgcjw3fj2nphkq284gmg0602y924jumyc5pmk5l44kdf5f68sh80dzyty4v8r0ukkd7s6apz5209f498z0s66v8h7j8qqxnd5hnp5rqkvqy8qja9hyu384vftuv6kksnhp5gupwr3j7sd6xn8rt5zurhu5rmfsqr8f6kqxjtsezcv0gtnlu5srnpxs9nq0uwejmc7ffu4lcdxn8jtfeqw5facxnqh68fx8mcw9w4tdts6v2q6upuzxyuxjshkpc4fzvdxye7vv5lq7sw6fs4afjkuyxmq827dwkwh0frzq3wv3sagkyyjrs6tt5f6zvy9y8x24dhrt04kcnzusv2tl54ycmr7new04cjfek6ssrl90q86x7mwskgr97f6d959jxea4ndegfxx9nm5rpqfclhsr9zl2ssykesnfrwj75xcp7znqpt4722rcfvm3xhkkad7f5zs7p4ccq239fztteqegr09sh6e9k0u7h2l2ylfahvx2z73k4kmlwt9zpxkntwtpuzrm0xcg2vn5n9q8cf0hrksc7r460vaeac26j9jqwhnza8k6gy9vmetvjq0wug9qrrc8zuk60zlnn3e5ye64fs0fnt6rlqfrja3ldehkn2faxs0lqv7vndhr4nxphnx2am26yeplsvn52c4ky0atr38qxkum80stjx6lzd459sy9csre5jnqwmpljvpfr3wv6xzc94ka59ygyrn2ldpxqhtl2n28zd87epd6sfc9tfqssdd2fnrrey5h5xks4t2t64klardlyfrth65u74uv0cl0wm40xp529p9cwy8w5rn2tw3pp325dxwqdyukkw7dvpgh7a25zx9qhewgu5hfesrr06ezvlddpmqh43e2f7f8crae43vnlmjxct392qr6f0wcxnu2vk9yzth6z4cvv9vkus3fmcyc0rev6ms55cxeuvan0ac6wkg2xl23sz2vy0q9spqsxq0ap0huka4ra6hetjhatgjkvr2e9g0em75wqg07e9y3ljmdujghyuf943yuq0y5hgz5c90ckzjm4y0zw4ftnasrzknnm3qngphsqm6e2nawj5fszvjua9peys76ctlh9gq0vx2ysd6umj0vsjds8cr5p90nseqauueeqe86qykskcttf4hm9m6qjgypl8s6u6kn80lt0wqx9ts4v5zt9hqc9xdm03qs3uh5haf5mdv06n3360nqg45vwhupac4ys6r7am9dypmrcg9q9j8jxj6vlamvzy2fsp974msxd6y6r88e92uz9zl53pn8lrkmem428r29mkr9p9xfw5zwwuy5x7k28l5p05pn7ezwvt8jkuaxm3clavkh3akel25d6lqf6y44mukru2fu8mxzd7n82vrtwzuysvcwl7hj8qvxqmxwsg2lyua7f3urkvwqz3hzd4u59cjjsg5f4ajn4kq9yu8nfhmr85yzy743xrt4xq2xz7ant7gpghzcygfzsjwq3h32pygvm270jj2ymcwjn7df6767fk3hecq3vyulgjvnajnfwdl3hj0ra9j3ntudxvsd7rnclptrwkn7l9ugznkut058cytax82z5px0376j3l7mlc6mh3qnfm82x9fe506vrdtvcfhtl4066xxhesfrjl0ajav5pvcmka6k4gqvadpsft5zztk9h40yv84feffdp2tzu08fsfycdz8hfcste0rd62lyjclmqwn6wd7tkvttge6qr7dz6zf6ahw4khdvjd3vw0m8e6qksplyuwk2yyhyh3fz9kl7fnx64c8z22mufncvcx90h3hvzgrvwak7eyfzuxaqyq53xkh0t2ksvl3vptc5e725rvljw4nc407yr3d96aukuyn3yrgvfe2j0jvvp6q72ycp7xdq7fwumnegj0jhqtkpfwqjzk7kuya5uznpkf5j5l82quj8zv5z3htfzdj4y4hcq8ytrph265cnhs4vaqazjx52ex8nxsjzh88ugv54wyhp0zgmsna5xpgwtf9a2tse6xqa9hn23s8dmlhkvcw00qa42u7dzxfp3pcz7vc8ffeudn2rjezqyplk3x7fx0nykmcdazphpwrvwlzvgk69autv3ruefaa9wda5xxrrvfpvjjm74ac3y4dvu9s0hlpkmmv5t45jazgpgtt6zz4m6uv6qxzgkcynggxyedte8f2gp2fw7mv8lq33uc3u7vkyyclz8x0fnjn4qgh4vsanugqy93l5a348ukejnz74swjvwxxdljad62kq3arcdw3kgfkcmzyk8a9v3kg2zrvhxkc9sg9a5kkuqj6yrlct0ya3ma5tunzep6uhwc785s2vz5j4ag9x0v0uw0cfd6vc7k6ww2rqekxzhvqr2sfpmlwyw6eqrcnk03cxltf4lrlunz20y0rzray903uqlcnly5s08c9ta6zfwtk3w4rhg36cx4w62466kcu7lvae5qe2cwf645me22qefrmvzajec4hgmdlezc92w67jj4fegg2yjxw3n7stc4hv26r4mtm894t2hrgua7ex4gk9qwq2gkcepnspv3gmf3la7sjrvapy98s9rfwnsl0zcaes3yjvz3kshgwy49jthrqx965e6m0ky0cj9ez2xwcgqslycvwjmx43ae8new67j4kac5hq60ljaus35zlp49fmthruyws87yyld8da8p2uax3na6nlkkzu5gq67kpgangh7hpmukgltp83msh3dd4agfj77gzsa9h03nu0g8updxkzxk5vvfw9mum0vznxlwjqhtcxjuyduzz7zgcprr027v6vslnpnn6m772vz52hpx08jrtmpfezj2dhr5vz69fydpm32ad707z6mqaej83rm87nwsxzlwcrdcetwdhnvxlemyda8m7xgvrggcw"],[2048,"nolgam160sm9el5f94d6tuem9zk2w6k5zzq7dkwtvdsgdgq4hvu0pvq89zfs3mp52a9fw74264ck52u40a440jmfwl02xvku3yc5u4ew444dwkdn7j92xyp0wyaewcljnvvzsy5mp4ncrre74upmf7uwekke3fdxakqzae8lsyn0keku2h9vgfm0ypqwzm29jw0n70a4chwhy6rh2uumc9kf3g9t5n22sn9k8jucp0jfucs6922xefvfkp5hyvpmglu8fvl57sryqngp3gahzlw9km0lz6x5n26594a5fctf8fa8wc60a3vqandfcenlepp4sa9ava6e0cq8sauns8hv653j22g5w85u2vkvw0ja6rn40falvenc7sra7g9665vg4lckesvwckkd98gkl0cr9puagytctuhaxqy3dpn4y8m7k4y9ljuq5puyec4ukn7ykes8q4kdf84cjf60394xyq2ggspun30uk2947mwy7awr98exea55qggqrx8wm7xu6rnsqf4vl3g2mn350vrjufdmzjypu79fcd7nxrqedalv26me4dtudtzm92pdcvwa2k4mtnrx3d82t8hu34x582vk9m84kxnygp0p7t5rg9ns6e2jwgevjrn8cr026yvsdw5evdh2k66yat5nltl57whr8hw7hg5zazzgawzz2r3636mg2p8jhaq8qclr0ufr6ksevdlal0urvl76nv48cxg04xw5felk5yks0mrvd4uxukak59xhgjk8p3umd62zxqvzr2wm0nxtskrsg7wareyrrpfs335jd64sl025najrkm3th8453vt3dmp2wyt86j0ez57xmleg088n9mskmhxs2l5e6xreevglf59zctlavquwwy7av7wu0c6edtrjvysxywmuhrmye0zaqvatw0euerucm7yj4243l200z3naew9g9zgskz5ayznjt3msky9h6psx6ms2p04kd0hutle23m8zwy8xrt8pzu87uy72gl269c896ay7rcgewedrpmza6pm58sgtq5zfx79ddcswfpnqgm9l9qrzaag0fnc4jmlrh988rqf4rkfrft3mxmraar60e0r5eg29znp0hy5da3fwgz3cxzucfwsquke3qscujpwmwakp5z9qhrnlvam0nlyzx98pg5axvwa0p64hur835gjtr96u5wlvqzctvp4ssw8jsuff64pr4hq50z6uxv08740n87vhgwpggkwaacmzrakgvlyghr8k5qdqvjj6yc3dkglxca85m64vfff644sqe7p2tdl6nc0z64294rr26zsjj7anyg28scj6608syydy5s8j3upuj774yu26ygpaf55ttsay75kajeqg85w562acthaltr6zx4g47s75vdqg4uxf5ny4v8qdtn2fnagnn4cm3wrkw6wuldwlx8hmcxfcxzhdu9pswdspxwxvq4lqaypfn687pt3t9uh7c9wnmskjhdsmzzy32sxq37aym38l0t5pdsyahvnkjw3nfndppvx7rp3886emd45d86zrz394df9zt3rdd7xpve8v4g0gmrhcpr8amwewce8pgv8m3ldjktkjd465w7drysfjy4p47l3kh2uldx50yrj9wz392fflf7xqp3cafey6kl4ln459szw2r9sjgpy65s4sdzmvjnt50yxp3d884u7ezhcfu0vmr59z0s8rt9yk27npl7jsm50thknjle8va4ezgvjt4erleg4qp3wa0twcmdaqunv6ffutvdkf0r3lv4usdgxar8epaeud364nhjcxk0gja6ncr0yx9e9awft64lyr6p8mfhgnvhlh5dakkta97z02jes9zuudx75k9a950ukfd7f0gjqdpts37gvpjltgrrrkvcxjqvjt6f6s7vyyc7xvja7gdtrchtew0tfw0766t9pq5ztpheuasf43s703qwwp9tnzrrl6fnmjv52hnp07cxlc4cs9me8g5ul552m6gtn52phgzq8zgcua35wj37qu8f9jcnyu2wke8v7hvzlfx7dkp9hnet884tk36lq7wdhhlqdxsd3fufdqsm2gpa39lu7t45ccgrsnj5lg89smplldsyt9aqt4vmy9sc4zas6lmtnmtuq6u0kjel706495ga0vz66c4ckyra06ya8eda88kytqdn3lakqq56c7mes2xea9nus6dkw4eqfnqfsz34nl2andrk7hv6ndf6ert7xvn3w8s8pggecj5gxklmj47s374jd40qqay0keun767stzwafhy46e9wyq22kgk6h3xwjvkl7qmrzc332kdg0hd4ewk3pydx3n98dx4kusc5ay6q9tn6ew9k8pnh6l4y4fmvu2vd2y6txwr8u6xml4pf9qdhksa2kel743j9t2fzdtrjph4kdanyx3j6erqcmg9hqmaqjva0m4tgyzmhlaq65refv3l3t4zveu4372nhlxq3c6padjly9gzxnyxwjzxpkams99qaz2yhxwc4kypx45fnes7709duplp3rwdc5zpm0lfd4j3vvdkdd8qvm7k6cc8m739fgxedy853gqv4d2e3mx0nc8e03v6l6nns7tgxlvv628v70ptz3u3rsu9gf85tscj9tk6ffpt566wzm8pu9nk6d3x5dyfqlwc75wrdan4uj5xghdaptnyv47v873tu44fdht8m9ywlhz538uzpdq8z5cetplq3sq04e837gg626ppjy4pnr77u68nq7q4pzvf7mjx9lqtx262e8dm6vy46sme59wn9ts4pepz0fag8gdxf29zd7ppfh3uesqpqz695upyx2x3sp5nj2s3vgg7fxhqzpc4a0r2nrfl2y6x02d88qy54dawrydruhm89949durapjx9atwl5n7x29tzdwe59njgsy2a96l76zzf03lx9hqchvhvydftpc9dr36mdzc5arzpypvl4a5eyn3fpq43lfzkh5tnu0mgm8h8xcuq5lh52492een86h4mmszyfefcdv7mpmucf9kws6sxqcatsx4lhrerfyl576l0f00wngpcnzaahm9fmnegtsa4rrhgh3pluprmxzqtqg7ud7q5vyca00apswfqxh4tzvau6zqvqv53j3kx6ufcrwvhxcx3rd44h2naqgt4ptfx07nepcq5gkvxzj6vnk0v26vf8gqmwf785v7ehnl9hdqk5np79yah50vr6s8atc9s7sgaqws5uunv0ny5f4frr3kdct5fzudjnugu6cu6hmtscrm4usaa3s7pg2ucvrv5asd5rjfyz0dpq5vwp9e8vxwx05t3wwld8hsala5990frjj4zltr9mq58dwhg7l9ht77vvy2pq7sp75h4epga07ezsxjdwlqvurjcsfyt3us0e4pyja6ckzn8ymafmjfge8e6nwhd5kletck46sreuyxwly0fakgeqwyxaka029vaf9qej6ndp9k6rvrsz"],[4096,"nolgam1pv7lvufa8k7y8gljg2tfvuumq8rn9yuvcnsf8pgj3gxyug803x4f92sxqjvlrgd4qxk8kj0a7mjrfu8fxs8gzj6lc6gm3grvg7ytcxhjczctkf20u3rdj6al960q0ad6n228m7pfy7ychmm20s4hjx4vdw5s0sp599vnluj0cn4m0ry5ta0adr7aevvatl9z69jt3ndugm2shdnurafugn6eaxgqghxeuyyu2fwnm0dtk6n3lsll0rljff6vculegr50hr88dkx5t38t7phyl6nr7gk7p6p72hhfn5zaxhyn5zch2yz3xa5smxnvxzsvuka8yv3psfkxvx6ly38n8rv5qdmquzjpaqtltkxaw2tsf29565ekr7p3fxzxfu542vaz9qxu94d88jjy3ztk4qlvg7k50umkw6z4a9vxct3l9lz6y6mw24jnfxjjvckr97qadwpwqwfc2nyemcyrn34jffvm5hhys8p8qmksqchuvuc048n85nz4eejn4l8uuft6vmeal7m0fqn25mzem5l5fedwmchhm08667g9annku33dalvas8uhdv6f9gfq9f7ym8fjeq5p567h6v8x30vkquln2wsfpmt2rc3uewq0g8m9ww52rsh6rw94669uxmtqcamyw5jhcac02vhljsq3g46hplrpqus6qgsqhu8623afnsnptfj5ltqmtt9xesdaq2qwhgwj6wla5xs6r7leq70vzyd59w0mqknc4awmjx74zguxu3mppqfh0rrpl522ar09q5dddul97a7prc93f9ety3t4938wq9uvnwyhqufjyzapa57lp7q5jlvd2kedav0pf9w3tgwjn2f5psa7kskl5pmpf8l4s0r77hp6uwardqj6lfc67s6sza3eharscm8e83sqqfhxmsnn7dt09jgdhu8vk484p40aqcvqw4tahm5a8tzut7e2335ne9xlpz563kmkeeyfslrvk7xweh78ptgp8p4gmuxfn82l2m8k5zv6wsspcys478t30pzj4sw3jgvmj3jz0tcr9es9x2jk5hnjh2rya4x9gdzpzy8xql099uek37545sclx4g4wrrnvjze5rwxu03ktj0sle6ny65skprrmggygmxzjulyj8nxdx76s7d3m7gp5azjryaeumudhr2c4t7xnmls2969zk4ya7jtlr45ayf7x3e220a04kwvah3xcsp62886mfdjtps5ujq8vkw4w8e3rrcwg022j35644wuq79ag23zfzgjs2vkphz7228ey7ymhq6e5pp56lgft2p9rgaqh7f9uqkyh6r6w0ga4ln962dgauza6nanj9j7jg7xhjdk2v2cxxpm6uc60u24x2594eg7hwmqna582r6r8gdetqusl8klzx5lkek7a6fel38z4nfnfvsrcmvvlxg3txzhn7ej9g2maf2zvqnq4v9gjmap5qtezd36man5m2hexehzgfw3erj2jcz6hr0dgujcna95r00eh0pvlykezzec6q329mkjcvkrtp6te0cj69mg840879v0zq9t0uppn2ppsh6mtst3npsxfzr0hnfjd75m55qpx4akykn2qzjd3mqwmnmkycr6wdn2eqjsmty2mx9mwlevrgecr34pgzqcxl5dg3q0dw2p3x3hvsvtt0r38hrmtdclz7cnxsccgvwaqu8smufmhagznzwxeyv2cxwzm4lcknz566vhut08gapr60k3gk8h8d67xfduah6yg0vsv8ryyly0tmmv0rguuqddk4hrzxsyzkfwrmg8y39lvsvx4cn7c4yzrh3ee5u936qy0sc9j08ugn68uj5qd82aaq6kw5qj3lk3efhmsg9ajvt2qd0w7re5z6jtd0dkhe99ct4jyhzjsg2hgrjgdgmtmyqew0xgxln9rda9afxt8eadg6c0ltklep3f45evcq9xzcgj6thwxus9gusqmddrg726xe04e8nzlgzszqe9e7d8hn425vxxe0drd2vmzugn45xtrxkpzv6zwdpc09r53pq0gwugvuqtu5mn2zrqgtrawurkwdndrqja2tjzmlaklwwqhy0cxuvawep90g56ttx9zqtvyqurv0aqqq6lu9hs8x26xeavrvnjceax0nxtp3lgva4klkkykye7n008elxe5glwhpxw8efjjg3fygnexauv8ckq2cw0ehufvy9c08waqy4r5kx5h9nw0uj4cfvj6w3d7zp85snctn55hm62zpku4h2qsc5n5mx6l6hrnnqmfw2enkzm5na8evstf2crf5qus74h3cf4dkgdkhea6ume5euaxg2ga57w3cktv4acvd6ev4u0dzdtexqwrjqg2mqlsahj4h8rhcsg8gsyft0gxcf7pffdt5dx4dumprq42nxajcm2ls5ywtja86thmk8xtug52040hle6ar5xjr7cx2nap35hg8kqpcekv6aw3nljrhwhzmlrp7qlhyd29jtc4efr7x9q7p5f0y86unvvsvq7asr4a4z32wcwet0tragewt0qq48ejkc5y9g5q3k8gkfe8kp4gz6ahcs32x33y754cxtq3exe88ug5n4ay5k3ugxy0qses2valfky2dgyndwpfca2298gpg3qc6vgwxrpmwjne3xdmm25xgegfzrkm2d7q9fk980vgpfhla625dcwrnvaed8wsk5fmr26zhzsn3cxlclqmqpa208xd76sldg002p0ejhs7yc0fufvuy7s47kxatpfe4ngr2y5sj9t7cqx5pyeghwlykwflcaf2qjqknw6xtqr4nm2f7xeje8pqmtqjlmafxv70y6h8unm4d06ecewrm9fmkl2duj5q0re8jh0sm0crcu2jq9mjs0jjg6z4y0z86qzesscmju7pjlx27m3yxsq3u7dhjydhg70lkcc7jur0eu3fq9lyrgfp93mxsvsryajaa8dmhsjep8vx53fn9y6q39aya2vgnmgflqw584vgan2gmax0w5gc6stz354khy5s0d72g3rn4tm225tcquem5ku04eptv667vsq8dtx9ghgwx0h8f0r8n8cvl0g3f69pvl59fevqd90v0ff2hxsagf87lwly27kcp4f47tsgd9ue6vs2zarwy40l6xahj7uv8gew3zr6cnkx8dm2l3v0da00pmg340ts34ke4e9u4xyr8kg9qzcdntazzjuvcfd62q24vsuk3ks5h9v7j9p0tlh9g50rjfkmgl366763wadlyhgmxf70m68kspwwawqhcy0mx27r7x77u67pn787z9865rvdm9hngp98wklyt7sgwxw3vzwthp89znm3lpmjedv9drgekggeynvk3mkmc0fc9een82l9cuyntprzugdcccjx6u73txxscu5zfec78uy0whzf5hsvjav9fvaakkvd0539ka665y8h8e9u2efws3dek66rsqjsgqqrjdg4xfdwpp60vl"],[32767,"nolgam1fl4z8kg6q5ahuwavlvnae2d5dhp9cf7gxtufdghs3ys4wfpmade0ly75ugua3mtkjlm4x6wm234qmsgeal666e55lhewtt9zg64txgjrd35hw87z6ehnscqlerzp6yugde6epxvyk94lu62zcnw4rjjn39utxkuaukcxzkuc49v99a2qxvfv2q357nu6pd0jtvff4pz7mw99px7y4lu6km67uwqy0gm3xap84th5alrgeyedwugtg4u7rxy3jvqu692ty4zuy5x229mye3d0esefu0l8r2pmnpnhrevaqg2gekwly9vcd7qj47qqaf7s4xmt0zm964xkhk695zxxlwgkx2fxz3ldnpq5zydkqgzpwffams3dahgl0j96vfqjvzuy8nysu3paw9l00hzf768zdxjrpekx4708tka8hmwqkn5wq6xshfwzjc9q00g643ewezsvgkz68ky3d62havs7a9k9alh8n3q6jp4qp08szwdefch3z2tnf9j0ck0mrxxcuywy8ll3cn4h24rwr7lfmy8lvpjgx08889ne0un5s44awm45nx3x8uehllrx6mnqlgexwruwv2g3frah6fzdrazcvqny5jc3uky7454syedcrvhqtv4008s2agpz08fl9dfe4le597akv3y2l8xe0ydjte9c29vkxyqmdzhhzgtmdk07zkqn90eawnzydt00r6t027r5k3rffqwuh5jvjr8q8858cjtvjt2r09kwt0q2n2rhh9uzy7v8nh04x9gfquqgsps3n2qzsezdmjkp9l8cwqnuvy2u9e7js0r549drpucxw7j5yx8uylqf0u8fsm29gt3shh475epy5q9fntfd004zpnke9kl9urx5rkwy7kfjxsln0qs05sul44x9qn9kze4ywlwxxk65yavrvg4c2fna9c9drydhhjrcsqs3wukhx6qmehdfgh5arsazy7cxpw2dtgjz4327dq8s7zl7jeecplusez986lfa6nxncxgdwl37zvkju3r9k602tcxf8lnhuf3gfcjtu2wrxckq3g2x6mc0tv3wygmrd4mdepujglucx7vfs6ml0hnevafhhrmmc6wudq2su7jeaz8lcqcf3mpeh7dd60l55xdstn2ep4pg6ewqla0qa9zj7dlxrdv49y82s95kpjuwp6295veq99n2ez4yggzz807x0je8ftp9830nuu9vds4sukyd942nfl6393tevkjprfhhy2ecmhmcgxy5hwwdx83gecfl9tmjen4dthfftyds7z09xckftp8gug7ssgn0utdxqxrpjdjy5n5k3rxt3drl3vn6zamu3ft9djr8kglky7wshsp0fxuh3fatpa9ce9tslt6u4330eu4ymcelg8njana5ppe76wsfqrf6r540erjqewqzu7dxlzd5wxl54zj8urm0zymdvgrjgem97fxdh0ale5g5wwrk9f9ccs4vk4rngxp674xt4lhqacrr45n2uamfmy4ghngmqc0tyetq3wnsdk93xgceuaemw0p7pucnxpv2jeg58t2jvjre35xasg4xgpj6ylls4crn3nh9nxpk94w6g6z0nf9fzmhnzelzdmm2zc54wqw06ngau805tcum0y3xj9hnt88gd9ruq2j6fnh6r8y4rry0xnyxv8t8qqcl9t4cf8amc4wtcg6mxc5226r404mgwk87fjldhzw8qjuhmncdy5elgudmdanjfpse8s5hyxevyq60q5nhclhs3cw9kmtysm0ka6u50065fnlvx7jaznwt2rjznh2etd75s6c43vmr7dz9rc37nh6hjuj6j3494wt6mkg6mwrkfaf4fy5udm9c567j4u97qxtrj2pxqywtzqjrw0xd4x6dgvyy28zgxzmh2t5452zklyfnzkhzu7pj2sz76khew7mt02uhc7jlrd082r0dncykw0jlxzmas5875edgxwu809aekcl50rygmp63630nrclfwlt5lk68pl5ztt833e9hdn06u4hz65pmgd392ls5awpxqznkwgdcjlqjc87h69uaxrx2s54rxvgy3xqdagmunrffvd3nhdxvuw6wstt5rpmvrcnd9w5jllqw77258r50vlxkpxpv7ptmmhgw8sy9l7jmh0etkyypctxf5q8uuyynxun05039hzm3w5thjmtx5700rpexjs6pj3jyummk2h4s4d4ss0p3anv2dzhxtygzz4kn4l545l3vks28emhad86aagrg5h60ynuqj2p6gnyxqfu0d9zk9d0v5wkmexqfx5glu7upmmxarpgnvv6dsk5haq6qw8aa47p0sq9zhmtakspm2r08p7rjm3nhmpp2fg4vu2ws84c7khyf6zx0uyc9s9j88672neztj87m8kd99cnqna43mhkqgc7wxt7glqhvwlnwu74xj3t5tx0hxejyaf9f8ca2vwgx7gelp84fym0dagkw4j33s5xslwc0d03jtz992qtv6vrntmg46vw7ehnsulcx6mfuzvsvncydap33606nn6zkw9zj7gcudvle95jqwya3awg7280alsu4r64kh2w7ugwvaea49uv54nu5spscfl3edqmu8l3wc3undsn3mjuuhut7ga2tkhyrlssnwcuvtlwd282hqrxfm65hkm0vqv66a7uqyrcxcva2c37wj9fmndu9zwz0z3dnptkkax3rprvamcwge7vgwy6ex9vm724egpkmpehg0epkppeng7rp3w68298qk2t52vtlq4dhye98ns2fmecc7htdecpwrda8pstxa3lg2tdnez5drx4lealu7mlxzrqne8j4f2yy6fmsn9hy9atvn4tqcq4z0c7j3w5cfc8thngfghz0jxhtc3etc5x527ka5nr0yguzz6slpxztgfla849xt3tjc8zgsjtevde9e47vvgm0hhkm0heja6j99qgn2396d5223v27jsps8s88jnaly0enhu6p5wyxa8w3my5ctgkkn44l0e9p80h8srd2jreuj5kzg4n392z9u346g4a5y88vlg3az8kvnh4u9vht92pgmpxhrxfvw5m9072h6tdw5ks8jzga0lxlacqcvz5em87e7uvl0wch70k9cddyezhsyhfng0g96eqqspjj76qt3dwam8mcws3mcs28wf82gadlq7wgd59kl9cfw0jada00swd5w0cfmc2cpgz7z9mwdm22pk8d4s4vh33rhhq0q69lnhvywe9n9w62d53glkljmcx4gq38wkpjzcf5264epg2r3ju2hhr5u3ukvyfjthm6vndglumh6n6mfvctejmc30jln00memjw43qvdpl9hd7c5naru0k8etnn2g7mtqxyzednlmas3czm6uunguzf7djvpdnlugxzvttlyj0989t4n7xumk2sllmw6n2jz7ssg83s94gfr4erty9yn4wkurrc6t8cxvmevwkfn8z"],[65535,"nolgam1ycx4zn404lawhymshk066x375w74d7euyhhmk6yndfjwkftqknax42k46tul3nzyrupl5mxsqfdt7ej273yp7wl7a9tr96tag2zyw8kspaguxhhwy9pr6snchyk3g2e3ns45wlk4sf255h0vl80vpm93yx6esvwzuf77swx4rsyr9djhtdwrafccxfdef0zu3n46fyudkcfs3du9qf7wk6khg0frw9faaxyg2ulvltg444lxnsqj0rvux5cnx9vs6wh0rej50ej9kfayaqxkxy5jpnq4v03m3d9tl7h2x0y3zfpeef5ndv3y392dlekz9hzfrgcrut7jvngrjychts02cdwafgvexskedtxefzs0kgyu3vh5d0a4u8hf04504lj8d42wlxgpcvjylevvc33v64w6kr754tjjk3eh46evdvycmp0spjn6zrhu5ctp3g23p5u34cjs4xdfc0u6wazmg9hnrtp09elzlk7fpqd54gupcz4v7srks8w7ft7keclcgfdn0ae573l3npe2hx4mrrm0enejr4sgvqqpa0qxt5f2quktgg5umywajl2vp6n8xy84v060yt639hwzmyn30etkwjxut7eu7luggadh53f6m8y3cdyg4hu7nmzx5g42ukvf2m8vm7j84hpul4hfvn29xx9m6a3qugevg842c66tm4mqh8tv25s8fp2vtkaza4t0yd3jprrksxq7wvwzq0lr40fwxm6t5vvrr45d5cq4slcskmdp0trq2xkl7lg5gzxkgvxfelh7up6ju9a8q7mhkut708j5s4322etv9gsd460gzc0yz9thnmelg7ph8uxn4juqxpf77l8adjahncwq02xqakj3dk4vjerwhpmxmjy94wn6uwp0t29dcuplqtd2hjr4570uer8wxr8xcgs07srzpllll0jj2k5tml77pttsdz7srs407g74vhlpneeqn7fkqdz8v69hvau08kxjrfth2lnwlwznyecqctgphpknf0dj2hpdxtp02s9x5qr0vt4ayar2t4f8jw4jzjx3gz92muje70mxrtklgultaezt0r8pvzq5mhhtzch3uzkf9zw9fcd4vmhssx6wrruhyc9yge22j5encrnaym3a5jwhs8hfwukztlc4kqyawjmgsjc6jajxrldzsn89r5f8pss5z0qre6wjl79gchhkajd8fjvdy2cldcvk24y6hpveyu39zhfcjxj0vsmpadc6ukjv42mfkrwqqqxcjfeg47gt32uzgh4efkj3gz3ceyqz6ckjygny2k5wx8qq0zg6ksxj0ar6ktf2faeh59yjve0l6g46l9a67gkje7we9pfed3gh8w87p239frvcstqhuvr2m7yhh4qje9mzkcmym0wjsz4ky4mntw3l9r5dttl0csnuydglq4w7j6lcr7eg4xymjck22rfp87nefrr3zs2360xc4y45lqza34c3c00waau5zyw9yygmwdvmr8k7zv94xsqmu45ccmldh200395sd53afcs8nluc5hvlw38ta0gql4klyavz2z6hk7mh7m02vpxef0x2ar4sdz4wpks65xvpld6nyv3lq5xekjgf8dnjc9jpzzpplcg6fp78d6r6yk4cepzaq2utczd3e6ysjtsdrgepxyxgesz9q7u78h8q5lnv725vlczskjsup3sygu65cuv89r3h82rpqlz5228n8euu393sryu84xedahkymfrqg8ulssz9cgyujgcuj2jh0mfp2w8gwy0cf2xkrfmgpa6qs4fj4ky0ye3gxr6t6xnsezckw5h6pp35wyu986cmhx5c8h65dfncaq87prhurt29h6h960gmqlzsj74sc5y0tz85l5dvvmplwfgfuejp9cpyek9q2wxpx9uuk90t68y75q0zf073ny8azwv7r8g3ap2q0d93gn6ly9zfvwzny9hk5zvy3k0ttxrhyujjckkn55d6wmseyuv6k3hqhe9vcg5dyn0g60c7eywy0g8t4340qn9e6zmdmpewve4clls3tutl24fu9ylke6e9qwygdkahle4l2cepypd5c30sjcvzadpdqvkxrx2c4mw67pjnl56lcpmm9wvhtd7xeccsrtx0ue5ynr5v76jp3mcu6207hdnxlgmfhq62mw4rts6ngvstdgk3n8axk0fur6t2xrpparu0e8dmlcw2mzgp4pllh3xe6r2jm3tlg3c38s9r2fawtlsmy23udmt3dps5774lqctu7yfxmzhx7mynnk0hscw2v0y5resrmjqku5m43z0yfd6dj7qzgytxzwgk00jchdpf5f4a4x0ym7k66enc77q22kmtx7746r22d8lqs39fjp96wkxgwqt9de2uhdv9p7dlxzmmvyw9n7f0ywxvh780ghxhvx9sa5xhsg95xt5tl8cxp54mczmfduz2ugskcs9mxfx4jly3cc2a488kr4ztfm9tvnqyerect584zu3cz4nuvanj2c4wq6jz2v72yxae55jn0vefw8ea9x588ezhq7sua68p2ryze55jdmj28p4dyqys2ed7erwm9yrqdqyxjehua0k70uccmwlgzykwklrrny97eaer9cptgxlppr78mm6k7ytu9mxkcr7ax60yt9kg9s4lygh8vsm2xurg3asa0exk909s9uglqnpmpqqhrez5tyvzkamh82ugh0wa6pelm29w8kex4d88njrc5k9nh2u3xm6fpelyeyyvamje57jt694kl2alpm0zngpakfn8c0wkz9tqyhkl6vy3nqkkga6f4fj2edpr7myyzj9cckmnlq50sexfyyjmxfmqtpvq7pa8fc0x0z49gepcw2rzknxvjffqgls8jtfk6d6yzcqmtgsdgc94u38cw0yxdwn6l6e6sxpp7e8mc6fnz4kfvr3dnrhd3pvguedswzf88ywn95r9tcm6j89z2vl8nsphtn6dcmsr90qw3efphazee8p6wrt6vlmgz433ekrr74xn8p3n339wy9akxeztgjckksjk4u8ntfknal6se94psrffv6sq07cn689xvc9yau43zklnswrns20jx7pcqgyc2yga5g62ancv2w3yymhrgzz6t4s4t88v5mlkzujvl7aarm3cjl76v9l4efg3g54atxasr2knv9t26pr8m42p9jd9jkt7wzjk3wvztz5nx3ezskfap6egqmh9g6dut07zmv4kkk4t0mx36zfpmt6xh4yq5shx8t08vsngc82ukfg3as79guy2nxv0tkxse24eqa6u85atuanes4uykrs3kgv9l60gwgh6qz7etc8wzz2egw8wn5c63anevemjywwren8d2k8nyszegnh703sg9n669hhax7927au94rc0h0psww53tw6hnzmrksc36u50z5j7lpqpadvsflmqu8atp97skzdpahtys5aqn4grrqnuvk26g57s349"]]
"#
            }

            // returns a vec of hard-coded keys that were generated from alphanet branch.
            pub fn known_keys() -> Vec<(u64, generation_address::GenerationSpendingKey)> {
                serde_json::from_str(json_serialized_known_keys()).unwrap()
            }

            // returns a json-serialized string of generation spending keys generated from betanet tag.
            pub fn json_serialized_known_keys() -> &'static str {
                r#"
[[0,{"seed":"cd452ef0ca60fcb00f0437d7d4993fe2b1cc5638b8b593f4718671a1c38e7c9289f98015b207ffeb"}],[1,{"seed":"55b425e2ad64ff70cb15dac12551bb6ceba8cd2e028568f4d616c9ab88a7923b903f9d21fe0a39a7"}],[2,{"seed":"77f967971f1c0bf5ac7bce3823c5574185bb0a15fdcee51e5a407164b748234357f767ef619e61c4"}],[3,{"seed":"c55612e5eb2578b97f8cd9b9ef60e51dc027864541939261e4e8f7e298400f735901fae529dc1867"}],[8,{"seed":"0ed4a1f0484c26bf3f14550afe30b3dbdc1733921ed7ab58e2c230a9affe50369aca52d2e169f929"}],[16,{"seed":"2b67fa94ebbbf8ea71505717d034de1207e51c1160c62a4ed755050d1c1361798ebe99f51fb97331"}],[256,{"seed":"9b137361290b135bb7274bcdf0e73ff4e6619a662c529e267d29fb1801c3099eaf3ae0f3934276bb"}],[512,{"seed":"c70429d1210d6cc130cdaaa926fa67782b71c41e5b70b4dab7546ba9594e104f18b3cc356dfb8501"}],[1024,{"seed":"60f25793c42f4fa3651b1e233c6571ec89d78fba629fcc1d2b84d0087b2f7ad51ea80cbc5e226245"}],[2048,{"seed":"5916c99e869814632d276cbf6f8aeb7f3b63c378de331c18a1ed8943b66c3d583b0f53f4d0c3a202"}],[4096,{"seed":"adb5cbe8e4448daae3302a2064432e59a068b75fdc65228c60a5dd759075343d3288a994f02c5c7e"}],[32767,{"seed":"7eec18df002a811a179c7b16212e29cf34382bab35372a847700c18d8e73dd03504048fa5e808047"}],[65535,{"seed":"7a48be11cc11d2052e3d57d42335d275e8300a7ac9cd5a21d8ea3a5b29b2129a3700aa32a369739f"}]]
"#
            }

            pub(crate) fn test_seed_phrases() -> Vec<[String; 24]> {
                vec![
                    // alphanet v0.5.0
                    [
                        "limit", "lend", "shed", "spoon", "number", "program", "talk", "mesh",
                        "invest", "promote", "layer", "nerve", "oblige", "benefit", "kangaroo",
                        "dance", "frost", "lesson", "tooth", "grape", "shoot", "claw", "motor",
                        "diary",
                    ]
                    .map(|s| s.to_string()),
                    // betanet v0.10.0
                    [
                        "float", "finger", "arm", "legend", "imitate", "drastic", "top", "eyebrow",
                        "pause", "royal", "connect", "occur", "random", "breeze", "weasel",
                        "depth", "vessel", "potato", "midnight", "sport", "chaos", "timber",
                        "various", "coin",
                    ]
                    // nth-receiving-address (3rd invocation)
                    .map(|s| s.to_string()),
                    [
                        "dumb", "medal", "vintage", "leaf", "merry", "neck", "hope", "orbit",
                        "gentle", "bring", "tuna", "pause", "potato", "female", "whisper", "throw",
                        "doctor", "vessel", "small", "couch", "bean", "matrix", "conduct", "wise",
                    ]
                    .map(|s| s.to_string()),
                ]
            }
        }
    }
}
