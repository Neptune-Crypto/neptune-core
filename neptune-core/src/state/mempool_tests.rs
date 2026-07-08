#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::collections::HashSet;

    use bytesize::ByteSize;
    use itertools::Itertools;
    use macro_rules_attr::apply;
    use neptune_consensus::block::block_transaction::BlockTransaction;
    use neptune_consensus::block::test_helpers::invalid_empty_block_with_timestamp;
    use neptune_consensus::block::Block;
    use neptune_consensus::consensus_rule_set::ConsensusRuleSet;
    use neptune_consensus::proof_abstractions::tasm::program::TritonVmProofJobOptions;
    use neptune_consensus::proof_abstractions::triton_vm_job_queue::TritonVmJobQueue;
    use neptune_consensus::proof_abstractions::tx_proving_capability::TxProvingCapability;
    use neptune_consensus::transaction::primitive_witness::PrimitiveWitness;
    use neptune_consensus::transaction::test_helpers::make_plenty_mock_transaction_supported_by_invalid_single_proofs;
    use neptune_consensus::transaction::transaction_kernel::TransactionKernelModifier;
    use neptune_consensus::transaction::validity::proof_collection::ProofCollection;
    use neptune_consensus::transaction::validity::single_proof::produce_single_proof;
    use neptune_consensus::transaction::Transaction;
    use neptune_consensus::transaction::TransactionProof;
    use neptune_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
    use neptune_mempool::mempool::Mempool;
    use neptune_mempool::mempool_event::MempoolEvent;
    use neptune_mempool::mempool_update_job::MempoolUpdateJob;
    use neptune_mempool::transaction_kernel_id::Txid;
    use neptune_mempool::transaction_proof_quality::TransactionProofQualityExt;
    use neptune_mempool::tx_upgrade_filter::TxUpgradeFilter;
    use neptune_mempool::upgrade_incentive::UpgradeIncentive;
    use neptune_mempool::upgrade_priority::UpgradePriority;
    use neptune_mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
    use neptune_primitives::block_height::BlockHeight;
    use neptune_primitives::network::Network;
    use neptune_primitives::timestamp::Timestamp;
    use neptune_wallet::expected_utxo::UtxoNotifier;
    use neptune_wallet::mock_block::make_mock_block;
    use neptune_wallet::transaction_output::TxOutput;
    use neptune_wallet::transaction_output::TxOutputList;
    use neptune_wallet::wallet_entropy::WalletEntropy;
    use num_traits::One;
    use num_traits::Zero;
    use proptest::prelude::Strategy;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    use proptest_arbitrary_interop::arb;
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::SeedableRng;
    use tasm_lib::prelude::Digest;
    use tracing_test::traced_test;

    use crate::application::config::cli_args;
    use crate::application::loops::main_loop::proof_upgrader::PrimitiveWitnessToProofCollection;
    use crate::application::loops::main_loop::proof_upgrader::UpdateMutatorSetDataJob;
    use crate::application::loops::mine_loop::tests::make_coinbase_transaction_from_state_lock;
    use crate::state::transaction::tx_creation_config::TxCreationConfig;
    use crate::state::GlobalStateLock;
    use crate::tests::shared::globalstate::mock_genesis_global_state;
    use crate::tests::shared_tokio_runtime;

    /// Create a mempool with n single proof-backed transactions, all "synced"
    /// to the provided block.
    ///
    /// All transactions inserted into the mempool this way are invalid and
    /// cannot be included in any block.
    fn mock_mempool_singleproofs(num_txs: usize, sync_block: &Block) -> Mempool {
        let mut mempool = Mempool::new(
            ByteSize::gb(1),
            TxProvingCapability::ProofCollection,
            sync_block,
        );
        let txs = make_plenty_mock_transaction_supported_by_invalid_single_proofs(num_txs);
        let mutator_set_hash = sync_block.mutator_set_accumulator_after().unwrap().hash();
        for mut tx in txs {
            tx.kernel = TransactionKernelModifier::default()
                .mutator_set_hash(mutator_set_hash)
                .modify(tx.kernel);
            mempool.insert(tx, UpgradePriority::Irrelevant);
        }

        assert_eq!(num_txs, mempool.len());

        mempool
    }

    /// Mocking what the caller might do with the update jobs.
    ///
    /// Assumes that all transactions in the mempool are valid.
    async fn mocked_mempool_update_handler(
        update_jobs: Vec<MempoolUpdateJob>,
        mempool: &mut Mempool,
        new_block: &Block,
        old_mutator_set: &MutatorSetAccumulator,
        network: Network,
    ) {
        let mut updated_txs = vec![];
        let mutator_set_update = new_block.mutator_set_update().unwrap();
        for job in update_jobs {
            match job {
                MempoolUpdateJob::PrimitiveWitness(primitive_witness_update) => {
                    let new_pw = primitive_witness_update
                        .old_primitive_witness
                        .update_with_new_ms_data(mutator_set_update.clone());
                    updated_txs.push((new_pw.clone().into(), Some(new_pw)))
                }
                MempoolUpdateJob::ProofCollection(primitive_witness_update) => {
                    let new_pw = primitive_witness_update
                        .old_primitive_witness
                        .update_with_new_ms_data(mutator_set_update.clone());
                    let pc_job = PrimitiveWitnessToProofCollection {
                        primitive_witness: new_pw.clone(),
                    };
                    let upgrade_result = pc_job
                        .upgrade(
                            TritonVmJobQueue::get_instance(),
                            &TritonVmProofJobOptions::default(),
                        )
                        .await
                        .unwrap();
                    updated_txs.push((upgrade_result, Some(new_pw)));
                }
                MempoolUpdateJob::SingleProof {
                    old_kernel,
                    old_single_proof,
                } => {
                    let consensus_rule_set =
                        ConsensusRuleSet::infer_from(network, new_block.header().height);
                    let upgrade_result = UpdateMutatorSetDataJob::new(
                        old_kernel,
                        old_single_proof,
                        old_mutator_set.clone(),
                        mutator_set_update.clone(),
                        UpgradeIncentive::Critical,
                        consensus_rule_set,
                    )
                    .upgrade(
                        TritonVmJobQueue::get_instance(),
                        TritonVmProofJobOptions::default(),
                    )
                    .await
                    .unwrap();
                    updated_txs.push((upgrade_result, None));
                }
            }
        }

        for (new_tx, new_pw) in updated_txs {
            let txid = new_tx.kernel.txid();
            let tx = mempool.get_mut(txid).unwrap();
            *tx = new_tx.clone();
            if let Some(new_pw) = new_pw {
                mempool.update_primitive_witness(txid, new_pw);
            }
        }
    }

    /// Update all single-proof backed transactions in the mempool.
    async fn update_all_sp_txs(
        mempool: &mut Mempool,
        previous_block: &Block,
        new_block: &Block,
        network: Network,
    ) {
        let consensus_rule_set = ConsensusRuleSet::infer_from(network, new_block.header().height);
        let old_mutator_set = previous_block.mutator_set_accumulator_after().unwrap();
        let mutator_set_update = new_block.mutator_set_update().unwrap();

        while let Some((old_kernel, old_single_proof, upgrade_priority)) =
            mempool.preferred_update(TxUpgradeFilter::match_all())
        {
            let job = UpdateMutatorSetDataJob::new(
                old_kernel.to_owned(),
                old_single_proof.to_owned(),
                old_mutator_set.clone(),
                mutator_set_update.clone(),
                upgrade_priority.incentive_given_gobble_potential(NativeCurrencyAmount::zero()),
                consensus_rule_set,
            );
            let new_tx = job
                .upgrade(
                    TritonVmJobQueue::get_instance(),
                    TritonVmProofJobOptions::default(),
                )
                .await
                .unwrap();
            mempool.insert(new_tx, upgrade_priority);
        }
    }

    /// Returns three transactions: Two transactions that are input to the
    /// transaction-merge function, and the resulting merged transaction. Also
    /// returns the mutator set these transactions are synced against.
    async fn merge_tx_triplet(
        consensus_rule_set: ConsensusRuleSet,
    ) -> (
        ((Transaction, Transaction), Transaction),
        MutatorSetAccumulator,
    ) {
        let mut test_runner = TestRunner::deterministic();
        let [left, right] =
            PrimitiveWitness::arbitrary_tuple_with_matching_mutator_sets([(2, 2, 2), (2, 2, 2)])
                .new_tree(&mut test_runner)
                .unwrap()
                .current();

        let mutator_set = left.mutator_set_accumulator.clone();
        let left_single_proof = produce_single_proof(
            &left,
            TritonVmJobQueue::get_instance(),
            TritonVmProofJobOptions::default_with_network(Network::Main),
            consensus_rule_set,
        )
        .await
        .unwrap();
        let right_single_proof = produce_single_proof(
            &right,
            TritonVmJobQueue::get_instance(),
            TritonVmProofJobOptions::default_with_network(Network::Main),
            consensus_rule_set,
        )
        .await
        .unwrap();

        let left = Transaction {
            kernel: left.kernel,
            proof: TransactionProof::SingleProof(left_single_proof),
        };
        let right = Transaction {
            kernel: right.kernel,
            proof: TransactionProof::SingleProof(right_single_proof),
        };

        let shuffle_seed = arb::<[u8; 32]>()
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let merged = Transaction::merge_with(
            left.clone(),
            right.clone(),
            shuffle_seed,
            TritonVmJobQueue::get_instance(),
            TritonVmProofJobOptions::default_with_network(Network::Main),
            consensus_rule_set,
        )
        .await
        .unwrap();

        (((left, right), merged), mutator_set)
    }

    /// Return a tree of transactions, where the parents are defined as the
    /// merger of the children. All three layers are returned.
    ///
    ///       final_tx
    ///      /      \
    ///   left      right
    ///   /  \      /  \
    /// tx0  tx1  tx0  tx1
    async fn nested_mergers(
        consensus_rule_set: ConsensusRuleSet,
    ) -> (
        [Transaction; 4],
        [Transaction; 2],
        Transaction,
        MutatorSetAccumulator,
    ) {
        let network = Network::Main;
        let mut test_runner = TestRunner::deterministic();
        let txs: [PrimitiveWitness; 4] =
            PrimitiveWitness::arbitrary_tuple_with_matching_mutator_sets([
                (2, 2, 2),
                (3, 3, 3),
                (4, 4, 4),
                (5, 5, 5),
            ])
            .new_tree(&mut test_runner)
            .unwrap()
            .current();

        let mutator_set = txs[0].mutator_set_accumulator.clone();
        let mut single_proofs = vec![];
        for tx in &txs {
            single_proofs.push(
                produce_single_proof(
                    tx,
                    TritonVmJobQueue::get_instance(),
                    TritonVmProofJobOptions::default_with_network(network),
                    consensus_rule_set,
                )
                .await
                .unwrap(),
            )
        }

        let txs: [Transaction; 4] = txs
            .into_iter()
            .zip_eq(single_proofs)
            .map(|(pw, sp)| Transaction {
                kernel: pw.kernel,
                proof: TransactionProof::SingleProof(sp),
            })
            .collect_vec()
            .try_into()
            .unwrap();

        let shuffle_seed = arb::<[u8; 32]>()
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let left = Transaction::merge_with(
            txs[0].clone(),
            txs[1].clone(),
            shuffle_seed,
            TritonVmJobQueue::get_instance(),
            TritonVmProofJobOptions::default_with_network(network),
            consensus_rule_set,
        )
        .await
        .unwrap();
        let right = Transaction::merge_with(
            txs[2].clone(),
            txs[3].clone(),
            shuffle_seed,
            TritonVmJobQueue::get_instance(),
            TritonVmProofJobOptions::default_with_network(network),
            consensus_rule_set,
        )
        .await
        .unwrap();
        let final_tx = Transaction::merge_with(
            left.clone(),
            right.clone(),
            shuffle_seed,
            TritonVmJobQueue::get_instance(),
            TritonVmProofJobOptions::default_with_network(network),
            consensus_rule_set,
        )
        .await
        .unwrap();

        (txs, [left, right], final_tx, mutator_set)
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn most_dense_proof_collection_test() {
        let network = Network::Main;
        let consensus_rule_set = ConsensusRuleSet::infer_from(network, BlockHeight::genesis());
        let sync_block = Block::genesis(network);
        let num_txs = 0;
        let mut mempool = mock_mempool_singleproofs(num_txs, &sync_block);
        let genesis_block = Block::genesis(network);
        let bob_wallet_secret = WalletEntropy::devnet_wallet();
        let bob_spending_key = bob_wallet_secret.nth_generation_spending_key_for_tests(0);
        let bob = mock_genesis_global_state(
            2,
            bob_wallet_secret.clone(),
            cli_args::Args::default_with_network(network),
        )
        .await;
        let in_seven_months = genesis_block.kernel.header.timestamp + Timestamp::months(7);
        let high_fee = NativeCurrencyAmount::coins(15);
        let config = TxCreationConfig::default()
            .recover_change_on_chain(bob_spending_key.into())
            .with_prover_capability(TxProvingCapability::ProofCollection);
        let tx_by_bob = bob
            .api()
            .tx_initiator_internal()
            .create_transaction(
                Vec::<TxOutput>::new().into(),
                high_fee,
                in_seven_months,
                config,
                consensus_rule_set,
            )
            .await
            .unwrap()
            .transaction;

        // No candidate when mempool is empty
        assert!(
            mempool
                .preferred_proof_collection(bob.cli.max_num_proofs, TxUpgradeFilter::match_all())
                .is_none(),
            "No proof collection when mempool is empty"
        );

        let tx_by_bob_txid = tx_by_bob.kernel.txid();
        mempool.insert(tx_by_bob.into(), UpgradePriority::Irrelevant);
        assert_eq!(
            mempool
                .preferred_proof_collection(bob.cli.max_num_proofs, TxUpgradeFilter::match_all())
                .unwrap()
                .0
                .txid(),
            tx_by_bob_txid
        );
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn remove_transactions_with_block_test() {
        // Check that the mempool removes transactions that were incorporated or
        // made unconfirmable by the new block.

        // This test makes valid transaction proofs but not valid block proofs.
        // What is being tested here is the correct mempool update.

        // Bob is premine receiver, Alice is not. The mempool is that of a
        // transaction-proof upgrader such that single-proof backed transactions
        // survive across block updates.
        let mut rng: StdRng = StdRng::seed_from_u64(0x03ce19960c467f90u64);
        let network = Network::Testnet(42);
        let consensus_rule_set = ConsensusRuleSet::infer_from(network, BlockHeight::genesis());
        let bob_wallet_secret = WalletEntropy::devnet_wallet();
        let bob_spending_key = bob_wallet_secret.nth_generation_spending_key_for_tests(0);
        let cli_args = cli_args::Args {
            guesser_fraction: 0.0,
            network,
            ..Default::default()
        };
        let mut bob = mock_genesis_global_state(2, bob_wallet_secret, cli_args.clone()).await;

        let bob_address = bob_spending_key.to_address();

        let alice_wallet = WalletEntropy::new_pseudorandom(rng.random());
        let alice_key = alice_wallet.nth_generation_spending_key_for_tests(0);
        let alice_address = alice_key.to_address();
        let mut alice = mock_genesis_global_state(2, alice_wallet, cli_args.clone()).await;

        // Ensure that both wallets have a non-zero balance by letting Alice
        // mine a block.
        let genesis_block = Block::genesis(network);
        let (block_1, expected_1) =
            make_mock_block(&genesis_block, None, alice_key, rng.random(), network);

        // Update both states with block 1
        alice
            .lock_guard_mut()
            .await
            .wallet_state
            .add_expected_utxos(expected_1)
            .await;
        alice.set_new_tip(block_1.clone()).await.unwrap();
        bob.set_new_tip(block_1.clone()).await.unwrap();

        // Create a transaction that's valid to be included in block 2
        let mut utxos_from_bob = TxOutputList::from(Vec::<TxOutput>::new());
        for i in 0..4 {
            let amount: NativeCurrencyAmount = NativeCurrencyAmount::coins(i);
            utxos_from_bob.push(TxOutput::onchain_native_currency(
                amount,
                rng.random(),
                bob_address.into(),
                true,
            ));
        }

        let now = genesis_block.kernel.header.timestamp;
        let in_seven_months = now + Timestamp::months(7);
        let config_bob = TxCreationConfig::default()
            .recover_change_on_chain(bob_spending_key.into())
            .with_prover_capability(TxProvingCapability::SingleProof);
        let artifacts_bob = bob
            .api()
            .tx_initiator_internal()
            .create_transaction(
                utxos_from_bob.clone(),
                NativeCurrencyAmount::coins(1),
                in_seven_months,
                config_bob,
                consensus_rule_set,
            )
            .await
            .unwrap();
        let tx_by_bob: Transaction = artifacts_bob.transaction.into();

        // inform wallet of any expected utxos from this tx.
        let expected_utxos = bob.lock_guard().await.wallet_state.extract_expected_utxos(
            utxos_from_bob
                .concat_with(Vec::from(artifacts_bob.details.tx_outputs.clone()))
                .iter(),
            UtxoNotifier::Myself,
        );
        bob.lock_guard_mut()
            .await
            .wallet_state
            .add_expected_utxos(expected_utxos)
            .await;

        // Add this transaction to a mempool
        let mut mempool = Mempool::new(ByteSize::gb(1), TxProvingCapability::SingleProof, &block_1);
        mempool.insert(tx_by_bob.clone(), UpgradePriority::Irrelevant);

        // Create another transaction that's valid to be included in block 2, but isn't actually
        // included by the miner. This transaction is inserted into the mempool, but since it's
        // not included in block 2 it must still be in the mempool after the mempool has been
        // updated with block 2. Also: The transaction must be valid after block 2 as the mempool
        // manager must keep mutator set data updated.
        let send_amount = NativeCurrencyAmount::coins(30);
        let utxos_from_alice = vec![TxOutput::onchain_native_currency(
            send_amount,
            rng.random(),
            alice_address.into(),
            true,
        )];
        let config_alice = TxCreationConfig::default()
            .recover_change_off_chain(alice_key.into())
            .with_prover_capability(TxProvingCapability::SingleProof);
        let tx_from_alice_original = alice
            .api()
            .tx_initiator_internal()
            .create_transaction(
                utxos_from_alice.into(),
                NativeCurrencyAmount::coins(1),
                in_seven_months,
                config_alice,
                consensus_rule_set,
            )
            .await
            .unwrap()
            .transaction;
        mempool.insert(tx_from_alice_original.into(), UpgradePriority::Critical);

        {
            // Verify that `most_dense_single_proof_pair` returns expected value
            // now that two single proofs are in the mempool.
            let densest_txs = mempool.fee_density_iter().map(|x| x.0).collect_vec();
            assert_eq!(
                densest_txs,
                mempool
                    .preferred_single_proof_pair(TxUpgradeFilter::match_all())
                    .unwrap()
                    .0
                    .map(|x| x.0.txid())
                    .to_vec()
            );
        }

        let light_state = &bob
            .global_state_lock
            .lock_guard()
            .await
            .chain
            .light_state_clone();
        // Create next block which includes Bob's, but not Alice's, transaction.
        let (coinbase_transaction, _expected_utxo) = make_coinbase_transaction_from_state_lock(
            light_state.tip(),
            &bob,
            in_seven_months,
            TritonVmProofJobOptions::default_with_network(network),
        )
        .await
        .unwrap();
        let block_transaction = BlockTransaction::merge(
            coinbase_transaction.into(),
            tx_by_bob,
            Default::default(),
            TritonVmJobQueue::get_instance(),
            TritonVmProofJobOptions::default_with_network(network),
            consensus_rule_set,
        )
        .await
        .unwrap();
        let block_2 = Block::block_template_invalid_proof(
            &block_1,
            block_transaction,
            in_seven_months,
            None,
            network,
        );

        // Update the mempool with block 2 and verify that the mempool now only contains one tx
        assert_eq!(2, mempool.len());
        let _ = mempool.update_with_block(&block_2);
        assert_eq!(1, mempool.len());

        update_all_sp_txs(&mut mempool, &block_1, &block_2, network).await;
        assert_eq!(1, mempool.len());

        // Create a new block to verify that the non-mined transaction contains
        // updated and valid-again mutator set data
        let block2_msa = block_2.mutator_set_accumulator_after().unwrap();
        let mut tx_by_alice_updated: Transaction =
            mempool.get_transactions_for_block_composition(usize::MAX, None)[0].clone();
        assert!(
            tx_by_alice_updated.is_confirmable_relative_to(&block2_msa),
            "Block with tx with updated mutator set data must be confirmable wrt. block_2"
        );

        alice.set_new_tip(block_2.clone()).await.unwrap();
        bob.set_new_tip(block_2.clone()).await.unwrap();

        // Mine 2 blocks without including the transaction but while still keeping the
        // mempool updated. After these 2 blocks are mined, the transaction must still be
        // valid.
        let mut previous_block = block_2;
        for _ in 0..2 {
            let (next_block, _) =
                make_mock_block(&previous_block, None, alice_key, rng.random(), network);
            alice.set_new_tip(next_block.clone()).await.unwrap();
            bob.set_new_tip(next_block.clone()).await.unwrap();
            let _ = mempool.update_with_block(&next_block);
            update_all_sp_txs(&mut mempool, &previous_block, &next_block, network).await;
            previous_block = next_block;
        }

        tx_by_alice_updated =
            mempool.get_transactions_for_block_composition(usize::MAX, None)[0].clone();
        let block_5_timestamp = previous_block.header().timestamp + Timestamp::hours(1);

        let tip_alice = alice
            .global_state_lock
            .lock_guard()
            .await
            .chain
            .tip()
            .to_owned();
        let (cbtx, _eutxo) = make_coinbase_transaction_from_state_lock(
            &tip_alice,
            &alice,
            block_5_timestamp,
            TritonVmProofJobOptions::default_with_network(network),
        )
        .await
        .unwrap();
        let block_tx_5 = BlockTransaction::merge(
            cbtx.into(),
            tx_by_alice_updated,
            Default::default(),
            TritonVmJobQueue::get_instance(),
            TritonVmProofJobOptions::default_with_network(network),
            consensus_rule_set,
        )
        .await
        .unwrap();
        let block_5 = Block::block_template_invalid_proof(
            &previous_block,
            block_tx_5,
            block_5_timestamp,
            None,
            network,
        );
        assert_eq!(Into::<BlockHeight>::into(5), block_5.kernel.header.height);

        let _ = mempool.update_with_block(&block_5);

        assert!(
            mempool.is_empty(),
            "Mempool must be empty after 2nd tx was mined"
        );
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn merged_tx_removes_merge_inputs_but_keeps_them_in_cache() {
        // Verify that a merged transaction replaces the two transactions that
        // are the input into the merge.
        let network = Network::Main;
        let genesis_block = Block::genesis(network);
        let mut mempool = Mempool::new(
            ByteSize::gb(1),
            TxProvingCapability::SingleProof,
            &genesis_block,
        );

        let consensus_rule_set = ConsensusRuleSet::HardforkGamma;
        let (((left, right), merged), _) = merge_tx_triplet(consensus_rule_set).await;
        mempool.insert(left.clone(), UpgradePriority::Irrelevant);
        mempool.insert(right.clone(), UpgradePriority::Irrelevant);
        assert_eq!(2, mempool.len());

        // mock that tip's mutator set hash matches that of transactions
        let tx_mutator_set_hash = merged.kernel.mutator_set_hash;
        mempool.set_tip_mutator_set_hash(tx_mutator_set_hash);

        // Verify that `most_dense_single_proof_pair` returns expected value
        // now that two single proofs are in the mempool.
        let densest_txs = mempool.fee_density_iter().map(|x| x.0).collect_vec();
        assert_eq!(
            densest_txs,
            mempool
                .preferred_single_proof_pair(TxUpgradeFilter::match_all())
                .unwrap()
                .0
                .map(|x| x.0.txid())
                .to_vec()
        );

        mempool.insert(merged.clone(), UpgradePriority::Irrelevant);
        assert_eq!(1, mempool.len());
        assert_eq!(&merged, mempool.get(merged.kernel.txid()).unwrap());

        assert!(mempool
            .preferred_single_proof_pair(TxUpgradeFilter::match_all())
            .is_none());

        assert_eq!(
            2,
            mempool.merge_input_cache_len(),
            "Merge input cache must contain two entries after the merger of the\
             two transactions in mempool was inserted."
        );
        assert!(
            !mempool.accept_transaction(
                left.txid(),
                left.proof.proof_quality().unwrap(),
                tx_mutator_set_hash
            ),
            "may not accept transaction as all have been inserted"
        );
        assert!(
            !mempool.accept_transaction(
                right.txid(),
                right.proof.proof_quality().unwrap(),
                tx_mutator_set_hash
            ),
            "may not accept transaction as all have been inserted"
        );
        assert!(
            !mempool.accept_transaction(
                merged.txid(),
                merged.proof.proof_quality().unwrap(),
                tx_mutator_set_hash
            ),
            "may not accept transaction as all have been inserted"
        );
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn mempool_insertion_is_stable_on_mergers() {
        // Ensure that the mempool state does not change once all
        // transactions in a merge tree has been seen by the mempool.
        let network = Network::Testnet(42);
        let mut mempool = Mempool::new(
            ByteSize::gb(1),
            TxProvingCapability::SingleProof,
            &Block::genesis(network),
        );
        let (bottom, middle, final_tx, _) = nested_mergers(ConsensusRuleSet::HardforkGamma).await;
        let tx_msa_hash = final_tx.kernel.mutator_set_hash;

        for tx in bottom.clone() {
            assert!(
                mempool.accept_transaction(
                    tx.txid(),
                    tx.proof.proof_quality().unwrap(),
                    tx_msa_hash
                ),
                "must accept transaction as it hasn't been inserted yet"
            );
            mempool.insert(tx, UpgradePriority::Irrelevant);
        }
        for tx in middle.clone() {
            assert!(
                mempool.accept_transaction(
                    tx.txid(),
                    tx.proof.proof_quality().unwrap(),
                    tx_msa_hash
                ),
                "must accept transaction as it hasn't been inserted yet"
            );
            mempool.insert(tx, UpgradePriority::Irrelevant);
        }

        let final_txid = final_tx.txid();
        assert!(
            mempool.accept_transaction(
                final_tx.txid(),
                final_tx.proof.proof_quality().unwrap(),
                tx_msa_hash
            ),
            "must accept transaction as it hasn't been inserted yet"
        );
        mempool.insert(final_tx.clone(), UpgradePriority::Irrelevant);
        assert!(mempool.contains(final_txid));
        assert_eq!(1, mempool.len());

        // Insert all transactions again and verify that nothing happens
        for tx in bottom.clone() {
            assert!(
                !mempool.accept_transaction(
                    tx.txid(),
                    tx.proof.proof_quality().unwrap(),
                    tx_msa_hash
                ),
                "may not accept transaction as all have already been inserted"
            );
            let events = mempool.insert(tx, UpgradePriority::Irrelevant);
            assert_eq!(0, events.len());
            assert!(mempool.contains(final_txid));
            assert_eq!(1, mempool.len());
        }
        for tx in middle.clone() {
            assert!(
                !mempool.accept_transaction(
                    tx.txid(),
                    tx.proof.proof_quality().unwrap(),
                    tx_msa_hash
                ),
                "may not accept transaction as all have already been inserted"
            );
            let events = mempool.insert(tx.clone(), UpgradePriority::Irrelevant);
            assert_eq!(0, events.len());
            assert!(mempool.contains(final_txid));
            assert_eq!(1, mempool.len());
        }

        assert!(
            !mempool.accept_transaction(
                final_tx.txid(),
                final_tx.proof.proof_quality().unwrap(),
                tx_msa_hash
            ),
            "may not accept transaction as all have already been inserted"
        );
        let events = mempool.insert(final_tx, UpgradePriority::Irrelevant);
        assert_eq!(0, events.len());
        assert!(mempool.contains(final_txid));
        assert_eq!(1, mempool.len());
    }

    #[apply(shared_tokio_runtime)]
    async fn reorganization_clears_mempool_and_merge_input_cache() {
        let network = Network::Main;
        let genesis = Block::genesis(network);

        let block_1a = invalid_empty_block_with_timestamp(
            &genesis,
            network.launch_date() + Timestamp::hours(1),
            network,
        );
        let block_1b = invalid_empty_block_with_timestamp(
            &genesis,
            network.launch_date() + Timestamp::hours(1),
            network,
        );
        let mut mempool =
            Mempool::new(ByteSize::gb(1), TxProvingCapability::SingleProof, &block_1a);

        let consensus_rule_set = ConsensusRuleSet::HardforkGamma;
        let (((a, b), c), _) = merge_tx_triplet(consensus_rule_set).await;
        mempool.insert(a.clone(), UpgradePriority::Irrelevant);
        mempool.insert(b.clone(), UpgradePriority::Irrelevant);
        mempool.insert(c.clone(), UpgradePriority::Irrelevant);

        assert!(
            !mempool.is_empty(),
            "Test assumption: Not empty prior to reorganization"
        );
        assert!(
            !mempool.merge_input_cache_is_empty(),
            "Test assumption: Not empty prior to reorganization"
        );

        mempool.update_with_block(&block_1b).unwrap();
        assert!(
            mempool.is_empty(),
            "Mempool must be cleared after reorganization"
        );
        assert!(
            mempool.merge_input_cache_is_empty(),
            "Merge input must be cleared after reorganization"
        );
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn reorganization_does_not_crash_mempool() {
        // Verify that reorganizations do not crash the client, and other
        // qualities.

        // First put a transaction into the mempool. Then mine block 1a that
        // does not contain this transaction, such that mempool is still
        // non-empty. Then mine a a block 1b that also does not contain this
        // transaction. Mempool state updater must not crash when changing tip
        // from 1a to 1b.
        let network = Network::Testnet(42);
        let consensus_rule_set =
            ConsensusRuleSet::infer_from(network, BlockHeight::genesis().next());
        let alice_wallet = WalletEntropy::devnet_wallet();
        let alice_key = alice_wallet.nth_generation_spending_key_for_tests(0);
        let proving_capability = TxProvingCapability::SingleProof;
        let cli_with_proof_capability = cli_args::Args {
            tx_proving_capability: Some(proving_capability),
            network,
            tx_proof_upgrading: true,
            ..Default::default()
        };
        let mut alice = mock_genesis_global_state(2, alice_wallet, cli_with_proof_capability).await;

        let mut rng: StdRng = StdRng::seed_from_u64(u64::from_str_radix("42", 6).unwrap());
        let bob_wallet_secret = WalletEntropy::new_pseudorandom(rng.random());
        let bob_key = bob_wallet_secret.nth_generation_spending_key_for_tests(0);
        let bob_address = bob_key.to_address();

        let send_amt = NativeCurrencyAmount::coins(1);
        let tx_receiver_data =
            TxOutput::onchain_native_currency(send_amt, rng.random(), bob_address.into(), false);

        let genesis_block = alice
            .lock_guard()
            .await
            .chain
            .archival_state()
            .genesis_block()
            .to_owned();
        let now = genesis_block.kernel.header.timestamp;
        let in_seven_years = now + Timestamp::months(7 * 12);
        let config = TxCreationConfig::default()
            .recover_change_off_chain(alice_key.into())
            .with_prover_capability(proving_capability);
        let never_mined_tx = alice
            .api()
            .tx_initiator_internal()
            .create_transaction(
                vec![tx_receiver_data].into(),
                NativeCurrencyAmount::coins(1),
                in_seven_years,
                config,
                consensus_rule_set,
            )
            .await
            .unwrap()
            .transaction;
        assert!(never_mined_tx.is_valid(network, consensus_rule_set).await);
        assert!(never_mined_tx
            .is_confirmable_relative_to(&genesis_block.mutator_set_accumulator_after().unwrap()));

        alice
            .lock_guard_mut()
            .await
            .mempool
            .insert(never_mined_tx.into(), UpgradePriority::Irrelevant);

        // Add some blocks. The transaction must stay in the mempool, since it
        // is not being mined.
        let mut current_block = genesis_block.clone();
        for i in 0..2 {
            assert_eq!(
                1,
                alice.lock_guard().await.mempool.len(),
                "The inserted tx must be in the mempool"
            );

            let (next_block, _) = make_mock_block(
                &current_block,
                Some(in_seven_years),
                bob_key,
                rng.random(),
                network,
            );
            let update_jobs = alice.set_new_tip(next_block.clone()).await.unwrap();
            assert!(
                update_jobs.is_empty(),
                "Must return zero update jobs, i = {i}"
            );
            update_all_sp_txs(
                &mut alice.lock_guard_mut().await.mempool,
                &current_block,
                &next_block,
                network,
            )
            .await;

            let mempool_txs = alice
                .lock_guard()
                .await
                .mempool
                .get_transactions_for_block_composition(usize::MAX, None);
            assert_eq!(
                1,
                mempool_txs.len(),
                "The inserted tx must stay in the mempool"
            );
            assert!(
                mempool_txs[0].is_confirmable_relative_to(
                    &next_block.mutator_set_accumulator_after().unwrap(),
                ),
                "Mempool tx must stay confirmable after new block of height {} has been applied \
                and SP-backed transactions have been updated.",
                next_block.header().height
            );
            assert!(
                mempool_txs[0].is_valid(network, consensus_rule_set).await,
                "Tx should be valid."
            );
            assert_eq!(
                next_block.hash(),
                alice.lock_guard().await.mempool.tip_digest(),
                "Mempool's sync digest must be set correctly"
            );

            current_block = next_block;
        }

        // Now make a reorganization and verify that nothing crashes
        let (block_1b, _) = make_mock_block(
            &genesis_block,
            Some(in_seven_years),
            bob_key,
            rng.random(),
            network,
        );
        assert!(
            block_1b.header().height.previous().unwrap().is_genesis(),
            "Sanity check that new tip has height 1"
        );
        alice.set_new_tip(block_1b.clone()).await.unwrap();

        // Verify that all retained txs (if any) are confirmable against
        // the new tip.
        assert!(
            alice
                .lock_guard()
                .await
                .mempool
                .get_transactions_for_block_composition(usize::MAX, None)
                .iter()
                .all(|tx| tx.is_confirmable_relative_to(
                    &block_1b.mutator_set_accumulator_after().unwrap(),
                )),
            "All retained txs in the mempool must be confirmable relative to the new block.
             Or the mempool must be empty."
        );
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn conflicting_txs_preserve_highest_fee() {
        // Create a global state object, controlled by a preminer who receives a premine-UTXO.
        let network = Network::Main;
        let mut preminer = mock_genesis_global_state(
            2,
            WalletEntropy::devnet_wallet(),
            cli_args::Args::default_with_network(network),
        )
        .await;
        let premine_spending_key = preminer
            .lock_guard()
            .await
            .wallet_state
            .wallet_entropy
            .nth_generation_spending_key_for_tests(0);
        let premine_address = premine_spending_key.to_address();
        let mut rng = StdRng::seed_from_u64(589111u64);

        let make_transaction_with_fee =
            |fee: NativeCurrencyAmount,
             preminer_clone: GlobalStateLock,
             sender_randomness: Digest| async move {
                let consensus_rule_set =
                    ConsensusRuleSet::infer_from(network, BlockHeight::genesis());
                let in_seven_months =
                    Block::genesis(network).kernel.header.timestamp + Timestamp::months(7);

                let receiver_data = TxOutput::offchain_native_currency(
                    NativeCurrencyAmount::coins(1),
                    sender_randomness,
                    premine_address.into(),
                    false,
                );
                let tx_outputs: TxOutputList = vec![receiver_data.clone()].into();
                let config = TxCreationConfig::default()
                    .recover_change_on_chain(premine_spending_key.into())
                    .with_prover_capability(TxProvingCapability::ProofCollection);
                preminer_clone
                    .api()
                    .tx_initiator_internal()
                    .create_transaction(
                        tx_outputs.clone(),
                        fee,
                        in_seven_months,
                        config,
                        consensus_rule_set,
                    )
                    .await
                    .expect("producing proof collection should succeed")
            };

        assert_eq!(0, preminer.lock_guard().await.mempool.len());

        // Insert transaction into mempool
        let tx_low_fee = make_transaction_with_fee(
            NativeCurrencyAmount::coins(1),
            preminer.clone(),
            rng.random(),
        )
        .await
        .transaction;
        {
            let mempool = &mut preminer.lock_guard_mut().await.mempool;
            let events = mempool.insert(tx_low_fee.clone().into(), UpgradePriority::Irrelevant);
            assert_eq!(1, events.len());
            assert_eq!(1, MempoolEvent::num_adds(&events));
            assert_eq!(1, mempool.len());
            assert_eq!(*tx_low_fee, *mempool.get(tx_low_fee.kernel.txid()).unwrap());
        }

        // Insert a transaction that spends the same UTXO and has a higher fee.
        // Verify that this replaces the previous transaction.
        let tx_high_fee = make_transaction_with_fee(
            NativeCurrencyAmount::coins(10),
            preminer.clone(),
            rng.random(),
        )
        .await
        .transaction;
        {
            let mempool = &mut preminer.lock_guard_mut().await.mempool;
            let events = mempool.insert(tx_high_fee.clone().into(), UpgradePriority::Irrelevant);
            assert_eq!(2, events.len());
            assert_eq!(1, MempoolEvent::num_removes(&events));
            assert_eq!(1, MempoolEvent::num_adds(&events));
            assert_eq!(1, mempool.len());
            assert_eq!(
                *tx_high_fee,
                *mempool.get(tx_high_fee.kernel.txid()).unwrap()
            );
        }

        // Insert a conflicting transaction with a lower fee and verify that it
        // does *not* replace the existing transaction.
        {
            let tx_medium_fee = make_transaction_with_fee(
                NativeCurrencyAmount::coins(4),
                preminer.clone(),
                rng.random(),
            )
            .await
            .transaction;
            let mempool = &mut preminer.lock_guard_mut().await.mempool;
            let events = mempool.insert(tx_medium_fee.clone().into(), UpgradePriority::Irrelevant);
            assert!(events.is_empty());
            assert_eq!(1, mempool.len());
            assert_eq!(
                *tx_high_fee,
                *mempool.get(tx_high_fee.kernel.txid()).unwrap()
            );
            assert!(mempool.get(tx_medium_fee.kernel.txid()).is_none());
            assert!(mempool.get(tx_low_fee.kernel.txid()).is_none());
        }
    }

    mod merge_input_cache {
        use neptune_consensus::block::test_helpers::invalid_block_with_kernel_and_mutator_set;

        use super::*;

        #[apply(shared_tokio_runtime)]
        async fn a_b_merged_b_mined() {
            // merge: (a, b) -> c
            // Scenario: a is mined => b is in mempool after block update
            let network = Network::Main;
            let consensus_rule_set = ConsensusRuleSet::HardforkGamma;
            let (((a, b), c), mutator_set) = merge_tx_triplet(consensus_rule_set).await;
            let block1 = invalid_block_with_kernel_and_mutator_set(b.kernel.clone(), mutator_set);

            let mut mempool = Mempool::new(
                ByteSize::gb(1),
                TxProvingCapability::SingleProof,
                &Block::genesis(network),
            );
            mempool.set_tip_digest(block1.header().prev_block_digest);

            mempool.insert(a.clone(), UpgradePriority::Irrelevant);
            mempool.insert(b.clone(), UpgradePriority::Irrelevant);
            mempool.insert(c.clone(), UpgradePriority::Irrelevant);
            assert!(!mempool.contains(a.txid()));
            assert!(!mempool.contains(b.txid()));
            assert!(mempool.contains(c.txid()));

            assert_eq!(2, mempool.merge_input_cache_len());
            let (events, _) = mempool.update_with_block(&block1).unwrap();
            assert!(mempool.contains(a.txid()));
            assert!(!mempool.contains(b.txid()));
            assert!(!mempool.contains(c.txid()));
            assert_eq!(1, mempool.len());

            assert_eq!(2, events.len());
            assert_eq!(1, MempoolEvent::num_removes(&events));
            assert_eq!(1, MempoolEvent::num_adds(&events));
            assert!(mempool.merge_input_cache_is_empty());
        }

        #[apply(shared_tokio_runtime)]
        async fn a_b_merged_c_mined() {
            // merge: (a, b) -> c
            // Scenario: c is mined => mempool is empty after block update
            let network = Network::Main;
            let consensus_rule_set = ConsensusRuleSet::HardforkGamma;
            let (((a, b), c), mutator_set) = merge_tx_triplet(consensus_rule_set).await;
            let block1 = invalid_block_with_kernel_and_mutator_set(c.kernel.clone(), mutator_set);

            let mut mempool = Mempool::new(
                ByteSize::gb(1),
                TxProvingCapability::SingleProof,
                &Block::genesis(network),
            );
            mempool.set_tip_digest(block1.header().prev_block_digest);

            mempool.insert(a.clone(), UpgradePriority::Irrelevant);
            mempool.insert(b.clone(), UpgradePriority::Irrelevant);
            mempool.insert(c.clone(), UpgradePriority::Irrelevant);
            assert!(!mempool.contains(a.txid()));
            assert!(!mempool.contains(b.txid()));
            assert!(mempool.contains(c.txid()));

            let (events, _) = mempool.update_with_block(&block1).unwrap();
            assert!(!mempool.contains(a.txid()));
            assert!(!mempool.contains(b.txid()));
            assert!(!mempool.contains(c.txid()));
            assert!(mempool.is_empty());

            assert_eq!(1, events.len());
            assert_eq!(1, MempoolEvent::num_removes(&events));
            assert_eq!(0, MempoolEvent::num_adds(&events));
        }

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn nested_mergers_behave() {
            let network = Network::Testnet(42);
            let (bottom, [left, right], final_tx, mutator_set) =
                nested_mergers(ConsensusRuleSet::HardforkGamma).await;
            let block_bottom = invalid_block_with_kernel_and_mutator_set(
                bottom[0].kernel.clone(),
                mutator_set.clone(),
            );
            let block_middle =
                invalid_block_with_kernel_and_mutator_set(left.kernel.clone(), mutator_set.clone());
            let block_top = invalid_block_with_kernel_and_mutator_set(
                final_tx.kernel.clone(),
                mutator_set.clone(),
            );

            let mut mempool = Mempool::new(
                ByteSize::gb(1),
                TxProvingCapability::SingleProof,
                &Block::genesis(network),
            );
            mempool.set_tip_digest(block_bottom.header().prev_block_digest);

            for tx in &bottom {
                let events = mempool.insert(tx.clone(), UpgradePriority::Irrelevant);
                assert_eq!(1, events.len());
                assert_eq!(1, MempoolEvent::num_adds(&events));
            }
            assert_eq!(4, mempool.len());
            assert_eq!(0, mempool.merge_input_cache_len());

            for tx in [&left, &right] {
                let events = mempool.insert(tx.clone(), UpgradePriority::Irrelevant);
                assert_eq!(3, events.len());
                assert_eq!(1, MempoolEvent::num_adds(&events));
                assert_eq!(2, MempoolEvent::num_removes(&events));
            }
            assert_eq!(2, mempool.len());
            assert_eq!(4, mempool.merge_input_cache_len());

            let events = mempool.insert(final_tx.clone(), UpgradePriority::Irrelevant);
            assert_eq!(3, events.len());
            assert_eq!(1, MempoolEvent::num_adds(&events));
            assert_eq!(2, MempoolEvent::num_removes(&events));
            assert_eq!(1, mempool.len());
            assert_eq!(6, mempool.merge_input_cache_len());

            // Scenario: non-merged transaction mined (bottom layer)
            let mut mempool_bottom = mempool.clone();
            let (events1, _) = mempool_bottom.update_with_block(&block_bottom).unwrap();
            assert!(!mempool_bottom.contains(bottom[0].txid()));
            assert!(mempool_bottom.contains(bottom[1].txid()));
            assert!(mempool_bottom.contains(right.txid()));
            assert_eq!(3, events1.len());
            assert_eq!(2, MempoolEvent::num_adds(&events1));
            assert_eq!(1, MempoolEvent::num_removes(&events1));
            assert_eq!(2, mempool_bottom.merge_input_cache_len());

            // Scenario: one-time-merged transaction mined (middle layer)
            let mut mempool_middle = mempool.clone();
            let (events2, _) = mempool_middle.update_with_block(&block_middle).unwrap();
            assert_eq!(2, events2.len());
            assert_eq!(1, MempoolEvent::num_adds(&events2));
            assert_eq!(1, MempoolEvent::num_removes(&events2));
            assert!(!mempool_middle.contains(bottom[0].txid()));
            assert!(!mempool_middle.contains(bottom[1].txid()));
            assert!(mempool_middle.contains(right.txid()));
            assert_eq!(2, mempool_middle.merge_input_cache_len());

            // Scenario: two-time-merged transaction mined (top layer)
            let mut mempool_top = mempool.clone();
            let (events3, _) = mempool_top.update_with_block(&block_top).unwrap();
            assert_eq!(1, events3.len());
            assert_eq!(0, MempoolEvent::num_adds(&events3));
            assert_eq!(1, MempoolEvent::num_removes(&events3));
            assert!(mempool_top.is_empty());
            assert!(mempool_top.merge_input_cache_is_empty());
        }
    }

    mod get_txs_based_on_inputs_or_outputs {
        use super::*;

        #[apply(shared_tokio_runtime)]
        async fn can_return_multiple_txs() {
            // Generate mempool with 11 synced single proofs
            let num_txs = 11;
            let mempool = mock_mempool_singleproofs(num_txs, &Block::genesis(Network::Main));

            let mut all_outputs = vec![];
            for (txid, _) in mempool.fee_density_iter() {
                let tx = mempool.get(txid).unwrap();
                all_outputs.extend(tx.kernel.outputs.clone());
            }

            let all_outputs: HashSet<_> = all_outputs.into_iter().collect();
            let res = mempool.with_matching_addition_records(&all_outputs);
            assert_eq!(num_txs, res.len());

            assert!(res.iter().map(|(_, pos)| pos.unwrap()).eq(0..num_txs));
        }
    }

    mod mutator_set_updates {
        use super::*;
        use crate::tests::shared::blocks::fake_valid_deterministic_successor;
        use crate::tests::shared::mock_tx::genesis_tx_with_proof_type;

        #[apply(shared_tokio_runtime)]
        async fn tx_ms_updating() {
            let network = Network::Testnet(42);
            let fee = NativeCurrencyAmount::coins(1);

            let genesis_block = Block::genesis(network);
            let block1 = fake_valid_deterministic_successor(&genesis_block, network).await;
            for tx_proving_capability in [
                TxProvingCapability::PrimitiveWitness,
                TxProvingCapability::ProofCollection,
                TxProvingCapability::SingleProof,
            ] {
                let mut mempool = Mempool::new(
                    ByteSize::gb(1),
                    TxProvingCapability::SingleProof,
                    &genesis_block,
                );

                // First insert a PW backed transaction to ensure PW is
                // present, as this determines what MS-data updating jobs are
                // returned.
                let pw_tx =
                    genesis_tx_with_proof_type(TxProvingCapability::PrimitiveWitness, network, fee)
                        .await;
                mempool.insert(pw_tx.into(), UpgradePriority::Critical);
                let tx = genesis_tx_with_proof_type(tx_proving_capability, network, fee).await;
                let txid = tx.txid();

                mempool.insert(tx.into(), UpgradePriority::Critical);

                let (_, update_jobs) = mempool.update_with_block(&block1).unwrap();
                assert_eq!(1, update_jobs.len(), "Must return 1 job for MS-updating");

                mocked_mempool_update_handler(
                    update_jobs,
                    &mut mempool,
                    &block1,
                    &genesis_block.mutator_set_accumulator_after().unwrap(),
                    network,
                )
                .await;

                assert!(
                    mempool
                        .get(txid)
                        .unwrap()
                        .clone()
                        .is_confirmable_relative_to(
                            &block1.mutator_set_accumulator_after().unwrap()
                        ),
                    "transaction must be updatable"
                );
            }
        }
    }

    mod proof_upgrade_candidates {
        use std::str::FromStr;

        use proptest::prop_assert;
        use test_strategy::proptest;

        use super::*;
        use crate::tests::shared::blocks::fake_valid_successor_for_tests;
        use crate::tests::shared::mock_tx::genesis_tx_with_proof_type;

        #[apply(shared_tokio_runtime)]
        async fn sp_update_only_returns_unsynced_txs() {
            let network = Network::Testnet(42);
            let fee = NativeCurrencyAmount::coins(1);
            let sp_tx =
                genesis_tx_with_proof_type(TxProvingCapability::SingleProof, network, fee).await;

            let mut rng = rand::rng();
            let genesis_block = Block::genesis(network);
            let mut mempool = Mempool::new(
                ByteSize::gb(1),
                TxProvingCapability::SingleProof,
                &genesis_block,
            );

            // Insert synced transaction into mempool, verify no transaction
            // is returned.
            mempool.insert(sp_tx.into(), UpgradePriority::Irrelevant);
            assert!(mempool
                .preferred_update(TxUpgradeFilter::match_all())
                .is_none());

            // Ensure tx in mempool becomes unsynced.
            let block1_timestamp = genesis_block.header().timestamp + Timestamp::hours(1);
            let block1 = fake_valid_successor_for_tests(
                &genesis_block,
                block1_timestamp,
                rng.random(),
                network,
            )
            .await;
            let (_, returned_jobs) = mempool.update_with_block(&block1).unwrap();
            assert!(returned_jobs.is_empty());
            assert!(mempool
                .preferred_update(TxUpgradeFilter::match_all())
                .is_some());

            // Verify filter behavior
            let accept_first_half = TxUpgradeFilter::from_str("2:0").unwrap();
            let accept_second_half = TxUpgradeFilter::from_str("2:1").unwrap();
            let num_matches = u8::from(mempool.preferred_update(accept_first_half).is_some())
                + u8::from(mempool.preferred_update(accept_second_half).is_some());
            assert_eq!(1, num_matches, "Exactly one filter must match transaction");
        }

        #[proptest(cases = 8, async = "tokio")]
        async fn preferred_proof_collection_respects_tx_upgrade_filter(
            #[strategy(PrimitiveWitness::arbitrary_with_size_numbers(Some(2), 3, 9))]
            primitive_witness: PrimitiveWitness,
        ) {
            let tx = Transaction {
                kernel: primitive_witness.kernel,
                proof: TransactionProof::ProofCollection(ProofCollection::invalid()),
            };
            let mut mempool = Mempool::new(
                ByteSize::gb(1),
                TxProvingCapability::SingleProof,
                &Block::genesis(Network::Main),
            );
            mempool.set_tip_mutator_set_hash(tx.kernel.mutator_set_hash);
            mempool.insert(tx, UpgradePriority::Irrelevant);

            let accept_all = TxUpgradeFilter::match_all();
            let accept_first_third = TxUpgradeFilter::from_str("3:0").unwrap();
            let accept_second_third = TxUpgradeFilter::from_str("3:1").unwrap();
            let accept_third_third = TxUpgradeFilter::from_str("3:2").unwrap();

            let num_proofs_threshold = 20;
            prop_assert!(mempool
                .preferred_proof_collection(num_proofs_threshold, accept_all)
                .is_some());
            let num_matches = u8::from(
                mempool
                    .preferred_proof_collection(num_proofs_threshold, accept_first_third)
                    .is_some(),
            ) + u8::from(
                mempool
                    .preferred_proof_collection(num_proofs_threshold, accept_second_third)
                    .is_some(),
            ) + u8::from(
                mempool
                    .preferred_proof_collection(num_proofs_threshold, accept_third_third)
                    .is_some(),
            );
            assert_eq!(
                1, num_matches,
                "Only one match from mutually exclusive filters"
            );
        }
    }

    mod proof_quality_tests {

        use super::*;
        use crate::tests::shared::mock_tx::genesis_tx_with_proof_type;

        #[apply(shared_tokio_runtime)]
        async fn always_preserve_primitive_witness_if_available() {
            let network = Network::Testnet(42);
            let fee = NativeCurrencyAmount::coins(1);
            let pw_tx =
                genesis_tx_with_proof_type(TxProvingCapability::PrimitiveWitness, network, fee)
                    .await;
            let txid = pw_tx.txid();

            let genesis_block = Block::genesis(network);
            let mut mempool = mock_mempool_singleproofs(0, &genesis_block);
            mempool.insert(pw_tx.into(), UpgradePriority::Critical);

            let pc_tx =
                genesis_tx_with_proof_type(TxProvingCapability::ProofCollection, network, fee)
                    .await;
            mempool.insert(pc_tx.into(), UpgradePriority::Critical);
            assert_eq!(
                1,
                mempool.len(),
                "assumption: original transaction replaced"
            );

            assert!(
                mempool.primitive_witness_is_some(txid),
                "proof collection may not delete primitive witness"
            );

            let sp_tx =
                genesis_tx_with_proof_type(TxProvingCapability::SingleProof, network, fee).await;
            mempool.insert(sp_tx.into(), UpgradePriority::Critical);
            assert_eq!(
                1,
                mempool.len(),
                "assumption: original transaction replaced"
            );

            assert_eq!(1, mempool.len());
            assert!(
                mempool.primitive_witness_is_some(txid),
                "single proof may not delete primitive witness"
            );
        }

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn single_proof_always_replaces_primitive_witness() {
            let network = Network::Testnet(42);
            let pw_high_fee = genesis_tx_with_proof_type(
                TxProvingCapability::PrimitiveWitness,
                network,
                NativeCurrencyAmount::coins(15),
            )
            .await;
            let genesis_block = Block::genesis(network);
            let mut mempool = mock_mempool_singleproofs(0, &genesis_block);
            mempool.insert(pw_high_fee.into(), UpgradePriority::Critical);
            assert!(mempool.len().is_one(), "One tx after insertion");

            let low_fee = NativeCurrencyAmount::coins(1);
            let sp_low_fee =
                genesis_tx_with_proof_type(TxProvingCapability::SingleProof, network, low_fee)
                    .await;
            let txid = sp_low_fee.kernel.txid();
            mempool.insert(sp_low_fee.into(), UpgradePriority::Critical);
            assert!(
                mempool.len().is_one(),
                "One tx after 2nd insertion. Because pw-tx was replaced."
            );
            let tx_in_mempool = mempool.get(txid).unwrap();
            assert!(matches!(
                tx_in_mempool.proof,
                TransactionProof::SingleProof(_)
            ));
        }

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn single_proof_always_replaces_proof_collection() {
            let network = Network::Testnet(42);
            let pc_high_fee = genesis_tx_with_proof_type(
                TxProvingCapability::ProofCollection,
                network,
                NativeCurrencyAmount::coins(15),
            )
            .await;
            let genesis_block = Block::genesis(network);
            let mut mempool = mock_mempool_singleproofs(0, &genesis_block);
            mempool.insert(pc_high_fee.into(), UpgradePriority::Irrelevant);
            assert!(mempool.len().is_one(), "One tx after insertion");

            let low_fee = NativeCurrencyAmount::coins(1);
            let sp_low_fee =
                genesis_tx_with_proof_type(TxProvingCapability::SingleProof, network, low_fee)
                    .await;
            let txid = sp_low_fee.kernel.txid();
            mempool.insert(sp_low_fee.into(), UpgradePriority::Irrelevant);
            assert!(
                mempool.len().is_one(),
                "One tx after 2nd insertion. Because pc-tx was replaced."
            );
            let tx_in_mempool = mempool.get(txid).unwrap();
            assert!(matches!(
                tx_in_mempool.proof,
                TransactionProof::SingleProof(_)
            ));
        }

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn proof_collection_always_replaces_primitive_witness() {
            let network = Network::Main;
            let pc_high_fee = genesis_tx_with_proof_type(
                TxProvingCapability::PrimitiveWitness,
                network,
                NativeCurrencyAmount::coins(15),
            )
            .await;
            let genesis_block = Block::genesis(network);
            let mut mempool = mock_mempool_singleproofs(0, &genesis_block);
            mempool.insert(pc_high_fee.into(), UpgradePriority::Critical);
            assert!(mempool.len().is_one(), "One tx after insertion");

            let low_fee = NativeCurrencyAmount::coins(1);
            let sp_low_fee =
                genesis_tx_with_proof_type(TxProvingCapability::ProofCollection, network, low_fee)
                    .await;
            let txid = sp_low_fee.kernel.txid();
            mempool.insert(sp_low_fee.into(), UpgradePriority::Critical);
            assert!(
                mempool.len().is_one(),
                "One tx after 2nd insertion. Because pw-tx was replaced."
            );
            let tx_in_mempool = mempool.get(txid).unwrap();
            assert!(matches!(
                tx_in_mempool.proof,
                TransactionProof::ProofCollection(_)
            ));
        }
    }
}
