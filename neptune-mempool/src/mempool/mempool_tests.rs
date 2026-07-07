#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::collections::HashSet;

    use bytesize::ByteSize;
    use get_size2::GetSize;
    use itertools::Itertools;
    use macro_rules_attr::apply;
    use neptune_consensus::block::Block;
    use neptune_consensus::proof_abstractions::tx_proving_capability::TxProvingCapability;
    use neptune_consensus::transaction::Transaction;
    use neptune_consensus::transaction::TransactionProof;
    use neptune_consensus::transaction::primitive_witness::PrimitiveWitness;
    use neptune_consensus::transaction::test_helpers::make_mock_txs_with_primitive_witness_with_timestamp;
    use neptune_consensus::transaction::test_helpers::make_plenty_mock_transaction_supported_by_invalid_single_proofs;
    use neptune_consensus::transaction::test_helpers::make_plenty_mock_transaction_supported_by_primitive_witness;
    use neptune_consensus::transaction::test_helpers::mock_transactions_with_sized_single_proof;
    use neptune_consensus::transaction::test_helpers::txkernel;
    use neptune_consensus::transaction::transaction_kernel::TransactionKernelModifier;
    use neptune_consensus::transaction::transaction_proof::TransactionProofType;
    use neptune_mutator_set::addition_record::AdditionRecord;
    use neptune_mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
    use neptune_primitives::network::Network;
    use neptune_primitives::timestamp::Timestamp;
    use num_bigint::BigInt;
    use num_rational::BigRational as FeeDensity;
    use num_traits::Zero;
    use proptest_arbitrary_interop::arb;
    use rand::Rng;
    use tracing_test::traced_test;

    use crate::mempool::Mempool;
    use crate::mempool::mempool_event::MempoolEvent;
    use crate::mempool::upgrade_priority::UpgradePriority;
    use crate::test_utils::shared_tokio_runtime;
    use crate::transaction_kernel_id::Txid;
    use crate::transaction_proof_quality::TransactionProofQualityExt;
    use crate::tx_upgrade_filter::TxUpgradeFilter;

    const SIZE_20MB_IN_BYTES: usize = 20_000_000;

    /// Create a mempool with n transactions backed by either primitive witness,
    /// proof collection, or single proof. Transactions may be either synced or
    /// not synced from the the perspective of the mempool but in a broader
    /// context they are invalid.
    fn mock_mempool_mixed(num_txs: usize, sync_block: &Block) -> Mempool {
        let mut mempool = Mempool::new(
            ByteSize::gb(1),
            TxProvingCapability::ProofCollection,
            sync_block,
        );

        let mut rng = rand::rng();

        let mutator_set_hash = sync_block.mutator_set_accumulator_after().unwrap().hash();
        let txs = make_plenty_mock_transaction_supported_by_primitive_witness(num_txs);
        for mut tx in txs {
            let proof_type = match rng.random_range(0..=2) {
                0 => TransactionProofType::PrimitiveWitness,
                1 => TransactionProofType::ProofCollection,
                2 => TransactionProofType::SingleProof,
                _ => unreachable!(),
            };
            tx.proof = proof_type.invalid();

            let is_synced = rng.random_bool(0.5);
            if is_synced {
                tx.kernel = TransactionKernelModifier::default()
                    .mutator_set_hash(mutator_set_hash)
                    .modify(tx.kernel);
            }

            mempool.insert(tx, UpgradePriority::Irrelevant);
        }

        mempool
    }

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

    #[apply(shared_tokio_runtime)]
    pub async fn insert_then_get_then_remove_then_get() {
        let network = Network::Main;
        let genesis_block = Block::genesis(network);
        let mut mempool = Mempool::new(
            ByteSize::gb(1),
            TxProvingCapability::ProofCollection,
            &genesis_block,
        );

        let txs = make_plenty_mock_transaction_supported_by_primitive_witness(2);
        let transaction_digests = txs.iter().map(|tx| tx.kernel.txid()).collect_vec();
        assert!(!mempool.contains(transaction_digests[0]));
        assert!(!mempool.contains(transaction_digests[1]));
        mempool.insert(txs[0].clone(), UpgradePriority::Irrelevant);
        assert!(mempool.contains(transaction_digests[0]));
        assert!(!mempool.contains(transaction_digests[1]));

        let transaction_get_option = mempool.get(transaction_digests[0]);
        assert_eq!(Some(&txs[0]), transaction_get_option);
        assert!(mempool.contains(transaction_digests[0]));
        assert!(!mempool.contains(transaction_digests[1]));

        let remove_event = mempool.remove(transaction_digests[0]);
        assert_eq!(
            Some(MempoolEvent::RemoveTx(txs[0].kernel.clone())),
            remove_event
        );
        for tx_id in &transaction_digests {
            assert!(!mempool.contains(*tx_id));
        }

        let transaction_second_get_option = mempool.get(transaction_digests[0]);
        assert_eq!(None, transaction_second_get_option);

        for tx_id in transaction_digests {
            assert!(!mempool.contains(tx_id));
        }

        assert!(mempool.is_empty());
        assert!(mempool.len().is_zero());
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn get_densest_transactions_no_tx_cap() {
        // Verify that transactions are returned ordered by fee density, with highest fee density first
        let num_txs = 10;
        let network = Network::Main;
        let sync_block = Block::genesis(network);
        let mempool = mock_mempool_singleproofs(num_txs, &sync_block);

        let max_fee_density: FeeDensity = FeeDensity::new(BigInt::from(u128::MAX), BigInt::from(1));
        let mut prev_fee_density = max_fee_density;
        for curr_transaction in
            mempool.get_transactions_for_block_composition(SIZE_20MB_IN_BYTES, None)
        {
            let curr_fee_density = curr_transaction.fee_density();
            assert!(curr_fee_density <= prev_fee_density);
            prev_fee_density = curr_fee_density;
        }

        assert!(!mempool.is_empty())
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn get_densest_transactions_with_tx_cap() {
        // Verify that transactions are returned ordered by fee density, with
        // highest fee density first, and that the transaction cap is respected.
        let num_txs_in_mempool = 12;
        let network = Network::Main;
        let sync_block = Block::genesis(network);
        let mempool = mock_mempool_singleproofs(num_txs_in_mempool, &sync_block);

        for num_mergers in 0..=num_txs_in_mempool {
            let returned_transactions = mempool
                .get_transactions_for_block_composition(SIZE_20MB_IN_BYTES, Some(num_mergers));
            assert_eq!(num_mergers, returned_transactions.len());

            let max_fee_density: FeeDensity =
                FeeDensity::new(BigInt::from(u128::MAX), BigInt::from(1));
            let mut prev_fee_density = max_fee_density;
            for curr_transaction in returned_transactions {
                let curr_fee_density = curr_transaction.fee_density();
                assert!(curr_fee_density <= prev_fee_density);
                prev_fee_density = curr_fee_density;
            }
        }

        assert!(
            !mempool.is_empty(),
            "Getting transactions for composition may not empty mempool."
        )
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn get_sorted_iter() {
        // Verify that the function `get_sorted_iter` returns transactions sorted by fee density
        let network = Network::Main;
        let sync_block = Block::genesis(network);
        let num_txs = 10;
        let mempool = mock_mempool_singleproofs(num_txs, &sync_block);

        let max_fee_density: FeeDensity = FeeDensity::new(BigInt::from(u128::MAX), BigInt::from(1));
        let mut prev_fee_density = max_fee_density;
        for (_transaction_id, curr_fee_density) in mempool.fee_density_iter() {
            assert!(curr_fee_density <= prev_fee_density);
            prev_fee_density = curr_fee_density;
        }

        assert!(!mempool.is_empty())
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn max_num_transactions_is_respected() {
        let network = Network::Main;
        let sync_block = Block::genesis(network);
        let num_txs = 12;
        let mempool = mock_mempool_singleproofs(num_txs, &sync_block);

        for i in 0..num_txs {
            assert_eq!(
                i,
                mempool
                    .get_transactions_for_block_composition(SIZE_20MB_IN_BYTES, Some(i))
                    .len()
            );
        }
    }

    #[traced_test]
    #[test]
    fn only_txs_with_up_to_date_mutator_set_hashes_are_returned_for_block_inclusion() {
        let network = Network::Main;
        let genesis_block = Block::genesis(network);
        let mutator_set_hash = genesis_block
            .mutator_set_accumulator_after()
            .unwrap()
            .hash();

        for i in 0..5 {
            let mut mempool = Mempool::new(
                ByteSize::gb(1),
                TxProvingCapability::ProofCollection,
                &genesis_block,
            );
            let mut txs = make_plenty_mock_transaction_supported_by_invalid_single_proofs(i);

            for tx in txs.clone() {
                mempool.insert(tx, UpgradePriority::Irrelevant);
            }

            let max_total_tx_size = 1_000_000_000;
            let txs_returned =
                mempool.get_transactions_for_block_composition(max_total_tx_size, None);
            assert_eq!(
                0,
                txs_returned.len(),
                "Must return 0/{i} transaction when mutator set hashes don't match. Got {}/{i}",
                txs_returned.len()
            );

            mempool.clear();
            for tx in &mut txs {
                tx.kernel = TransactionKernelModifier::default()
                    .mutator_set_hash(mutator_set_hash)
                    .modify(tx.kernel.clone());
                mempool.insert(tx.to_owned(), UpgradePriority::Irrelevant);
            }
            assert_eq!(
                i,
                mempool
                    .get_transactions_for_block_composition(max_total_tx_size, None)
                    .len(),
                "Must return {i}/{i} transaction when mutator set hashes do match"
            );
        }
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn prune_stale_transactions() {
        let network = Network::Main;
        let genesis_block = Block::genesis(network);
        let mut mempool = Mempool::new(
            ByteSize::gb(1),
            TxProvingCapability::ProofCollection,
            &genesis_block,
        );
        assert!(
            mempool.is_empty(),
            "Mempool must be empty after initialization"
        );

        let now = Timestamp::now();
        let eight_days_ago = now - Timestamp::days(8);
        let old_txs = make_mock_txs_with_primitive_witness_with_timestamp(6, eight_days_ago);

        for tx in old_txs {
            mempool.insert(tx, UpgradePriority::Irrelevant);
        }

        let new_txs = make_mock_txs_with_primitive_witness_with_timestamp(5, now);

        for tx in new_txs {
            mempool.insert(tx, UpgradePriority::Irrelevant);
        }

        assert_eq!(mempool.len(), 11);
        mempool.prune_stale_transactions();
        assert_eq!(mempool.len(), 5);
    }

    #[apply(shared_tokio_runtime)]
    async fn single_proof_status_is_respected_for_block_composition() {
        let network = Network::Main;
        let genesis_block = Block::genesis(network);

        // Set up mempool with primitive-witness-backed transactions and
        // up-to-date mutator set hash, i.e., cannot use set_up_mempool().
        let txs = make_plenty_mock_transaction_supported_by_primitive_witness(11);
        let mut mempool = Mempool::new(
            ByteSize::gb(1),
            TxProvingCapability::SingleProof,
            &genesis_block,
        );

        let mutator_set_hash = genesis_block
            .mutator_set_accumulator_after()
            .unwrap()
            .hash();
        for mut tx in txs {
            tx.kernel = TransactionKernelModifier::default()
                .mutator_set_hash(mutator_set_hash)
                .modify(tx.kernel);
            mempool.insert(tx, UpgradePriority::Irrelevant);
        }

        assert!(!mempool.is_empty());
        assert!(
            mempool
                .get_transactions_for_block_composition(usize::MAX, None)
                .is_empty()
        );
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn insert_11_transactions() {
        let network = Network::Main;
        let genesis_block = Block::genesis(network);
        let txs = make_plenty_mock_transaction_supported_by_primitive_witness(11);
        let mut mempool = Mempool::new(
            ByteSize::gb(1),
            TxProvingCapability::ProofCollection,
            &genesis_block,
        );

        for tx in txs {
            let txid = tx.txid();
            assert!(!mempool.contains(txid));
            let events = mempool.insert(tx, UpgradePriority::Irrelevant);
            assert_eq!(1, events.len());
            assert!(mempool.contains(txid));
        }

        assert_eq!(
            11,
            mempool.len(),
            "All transactions are inserted into mempool"
        );
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn max_size_is_respected() {
        let network = Network::Main;
        let genesis_block = Block::genesis(network);
        let num_insertions = 20;
        let txs = mock_transactions_with_sized_single_proof(
            num_insertions,
            ByteSize::kb(100).as_u64() as usize,
        );

        let mut expected_txs = txs.clone();
        expected_txs.sort_by_key(|x| x.fee_density());
        expected_txs.reverse();

        let max_size = ByteSize::mb(1);
        let mut mempool = Mempool::new(
            max_size,
            TxProvingCapability::ProofCollection,
            &genesis_block,
        );
        for tx in txs.clone() {
            mempool.insert(tx, UpgradePriority::Irrelevant);
            println!("mempool len: {}", mempool.len());
            println!("mempool size: {}", mempool.get_size());
        }

        assert!(
            num_insertions > mempool.len(),
            "Test assumption: Transactions' sizes must exceed max allowed size"
        );
        assert!(!mempool.is_empty(), "Test assumption: Mempool not empty");

        let max_size: usize = max_size.0.try_into().unwrap();
        assert!(mempool.get_size() < max_size);

        let mempool_iter = mempool.fee_density_iter();
        for (expected, (txid, fee_density)) in expected_txs.iter().zip(mempool_iter) {
            assert_eq!(expected.txid(), txid);
            assert_eq!(expected.fee_density(), fee_density);
        }
    }

    #[test]
    fn txs_kicked_out_bc_max_size_exceeded_return_events() {
        let network = Network::Main;
        let genesis_block = Block::genesis(network);
        let mut mempool = Mempool::new(
            ByteSize::mb(3),
            TxProvingCapability::ProofCollection,
            &genesis_block,
        );

        let num_insertions = 7;
        let mut txs = mock_transactions_with_sized_single_proof(
            num_insertions,
            ByteSize::mb(1).as_u64() as usize,
        );
        txs.sort_unstable_by_key(|x| x.fee_density());
        let mut all_events = vec![];
        for tx in txs {
            all_events.extend(mempool.insert(tx, UpgradePriority::Critical));
        }

        let removal_events = all_events
            .into_iter()
            .filter(|x| matches!(x, MempoolEvent::RemoveTx(_)))
            .collect_vec();
        let num_removal_events = removal_events.len();
        assert_ne!(
            0, num_removal_events,
            "Test assumption: Not all txs can fit into mempool"
        );
        assert_eq!(
            num_insertions,
            num_removal_events + mempool.len(),
            "All insertions must be either in mempool or in the removal events. \
            Got #removal events: {num_removal_events}; mempool length: {}",
            mempool.len()
        );
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn get_mempool_size() {
        // Verify that the `get_size` method on mempool returns sane results
        let network = Network::Main;
        let tx_count_small = 2;
        let genesis_block = Block::genesis(network);
        let mempool_small = mock_mempool_singleproofs(tx_count_small, &genesis_block);
        let size_gs_small = mempool_small.get_size();
        let size_serialized_small = mempool_small.tx_dictionary_serialized_len();
        assert!(size_gs_small >= size_serialized_small);
        println!(
            "size of mempool with {tx_count_small} empty txs reported as: {}",
            size_gs_small
        );
        println!(
            "actual size of mempool with {tx_count_small} empty txs when serialized: {}",
            size_serialized_small
        );

        let tx_count_big = 6;
        let mempool_big = mock_mempool_singleproofs(tx_count_big, &genesis_block);
        let size_gs_big = mempool_big.get_size();
        let size_serialized_big = mempool_big.tx_dictionary_serialized_len();
        assert!(size_gs_big >= size_serialized_big);
        assert!(
            (size_gs_big * tx_count_small) as f64 * 1.2 >= (size_gs_small * tx_count_big) as f64,
            "size_gs_big: {size_gs_big}\nsize_gs_small: {size_gs_small}"
        );
        println!("size of mempool with {tx_count_big} empty txs reported as: {size_gs_big}",);
        println!(
            "actual size of mempool with {tx_count_big} empty txs when serialized: {size_serialized_big}",
        );
    }

    mod get_txs_based_on_inputs_or_outputs {
        use super::*;

        #[test_strategy::proptest(async = "tokio", cases = 2)]
        async fn return_empty_vec_on_empty_input_output_set(
            #[strategy(txkernel::with_lengths(1, 1, 1, true))]
        kernel: neptune_consensus::transaction::transaction_kernel::TransactionKernel,
            #[strategy(arb())] quality: TransactionProofType,
        ) {
            let tx = Transaction {
                kernel: kernel.clone(),
                proof: quality.invalid(),
            };
            let mut mempool = Mempool::new(
                ByteSize::gb(1),
                TxProvingCapability::SingleProof,
                &Block::genesis(Network::Main),
            );
            mempool.set_tip_mutator_set_hash(kernel.mutator_set_hash);
            mempool.insert(tx, UpgradePriority::Irrelevant);

            assert!(
                mempool
                    .with_matching_absolute_index_sets(&HashSet::new())
                    .is_empty()
            );
            assert!(
                mempool
                    .with_matching_addition_records(&HashSet::new())
                    .is_empty()
            );
        }

        #[test_strategy::proptest(async = "tokio", cases = 20)]
        async fn one_tx_in_mempool(
            #[strategy(txkernel::with_lengths(3, 3, 3, true))]
        kernel: neptune_consensus::transaction::transaction_kernel::TransactionKernel,
            #[strategy(arb())] quality: TransactionProofType,
            #[strategy(arb())] has_synced_mutator_set: bool,
        ) {
            let tx = Transaction {
                kernel: kernel.clone(),
                proof: quality.invalid(),
            };
            let mut mempool = Mempool::new(
                ByteSize::gb(1),
                TxProvingCapability::SingleProof,
                &Block::genesis(Network::Main),
            );
            mempool.insert(tx, UpgradePriority::Irrelevant);
            if has_synced_mutator_set {
                mempool.set_tip_mutator_set_hash(kernel.mutator_set_hash);
            }

            /* Test input picker */
            let all_sets: HashSet<AbsoluteIndexSet> =
                kernel.inputs.iter().map(|x| x.absolute_indices).collect();
            let mut index_setss: Vec<HashSet<AbsoluteIndexSet>> = vec![all_sets];
            for index_set in kernel.inputs.iter().map(|x| x.absolute_indices) {
                let index_set: HashSet<_> = [index_set].into_iter().collect();
                index_setss.push(index_set);
            }

            let has_expected_queue_order =
                has_synced_mutator_set && quality == TransactionProofType::SingleProof;

            for index_set in index_setss {
                let res = mempool.with_matching_absolute_index_sets(&index_set);
                if has_expected_queue_order {
                    assert_eq!(1, res.len());
                    let (returned_kernel, queue_pos) = &res[0];
                    assert_eq!(&kernel, returned_kernel);
                    assert_eq!(Some(0), *queue_pos);
                } else {
                    assert_eq!(1, res.len());
                    let (returned_kernel, queue_pos) = &res[0];
                    assert_eq!(&kernel, returned_kernel);
                    assert!(queue_pos.is_none());
                }
            }

            /* Test output picker */
            let all_outputs: HashSet<AdditionRecord> = kernel.outputs.iter().copied().collect();
            let mut output_sets: Vec<HashSet<AdditionRecord>> = vec![all_outputs];
            for output in &kernel.outputs {
                let output: HashSet<AdditionRecord> = [*output].into_iter().collect();
                output_sets.push(output);
            }

            for output_set in output_sets {
                let res = mempool.with_matching_addition_records(&output_set);
                if has_expected_queue_order {
                    assert_eq!(1, res.len());
                    let (returned_kernel, queue_pos) = &res[0];
                    assert_eq!(&kernel, returned_kernel);
                    assert_eq!(Some(0), *queue_pos);
                } else {
                    assert_eq!(1, res.len());
                    let (returned_kernel, queue_pos) = &res[0];
                    assert_eq!(&kernel, returned_kernel);
                    assert!(queue_pos.is_none());
                }
            }
        }

        #[apply(shared_tokio_runtime)]
        async fn queue_order_matches_density_ordering_when_all_txs_are_sp_and_synced() {
            // Generate mempool with 10 synced single proofs
            let mempool = mock_mempool_singleproofs(10, &Block::genesis(Network::Main));

            for (expected_queue_order, (txid, _)) in mempool.fee_density_iter().enumerate() {
                let tx = mempool.get(txid).unwrap();

                for output in &tx.kernel.outputs {
                    let output = [*output].into_iter().collect();
                    let res = mempool.with_matching_addition_records(&output);
                    assert_eq!(1, res.len());
                    let (returned_kernel, queue_pos) = &res[0];
                    assert_eq!(&tx.kernel, returned_kernel);
                    assert_eq!(Some(expected_queue_order), *queue_pos);
                }
            }
        }

        #[apply(shared_tokio_runtime)]
        async fn queue_order_matches_block_selection_order() {
            let mempool = mock_mempool_mixed(20, &Block::genesis(Network::Main));

            let txs_for_block_inclusion =
                mempool.get_transactions_for_block_composition(usize::MAX, None);
            let txs_for_block_inclusion = txs_for_block_inclusion
                .into_iter()
                .map(|x| x.txid())
                .collect_vec();

            for (txid, _) in mempool.fee_density_iter() {
                let tx = mempool.get(txid).unwrap();
                let an_output = tx.kernel.outputs[0];
                let an_output = [an_output].into_iter().collect();
                let (_, queue_pos) = mempool.with_matching_addition_records(&an_output)[0].clone();
                let expected_queue_pos = txs_for_block_inclusion.iter().position(|x| *x == txid);

                assert_eq!(expected_queue_pos, queue_pos);
            }
        }
    }

    mod proof_upgrade_candidates {

        use proptest::prop_assert;
        use proptest::prop_assert_eq;
        use test_strategy::proptest;

        use super::*;

        #[proptest(cases = 15, async = "tokio")]
        async fn preferred_update_is_tx_with_highest_upgrade_priority(
            #[strategy(arb())] upgrade_priority_a: UpgradePriority,
            #[strategy(arb())] upgrade_priority_b: UpgradePriority,
            #[strategy(PrimitiveWitness::arbitrary_tuple_with_matching_mutator_sets(
                [(2, 2, 2),
                 (1, 1, 1),],
    ))]
            pws: [PrimitiveWitness; 2],
        ) {
            // Transactions in the mempool do not need to be valid, so we just
            // pretend that the primitive-witness backed transactions have a
            // SingleProof.
            let into_single_proof_transaction = |pw: PrimitiveWitness| {
                let mock_proof = TransactionProof::invalid();
                Transaction {
                    kernel: pw.kernel,
                    proof: mock_proof,
                }
            };
            let [tx_a, tx_b] = pws;
            let tx_a = into_single_proof_transaction(tx_a);
            let tx_b = into_single_proof_transaction(tx_b);

            let mut mempool = Mempool::new(
                ByteSize::gb(1),
                TxProvingCapability::SingleProof,
                &Block::genesis(Network::Main),
            );
            mempool.insert(tx_a.clone(), upgrade_priority_a);
            mempool.insert(tx_b.clone(), upgrade_priority_b);

            // All transactions in the mempool should be considered unsynced at
            // this point, so a transaction will be returned from below call.
            let (preferred_txk, _, upgrade_priority) = mempool
                .preferred_update(TxUpgradeFilter::match_all())
                .unwrap();

            if preferred_txk.txid() == tx_a.txid() {
                prop_assert!(upgrade_priority_a >= upgrade_priority_b);
                prop_assert_eq!(upgrade_priority_a, upgrade_priority);
            } else if preferred_txk.txid() == tx_b.txid() {
                prop_assert!(upgrade_priority_a <= upgrade_priority_b);
                prop_assert_eq!(upgrade_priority_b, upgrade_priority);
            } else {
                panic!("Must return either tx_a or tx_b");
            }
        }
    }

    mod proof_quality_tests {
        use neptune_consensus::block::mutator_set_update::MutatorSetUpdate;
        use proptest::prop_assert;
        use proptest::prop_assert_eq;
        use proptest::prop_assert_ne;
        use proptest::prop_assume;
        use test_strategy::proptest;

        use super::*;

        #[proptest(cases = 15, async = "tokio")]
        async fn ms_updated_transaction_always_replaces_progenitor(
            #[strategy(0usize..20)] _num_inputs_own: usize,
            #[strategy(0usize..20)] _num_outputs_own: usize,
            #[strategy(0usize..20)] _num_announcements_own: usize,
            #[filter(#_num_inputs_mined+#_num_outputs_mined>0)]
            #[strategy(1usize..20)]
            _num_inputs_mined: usize,
            #[strategy(0usize..20)] _num_outputs_mined: usize,
            #[strategy(0usize..20)] _num_announcements_mined: usize,
            #[strategy(0usize..200_000)] size_old_proof: usize,
            #[strategy(0usize..200_000)] size_new_proof: usize,
            #[strategy(arb())] upgrade_priority: UpgradePriority,
            #[strategy(PrimitiveWitness::arbitrary_tuple_with_matching_mutator_sets(
            [(#_num_inputs_own, #_num_outputs_own, #_num_announcements_own),
            (#_num_inputs_mined, #_num_outputs_mined, #_num_announcements_mined),],
    ))]
            pws: [PrimitiveWitness; 2],
        ) {
            // Transactions in the mempool do not need to be valid, so we just
            // pretend that the primitive-witness backed transactions have a
            // SingleProof.
            let into_single_proof_transaction = |pw: PrimitiveWitness, size_of_proof: usize| {
                let mock_proof = TransactionProof::invalid_single_proof_of_size(size_of_proof);
                Transaction {
                    kernel: pw.kernel,
                    proof: mock_proof,
                }
            };
            let [mempool_tx, mined_tx] = pws;

            // Build the mutator set update and skip test case if it's empty, as
            // this test assumes an update to the mutator set takes place.
            let ms_update = MutatorSetUpdate::new(
                mined_tx.kernel.inputs.clone(),
                mined_tx.kernel.outputs.clone(),
            );
            prop_assume!(!ms_update.is_empty());

            let updated_tx =
                PrimitiveWitness::update_with_new_ms_data(mempool_tx.clone(), ms_update);

            let original_tx = into_single_proof_transaction(mempool_tx, size_old_proof);
            let updated_tx = into_single_proof_transaction(updated_tx, size_new_proof);

            assert_eq!(original_tx.kernel.txid(), updated_tx.kernel.txid());
            let txid = original_tx.kernel.txid();

            let genesis_block = Block::genesis(Network::Main);
            let mut mempool = Mempool::new(
                ByteSize::gb(1),
                TxProvingCapability::SingleProof,
                &genesis_block,
            );

            // First insert original transaction, then updated which should
            // always replace the original transaction, regardless of its size.
            prop_assert!(
                mempool.accept_transaction(
                    txid,
                    original_tx.proof.proof_quality().unwrap(),
                    original_tx.kernel.mutator_set_hash
                ),
                "Must return true since tx not known"
            );
            mempool.insert(original_tx.clone(), upgrade_priority);
            let in_mempool_start = mempool.get(txid).map(|tx| tx.to_owned()).unwrap();
            prop_assert_eq!(&original_tx, &in_mempool_start);
            prop_assert_ne!(&updated_tx, &in_mempool_start);

            // Mock that the new transaction is synced to the tip.
            mempool.set_tip_mutator_set_hash(updated_tx.kernel.mutator_set_hash);

            prop_assert!(
                mempool.accept_transaction(
                    txid,
                    updated_tx.proof.proof_quality().unwrap(),
                    updated_tx.kernel.mutator_set_hash
                ),
                "Must return true since updated tx not yet known to mempool"
            );

            assert_eq!(
                1,
                mempool.len(),
                "Mempool length must be 1 prior to MS update insertion"
            );
            let events = mempool.insert(updated_tx.clone(), upgrade_priority);
            assert_eq!(
                1,
                mempool.len(),
                "Mempool length must be 1 after MS update insertion"
            );
            assert_eq!(
                2,
                events.len(),
                "Must return one event for addition, one for removal. Got: {events:#?}"
            );
            assert_eq!(1, MempoolEvent::num_removes(&events));
            assert_eq!(1, MempoolEvent::num_adds(&events));
            let in_mempool_end = mempool.get(txid).map(|tx| tx.to_owned()).unwrap();
            prop_assert_eq!(&updated_tx, &in_mempool_end);
            prop_assert_ne!(&original_tx, &in_mempool_end);
            prop_assert!(
                !mempool.accept_transaction(
                    txid,
                    updated_tx.proof.proof_quality().unwrap(),
                    updated_tx.kernel.mutator_set_hash
                ),
                "Must return false on updated after insertion of updated tx"
            );
            prop_assert!(
                !mempool.accept_transaction(
                    txid,
                    original_tx.proof.proof_quality().unwrap(),
                    updated_tx.kernel.mutator_set_hash
                ),
                "Must return false on original after insertion of updated tx"
            );
        }
    }
}
