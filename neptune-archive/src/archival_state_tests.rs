#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {

    use std::collections::HashMap;
    use std::collections::HashSet;
    use std::path::Path;
    use std::path::PathBuf;

    use anyhow::Result;
    use macro_rules_attr::apply;
    use neptune_consensus::block::Block;
    use neptune_consensus::block::block_header::BlockHeaderWithBlockHashWitness;
    use neptune_consensus::block::test_helpers::invalid_empty_block;
    use neptune_consensus::block::test_helpers::invalid_empty_block_with_announcements;
    use neptune_consensus::block::test_helpers::invalid_empty_block_with_proof_size;
    use neptune_consensus::block::test_helpers::invalid_empty_blocks;
    use neptune_consensus::transaction::announcement::Announcement;
    use neptune_mutator_set::addition_record::AdditionRecord;
    use neptune_mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
    use neptune_mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
    use neptune_primitives::block_height::BlockHeight;
    use neptune_primitives::data_directory::DataDirectory;
    use neptune_primitives::network::Network;
    use neptune_wallet::mock_block::block_with_num_puts;
    use neptune_wallet::mock_block::make_mock_block;
    use neptune_wallet::wallet_entropy::WalletEntropy;
    use rand::Rng;
    use rand::RngCore;
    use rand::SeedableRng;
    use rand::distr::Alphanumeric;
    use rand::distr::SampleString;
    use rand::random;
    use rand::rngs::StdRng;
    use tasm_lib::prelude::Digest;
    use tasm_lib::prelude::Tip5;
    use tasm_lib::triton_vm::prelude::BFieldElement;
    use tasm_lib::twenty_first::bfe;
    use tasm_lib::twenty_first::util_types::mmr::mmr_trait::Mmr;
    use tracing_test::traced_test;

    use crate::archival_state::ArchivalState;
    use crate::block_index::BlockIndexKey;
    use crate::block_index::BlockRecord;
    use crate::block_index::FileRecord;
    use crate::block_index::LastFileRecord;
    use crate::test_utils::shared_tokio_runtime;

    /// A throwaway per-process temp data directory for tests.
    fn unit_test_data_directory(network: Network) -> Result<DataDirectory> {
        let mut rng = rand::rng();
        let user = std::env::var("USER").unwrap_or_else(|_| "default".to_string());
        let pid = std::process::id();
        let tmp_root: PathBuf = std::env::temp_dir()
            .join(format!("neptune-unit-tests-{user}-{pid}"))
            .join(Path::new(&Alphanumeric.sample_string(&mut rng, 16)));
        DataDirectory::get(Some(tmp_root), network)
    }

    /// Build an `ArchivalState` on a throwaway data directory.
    async fn make_test_archival_state(network: Network, utxo_index: bool) -> ArchivalState {
        let data_dir = unit_test_data_directory(network).unwrap();
        ArchivalState::new(data_dir, Block::genesis(network), utxo_index, network).await
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn can_initialize_mutator_set_database() {
        let network = Network::Main;
        let data_dir = unit_test_data_directory(network).unwrap();
        println!("data_dir for MS initialization test: {data_dir}");
        let _rams = ArchivalState::initialize_mutator_set(&data_dir)
            .await
            .unwrap();
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn stored_block_hash_witness_agrees_with_block_hash() {
        let network = Network::Main;
        let mut archival_state = make_test_archival_state(network, false).await;
        let genesis_block = Block::genesis(network);
        let mut blocks = vec![];
        let mut predecessor = genesis_block;
        for _ in 0..3 {
            let block = invalid_empty_block(&predecessor, network);
            blocks.push(block.clone());
            predecessor = block;
        }

        for block in &blocks {
            archival_state.write_block_as_tip(block).await.unwrap();
        }

        for block in &blocks {
            let block_digest = block.hash();
            let stored_record = archival_state.get_block_record(block_digest).await.unwrap();
            assert_eq!(
                block.hash(),
                BlockHeaderWithBlockHashWitness::new(
                    stored_record.block_header,
                    stored_record.block_hash_witness
                )
                .hash(),
                "Block hash from stored witness must agree with block hash for block height {}",
                block.header().height
            );

            let block_header_with_block_hash_witness = archival_state
                .block_header_with_hash_witness(block_digest)
                .await
                .unwrap();
            assert_eq!(
                block.hash(),
                block_header_with_block_hash_witness.hash(),
                "Block hash from stored witness must agree with block hash for block height {}",
                block.header().height
            );
        }
    }

    #[test]
    fn can_produce_list_of_known_burns() {
        let burns = ArchivalState::known_burns(); // no crash
        assert!(!burns.is_empty());
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn block_kernel_with_proof_digest_simple() {
        let network = Network::Main;
        let mut archive = make_test_archival_state(network, false).await;
        let genesis = Block::genesis(network);
        assert_eq!(
            Some((genesis.kernel.clone(), None)),
            archive
                .get_block_kernel_with_proof_digest(genesis.hash())
                .await
                .unwrap()
        );

        let block_1 = invalid_empty_block_with_proof_size(&genesis, network, 62);
        assert!(
            archive
                .get_block_kernel_with_proof_digest(block_1.hash())
                .await
                .unwrap()
                .is_none()
        );

        archive.set_new_tip(&block_1).await.unwrap();
        let (block_1_kernel, proof_leaf_1) = archive
            .get_block_kernel_with_proof_digest(block_1.hash())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(block_1.kernel, block_1_kernel);
        assert_eq!(Some(Tip5::hash(&block_1.proof)), proof_leaf_1);
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn archival_state_init_test() -> Result<()> {
        // Verify that archival mutator set is populated with outputs from genesis block
        let network = Network::RegTest;
        let archival_state = make_test_archival_state(network, false).await;

        assert_eq!(
            Block::genesis(network)
                .kernel
                .body
                .transaction_kernel
                .outputs
                .len() as u64,
            archival_state
                .archival_mutator_set
                .ams()
                .aocl
                .num_leafs()
                .await,
            "Archival mutator set must be populated with premine outputs",
        );

        assert_eq!(
            Block::genesis(network).hash(),
            archival_state.archival_mutator_set.get_sync_label(),
            "AMS must be synced to genesis block after initialization from genesis block",
        );

        for (i, tx_output) in Block::genesis(network)
            .kernel
            .body
            .transaction_kernel
            .outputs
            .iter()
            .enumerate()
        {
            assert_eq!(
                tx_output.canonical_commitment,
                archival_state
                    .archival_mutator_set
                    .ams()
                    .aocl
                    .get_leaf_async(i as u64)
                    .await
            );
        }

        Ok(())
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn ms_update_to_tip_genesis() {
        let network = Network::Main;
        let mut archival_state = make_test_archival_state(network, false).await;
        let current_msa = archival_state
            .archival_mutator_set
            .ams()
            .accumulator()
            .await;

        for i in 0..10 {
            assert!(
                archival_state
                    .get_mutator_set_update_to_tip(&current_msa, i)
                    .await
                    .unwrap()
                    .is_empty()
            );
        }
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn find_canonical_block_with_aocl_index_genesis() {
        for network in [
            Network::Main,
            Network::TestnetMock,
            Network::RegTest,
            Network::Testnet(0),
            Network::Testnet(1),
        ] {
            let archival_state = make_test_archival_state(network, false).await;
            let genesis_block_digest = archival_state.genesis_block().hash();
            let num_premine_outputs = Block::premine_utxos().len() as u64;

            // Verify correct result for all premine outputs
            for aocl_leaf_index in 0..num_premine_outputs {
                let needle = archival_state
                    .canonical_block_digest_of_aocl_index(aocl_leaf_index)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(genesis_block_digest, needle);
            }

            // Verify that indices beyond return None
            assert!(
                archival_state
                    .canonical_block_digest_of_aocl_index(num_premine_outputs)
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(
                archival_state
                    .canonical_block_digest_of_aocl_index(num_premine_outputs + 1)
                    .await
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[apply(shared_tokio_runtime)]
    async fn is_canonical_block_false_on_future_blocks() {
        let network = Network::Main;
        let mut archival_state = make_test_archival_state(network, false).await;
        let block_1 = invalid_empty_block(archival_state.genesis_block(), network);
        archival_state.set_new_tip(&block_1).await.unwrap();
        let genesis = archival_state.genesis_block().clone();
        archival_state.set_new_tip(&genesis).await.unwrap();
        assert!(
            !archival_state
                .is_canonical_block(block_1.hash(), block_1.header().height)
                .await
        );
        assert!(
            archival_state
                .is_canonical_block(genesis.hash(), genesis.header().height)
                .await
        );
    }

    #[apply(shared_tokio_runtime)]
    async fn block_belongs_to_canonical_chain_doesnt_crash_on_unknown_block() {
        let archival_state = make_test_archival_state(Network::Main, false).await;
        assert!(
            !archival_state
                .block_belongs_to_canonical_chain(random())
                .await
        );
    }

    #[should_panic]
    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn digest_of_ancestors_panic_test() {
        let archival_state = make_test_archival_state(Network::Main, false).await;

        let genesis = archival_state.genesis_block.clone();
        archival_state
            .get_ancestor_block_digests(genesis.kernel.header.prev_block_digest, 10)
            .await;
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn tip_header_genesis() {
        let network = Network::Main;
        let archival_state = make_test_archival_state(network, false).await;

        assert_eq!(
            Block::genesis(network).header(),
            &archival_state.tip_header().await
        );
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn tip_header_block_1() {
        let network = Network::Main;
        let mut archival_state = make_test_archival_state(network, false).await;
        let block1 = invalid_empty_block(archival_state.genesis_block(), network);
        archival_state.write_block_as_tip(&block1).await.unwrap();

        assert_eq!(block1.header(), &archival_state.tip_header().await);
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn find_canonical_block_with_output_genesis() {
        let network = Network::Main;

        for maintain_utxo_index in [false, true] {
            let __utxo_index = maintain_utxo_index;
            let archival_state = make_test_archival_state(network, __utxo_index).await;
            let genesis_block = Block::genesis(network);
            let addition_records = Block::genesis(network)
                .body()
                .transaction_kernel
                .outputs
                .clone();

            for ar in &addition_records {
                let found_block = archival_state
                    .find_canonical_block_with_output(*ar, None)
                    .await
                    .unwrap();
                assert_eq!(genesis_block.hash(), found_block.hash());
            }
        }
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn max_search_depth_is_respected_when_no_utxo_index_is_maintained() {
        let network = Network::Main;
        let __utxo_index = false;
        let mut archival_state = make_test_archival_state(network, __utxo_index).await;
        let genesis = Block::genesis(network);
        let genesis_outputs = genesis.body().transaction_kernel.outputs.clone();

        for ar in &genesis_outputs {
            let found_block = archival_state
                .find_canonical_block_with_output(*ar, Some(0))
                .await
                .unwrap();
            assert_eq!(genesis.hash(), found_block.hash());
        }

        let block1 = invalid_empty_block(&Block::genesis(network), network);
        archival_state.set_new_tip(&block1).await.unwrap();

        for ar in &genesis_outputs {
            assert!(
                archival_state
                    .find_canonical_block_with_output(*ar, Some(0))
                    .await
                    .is_none(),
                "No match when block is buried to deep and UTXO index is not maintained"
            );
        }

        for ar in &genesis_outputs {
            assert_eq!(
                genesis.hash(),
                archival_state
                    .find_canonical_block_with_output(*ar, Some(1))
                    .await
                    .unwrap()
                    .hash(),
                "Must match when search depth is set high enough"
            );

            assert_eq!(
                genesis.hash(),
                archival_state
                    .find_canonical_block_with_output(*ar, Some(100))
                    .await
                    .unwrap()
                    .hash(),
                "Must match when search depth exceeds tip height"
            );
        }
    }

    #[traced_test]
    #[test_strategy::proptest(async = "tokio", cases = 3)]
    async fn find_canonical_block_with_input_genesis_block_test(
        #[strategy(neptune_mutator_set::strategies::absindset())]
        random_index_set: AbsoluteIndexSet,
    ) {
        let network = Network::Main;

        for maintain_utxo_index in [false, true] {
            let __utxo_index = maintain_utxo_index;
            let archival_state = make_test_archival_state(network, __utxo_index).await;

            assert!(
                archival_state
                    .find_canonical_block_with_input(random_index_set, None)
                    .await
                    .is_none()
            );
        }
    }

    #[apply(shared_tokio_runtime)]
    async fn no_panic_when_utxo_index_is_not_present() {
        let network = Network::Main;
        let __utxo_index = false;
        let archive = make_test_archival_state(network, __utxo_index).await;
        assert!(archive.utxo_index.is_none());

        let dummy_tx_input = AbsoluteIndexSet::empty_dummy();
        let dummy_tx_input = [dummy_tx_input].into_iter().collect();
        assert!(
            archive
                .absolute_index_sets_to_block_heights(dummy_tx_input)
                .await
                .is_err()
        );

        let dummy_tx_output = AdditionRecord::new(Digest::default());
        let dummy_tx_output = HashSet::from([dummy_tx_output]);
        assert!(
            archive
                .addition_records_to_block_height(dummy_tx_output.clone())
                .await
                .is_err()
        );

        assert!(
            archive
                .canonical_block_heights_with_puts(HashSet::new(), dummy_tx_output)
                .await
                .is_err()
        );
    }

    async fn genesis_setup() -> (ArchivalState, Block, Network) {
        let network = Network::Main;
        let __utxo_index = true;
        let archive = make_test_archival_state(network, __utxo_index).await;

        let genesis = Block::genesis(network);

        (archive, genesis, network)
    }

    #[apply(shared_tokio_runtime)]
    async fn recover_happy_case() {
        let (mut archive, genesis, network) = genesis_setup().await;
        archive.assert_consistent(&genesis).await;
        archive.recover().await.unwrap();
        archive.assert_consistent(&genesis).await;

        let block1 = invalid_empty_block(&genesis, network);
        archive.set_new_tip(&block1).await.unwrap();

        // consistent before and after recover. From block 1.
        archive.assert_consistent(&block1).await;
        archive.recover().await.unwrap();
        archive.assert_consistent(&block1).await;
    }

    #[apply(shared_tokio_runtime)]
    async fn recover_stored_block_one_ahead_rest() {
        // Block is stored as tip. But no other part of the archival state
        // has seen this block.

        let (mut archive, genesis, network) = genesis_setup().await;
        let block1 = invalid_empty_block(&genesis, network);
        archive.write_block_as_tip(&block1).await.unwrap();

        assert!(!archive.is_consistent(&block1).await);
        assert!(!archive.is_consistent(&genesis).await);

        // Recover everything but the block storage/block index DB:
        // archival mutator set, archival block MMR, UTXO index.
        archive.recover().await.unwrap();
        assert!(archive.is_consistent(&block1).await);
        assert!(!archive.is_consistent(&genesis).await);
    }

    #[apply(shared_tokio_runtime)]
    async fn recover_stored_block_two_ahead_rest() {
        // Two blocks stored on disk and in block index DB. But other parts
        // of the archival state have not seen these two blocks.

        let (mut archive, genesis, network) = genesis_setup().await;
        let block1 = invalid_empty_block(&genesis, network);
        let block2 = invalid_empty_block(&block1, network);
        archive.write_block_as_tip(&block1).await.unwrap();
        archive.write_block_as_tip(&block2).await.unwrap();

        assert!(!archive.is_consistent(&block2).await);
        assert!(!archive.is_consistent(&block1).await);
        assert!(!archive.is_consistent(&genesis).await);

        archive.recover().await.unwrap();
        assert!(archive.is_consistent(&block2).await);
        assert!(!archive.is_consistent(&block1).await);
        assert!(!archive.is_consistent(&genesis).await);
    }

    #[apply(shared_tokio_runtime)]
    async fn reorganization_one_deep() {
        let (mut archive, genesis, network) = genesis_setup().await;

        let block1a = invalid_empty_block_with_proof_size(&genesis, network, 12);
        let block1b = invalid_empty_block_with_proof_size(&genesis, network, 13);

        archive.set_new_tip(&block1a).await.unwrap();
        archive.write_block_as_tip(&block1b).await.unwrap();

        assert!(!archive.is_consistent(&block1b).await);
        archive.recover().await.unwrap();
        assert!(archive.is_consistent(&block1b).await);
    }

    #[apply(shared_tokio_runtime)]
    async fn reorganization_two_deep() {
        let (mut archive, genesis, network) = genesis_setup().await;

        let block1a = invalid_empty_block_with_proof_size(&genesis, network, 12);
        let block2a = invalid_empty_block_with_proof_size(&block1a, network, 12);
        let block1b = invalid_empty_block_with_proof_size(&genesis, network, 13);
        let block2b = invalid_empty_block_with_proof_size(&block1b, network, 13);

        archive.set_new_tip(&block1a).await.unwrap();
        archive.set_new_tip(&block2a).await.unwrap();
        archive.write_block_as_tip(&block1b).await.unwrap();
        archive.write_block_as_tip(&block2b).await.unwrap();

        assert!(!archive.is_consistent(&block2b).await);
        archive.recover().await.unwrap();
        assert!(archive.is_consistent(&block2b).await);
    }

    #[apply(shared_tokio_runtime)]
    async fn roll_back_one() {
        let (mut archive, genesis, network) = genesis_setup().await;

        let block1 = invalid_empty_block_with_proof_size(&genesis, network, 12);
        let block2 = invalid_empty_block_with_proof_size(&block1, network, 12);

        archive.set_new_tip(&block1).await.unwrap();
        archive.set_new_tip(&block2).await.unwrap();
        archive.write_block_as_tip(&block1).await.unwrap();

        assert!(!archive.is_consistent(&block1).await);
        archive.recover().await.unwrap();
        assert!(archive.is_consistent(&block1).await);
    }

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
        assert!(
            archival_state
                .get_mutator_set_update_to_tip(&new_msa, search_depth)
                .await
                .unwrap()
                .apply_to_accumulator(&mut new_msa)
                .is_ok()
        );
        assert_eq!(tip_msa, new_msa);
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn initialize_archival_state_test() -> Result<()> {
        // Ensure that the archival state can be initialized without overflowing the stack
        let seed: [u8; 32] = rand::rng().random();
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let network = Network::RegTest;

        let mut archival_state0 = make_test_archival_state(network, false).await;

        let b = Block::genesis(network);
        let some_wallet_secret = WalletEntropy::new_random();
        let some_key = some_wallet_secret.nth_generation_spending_key_for_tests(0);

        let (block_1, _) = make_mock_block(&b, None, some_key, rng.random(), network);
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
    async fn update_mutator_set_rollback_ms_block_sync_test() -> Result<()> {
        let mut rng = rand::rng();
        let network = Network::Main;
        let data_dir = unit_test_data_directory(network).unwrap();
        let mut archival_state =
            ArchivalState::new(data_dir, Block::genesis(network), false, network).await;

        let own_wallet = WalletEntropy::new_random();
        let own_key = own_wallet.nth_generation_spending_key_for_tests(0);

        // 1. Create new block 1 and store it to the DB
        let (mock_block_1a, _) = make_mock_block(
            &archival_state.genesis_block,
            None,
            own_key,
            rng.random(),
            network,
        );
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
        );
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
    async fn get_tip_block_test() -> Result<()> {
        for network in [
            Network::Main,
            Network::RegTest,
            Network::TestnetMock,
            Network::Testnet(0),
            Network::Testnet(1),
        ] {
            let mut archival_state: ArchivalState = make_test_archival_state(network, false).await;

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
            let (mock_block_1, _) = make_mock_block(&genesis, None, own_key, rng.random(), network);
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
                make_mock_block(&mock_block_1, None, own_key, rng.random(), network);
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
        let mut archival_state = make_test_archival_state(network, false).await;

        let genesis = *archival_state.genesis_block.clone();
        let own_wallet = WalletEntropy::new_random();
        let own_key = own_wallet.nth_generation_spending_key_for_tests(0);
        let (mock_block_1, _) =
            make_mock_block(&genesis.clone(), None, own_key, rng.random(), network);

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
            make_mock_block(&mock_block_1.clone(), None, own_key, rng.random(), network);
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
            let (new_block, _) = make_mock_block(&last_block, None, own_key, rng.random(), network);
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
        let mut archival_state = make_test_archival_state(network, false).await;

        // Digest::default ==> no block found
        assert!(
            archival_state
                .get_addition_record_indices_for_block(Digest::default())
                .await
                .is_none()
        );

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
            make_mock_block(&genesis_block.clone(), None, own_key, rng.random(), network);

        // apply block 1a
        archival_state.write_block_as_tip(&block_1a).await.unwrap();
        archival_state.append_to_archival_block_mmr(&block_1a).await;
        archival_state.update_mutator_set(&block_1a).await.unwrap();

        // mine block 1b
        let (block_1b, _) =
            make_mock_block(&genesis_block.clone(), None, own_key, rng.random(), network);

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
        let mut archival_state = make_test_archival_state(network, false).await;
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
            .0;
            archival_state.set_new_tip(&next_block).await.unwrap();
            current_block = next_block;
        }

        let current_msa = current_block.mutator_set_accumulator_after().unwrap();
        for search_depth in 0..10 {
            println!("{search_depth}");
            if search_depth < 5 {
                assert!(
                    archival_state
                        .get_mutator_set_update_to_tip(&genesis_msa, search_depth)
                        .await
                        .is_none()
                );
            } else {
                positive_prop_ms_update_to_tip(&genesis_msa, &mut archival_state, search_depth)
                    .await;
            }
        }

        // Walking the opposite way returns None, and does not crash.
        let mut genesis_archival_state = make_test_archival_state(network, false).await;
        for i in 0..10 {
            assert!(
                genesis_archival_state
                    .get_mutator_set_update_to_tip(&current_msa, i)
                    .await
                    .is_none()
            );
        }
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn find_canonical_block_with_aocl_index_five_blocks() {
        let network = Network::Main;
        let wallet = WalletEntropy::new_random();
        let mut rng = rand::rng();
        let mut archival_state = make_test_archival_state(network, false).await;
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
            );
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
        let mut archival_state = make_test_archival_state(network, false).await;
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
        .0;
        let block_1b = make_mock_block(
            &genesis_block,
            None,
            compose_beneficiary,
            rng.random(),
            network,
        )
        .0;
        let block_1a_msa = &block_1a.mutator_set_accumulator_after().unwrap();
        let block_1b_msa = &block_1b.mutator_set_accumulator_after().unwrap();

        // 1a is tip
        let search_depth = 1;
        archival_state.set_new_tip(&block_1a).await.unwrap();
        positive_prop_ms_update_to_tip(genesis_msa, &mut archival_state, search_depth).await;
        positive_prop_ms_update_to_tip(block_1a_msa, &mut archival_state, search_depth).await;
        assert!(
            archival_state
                .get_mutator_set_update_to_tip(block_1b_msa, 1)
                .await
                .is_none()
        );

        // 1b is tip
        archival_state.set_new_tip(&block_1b).await.unwrap();
        positive_prop_ms_update_to_tip(genesis_msa, &mut archival_state, search_depth).await;
        assert!(
            archival_state
                .get_mutator_set_update_to_tip(block_1a_msa, 1)
                .await
                .is_none()
        );
        positive_prop_ms_update_to_tip(block_1b_msa, &mut archival_state, search_depth).await;
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn ms_update_to_tip_fork_depth_2() {
        let mut rng = rand::rng();
        let network = Network::Main;
        let wallet = WalletEntropy::new_random();
        let mut archival_state = make_test_archival_state(network, false).await;
        let genesis_block = Block::genesis(network);
        let genesis_msa = &genesis_block.mutator_set_accumulator_after().unwrap();
        let cb_beneficiary = wallet.nth_generation_spending_key_for_tests(0);

        let block_1a =
            make_mock_block(&genesis_block, None, cb_beneficiary, rng.random(), network).0;
        let block_2a = make_mock_block(&block_1a, None, cb_beneficiary, rng.random(), network).0;
        let block_1b =
            make_mock_block(&genesis_block, None, cb_beneficiary, rng.random(), network).0;
        let block_2b = make_mock_block(&block_1b, None, cb_beneficiary, rng.random(), network).0;
        let block_1a_msa = &block_1a.mutator_set_accumulator_after().unwrap();
        let block_2a_msa = &block_2a.mutator_set_accumulator_after().unwrap();
        let block_1b_msa = &block_1b.mutator_set_accumulator_after().unwrap();
        let block_2b_msa = &block_2b.mutator_set_accumulator_after().unwrap();

        // 1a is tip
        let search_depth = 10;
        archival_state.set_new_tip(&block_1a).await.unwrap();
        assert!(
            archival_state
                .get_mutator_set_update_to_tip(block_2a_msa, search_depth)
                .await
                .is_none()
        );
        assert!(
            archival_state
                .get_mutator_set_update_to_tip(block_2b_msa, search_depth)
                .await
                .is_none()
        );

        // 1b is tip
        archival_state.set_new_tip(&block_1b).await.unwrap();
        assert!(
            archival_state
                .get_mutator_set_update_to_tip(block_2a_msa, search_depth)
                .await
                .is_none()
        );
        assert!(
            archival_state
                .get_mutator_set_update_to_tip(block_2b_msa, search_depth)
                .await
                .is_none()
        );

        // 2a is tip
        archival_state.set_new_tip(&block_2a).await.unwrap();
        positive_prop_ms_update_to_tip(genesis_msa, &mut archival_state, search_depth).await;
        positive_prop_ms_update_to_tip(block_1a_msa, &mut archival_state, search_depth).await;
        positive_prop_ms_update_to_tip(block_2a_msa, &mut archival_state, search_depth).await;
        assert!(
            archival_state
                .get_mutator_set_update_to_tip(block_1b_msa, search_depth)
                .await
                .is_none()
        );
        assert!(
            archival_state
                .get_mutator_set_update_to_tip(block_2b_msa, search_depth)
                .await
                .is_none()
        );

        // 2b is tip
        archival_state.set_new_tip(&block_2b).await.unwrap();
        positive_prop_ms_update_to_tip(genesis_msa, &mut archival_state, search_depth).await;
        positive_prop_ms_update_to_tip(block_1b_msa, &mut archival_state, search_depth).await;
        positive_prop_ms_update_to_tip(block_2b_msa, &mut archival_state, search_depth).await;
        assert!(
            archival_state
                .get_mutator_set_update_to_tip(block_1a_msa, search_depth)
                .await
                .is_none()
        );
        assert!(
            archival_state
                .get_mutator_set_update_to_tip(block_2a_msa, search_depth)
                .await
                .is_none()
        );
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn find_path_simple_test() -> Result<()> {
        let mut rng = rand::rng();
        let network = Network::Main;
        let mut archival_state = make_test_archival_state(network, false).await;
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
            make_mock_block(&genesis.clone(), None, key, rng.random(), network);
        archival_state.set_new_tip(&mock_block_1_a).await.unwrap();

        let (mock_block_1_b, _) =
            make_mock_block(&genesis.clone(), None, key, rng.random(), network);
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
        let mut archival_state = make_test_archival_state(network, false).await;
        let genesis = *archival_state.genesis_block.clone();
        let wallet = WalletEntropy::new_random();
        let key = wallet.nth_generation_spending_key_for_tests(0);

        assert!(
            archival_state
                .get_ancestor_block_digests(genesis.hash(), 10)
                .await
                .is_empty()
        );
        assert!(
            archival_state
                .get_ancestor_block_digests(genesis.hash(), 1)
                .await
                .is_empty()
        );
        assert!(
            archival_state
                .get_ancestor_block_digests(genesis.hash(), 0)
                .await
                .is_empty()
        );

        // Insert blocks and verify that the same result is returned
        let (mock_block_1, _) = make_mock_block(&genesis.clone(), None, key, rng.random(), network);
        archival_state.set_new_tip(&mock_block_1).await.unwrap();
        let (mock_block_2, _) =
            make_mock_block(&mock_block_1.clone(), None, key, rng.random(), network);
        archival_state.set_new_tip(&mock_block_2).await.unwrap();
        let (mock_block_3, _) =
            make_mock_block(&mock_block_2.clone(), None, key, rng.random(), network);
        archival_state.set_new_tip(&mock_block_3).await.unwrap();
        let (mock_block_4, _) =
            make_mock_block(&mock_block_3.clone(), None, key, rng.random(), network);
        archival_state.set_new_tip(&mock_block_4).await.unwrap();

        assert!(
            archival_state
                .get_ancestor_block_digests(genesis.hash(), 10)
                .await
                .is_empty()
        );
        assert!(
            archival_state
                .get_ancestor_block_digests(genesis.hash(), 1)
                .await
                .is_empty()
        );
        assert!(
            archival_state
                .get_ancestor_block_digests(genesis.hash(), 0)
                .await
                .is_empty()
        );

        // Check that ancestors of block 1 and 2 return the right values
        let ancestors_of_1 = archival_state
            .get_ancestor_block_digests(mock_block_1.hash(), 10)
            .await;
        assert_eq!(1, ancestors_of_1.len());
        assert_eq!(genesis.hash(), ancestors_of_1[0]);
        assert!(
            archival_state
                .get_ancestor_block_digests(mock_block_1.hash(), 0)
                .await
                .is_empty()
        );

        let ancestors_of_2 = archival_state
            .get_ancestor_block_digests(mock_block_2.hash(), 10)
            .await;
        assert_eq!(2, ancestors_of_2.len());
        assert_eq!(mock_block_1.hash(), ancestors_of_2[0]);
        assert_eq!(genesis.hash(), ancestors_of_2[1]);
        assert!(
            archival_state
                .get_ancestor_block_digests(mock_block_2.hash(), 0)
                .await
                .is_empty()
        );

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
        assert!(
            archival_state
                .get_ancestor_block_digests(mock_block_4.hash(), 0)
                .await
                .is_empty()
        );
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn write_block_db_test() -> Result<()> {
        let network = Network::Main;
        let mut rng = rand::rng();
        let mut archival_state = make_test_archival_state(network, false).await;
        let genesis = *archival_state.genesis_block.clone();
        let wallet = WalletEntropy::new_random();
        let key = wallet.nth_generation_spending_key_for_tests(0);

        let (mock_block_1, _) = make_mock_block(&genesis.clone(), None, key, rng.random(), network);
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
            make_mock_block(&mock_block_1.clone(), None, key, rng.random(), network);
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
            assert_eq!(
                backwards_expected, backwards,
                "\n\nbackwards digests must match expected value. Got:\n {backwards:?}\n\n, Expected from helper function:\n {backwards_expected:?}\n"
            );

            let mut forwards_expected = archival_state
                .get_ancestor_block_digests(stop.to_owned(), forwards.len())
                .await;
            forwards_expected.reverse();
            assert_eq!(
                forwards_expected, forwards,
                "\n\nforwards digests must match expected value. Got:\n {forwards:?}\n\n, Expected from helper function:\n{forwards_expected:?}\n"
            );
        }

        let network = Network::Main;
        let mut archival_state = make_test_archival_state(network, false).await;

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
        let (block1, _) = make_mock_block(&genesis.clone(), None, key, rng.random(), network);
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
            make_mock_block(&block1.clone(), None, key, rng.random(), network);
        archival_state.set_new_tip(&mock_block_2_a).await.unwrap();
        let (mock_block_3_a, _) =
            make_mock_block(&mock_block_2_a.clone(), None, key, rng.random(), network);
        archival_state.set_new_tip(&mock_block_3_a).await.unwrap();
        let (mock_block_4_a, _) =
            make_mock_block(&mock_block_3_a.clone(), None, key, rng.random(), network);
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
            make_mock_block(&block1.clone(), None, key, rng.random(), network);
        archival_state.set_new_tip(&mock_block_2_b).await.unwrap();
        let (mock_block_3_b, _) =
            make_mock_block(&mock_block_2_b.clone(), None, key, rng.random(), network);
        archival_state.set_new_tip(&mock_block_3_b).await.unwrap();
        let (mock_block_4_b, _) =
            make_mock_block(&mock_block_3_b.clone(), None, key, rng.random(), network);
        archival_state.set_new_tip(&mock_block_4_b).await.unwrap();
        let (mock_block_5_b, _) =
            make_mock_block(&mock_block_4_b.clone(), None, key, rng.random(), network);
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
            make_mock_block(&mock_block_2_a.clone(), None, key, rng.random(), network);
        archival_state.set_new_tip(&mock_block_3_c).await.unwrap();
        let (mock_block_4_c, _) =
            make_mock_block(&mock_block_3_c.clone(), None, key, rng.random(), network);
        archival_state.set_new_tip(&mock_block_4_c).await.unwrap();
        let (mock_block_5_c, _) =
            make_mock_block(&mock_block_4_c.clone(), None, key, rng.random(), network);
        archival_state.set_new_tip(&mock_block_5_c).await.unwrap();
        let (mock_block_6_c, _) =
            make_mock_block(&mock_block_5_c.clone(), None, key, rng.random(), network);
        archival_state.set_new_tip(&mock_block_6_c).await.unwrap();
        let (mock_block_7_c, _) =
            make_mock_block(&mock_block_6_c.clone(), None, key, rng.random(), network);
        archival_state.set_new_tip(&mock_block_7_c).await.unwrap();
        let (mock_block_8_c, _) =
            make_mock_block(&mock_block_7_c.clone(), None, key, rng.random(), network);
        archival_state.set_new_tip(&mock_block_8_c).await.unwrap();
        let (mock_block_5_a, _) =
            make_mock_block(&mock_block_4_a.clone(), None, key, rng.random(), network);
        archival_state.set_new_tip(&mock_block_5_a).await.unwrap();
        let (mock_block_3_d, _) =
            make_mock_block(&mock_block_2_a.clone(), None, key, rng.random(), network);
        archival_state.set_new_tip(&mock_block_3_d).await.unwrap();

        let (mock_block_4_e, _) =
            make_mock_block(&mock_block_3_d.clone(), None, key, rng.random(), network);
        archival_state.set_new_tip(&mock_block_4_e).await.unwrap();
        let (mock_block_5_e, _) =
            make_mock_block(&mock_block_4_e.clone(), None, key, rng.random(), network);
        archival_state.set_new_tip(&mock_block_5_e).await.unwrap();

        let (mock_block_4_d, _) =
            make_mock_block(&mock_block_3_d.clone(), None, key, rng.random(), network);
        archival_state.set_new_tip(&mock_block_4_d).await.unwrap();
        let (mock_block_5_d, _) =
            make_mock_block(&mock_block_4_d.clone(), None, key, rng.random(), network);
        archival_state.set_new_tip(&mock_block_5_d).await.unwrap();

        // This is the most canonical block in the known set
        let (mock_block_6_d, _) =
            make_mock_block(&mock_block_5_d.clone(), None, key, rng.random(), network);
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
            make_mock_block(&mock_block_5_b.clone(), None, key, rng.random(), network);
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
            assert!(
                archive
                    .canonical_block_heights_with_puts(
                        inputs.into_iter().collect(),
                        outputs.into_iter().collect(),
                    )
                    .await
                    .unwrap()
                    .is_empty()
            )
        }

        let network = Network::Main;

        let genesis = Block::genesis(network);
        let mut archive = make_test_archival_state(network, true).await;
        let block1 = block_with_num_puts(network, &genesis, 4, 4);
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

    mod rusty_utxo_index_tests {
        use std::collections::HashMap;

        use neptune_primitives::announcement_flag::AnnouncementFlag;
        use neptune_wallet::address::generation_address::GenerationSpendingKey;
        use neptune_wallet::mock_block::block_with_num_puts;
        use neptune_wallet::mock_block::make_mock_block_with_inputs_and_outputs;
        use tasm_lib::twenty_first::bfe_vec;

        use super::*;
        use crate::archival_state::rusty_utxo_index::*;

        async fn test_utxo_index(network: Network) -> RustyUtxoIndex {
            let data_dir = super::unit_test_data_directory(network).unwrap();
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

        #[apply(shared_tokio_runtime)]
        async fn announcement_flag_to_block_heights_unit_test() {
            let network = Network::Main;
            let mut utxo_index = test_utxo_index(network).await;

            let genesis = Block::genesis(network);

            let announcements1 = vec![
                Announcement {
                    message: bfe_vec![22, 55],
                },
                Announcement {
                    message: bfe_vec![1, 444, 500],
                },
            ];
            let announcements2 = vec![
                Announcement {
                    message: bfe_vec![22, 55],
                },
                Announcement {
                    message: bfe_vec![22, 55, 200],
                },
                Announcement {
                    message: bfe_vec![22, 55, 500],
                },
                Announcement {
                    message: bfe_vec![1, 888, 500],
                },
            ];
            let announcements3 = announcements1.clone();
            let block1 = invalid_empty_block_with_announcements(&genesis, network, announcements1);
            let block2 = invalid_empty_block_with_announcements(&block1, network, announcements2);
            let block3 = invalid_empty_block_with_announcements(&block2, network, announcements3);

            let blocks = [block1, block2, block3];
            for block in &blocks {
                utxo_index.index_block(block).await;
            }

            // All announcements in all blocks must return block's height.
            for block in &blocks {
                for announcement in &block.body().transaction_kernel().announcements {
                    let Ok(announcement_flag) = AnnouncementFlag::try_from(announcement) else {
                        continue;
                    };
                    let announcement_flag: HashSet<_> = [announcement_flag].into_iter().collect();
                    assert!(
                        utxo_index
                            .blocks_by_announcement_flags(&announcement_flag)
                            .await
                            .contains(&block.header().height),
                    );
                }
            }

            assert_eq!(
                vec![
                    BlockHeight::from(1u64),
                    BlockHeight::from(2u64),
                    BlockHeight::from(3u64)
                ],
                utxo_index
                    .db
                    .get(UtxoIndexKey::BlocksByAnnouncementFlag(AnnouncementFlag {
                        flag: bfe!(22),
                        receiver_id: bfe!(55),
                    }))
                    .await
                    .unwrap()
                    .expect_blocks_by_announcements()
            );
            assert_eq!(
                vec![BlockHeight::from(1u64), BlockHeight::from(3u64)],
                utxo_index
                    .db
                    .get(UtxoIndexKey::BlocksByAnnouncementFlag(AnnouncementFlag {
                        flag: bfe!(1),
                        receiver_id: bfe!(444),
                    }))
                    .await
                    .unwrap()
                    .expect_blocks_by_announcements()
            );
            assert_eq!(
                vec![BlockHeight::from(2u64),],
                utxo_index
                    .db
                    .get(UtxoIndexKey::BlocksByAnnouncementFlag(AnnouncementFlag {
                        flag: bfe!(1),
                        receiver_id: bfe!(888),
                    }))
                    .await
                    .unwrap()
                    .expect_blocks_by_announcements()
            );
        }

        #[apply(shared_tokio_runtime)]
        async fn can_handle_short_announcements() {
            let network = Network::Main;
            let mut utxo_index = test_utxo_index(network).await;

            let announcements = announcements_length_0_to_3();
            let genesis = Block::genesis(network);
            let block1 = invalid_empty_block_with_announcements(&genesis, network, announcements);

            utxo_index.index_block(&block1).await;

            assert_eq!(
                2,
                utxo_index
                    .announcement_flags(block1.hash())
                    .await
                    .unwrap()
                    .len(),
                "Announcements of length 2 and above should be indexed"
            );
        }

        #[apply(shared_tokio_runtime)]
        async fn initialize_sets_sync_label() {
            let network = Network::Main;
            let utxo_index = test_utxo_index(network).await;
            assert!(
                utxo_index.db.get(UtxoIndexKey::SyncLabel).await.is_some(),
                "sync label must be set during initialization"
            );
            assert!(
                utxo_index.is_empty().await,
                "UTXO index must be marked as empty after new initialization with empty database"
            );

            // ensure no panic
            utxo_index.sync_label().await;
        }

        #[apply(shared_tokio_runtime)]
        async fn index_set_by_block_unit_test() {
            let network = Network::Main;
            let genesis = Block::genesis(network);
            let block1 = block_with_num_puts(network, &genesis, 12, 11);
            let block2 = block_with_num_puts(network, &block1, 4, 55);

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
            let block1 = block_with_num_puts(network, &genesis, 12, 11);
            let block2 = block_with_num_puts(network, &block1, 4, 55);
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
            );
            let (block2_two_repeated_addition_records, _) = make_mock_block_with_inputs_and_outputs(
                &block1_one_addition_record,
                inputs,
                vec![an_addition_record, an_addition_record],
                None,
                GenerationSpendingKey::derive_from_seed(Digest::default()),
                Digest::default(),
                network,
            );
            let block3_other_addition_records =
                block_with_num_puts(network, &block2_two_repeated_addition_records, 10, 10);

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
            let block1 = block_with_num_puts(network, &genesis, 20, 2);
            let block2 = block_with_num_puts(network, &block1, 21, 3);

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
            let block1 = block_with_num_puts(network, &genesis, 1, 0);
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

    mod import_blocks_tests {
        use super::*;

        #[test]
        fn blk_file_names_sorted_correctly() {
            let input = [
                "blk10.dat",
                "blk2.dat",
                "blk3.dat",
                "blk4.dat",
                "blk5.dat",
                "blk0.dat",
                "blk99.dat",
                "not-parseable",
                ".",
                "..",
                "blk1.dat",
            ]
            .map(|x| x.to_owned())
            .to_vec();

            let expected = [
                "blk0.dat",
                "blk1.dat",
                "blk2.dat",
                "blk3.dat",
                "blk4.dat",
                "blk5.dat",
                "blk10.dat",
                "blk99.dat",
            ]
            .map(|x| x.to_owned())
            .to_vec();
            assert_eq!(
                expected,
                ArchivalState::sorted_blk_file_names(input).unwrap()
            );
        }

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn get_blocks_directly_from_file_without_database() {
            let network = Network::Main;
            let mut archival_state = make_test_archival_state(network, false).await;
            let blocks = invalid_empty_blocks(&archival_state.genesis_block, 10, network);

            for i in 0..10 {
                archival_state
                    .write_block_internal(&blocks[i], true)
                    .await
                    .unwrap();

                let assumed_block_file = archival_state.data_dir.block_file_path(0);
                let returned = ArchivalState::blocks_from_file_without_record(&assumed_block_file)
                    .await
                    .unwrap();

                assert_eq!(blocks[0..=i], returned[..]);
            }
        }
    }

    mod find_canonical_block_with_puts {
        use neptune_wallet::mock_block::block_with_num_puts;
        use neptune_wallet::mock_block::block_with_puts;
        use proptest::collection;
        use proptest::prop_assert;
        use proptest::prop_assert_eq;
        use proptest_arbitrary_interop::arb;

        use super::*;

        #[traced_test]
        #[test_strategy::proptest(async = "tokio", cases = 3)]
        async fn only_reports_on_canonical_blocks_with_outputs(
            #[strategy(collection::vec(arb::<AdditionRecord>(), 0usize..22))]
            addition_records_1a: Vec<AdditionRecord>,
        ) {
            let network = Network::Main;

            for maintain_utxo_index in [false, true] {
                let genesis = Block::genesis(network);
                let block1a =
                    block_with_puts(network, &genesis, addition_records_1a.clone(), vec![]);
                let block1b = invalid_empty_block(&genesis, network);
                let mut archival_state =
                    make_test_archival_state(network, maintain_utxo_index).await;
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
                let mut archival_state =
                    make_test_archival_state(network, maintain_utxo_index).await;

                for ar in &addition_records {
                    prop_assert!(
                        archival_state
                            .find_canonical_block_with_output(*ar, None)
                            .await
                            .is_none()
                    );
                }

                let block1 = block_with_puts(
                    network,
                    &Block::genesis(network),
                    addition_records.clone(),
                    vec![],
                );
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
        async fn canonical_block_with_input_block1() {
            let network = Network::Main;
            let genesis = Block::genesis(network);
            for maintain_utxo_index in [false, true] {
                let mut archival_state =
                    make_test_archival_state(network, maintain_utxo_index).await;
                let block1a = block_with_num_puts(network, &genesis, 2, 3);

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
                    assert!(
                        archival_state
                            .find_canonical_block_with_input(input, Some(12))
                            .await
                            .is_none()
                    );
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

    mod utxo_index {
        use neptune_wallet::mock_block::block_with_num_puts;
        use neptune_wallet::mock_block::block_with_puts;
        use rand::Rng;

        use super::*;

        #[apply(shared_tokio_runtime)]
        async fn only_canonical_addition_records_are_matched() {
            let network = Network::Main;
            let mut archive = make_test_archival_state(network, true).await;

            let genesis = Block::genesis(network);
            let mut rng = rand::rng();

            let abandoned_output = AdditionRecord::new(rng.random());
            let block1_orphaned =
                block_with_puts(network, &genesis, vec![abandoned_output], vec![]);
            archive.set_new_tip(&block1_orphaned).await.unwrap();

            let canonical_output = AdditionRecord::new(rng.random());
            let block1_canonical =
                block_with_puts(network, &genesis, vec![canonical_output], vec![]);
            archive.set_new_tip(&block1_canonical).await.unwrap();

            let abandoned_output = HashSet::from([abandoned_output]);
            assert!(
                archive
                    .addition_records_to_block_height(abandoned_output.clone())
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert!(
                archive
                    .canonical_block_heights_with_puts(HashSet::new(), abandoned_output)
                    .await
                    .unwrap()
                    .is_empty()
            );

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
            let mut archive = make_test_archival_state(network, true).await;

            let genesis = Block::genesis(network);
            let abandoned_block1 = block_with_num_puts(network, &genesis, 4, 4);
            let canonical_block1 = block_with_num_puts(network, &genesis, 4, 4);

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
                assert!(
                    archive
                        .absolute_index_sets_to_block_heights(abs_index_set.clone())
                        .await
                        .unwrap()
                        .is_empty()
                );

                assert!(
                    archive
                        .canonical_block_heights_with_puts(abs_index_set, HashSet::new())
                        .await
                        .unwrap()
                        .is_empty()
                );
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
            let mut archive = make_test_archival_state(network, true).await;
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
            );
            archive.set_new_tip(&block1).await.unwrap();
            let block2 = block_with_puts(
                network,
                &block1,
                vec![repeated_output, repeated_output],
                vec![],
            );
            archive.set_new_tip(&block2).await.unwrap();
            let block3 = invalid_empty_block(&block2, network);
            archive.set_new_tip(&block3).await.unwrap();
            let block4 = block_with_puts(network, &block3, vec![repeated_output], vec![]);
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
}
