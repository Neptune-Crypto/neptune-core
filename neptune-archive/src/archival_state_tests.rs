#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {

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
    use neptune_mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
    use neptune_primitives::block_height::BlockHeight;
    use neptune_primitives::data_directory::DataDirectory;
    use neptune_primitives::network::Network;
    use rand::distr::Alphanumeric;
    use rand::distr::SampleString;
    use rand::random;
    use tasm_lib::prelude::Digest;
    use tasm_lib::prelude::Tip5;
    use tasm_lib::triton_vm::prelude::BFieldElement;
    use tasm_lib::twenty_first::bfe;
    use tracing_test::traced_test;

    use crate::archival_state::ArchivalState;
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

    mod rusty_utxo_index_tests {
        use neptune_wallet::address::announcement_flag::AnnouncementFlag;
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
}
