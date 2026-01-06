use std::collections::HashSet;

use itertools::Itertools;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;
use tracing::warn;

use crate::application::database::storage::storage_schema::traits::*;
use crate::application::database::storage::storage_schema::DbtMap;
use crate::application::database::storage::storage_schema::DbtSingleton;
use crate::application::database::storage::storage_schema::RustyKey;
use crate::application::database::storage::storage_schema::RustyValue;
use crate::application::database::storage::storage_schema::SimpleRustyStorage;
use crate::application::database::NeptuneLevelDb;
use crate::protocol::consensus::block::Block;
use crate::state::wallet::address::announcement_flag::AnnouncementFlag;

/// The maximum number of blocks stored for each [`AnnouncementFlag`]. Wallets
/// with incoming UTXOs in more than this number of blocks cannot rely on the
/// mapping from announcement flags to block hashes to restore a wallet. They
/// must instead use other methods.
pub const MAX_BLOCK_COUNT_FOR_ANNOUNCEMENT_FLAGS: usize = 10_000;

/// The purpose of the UTXO index is to speed up the rescanning of historical
/// blocks, and to serve 3rd parties with information required to detect
/// incoming and outgoing UTXOs as quickly as possible. It assumes the presence
/// of an [`ArchivalState`]. Any decision about tables in the UTXO index should
/// be made in the light of allowing clients or 3rd parties to discover balance-
/// affecting input or output UTXOs in historical blocks as quickly as possible.
///
/// The tables of the UTXO index database. Does not include the addition records
/// in the block since those are included in the [`ArchivalMutatorSet`] which is
/// assumed to be part of the state of all nodes that also maintain a UTXO
/// index.
///
/// [`ArchivalMutatorSet`]: crate::util_types::mutator_set::archival_mutator_set::ArchivalMutatorSet
/// [`ArchivalState`]: crate::state::archival_state::ArchivalState
#[derive(Debug)]
struct UtxoIndexTables {
    #[allow(dead_code)]
    /// Schema version to be used in case this model changes, and data needs to
    /// be migrated or recreated.
    pub(super) schema_version: DbtSingleton<u16>,

    /// Mapping from block hash to the list of announcement flags contained in
    /// the block.
    ///
    /// Can be used to speed up the scanning for incoming, announced UTXOs.
    pub(super) announcements_by_block: DbtMap<Digest, Vec<AnnouncementFlag>>,

    /// Mapping from block hash to the list of digests of the absolute indices
    /// being set in the block.
    ///
    /// Can be used to speed up the scanning for used UTXOs, i.e. expenditures.
    pub(super) index_set_digests: DbtMap<Digest, Vec<Digest>>,

    /// Latest block handled by this database
    pub(super) sync_label: DbtSingleton<Digest>,

    /// Mapping from announcement flag to block hash for all blocks in which
    /// announcements with this flag are present. Length of list of block digests
    /// is capped by [MAX_BLOCK_COUNT_FOR_ANNOUNCEMENT_FLAGS] in order to foil
    /// certain DOS attacks. This means that extremely active wallets or smart
    /// contracts, wallets/smart contracts that have received announced UTXOs
    /// in more than [MAX_BLOCK_COUNT_FOR_ANNOUNCEMENT_FLAGS] blocks, cannot use
    /// this index to fully restore a wallet. But with that many blocks that
    /// they'd have to scan anyway, they might as well scan all blocks.
    ///
    /// Can be used to speed up the scanning for incoming, announced UTXOs, and
    /// to server RPC requests from external wallet programs.
    pub(super) blocks_by_announcement_flag: DbtMap<AnnouncementFlag, Vec<Digest>>,
}

#[derive(Debug)]
pub(crate) struct RustyUtxoIndex {
    storage: SimpleRustyStorage,
    tables: UtxoIndexTables,
}

impl RustyUtxoIndex {
    pub(super) async fn connect(db: NeptuneLevelDb<RustyKey, RustyValue>) -> Self {
        let mut storage = SimpleRustyStorage::new_with_callback(
            db,
            "RustyUtxoIndex-Schema",
            crate::LOG_TOKIO_LOCK_EVENT_CB,
        );

        let schema_version = storage.schema.new_singleton::<u16>("schema_version").await;
        let announcements_by_block = storage.schema.new_map("announcements_by_block").await;
        let index_sets = storage.schema.new_map("index_sets").await;
        let sync_label = storage.schema.new_singleton::<Digest>("sync_label").await;
        let blocks_by_announcement_flag =
            storage.schema.new_map("blocks_by_announcement_flag").await;

        let tables = UtxoIndexTables {
            schema_version,
            announcements_by_block,
            index_set_digests: index_sets,
            sync_label,
            blocks_by_announcement_flag,
        };

        Self { storage, tables }
    }

    /// Return the announcement keys for the announcement in the specified
    /// block. Returns Some(vec![]) list if no compatible announcement (of
    /// minimum lenth 2) were mined in the block. Returns `None` if the block
    /// is not known to this index.
    pub(crate) async fn announcement_flags_by_block(
        &self,
        block_hash: Digest,
    ) -> Option<Vec<AnnouncementFlag>> {
        self.tables.announcements_by_block.get(&block_hash).await
    }

    /// Return the block hashes for blocks containing announcements matching the
    /// [`AnnouncementFlag`]s. The referenced blocks are not guaranteed to be
    /// canonical.
    ///
    /// # Warning
    ///
    /// For each announcement flag, the returned list is capped in length (for
    /// DOS reasons) by [`MAX_BLOCK_COUNT_FOR_ANNOUNCEMENT_FLAGS`] so extremely
    /// active wallets cannot rely on this method for wallet recovery. They
    /// should instead use [`Self::announcement_flags_by_block`] to scan through
    /// each block.
    pub(crate) async fn block_hashes_by_announcement_flags(
        &self,
        announcement_flags: &HashSet<AnnouncementFlag>,
    ) -> HashSet<Digest> {
        let mut block_hashes = HashSet::new();
        for flag in announcement_flags {
            let blocks_matching_flag = self
                .tables
                .blocks_by_announcement_flag
                .get(flag)
                .await
                .unwrap_or_default();
            block_hashes.extend(blocks_matching_flag);
        }

        block_hashes
    }

    /// Return the digests of all absolute index sets of the removal records in
    /// this block. Returns `None` if the block is not known to this index.
    pub(crate) async fn index_set_digests(&self, block_hash: Digest) -> Option<Vec<Digest>> {
        self.tables.index_set_digests.get(&block_hash).await
    }

    /// Add block to UTXO index. Adds all announcements, addition records, and
    /// index set digests to the UTXO index.
    ///
    /// This method is idempotent, meaning that it does not alter the index if
    /// the same block is indexed twice. The [`Self::sync_label`] always points
    /// to the latest blocks that was indexed.
    pub(crate) async fn index_block(&mut self, block: &Block) {
        let hash = block.hash();

        let tx_kernel = &block.body().transaction_kernel;

        // Get flags for all announcements in block, removing duplicates
        let announcement_flags: HashSet<AnnouncementFlag> = tx_kernel
            .announcements
            .iter()
            .filter_map(|ann| ann.try_into().ok())
            .collect();
        self.tables
            .announcements_by_block
            .insert(hash, announcement_flags.iter().copied().collect_vec())
            .await;

        for announcement_flag in announcement_flags {
            let mut block_hashes = self
                .tables
                .blocks_by_announcement_flag
                .get(&announcement_flag)
                .await
                .unwrap_or_default();

            // Ensure same block is not added twice, to ensure function's
            // idempotency.
            if block_hashes.contains(&hash) {
                continue;
            }

            // DOS protection: Do not allow list to grow indefinitely as list is
            // stored in RAM during this function call.
            if block_hashes.len() >= MAX_BLOCK_COUNT_FOR_ANNOUNCEMENT_FLAGS {
                warn!(
                    "List of block hashes matching announcement flag exceeds max.\
                 Not adding new block to list."
                );
                continue;
            }

            block_hashes.push(hash);

            self.tables
                .blocks_by_announcement_flag
                .insert(announcement_flag, block_hashes)
                .await;
        }

        let index_set_digests = tx_kernel
            .inputs
            .iter()
            .map(|rr| Tip5::hash(&rr.absolute_indices))
            .collect_vec();
        self.tables
            .index_set_digests
            .insert(hash, index_set_digests)
            .await;

        self.tables.sync_label.set(hash).await;
    }

    pub(crate) fn sync_label(&self) -> Digest {
        self.tables.sync_label.get()
    }

    /// Returns true if the block was already indexed.
    pub(crate) async fn block_was_indexed(&self, block_hash: Digest) -> bool {
        self.tables
            .announcements_by_block
            .contains_key(&block_hash)
            .await
    }
}

impl StorageWriter for RustyUtxoIndex {
    async fn persist(&mut self) {
        self.storage.persist().await;
    }

    async fn drop_unpersisted(&mut self) {
        unimplemented!("announcement index does not need it")
    }
}

#[cfg(test)]
mod tests {
    use macro_rules_attr::apply;
    use tasm_lib::twenty_first::bfe;
    use tasm_lib::twenty_first::bfe_vec;

    use super::*;
    use crate::api::export::Announcement;
    use crate::api::export::GenerationSpendingKey;
    use crate::api::export::Network;
    use crate::state::archival_state::ArchivalState;
    use crate::tests::shared::blocks::invalid_empty_block_with_announcements;
    use crate::tests::shared::blocks::make_mock_block_with_inputs_and_outputs;
    use crate::tests::shared_tokio_runtime;
    use crate::util_types::mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
    use crate::util_types::mutator_set::removal_record::chunk_dictionary::ChunkDictionary;
    use crate::util_types::mutator_set::removal_record::RemovalRecord;
    use crate::util_types::mutator_set::shared::NUM_TRIALS;
    use crate::BFieldElement;

    impl RustyUtxoIndex {
        /// Return a list of block digests for each announcement in the input
        /// list.
        async fn block_hashes_by_announcements(
            &self,
            announcements: &[Announcement],
        ) -> HashSet<Digest> {
            let announcement_flags: HashSet<AnnouncementFlag> = announcements
                .iter()
                .filter_map(|ann| ann.try_into().ok())
                .collect();

            self.block_hashes_by_announcement_flags(&announcement_flags)
                .await
        }
    }

    async fn test_utxo_index(network: Network) -> RustyUtxoIndex {
        let data_dir = crate::tests::shared::files::unit_test_data_directory(network).unwrap();
        ArchivalState::initialize_utxo_index(&data_dir)
            .await
            .unwrap()
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
    async fn announcement_flag_to_block_digests_unit_test() {
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

        utxo_index.index_block(&block1).await;
        utxo_index.index_block(&block2).await;
        utxo_index.index_block(&block3).await;

        assert_eq!(
            vec![block1.hash(), block2.hash(), block3.hash()],
            utxo_index
                .tables
                .blocks_by_announcement_flag
                .get(&AnnouncementFlag {
                    flag: bfe!(22),
                    receiver_id: bfe!(55),
                })
                .await
                .unwrap()
        );
        assert_eq!(
            vec![block1.hash(), block3.hash()],
            utxo_index
                .tables
                .blocks_by_announcement_flag
                .get(&AnnouncementFlag {
                    flag: bfe!(1),
                    receiver_id: bfe!(444),
                })
                .await
                .unwrap()
        );
        assert_eq!(
            vec![block2.hash()],
            utxo_index
                .tables
                .blocks_by_announcement_flag
                .get(&AnnouncementFlag {
                    flag: bfe!(1),
                    receiver_id: bfe!(888),
                })
                .await
                .unwrap()
        );
    }

    #[apply(shared_tokio_runtime)]
    async fn block_index_is_idempotent() {
        let network = Network::Main;
        let mut utxo_index = test_utxo_index(network).await;
        let an_input = RemovalRecord {
            absolute_indices: AbsoluteIndexSet::new([(1u128 << 20); NUM_TRIALS as usize]),
            target_chunks: ChunkDictionary::default(),
        };

        let genesis = Block::genesis(network);
        let (block1, _) = make_mock_block_with_inputs_and_outputs(
            &genesis,
            vec![an_input],
            vec![],
            None,
            GenerationSpendingKey::derive_from_seed(Digest::default()),
            Digest::default(),
            network,
        )
        .await;
        let announcements = announcements_length_0_to_3();
        let block2 =
            invalid_empty_block_with_announcements(&block1, network, announcements.clone());

        utxo_index.index_block(&block1).await;
        utxo_index.index_block(&block2).await;

        let expected_index_set_digests = utxo_index.index_set_digests(block1.hash()).await;
        let expected_announcement_flags =
            utxo_index.announcement_flags_by_block(block2.hash()).await;

        let expected_block_digests_by_flag = utxo_index
            .block_hashes_by_announcements(&announcements)
            .await;

        utxo_index.index_block(&block1).await;
        utxo_index.index_block(&block2).await;

        assert_eq!(
            expected_index_set_digests,
            utxo_index.index_set_digests(block1.hash()).await
        );
        assert_eq!(
            expected_announcement_flags,
            utxo_index.announcement_flags_by_block(block2.hash()).await
        );
        assert_eq!(
            expected_block_digests_by_flag,
            utxo_index
                .block_hashes_by_announcements(&announcements)
                .await
        );
        assert_eq!(block2.hash(), utxo_index.sync_label());
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
                .announcement_flags_by_block(block1.hash())
                .await
                .unwrap()
                .len(),
            "Announcements of length 2 and above should be indexed"
        );
    }
}
