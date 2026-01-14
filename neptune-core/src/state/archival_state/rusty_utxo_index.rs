use std::collections::HashSet;

use anyhow::Result;
use itertools::Itertools;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;
use tracing::warn;

use crate::api::export::AdditionRecord;
use crate::api::export::BlockHeight;
use crate::application::config::data_directory::DataDirectory;
use crate::application::database::create_db_if_missing;
use crate::application::database::storage::storage_schema::traits::*;
use crate::application::database::NeptuneLevelDb;
use crate::application::database::WriteBatchAsync;
use crate::protocol::consensus::block::Block;
use crate::state::wallet::address::announcement_flag::AnnouncementFlag;
use crate::util_types::mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;

/// The maximum number of blocks stored for each [`AnnouncementFlag`]. Wallets
/// with incoming UTXOs in more than this number of blocks cannot rely on the
/// mapping from announcement flags to block heights to restore a wallet. They
/// must instead use other methods. Also used to cap mapping from addition
/// records to block heights.
pub const MAX_NUM_BLOCKS_IN_LOOKUP_LIST: usize = 10_000;

/// The purpose of the UTXO index is to speed up the rescanning of historical
/// blocks, and to serve 3rd parties with information required to detect
/// incoming and outgoing UTXOs as quickly as possible. It assumes the presence
/// of an [`ArchivalState`]. Any decision about tables in the UTXO index should
/// be made in the light of allowing clients or 3rd parties to discover balance-
/// affecting input or output UTXOs in historical blocks as quickly as possible,
/// and to minimize storage requirements for the UTXO index.
///
/// The tables of the UTXO index database. Does not include a mapping from
/// block digest to the block's addition records since that mapping can be found
/// from the [`ArchivalMutatorSet`] which is assumed to be part of the state of
/// all nodes that maintain a UTXO index.
///
/// Block heights are often preferred over block digests due to their smaller
/// serialized size (8 bytes vs. 40).
///
/// [`ArchivalMutatorSet`]: crate::util_types::mutator_set::archival_mutator_set::ArchivalMutatorSet
/// [`ArchivalState`]: crate::state::archival_state::ArchivalState
#[derive(Debug)]
pub(crate) struct RustyUtxoIndex {
    db: NeptuneLevelDb<UtxoIndexKey, UtxoIndexValue>,
}

/// The key types used by the UTXO index database.
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
enum UtxoIndexKey {
    /// Latest block handled by this database. Any initialized database must
    /// have a sync label set. The default value indicates that no blocks have
    /// been processed by the UTXO index.
    SyncLabel,

    /// Mapping from block hash to the list of announcement flags contained in
    /// the block.
    ///
    /// Can be used to speed up the scanning for incoming, announced UTXOs.
    AnnouncementsByBlock(Digest),

    /// Mapping from block hash to the list of digests of the absolute indices
    /// being set in the block.
    ///
    /// Can be used to speed up the scanning for spent UTXOs, i.e. expenditures.
    IndexSetDigestsByBlock(Digest),

    /// Mapping from announcement flag to block height for all blocks in which
    /// announcements with this flag are present. Length of list of block
    /// heights is capped by [MAX_NUM_BLOCKS_IN_LOOKUP_LIST] in order to foil
    /// certain DOS attacks. This means that extremely active wallets/smart
    /// contracts that have received announced UTXOs in more than
    /// [MAX_NUM_BLOCKS_IN_LOOKUP_LIST] blocks, cannot use this index to fully
    /// restore a wallet. But in their case, they might as well scan all blocks
    /// anyway.
    ///
    /// Since the indexed blocks are not guaranteed to be canonical, this
    /// mapping may contain entries for blocks that are not part of the
    /// canonical chain.
    ///
    /// Can be used to speed up the scanning for incoming, announced UTXOs, and
    /// to serve RPC requests from external wallet programs.
    BlocksByAnnouncementFlag(AnnouncementFlag),

    /// Mapping from addition record to block height for all blocks containing
    /// the specific addition record. Length of list of block heights is capped
    /// by [MAX_NUM_BLOCKS_IN_LOOKUP_LIST] in order to foil certain DOS attacks.
    /// This means that if this addition record is present in more than
    /// [MAX_NUM_BLOCKS_IN_LOOKUP_LIST] different blocks, the list will be
    /// capped.
    ///
    /// This mapping includes guesser-reward addition records.
    ///
    /// Since the indexed blocks are not guaranteed to be canonical, this
    /// mapping may contain entries for blocks that are not part of the
    /// canonical chain.
    ///
    /// Can be used to serve an RPC endpoint that maps addition records to block
    /// heights.
    BlocksByAdditionRecord(AdditionRecord),

    /// Mapping from hash of absolute index set to block height.
    ///
    /// Can be used to serve an RPC endpoint that maps absolute index sets to
    /// block heights.
    BlockByIndexSetDigest(Digest),
}

/// The values used by the UTXO index database.
///
/// See documentstion in [`UtxoIndexKey`] for each variant of this enum.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum UtxoIndexValue {
    SyncLabel(Digest),
    AnnouncementsByBlock(Vec<AnnouncementFlag>),
    IndexSetDigestsByBlock(Vec<Digest>),
    BlocksByAnnouncementFlag(Vec<BlockHeight>),
    BlocksByAdditionRecord(Vec<BlockHeight>),
    BlockByIndexSetDigest(BlockHeight),
}

impl UtxoIndexValue {
    fn expect_sync_label(self) -> Digest {
        match self {
            UtxoIndexValue::SyncLabel(digest) => digest,
            _ => panic!("Expected SyncLabel found {:?}", self),
        }
    }

    fn expect_announcements_by_block(self) -> Vec<AnnouncementFlag> {
        match self {
            UtxoIndexValue::AnnouncementsByBlock(flags) => flags,
            _ => panic!("Expected AnnouncementsByBlock found {:?}", self),
        }
    }

    fn expect_index_set_digests_by_block(self) -> Vec<Digest> {
        match self {
            UtxoIndexValue::IndexSetDigestsByBlock(index_set_digests) => index_set_digests,
            _ => panic!("Expected IndexSetDigestsByBlock found {:?}", self),
        }
    }

    fn expect_blocks_by_announcements(self) -> Vec<BlockHeight> {
        match self {
            UtxoIndexValue::BlocksByAnnouncementFlag(block_heights) => block_heights,
            _ => panic!("Expected BlocksByAnnouncementFlag found {:?}", self),
        }
    }

    fn expect_blocks_by_addition_records(self) -> Vec<BlockHeight> {
        match self {
            UtxoIndexValue::BlocksByAdditionRecord(block_heights) => block_heights,
            _ => panic!("Expected BlocksByAdditionRecord found {:?}", self),
        }
    }

    fn expect_block_by_index_set_digest(self) -> BlockHeight {
        match self {
            UtxoIndexValue::BlockByIndexSetDigest(height) => height,
            _ => panic!("Expected BlockByIndexSetDigest found {:?}", self),
        }
    }
}

impl RustyUtxoIndex {
    /// Returns true iff no blocks have been indexed.
    pub(super) async fn is_empty(&self) -> bool {
        self.sync_label().await == Default::default()
    }

    /// Returns true if the block was already indexed.
    pub(crate) async fn block_was_indexed(&self, block_hash: Digest) -> bool {
        self.db
            .get(UtxoIndexKey::AnnouncementsByBlock(block_hash))
            .await
            .is_some()
    }

    /// Initialize a UTXO index. Does not apply the genesis block to the index.
    pub(super) async fn initialize(data_dir: &DataDirectory) -> Result<Self> {
        let utxo_index_db_dir_path = data_dir.utxo_index_dir_path();
        DataDirectory::create_dir_if_not_exists(&utxo_index_db_dir_path).await?;

        let utxo_index = NeptuneLevelDb::<UtxoIndexKey, UtxoIndexValue>::new(
            &utxo_index_db_dir_path,
            &create_db_if_missing(),
        )
        .await?;

        let mut utxo_index = RustyUtxoIndex { db: utxo_index };

        // After initialization a value for sync label must always be set.
        if utxo_index.db.get(UtxoIndexKey::SyncLabel).await.is_none() {
            utxo_index
                .db
                .put(
                    UtxoIndexKey::SyncLabel,
                    UtxoIndexValue::SyncLabel(Digest::default()),
                )
                .await;
        }

        Ok(utxo_index)
    }

    /// Return the announcement keys for the announcement in the specified
    /// block. Returns Some(vec![]) list if no compatible announcement (of
    /// minimum lenth 2) were mined in the block. Returns `None` if the block
    /// is not known to this index.
    pub(crate) async fn announcement_flags(
        &self,
        block_hash: Digest,
    ) -> Option<Vec<AnnouncementFlag>> {
        let key = UtxoIndexKey::AnnouncementsByBlock(block_hash);
        self.db
            .get(key)
            .await
            .map(|x| x.expect_announcements_by_block())
    }

    /// Return the digests of all absolute index sets of the removal records in
    /// this block. Returns `None` if the block is not known to this index.
    pub(crate) async fn index_set_digests(&self, block_hash: Digest) -> Option<Vec<Digest>> {
        let key = UtxoIndexKey::IndexSetDigestsByBlock(block_hash);
        self.db
            .get(key)
            .await
            .map(|x| x.expect_index_set_digests_by_block())
    }

    /// Return the block heights for blocks containing announcements matching
    /// the [`AnnouncementFlag`]s. The referenced blocks are not guaranteed to
    /// be canonical.
    ///
    /// # Warning
    ///
    /// For each announcement flag, the returned list is capped in length (for
    /// DOS reasons) by [`MAX_NUM_BLOCKS_IN_LOOKUP_LIST`] so extremely active
    /// wallets cannot rely on this method for wallet recovery. They should
    /// instead use [`UtxoIndexKey::AnnouncementsByBlock`] to scan through
    /// each block.
    pub(crate) async fn blocks_by_announcement_flags(
        &self,
        announcement_flags: &HashSet<AnnouncementFlag>,
    ) -> HashSet<BlockHeight> {
        let mut block_heights = HashSet::new();
        for flag in announcement_flags {
            let key = UtxoIndexKey::BlocksByAnnouncementFlag(*flag);
            let matching_blocks = self
                .db
                .get(key)
                .await
                .map(|x| x.expect_blocks_by_announcements())
                .unwrap_or_default();
            block_heights.extend(matching_blocks);
        }

        block_heights
    }

    /// Return all block heights for blocks containing the requested
    /// addition record. The referenced blocks are not guaranteed to be
    /// canonical.
    /// # Warning
    ///
    /// For each addition record, the returned list is capped in length (for
    /// DOS reasons) by [`MAX_NUM_BLOCKS_IN_LOOKUP_LIST`]. But since addition
    /// records are unlikely to be repeated in large numbers, this truncation
    /// is probably never met.
    pub(crate) async fn blocks_by_addition_record(
        &self,
        addition_record: AdditionRecord,
    ) -> HashSet<BlockHeight> {
        let key = UtxoIndexKey::BlocksByAdditionRecord(addition_record);
        let blocks = self
            .db
            .get(key)
            .await
            .map(|x| x.expect_blocks_by_addition_records())
            .unwrap_or_default();

        blocks.into_iter().collect()
    }

    /// Return the block height of the block containing the specified
    /// transaction input. Any referenced block is not guaranteed to be
    /// canonical.
    ///
    /// Returns `None` if the UTXO index has never seen this absolute index set.
    pub(crate) async fn block_by_index_set(
        &self,
        index_set: &AbsoluteIndexSet,
    ) -> Option<BlockHeight> {
        let index_set_digest = Tip5::hash(index_set);
        let key = UtxoIndexKey::BlockByIndexSetDigest(index_set_digest);
        self.db
            .get(key)
            .await
            .map(|x| x.expect_block_by_index_set_digest())
    }

    /// Add block to UTXO index. Adds all announcements, addition records, and
    /// index set digests to the UTXO index.
    ///
    /// This method is idempotent, meaning that it does not alter the index if
    /// the same block is indexed twice, apart from the [`Self::sync_label`]
    /// which always points to the latest blocks that was indexed.
    pub(crate) async fn index_block(&mut self, block: &Block) {
        let hash = block.hash();
        let height = block.header().height;

        let tx_kernel = &block.body().transaction_kernel;

        // Get flags for all announcements in block, removing duplicates
        let announcement_flags: HashSet<AnnouncementFlag> = tx_kernel
            .announcements
            .iter()
            .filter_map(|ann| AnnouncementFlag::try_from(ann).ok())
            .collect();

        // sort announcement flags to ensure idempotency
        let mut announcement_flags = announcement_flags.iter().copied().collect_vec();
        announcement_flags.sort_unstable();
        let mut batch_writes = WriteBatchAsync::new();
        batch_writes.op_write(
            UtxoIndexKey::AnnouncementsByBlock(hash),
            UtxoIndexValue::AnnouncementsByBlock(announcement_flags.clone()),
        );

        // Loop over all announcement flags to maintain flag to block mapping
        for announcement_flag in announcement_flags {
            let announcement_flag = UtxoIndexKey::BlocksByAnnouncementFlag(announcement_flag);
            let mut block_heights = self
                .db
                .get(announcement_flag)
                .await
                .map(|x| x.expect_blocks_by_announcements())
                .unwrap_or_default();

            // Ensure same block is not added twice, to ensure function's
            // idempotency.
            if block_heights.contains(&height) {
                continue;
            }

            // DOS protection: Do not allow list to grow indefinitely as list is
            // stored in RAM during this function call.
            if block_heights.len() >= MAX_NUM_BLOCKS_IN_LOOKUP_LIST {
                warn!(
                    "List of block heights matching announcement flag exceeds max.\
                 Not adding new block to list."
                );
                continue;
            }

            block_heights.push(height);

            batch_writes.op_write(
                announcement_flag,
                UtxoIndexValue::BlocksByAnnouncementFlag(block_heights),
            );
        }

        // Loop over all addition records to maintain addition record to block
        // mapping.
        for addition_record in block
            .all_addition_records()
            .expect("Block must have mutator set update")
        {
            let addition_record = UtxoIndexKey::BlocksByAdditionRecord(addition_record);
            let mut block_heights = self
                .db
                .get(addition_record)
                .await
                .map(|x| x.expect_blocks_by_addition_records())
                .unwrap_or_default();

            // Ensure same block is not added twice, to ensure function's
            // idempotency.
            if block_heights.contains(&height) {
                continue;
            }

            // DOS protection: Do not allow list to grow indefinitely as list is
            // stored in RAM during this function call. Very unlikely this is
            // ever hit.
            if block_heights.len() >= MAX_NUM_BLOCKS_IN_LOOKUP_LIST {
                warn!(
                    "List of block heights matching addition record exceeds max.\
                 Not adding new block to list."
                );
                continue;
            }

            block_heights.push(height);

            batch_writes.op_write(
                addition_record,
                UtxoIndexValue::BlocksByAdditionRecord(block_heights),
            );
        }

        // Loop over all inputs to maintain hash(absolute index set) to block
        // mapping.
        let index_set_digests = tx_kernel
            .inputs
            .iter()
            .map(|rr| Tip5::hash(&rr.absolute_indices))
            .collect_vec();
        for index_set_digest in &index_set_digests {
            // All absolute index sets are assumed to be unique, so no
            // duplication removal is needed here.
            batch_writes.op_write(
                UtxoIndexKey::BlockByIndexSetDigest(*index_set_digest),
                UtxoIndexValue::BlockByIndexSetDigest(height),
            );
        }

        batch_writes.op_write(
            UtxoIndexKey::IndexSetDigestsByBlock(hash),
            UtxoIndexValue::IndexSetDigestsByBlock(index_set_digests),
        );

        batch_writes.op_write(UtxoIndexKey::SyncLabel, UtxoIndexValue::SyncLabel(hash));

        self.db.batch_write(batch_writes).await;
    }

    /// Return the hash of the latest block indexed. The default value means
    /// that no blocks have been indexed.
    pub(crate) async fn sync_label(&self) -> Digest {
        self.db
            .get(UtxoIndexKey::SyncLabel)
            .await
            .expect("UTXO index must have a SyncLabel set")
            .expect_sync_label()
    }
}

impl StorageWriter for RustyUtxoIndex {
    async fn persist(&mut self) {
        self.db.flush().await;
    }

    async fn drop_unpersisted(&mut self) {
        unimplemented!("utxo index does not need it")
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use macro_rules_attr::apply;
    use rand::Rng;
    use tasm_lib::twenty_first::bfe;
    use tasm_lib::twenty_first::bfe_vec;

    use super::*;
    use crate::api::export::Announcement;
    use crate::api::export::GenerationSpendingKey;
    use crate::api::export::Network;
    use crate::tests::shared::blocks::invalid_empty_block_with_announcements;
    use crate::tests::shared::blocks::make_mock_block_with_inputs_and_outputs;
    use crate::tests::shared_tokio_runtime;
    use crate::util_types::mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
    use crate::util_types::mutator_set::removal_record::chunk_dictionary::ChunkDictionary;
    use crate::util_types::mutator_set::removal_record::RemovalRecord;
    use crate::util_types::mutator_set::shared::CHUNK_SIZE;
    use crate::util_types::mutator_set::shared::NUM_TRIALS;
    use crate::BFieldElement;

    impl RustyUtxoIndex {
        /// Return a list of block heights for each announcement in the input
        /// list.
        async fn block_heights_by_announcements(
            &self,
            announcements: &[Announcement],
        ) -> HashSet<BlockHeight> {
            let announcement_flags: HashSet<AnnouncementFlag> = announcements
                .iter()
                .filter_map(|ann| AnnouncementFlag::try_from(ann).ok())
                .collect();

            self.blocks_by_announcement_flags(&announcement_flags).await
        }
    }

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

    /// Return a block with the specied number of inputs/outputs. Inputs and
    /// outputs are random. Also contains randomized composer rewards.
    async fn block_with_num_puts(
        network: Network,
        predecessor: &Block,
        num_inputs: u128,
        num_outputs: usize,
    ) -> Block {
        let mut rng = rand::rng();
        let inputs = (0..num_inputs)
            .map(|_| RemovalRecord {
                absolute_indices: AbsoluteIndexSet::new(
                    vec![
                        (1u128 << 20) + rng.random_range(0..=u128::from(CHUNK_SIZE));
                        NUM_TRIALS as usize
                    ]
                    .try_into()
                    .unwrap(),
                ),
                target_chunks: ChunkDictionary::default(),
            })
            .collect_vec();

        let outputs = vec![rng.random(); num_outputs];

        let (block, _) = make_mock_block_with_inputs_and_outputs(
            predecessor,
            inputs,
            outputs,
            None,
            GenerationSpendingKey::derive_from_seed(rng.random()),
            rng.random(),
            network,
        )
        .await;

        block
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
                assert!(utxo_index
                    .blocks_by_announcement_flags(&announcement_flag)
                    .await
                    .contains(&block.header().height),);
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
        let (block2_two_repeated_addition_records, _) = make_mock_block_with_inputs_and_outputs(
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
