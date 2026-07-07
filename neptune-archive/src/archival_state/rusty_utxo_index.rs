use std::collections::HashSet;

use anyhow::Result;
use itertools::Itertools;
use neptune_consensus::block::Block;
use neptune_database::NeptuneLevelDb;
use neptune_database::WriteBatchAsync;
use neptune_database::create_db_if_missing;
use neptune_database::storage::storage_schema::traits::*;
use neptune_mutator_set::addition_record::AdditionRecord;
use neptune_mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
use neptune_primitives::announcement_flag::AnnouncementFlag;
use neptune_primitives::block_height::BlockHeight;
use neptune_primitives::data_directory::DataDirectory;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;
use tracing::warn;

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
/// [`ArchivalMutatorSet`]: neptune_mutator_set::archival_mutator_set::ArchivalMutatorSet
/// [`ArchivalState`]: crate::archival_state::ArchivalState
#[derive(Debug)]
pub struct RustyUtxoIndex {
    pub(crate) db: NeptuneLevelDb<UtxoIndexKey, UtxoIndexValue>,
}

/// The key types used by the UTXO index database.
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub(crate) enum UtxoIndexKey {
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
pub(crate) enum UtxoIndexValue {
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

    pub(crate) fn expect_blocks_by_announcements(self) -> Vec<BlockHeight> {
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
    pub(crate) async fn is_empty(&self) -> bool {
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
    pub async fn initialize(data_dir: &DataDirectory) -> Result<Self> {
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
    pub async fn announcement_flags(&self, block_hash: Digest) -> Option<Vec<AnnouncementFlag>> {
        let key = UtxoIndexKey::AnnouncementsByBlock(block_hash);
        self.db
            .get(key)
            .await
            .map(|x| x.expect_announcements_by_block())
    }

    /// Return the digests of all absolute index sets of the removal records in
    /// this block. Returns `None` if the block is not known to this index.
    pub async fn index_set_digests(&self, block_hash: Digest) -> Option<Vec<Digest>> {
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
    /// instead use `UtxoIndexKey::AnnouncementsByBlock` to scan through
    /// each block.
    pub async fn blocks_by_announcement_flags(
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
    pub async fn blocks_by_addition_record(
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
    pub async fn block_by_index_set(&self, index_set: &AbsoluteIndexSet) -> Option<BlockHeight> {
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
    pub async fn index_block(&mut self, block: &Block) {
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
    pub async fn sync_label(&self) -> Digest {
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

/// Test-support query over announcements.
#[cfg(any(test, feature = "test-helpers"))]
impl RustyUtxoIndex {
    /// Return the set of block heights for each announcement in the input list.
    pub async fn block_heights_by_announcements(
        &self,
        announcements: &[neptune_consensus::transaction::announcement::Announcement],
    ) -> std::collections::HashSet<neptune_primitives::block_height::BlockHeight> {
        let announcement_flags: std::collections::HashSet<AnnouncementFlag> = announcements
            .iter()
            .filter_map(|ann| AnnouncementFlag::try_from(ann).ok())
            .collect();

        self.blocks_by_announcement_flags(&announcement_flags).await
    }
}
