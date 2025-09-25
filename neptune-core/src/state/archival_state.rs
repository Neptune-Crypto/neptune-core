use std::collections::HashMap;
use std::ops::DerefMut;
use std::path::PathBuf;

use anyhow::bail;
use anyhow::Result;
use memmap2::MmapOptions;
use num_traits::Zero;
use tasm_lib::twenty_first::prelude::Mmr;
use tasm_lib::twenty_first::tip5::digest::Digest;
use tokio::io::AsyncSeekExt;
use tokio::io::AsyncWriteExt;
use tokio::io::SeekFrom;
use tracing::debug;
use tracing::warn;

pub(crate) mod import_blocks_from_files;

use super::shared::new_block_file_is_needed;
use super::StorageVecBase;
use crate::api::export::Network;
use crate::application::config::data_directory::DataDirectory;
use crate::application::database::create_db_if_missing;
use crate::application::database::storage::storage_schema::traits::*;
use crate::application::database::NeptuneLevelDb;
use crate::application::database::WriteBatchAsync;
use crate::protocol::consensus::block::block_header::BlockHeader;
use crate::protocol::consensus::block::block_header::BlockHeaderWithBlockHashWitness;
use crate::protocol::consensus::block::block_header::HeaderToBlockHashWitness;
use crate::protocol::consensus::block::block_height::BlockHeight;
use crate::protocol::consensus::block::mutator_set_update::MutatorSetUpdate;
use crate::protocol::consensus::block::Block;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelProxy;
use crate::state::database::BlockFileLocation;
use crate::state::database::BlockIndexKey;
use crate::state::database::BlockIndexValue;
use crate::state::database::BlockRecord;
use crate::state::database::FileRecord;
use crate::state::database::LastFileRecord;
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use crate::util_types::mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
use crate::util_types::mutator_set::removal_record::RemovalRecord;
use crate::util_types::mutator_set::rusty_archival_mutator_set::RustyArchivalMutatorSet;
use crate::util_types::rusty_archival_block_mmr::RustyArchivalBlockMmr;

pub(crate) const BLOCK_INDEX_DB_NAME: &str = "block_index";
pub(crate) const MUTATOR_SET_DIRECTORY_NAME: &str = "mutator_set";
pub(crate) const ARCHIVAL_BLOCK_MMR_DIRECTORY_NAME: &str = "archival_block_mmr";

/// Provides interface to historic blockchain data which consists of
///  * block-data stored in individual files (append-only)
///  * block-index database stored in levelDB
///  * mutator set stored in LevelDB,
///
/// all file operations are async, or async-friendly.
///       see <https://github.com/Neptune-Crypto/neptune-core/issues/75>
pub struct ArchivalState {
    data_dir: DataDirectory,

    /// maps block index key to block index value where key/val pairs can be:
    /// ```ignore
    ///   Block(Digest)        -> Block(Box<BlockRecord>)
    ///   File(u32)            -> File(FileRecord)
    ///   Height(BlockHeight)  -> Height(Vec<Digest>)
    ///   LastFile             -> LastFile(LastFileRecord)
    ///   BlockTipDigest       -> BlockTipDigest(Digest)
    /// ```
    ///
    /// So this is effectively 5 logical indexes.
    pub(crate) block_index_db: NeptuneLevelDb<BlockIndexKey, BlockIndexValue>,

    // The genesis block is stored on the heap, as we would otherwise get stack overflows whenever we instantiate
    // this object in a spawned worker task.
    pub(super) genesis_block: Box<Block>,

    // The archival mutator set is persisted to one database that also records a sync label,
    // which corresponds to the hash of the block to which the mutator set is synced.
    pub(crate) archival_mutator_set: RustyArchivalMutatorSet,

    /// Archival-MMR of the block digests belonging to the canonical chain.
    pub(crate) archival_block_mmr: RustyArchivalBlockMmr,

    /// The network that this node is on. Used to simplify method interfaces.
    network: Network,
}

// The only reason we have this `Debug` implementation is that it's required
// for some tracing/logging functionalities.
impl core::fmt::Debug for ArchivalState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArchivalState")
            .field("data_dir", &self.data_dir)
            .field("block_index_db", &self.block_index_db)
            .field("genesis_block", &self.genesis_block)
            .field("network", &self.network)
            .finish()
    }
}

impl ArchivalState {
    /// Create databases for block persistence
    async fn initialize_block_index_database(
        data_dir: &DataDirectory,
    ) -> Result<NeptuneLevelDb<BlockIndexKey, BlockIndexValue>> {
        let block_index_db_dir_path = data_dir.block_index_database_dir_path();
        DataDirectory::create_dir_if_not_exists(&block_index_db_dir_path).await?;

        let block_index = NeptuneLevelDb::<BlockIndexKey, BlockIndexValue>::new(
            &block_index_db_dir_path,
            &create_db_if_missing(),
        )
        .await?;

        Ok(block_index)
    }

    /// Initialize an `ArchivalMutatorSet` by opening or creating its databases.
    async fn initialize_mutator_set(data_dir: &DataDirectory) -> Result<RustyArchivalMutatorSet> {
        let ms_db_dir_path = data_dir.mutator_set_database_dir_path();
        DataDirectory::create_dir_if_not_exists(&ms_db_dir_path).await?;

        let path = ms_db_dir_path.clone();
        let result = NeptuneLevelDb::new(&path, &create_db_if_missing()).await;

        let db = match result {
            Ok(db) => db,
            Err(e) => {
                tracing::error!(
                    "Could not open mutator set database at {}: {e}",
                    ms_db_dir_path.display()
                );
                panic!(
                    "Could not open database; do not know how to proceed. Panicking.\n\
                    If you suspect the database may be corrupted, consider renaming the directory {}\
                     or removing it altogether. Or perhaps a node is already running?",
                    ms_db_dir_path.display()
                );
            }
        };

        let mut archival_set = RustyArchivalMutatorSet::connect(db).await;
        archival_set.restore_or_new().await;

        Ok(archival_set)
    }

    async fn initialize_archival_block_mmr(
        data_dir: &DataDirectory,
    ) -> Result<RustyArchivalBlockMmr> {
        let abmmr_dir_path = data_dir.archival_block_mmr_dir_path();
        DataDirectory::create_dir_if_not_exists(&abmmr_dir_path).await?;

        let path = abmmr_dir_path.clone();
        let result = NeptuneLevelDb::new(&path, &create_db_if_missing()).await;

        let db = match result {
            Ok(db) => db,
            Err(e) => {
                tracing::error!(
                    "Could not open archival MMR database at {}: {e}",
                    abmmr_dir_path.display()
                );
                panic!(
                    "Could not open database; do not know how to proceed. Panicking.\n\
                    If you suspect the database may be corrupted, consider renaming the directory {}\
                     or removing it altogether. Or perhaps a node is already running?",
                     abmmr_dir_path.display()
                );
            }
        };

        let archival_bmmr = RustyArchivalBlockMmr::connect(db).await;

        Ok(archival_bmmr)
    }

    /// Find the path connecting two blocks. Every path involves going down some
    /// number of steps and then going up some number of steps. So this function
    /// returns two lists: the list of down steps and the list of up steps. It
    /// also returns their latest common ancestor.
    ///
    /// # Panics
    ///
    ///  - If there is no path. (Meaning: different genesis blocks.)
    ///  - If the blocks on the path are not stored.
    pub(crate) async fn find_path(
        &self,
        start: Digest,
        stop: Digest,
    ) -> (Vec<Digest>, Digest, Vec<Digest>) {
        // We build two lists, initially populated with the start
        // and stop of the walk. We extend the lists downwards by
        // appending predecessors.
        let mut leaving = vec![start];
        let mut arriving = vec![stop];

        let mut leaving_deepest_block_header = self
            .get_block_header(*leaving.last().unwrap())
            .await
            .unwrap();
        let mut arriving_deepest_block_header = self
            .get_block_header(*arriving.last().unwrap())
            .await
            .unwrap();
        while leaving_deepest_block_header.height != arriving_deepest_block_header.height {
            if leaving_deepest_block_header.height < arriving_deepest_block_header.height {
                arriving.push(arriving_deepest_block_header.prev_block_digest);
                arriving_deepest_block_header = self
                    .get_block_header(arriving_deepest_block_header.prev_block_digest)
                    .await
                    .unwrap();
            } else {
                leaving.push(leaving_deepest_block_header.prev_block_digest);
                leaving_deepest_block_header = self
                    .get_block_header(leaving_deepest_block_header.prev_block_digest)
                    .await
                    .unwrap();
            }
        }

        // Extend both lists until their deepest blocks match.
        while leaving.last().unwrap() != arriving.last().unwrap() {
            let leaving_predecessor = self
                .get_block_header(*leaving.last().unwrap())
                .await
                .unwrap()
                .prev_block_digest;
            leaving.push(leaving_predecessor);
            let arriving_predecessor = self
                .get_block_header(*arriving.last().unwrap())
                .await
                .unwrap()
                .prev_block_digest;
            arriving.push(arriving_predecessor);
        }

        // reformat
        let luca = leaving.pop().unwrap();
        arriving.pop();
        arriving.reverse();

        (leaving, luca, arriving)
    }

    /// Apply all [AdditionRecord]s in the genesis block to the archival mutator
    /// set. Set the sync label to the genesis block hash. Persist.
    async fn populate_archival_mutator_set_with_genesis_block(
        archival_mutator_set: &mut RustyArchivalMutatorSet,
        genesis_block: &Block,
    ) {
        for addition_record in &genesis_block.kernel.body.transaction_kernel.outputs {
            archival_mutator_set.ams_mut().add(addition_record).await;
        }
        let genesis_hash = genesis_block.hash();
        archival_mutator_set.set_sync_label(genesis_hash).await;
        archival_mutator_set.persist().await;
    }

    pub(crate) async fn new(
        data_dir: DataDirectory,
        genesis_block: Block,
        network: Network,
    ) -> Self {
        let mut archival_mutator_set = ArchivalState::initialize_mutator_set(&data_dir)
            .await
            .expect("Must be able to initialize archival mutator set");
        debug!("Got archival mutator set");

        // If archival mutator set is empty, populate it with the addition records from genesis block
        // This assumes genesis block doesn't spend anything -- which it can't so that should be OK.
        // We could have populated the archival mutator set with the genesis block UTXOs earlier in
        // the setup, but we don't have the genesis block in scope before this function, so it makes
        // sense to do it here.
        if archival_mutator_set.ams().aocl.is_empty().await {
            Self::populate_archival_mutator_set_with_genesis_block(
                &mut archival_mutator_set,
                &genesis_block,
            )
            .await;
        }

        let mut archival_block_mmr = ArchivalState::initialize_archival_block_mmr(&data_dir)
            .await
            .expect("Must be able to initialize archival block MMR");
        debug!("Got archival block MMR");

        // Add genesis block digest to archival MMR, if empty.
        if archival_block_mmr.ammr().is_empty().await {
            archival_block_mmr
                .ammr_mut()
                .append(genesis_block.hash())
                .await;
        }

        let block_index_db = ArchivalState::initialize_block_index_database(&data_dir)
            .await
            .expect("Must be able to initialize block index database");
        debug!("Got block index database");
        let genesis_block = Box::new(genesis_block);
        Self {
            data_dir,
            block_index_db,
            genesis_block,
            archival_mutator_set,
            archival_block_mmr,
            network,
        }
    }

    pub(crate) fn genesis_block(&self) -> &Block {
        &self.genesis_block
    }

    /// Return the number of files used to store the raw blocks.
    #[cfg(test)]
    pub(crate) async fn num_block_files(&self) -> u32 {
        let last_rec = self
            .block_index_db
            .get(BlockIndexKey::LastFile)
            .await
            .map(|x| x.as_last_file_record())
            .unwrap_or_default();
        last_rec.last_file + 1
    }

    /// Return the directory in which the raw blocks are stored.
    #[cfg(test)]
    pub(crate) fn block_dir_path(&self) -> PathBuf {
        self.data_dir.block_dir_path()
    }

    /// Write a block disk, without setting it as tip. The returned (key, value)
    /// pairs must be stored to the block-index database for this block to be
    /// retrievable.
    ///
    /// This function only stores the block to a file. It does not modify any
    /// database. It does, however, read from the block index database.
    ///
    /// The caller should verify that the block is not already stored, otherwise
    /// the block will be stored twice which will lead to inconsistencies.
    async fn store_block(
        self: &mut ArchivalState,
        new_block: &Block,
    ) -> Result<Vec<(BlockIndexKey, BlockIndexValue)>> {
        // abort early if mutator set update is invalid.
        if new_block.mutator_set_update().is_err() {
            bail!("invalid block: could not get mutator set update");
        }

        // Fetch last file record to find disk location to store block.
        // This record must exist in the DB already, unless this is the first block
        // stored on disk.
        let mut last_rec: LastFileRecord = self
            .block_index_db
            .get(BlockIndexKey::LastFile)
            .await
            .map(|x| x.as_last_file_record())
            .unwrap_or_default();

        // Open the file that was last used for storing a block
        let mut block_file_path = self.data_dir.block_file_path(last_rec.last_file);
        let serialized_block: Vec<u8> = bincode::serialize(new_block)?;
        let serialized_block_size: u64 = serialized_block.len() as u64;

        let mut block_file = DataDirectory::open_ensure_parent_dir_exists(&block_file_path).await?;

        // Check if we should use the last file, or we need a new one.
        if new_block_file_is_needed(&block_file, serialized_block_size).await {
            last_rec = LastFileRecord {
                last_file: last_rec.last_file + 1,
            };
            block_file_path = self.data_dir.block_file_path(last_rec.last_file);
            block_file = DataDirectory::open_ensure_parent_dir_exists(&block_file_path).await?;
        }

        debug!("Writing block to: {}", block_file_path.display());
        // Get associated file record from database, otherwise create it
        let file_record_key: BlockIndexKey = BlockIndexKey::File(last_rec.last_file);
        let file_record_value: Option<FileRecord> = self
            .block_index_db
            .get(file_record_key)
            .await
            .map(|x| x.as_file_record());
        let file_record_value: FileRecord = match file_record_value {
            Some(record) => record.add(serialized_block_size, new_block.header()),
            None => {
                assert!(
                    block_file.metadata().await.unwrap().len().is_zero(),
                    "If no file record exists, block file must be empty"
                );
                FileRecord::new(serialized_block_size, new_block.header())
            }
        };

        // Make room in file for mmapping and record where block starts
        let pos = block_file.seek(SeekFrom::End(0)).await.unwrap();
        debug!("Size of file prior to block writing: {}", pos);
        block_file
            .seek(SeekFrom::Current(serialized_block_size as i64 - 1))
            .await
            .unwrap();
        block_file.write_all(&[0]).await.unwrap();
        let file_offset: u64 = block_file
            .seek(SeekFrom::Current(-(serialized_block_size as i64)))
            .await
            .unwrap();
        debug!(
            "New file size: {} bytes",
            block_file.metadata().await.unwrap().len()
        );

        let height_record_key = BlockIndexKey::Height(new_block.header().height);
        let mut blocks_at_same_height: Vec<Digest> =
            match self.block_index_db.get(height_record_key).await {
                Some(rec) => rec.as_height_record(),
                None => vec![],
            };

        // Write to file with mmap, only map relevant part of file into memory
        // we use spawn_blocking to make the blocking mmap async-friendly.
        tokio::task::spawn_blocking(move || {
            let mmap = unsafe {
                MmapOptions::new()
                    .offset(pos)
                    .len(serialized_block_size as usize)
                    .map(&block_file)
                    .unwrap()
            };
            let mut mmap: memmap2::MmapMut = mmap.make_mut().unwrap();
            mmap.deref_mut()[..].copy_from_slice(&serialized_block);

            // Flush the memory-mapped pages to the physical disk.
            // This call will block until the data is safely persisted.
            // This ensures block data is written to the blkXX.dat file before
            // updating the DB.  Otherwise we can have situations where the DB
            // references a block that does not exist on disk.
            mmap.flush().unwrap();
        })
        .await?;

        // Update block index database with newly stored block
        let mut block_index_entries: Vec<(BlockIndexKey, BlockIndexValue)> = vec![];
        let block_record_key: BlockIndexKey = BlockIndexKey::Block(new_block.hash());
        let num_additions: u64 = new_block
            .mutator_set_update()
            .expect("MS update for new block must exist")
            .additions
            .len()
            .try_into()
            .expect("Num addition records cannot exceed u64::MAX");
        let block_record_value: BlockIndexValue = BlockIndexValue::Block(Box::new(BlockRecord {
            block_header: *new_block.header(),
            file_location: BlockFileLocation {
                file_index: last_rec.last_file,
                offset: file_offset,
                block_length: serialized_block_size as usize,
            },
            min_aocl_index: new_block
                .mutator_set_accumulator_after()
                .expect("MS update for new block must exist")
                .aocl
                .num_leafs()
                - num_additions,
            num_additions,
            block_hash_witness: HeaderToBlockHashWitness::from(new_block),
        }));

        block_index_entries.push((file_record_key, BlockIndexValue::File(file_record_value)));
        block_index_entries.push((block_record_key, block_record_value));

        block_index_entries.push((BlockIndexKey::LastFile, BlockIndexValue::LastFile(last_rec)));
        blocks_at_same_height.push(new_block.hash());
        block_index_entries.push((
            height_record_key,
            BlockIndexValue::Height(blocks_at_same_height),
        ));

        Ok(block_index_entries)
    }

    async fn write_block_internal(&mut self, block: &Block, is_canonical_tip: bool) -> Result<()> {
        let block_is_new = self.get_block_header(block.hash()).await.is_none();
        let mut block_index_entries = if block_is_new {
            self.store_block(block).await?
        } else {
            warn!(
                "Attempted to store block but block was already stored.\nBlock digest: {:x}",
                block.hash()
            );
            vec![]
        };

        // Mark block as tip, conditionally
        if is_canonical_tip {
            block_index_entries.push((
                BlockIndexKey::BlockTipDigest,
                BlockIndexValue::BlockTipDigest(block.hash()),
            ));
        }

        let mut batch = WriteBatchAsync::new();
        for (k, v) in block_index_entries {
            batch.op_write(k, v);
        }

        self.block_index_db.batch_write(batch).await;

        Ok(())
    }

    /// Write a newly found block to database and to disk, without setting it as
    /// tip.
    ///
    /// If block was already written to database, then this is a nop as the old
    /// database entries and block stored on disk are considered valid.
    pub(crate) async fn write_block_not_tip(&mut self, block: &Block) -> Result<()> {
        self.write_block_internal(block, false).await
    }

    /// Write a newly found block to database and to disk, and set it as tip.
    ///
    /// If block was already written to database, then it is only marked as
    /// tip, and no write to disk occurs. Instead, the old block database entry
    /// is assumed to be valid, and so is the block stored on disk.
    pub(crate) async fn write_block_as_tip(&mut self, new_block: &Block) -> Result<()> {
        self.write_block_internal(new_block, true).await
    }

    /// Sets a block as tip for the archival block MMR.
    ///
    /// This method handles reorganizations, but all predecessors of this block
    /// must be known and stored in the block index database for it to work.
    pub(crate) async fn append_to_archival_block_mmr(&mut self, new_block: &Block) {
        #[cfg(test)]
        {
            // In tests you're allowed to set a genesis block with a height
            // different than zero. In such cases, this part of the archival state
            // update cannot work. So we skip it.
            if !self.genesis_block.header().height.is_genesis() {
                return;
            }
        }

        // If the new block is the genesis block, special case and exit early
        if new_block.header().height.is_genesis() {
            let genesis_block_hash = self.genesis_block().hash();
            assert_eq!(genesis_block_hash, new_block.hash(), "Wrong genesis block.");
            if let Some(leaf) = self.archival_block_mmr.ammr().try_get_leaf(0).await {
                assert_eq!(leaf, new_block.hash(), "Corrupt block MMR.");
            } else {
                self.archival_block_mmr
                    .ammr_mut()
                    .append(new_block.hash())
                    .await;
            }
            self.archival_block_mmr
                .ammr_mut()
                .prune_to_num_leafs(1)
                .await;
            return;
        }

        // Roll back to length of parent then add new digest.
        let num_leafs_prior_to_this_block = new_block.header().height.into();
        self.archival_block_mmr
            .ammr_mut()
            .prune_to_num_leafs(num_leafs_prior_to_this_block)
            .await;

        let latest_leaf = self
            .archival_block_mmr
            .ammr()
            .get_latest_leaf()
            .await
            .expect("block MMR must always have at least one leaf");
        if new_block.header().prev_block_digest != latest_leaf {
            let (backwards, _, forwards) = self
                .find_path(latest_leaf, new_block.header().prev_block_digest)
                .await;
            for _ in backwards {
                self.archival_block_mmr
                    .ammr_mut()
                    .remove_last_leaf_async()
                    .await;
            }
            for digest in forwards {
                self.archival_block_mmr.ammr_mut().append(digest).await;
            }
        }

        assert_eq!(
            new_block.header().prev_block_digest,
            self.archival_block_mmr.ammr()
                .get_latest_leaf()
                .await
                .expect("block MMR must always have at least one leaf"),
            "Archival block-MMR must be in a consistent state. Try deleting this database to have it rebuilt."
        );
        self.archival_block_mmr
            .ammr_mut()
            .append(new_block.hash())
            .await;
    }

    async fn get_block_from_block_record(&self, block_record: BlockRecord) -> Result<Block> {
        let block_file_path: PathBuf = self
            .data_dir
            .block_file_path(block_record.file_location.file_index);

        tokio::task::spawn_blocking(move || {
            let block_file = std::fs::File::open(&block_file_path)?;

            // 1. Get file metadata to find its actual size on disk.
            let metadata = block_file.metadata()?;
            let file_size = metadata.len();

            // 2. validate that the requested slice is within the file's bounds.
            // See: https://github.com/Neptune-Crypto/neptune-core/issues/471
            let requested_end = block_record.file_location.offset
                .saturating_add(block_record.file_location.block_length as u64);

            if requested_end > file_size {
                bail!(
                    "Data corruption: Attempted to read beyond end of file '{}'. (Size: {}, Requested End: {})",
                    block_file_path.display(), file_size, requested_end
                );
            }

            // 3. The slice is valid, so we can safely memory-map it.
            let mmap = unsafe {
                MmapOptions::new()
                    .offset(block_record.file_location.offset)
                    .len(block_record.file_location.block_length)
                    .map(&block_file)?
            };

            // 4. deserialize directly from the validated mmap slice.
            bincode::deserialize(&mmap).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to deserialize block from file {}. Data may be corrupt or incompatible\
                     with current version of neptune-core. Error: {}",
                    block_file_path.display(), e
                )
            })
        })
        .await?
    }

    async fn tip_block_record(&self) -> Option<BlockRecord> {
        let tip_digest = self.block_index_db.get(BlockIndexKey::BlockTipDigest).await;
        let tip_digest: Digest = match tip_digest {
            Some(digest) => digest.as_tip_digest(),
            None => return None,
        };

        self.get_block_record(tip_digest).await
    }

    /// Return the latest block that was stored to disk. If no block has been stored to disk, i.e.
    /// if tip is genesis, then `None` is returned
    async fn get_tip_from_disk(&self) -> Result<Option<Block>> {
        let tip_block_record = self.tip_block_record().await;
        let Some(tip_block_record) = tip_block_record else {
            return Ok(None);
        };

        let block: Block = self.get_block_from_block_record(tip_block_record).await?;

        Ok(Some(block))
    }

    /// Return the block digest of the block in which an AOCL leaf with
    /// specified index is contained.
    pub(crate) async fn canonical_block_digest_of_aocl_index(
        &self,
        aocl_leaf_index: u64,
    ) -> Result<Option<Digest>> {
        // Is AOCL leaf contained in genesis block? Special-case this, as
        // genesis block does not have a block record.
        let genesis_tx: TransactionKernelProxy =
            self.genesis_block.body().transaction_kernel.clone().into();
        if aocl_leaf_index < genesis_tx.outputs.len().try_into().unwrap() {
            return Ok(Some(self.genesis_block.hash()));
        }

        let (mut record, mut block_hash) = match self
            .block_index_db
            .get(BlockIndexKey::BlockTipDigest)
            .await
            .map(|record| record.as_tip_digest())
        {
            Some(tip_digest) => {
                let record = self.get_block_record(tip_digest).await.unwrap();
                (record, tip_digest)
            }
            None => {
                // Tip is genesis block. But genesis block was checked. So this
                // leaf index is not known.
                return Ok(None);
            }
        };

        // Is AOCL leaf index after current tip?
        if aocl_leaf_index > record.max_aocl_index() {
            return Ok(None);
        }

        let mut min_block_height = BlockHeight::genesis().next();
        let mut max_block_height = record.block_header.height;

        // Do binary search to find block
        loop {
            if aocl_leaf_index < record.min_aocl_index {
                // Look below current height
                max_block_height = record
                    .block_header
                    .height
                    .previous()
                    .expect("Genesis-block should be special-cased earlier in function.");
            } else if aocl_leaf_index > record.max_aocl_index() {
                // Look above current height
                min_block_height = record.block_header.height.next();
            } else {
                return Ok(Some(block_hash));
            };

            let new_guess_height = BlockHeight::arithmetic_mean(min_block_height, max_block_height);
            block_hash = self
                .archival_block_mmr
                .ammr()
                .get_leaf_async(new_guess_height.into())
                .await;
            record = self.get_block_record(block_hash).await.unwrap();
        }
    }

    /// searches max `max_search_depth` from tip for a matching transaction
    /// input.
    ///
    /// If `max_search_depth` is set to `None`, then all blocks are searched
    /// until a match is found. A `max_search_depth` of `Some(0)` will only
    /// consider the tip.
    pub(crate) async fn find_canonical_block_with_output(
        &self,
        output: AdditionRecord,
        max_search_depth: Option<u64>,
    ) -> Option<Block> {
        let mut block = self.get_tip().await;
        let mut search_depth = 0;

        loop {
            if block.body().transaction_kernel.outputs.contains(&output) {
                break Some(block);
            }

            if max_search_depth.is_some_and(|max| max <= search_depth) {
                return None;
            }

            block = self
                .get_block(block.header().prev_block_digest)
                .await
                .ok()??;

            search_depth += 1;
        }
    }

    /// searches max `max_search_depth` from tip for a matching transaction
    /// input.
    ///
    /// If `max_search_depth` is set to `None`, then all blocks are searched
    /// until a match is found. A `max_search_depth` of `Some(0)` will only
    /// consider the tip.
    pub(crate) async fn find_canonical_block_with_input(
        &self,
        input: AbsoluteIndexSet,
        max_search_depth: Option<u64>,
    ) -> Option<Block> {
        let mut block = self.get_tip().await;
        let mut search_depth = 0;

        loop {
            if block
                .body()
                .transaction_kernel
                .inputs
                .iter()
                .any(|rr| rr.absolute_indices == input)
            {
                break Some(block);
            }

            if max_search_depth.is_some_and(|max| max <= search_depth) {
                return None;
            }

            block = self
                .get_block(block.header().prev_block_digest)
                .await
                .ok()??;

            search_depth += 1;
        }
    }

    /// Return latest block from database, or genesis block if no other block
    /// is known.
    pub(crate) async fn get_tip(&self) -> Block {
        let lookup_res_info: Option<Block> = self
            .get_tip_from_disk()
            .await
            .expect("Failed to read block from disk");

        match lookup_res_info {
            None => *self.genesis_block.clone(),
            Some(block) => block,
        }
    }

    /// Return parent of tip block. Returns `None` iff tip is genesis block.
    pub(crate) async fn get_tip_parent(&self) -> Option<Block> {
        // Tip can be genesis block in two cases: If no block tip key is known,
        // or if one is known and it matches with the genesis block.
        let tip_digest = self
            .block_index_db
            .get(BlockIndexKey::BlockTipDigest)
            .await?
            .as_tip_digest();
        if tip_digest == self.genesis_block().hash() {
            return None;
        }

        let tip_header = self
            .get_block_record(tip_digest)
            .await
            .map(|record| record.block_header)
            .expect("tip must have block record");

        let parent = self
            .get_block(tip_header.prev_block_digest)
            .await
            .expect("Fetching indicated block must succeed");

        Some(parent.expect("Indicated block must exist"))
    }

    /// Get the header of the block identified by digest.
    ///
    /// Returns `None` if no block with this digest is known. Returns the
    /// genesis header if the block digest is that of the genesis block.
    pub(crate) async fn get_block_header(&self, block_digest: Digest) -> Option<BlockHeader> {
        let mut ret = self
            .block_index_db
            .get(BlockIndexKey::Block(block_digest))
            .await
            .map(|x| x.as_block_record().block_header);

        // If no block was found, check if digest is genesis digest
        if ret.is_none() && block_digest == self.genesis_block.hash() {
            ret = Some(*self.genesis_block.header());
        }

        ret
    }

    /// Returns the block header with a witness to the block hash if that block
    /// is known.
    ///
    /// Returns `None` if the block is not known *or* if the block is the
    /// genesis block, as the genesis block does not need a witness for its
    /// hash.
    pub(crate) async fn block_header_with_hash_witness(
        &self,
        block_digest: Digest,
    ) -> Option<BlockHeaderWithBlockHashWitness> {
        self.block_index_db
            .get(BlockIndexKey::Block(block_digest))
            .await
            .map(|x| {
                let record = x.as_block_record();
                BlockHeaderWithBlockHashWitness::new(record.block_header, record.block_hash_witness)
            })
    }

    /// Get the block record from the block digest, if it is stored.
    ///
    /// Note that the genesis block is not stored, and so does not have a block
    /// record.
    async fn get_block_record(&self, block_digest: Digest) -> Option<BlockRecord> {
        self.block_index_db
            .get(BlockIndexKey::Block(block_digest))
            .await
            .map(|x| x.as_block_record())
    }

    /// Return the block as identified by its digest.
    ///
    /// Return:
    ///  - `Ok(Some(block))` in case of success.
    ///  - `Ok(None)` if the block does not live in archival state.
    ///  - `Err(_)` if there was a problem reading from archival state.
    pub(crate) async fn get_block(&self, block_digest: Digest) -> Result<Option<Block>> {
        let maybe_record = self.get_block_record(block_digest).await;
        let Some(record) = maybe_record else {
            let maybe_genesis_block =
                (self.genesis_block.hash() == block_digest).then_some(*self.genesis_block.clone());
            return Ok(maybe_genesis_block);
        };

        // Fetch block from disk
        let block = self.get_block_from_block_record(record).await?;

        Ok(Some(block))
    }

    /// Returns a [`HashMap`] of [`AdditionRecord`] to [`Option`] of AOCL leaf
    /// index (`u64`) for all outputs in a given block. If the block is not
    /// canonical, the indices are all `None`, and conversely, if the block is
    /// canonical then the indices point into the current mutator set AOCL.
    /// If the block does not live in the archival state, return `None`.
    ///
    /// # Panics
    ///
    ///  - If the block is not canonical, was stored, and reading it from disk
    ///    fails.
    ///  - If the block is not canonical, was stored, and is invalid.
    pub(crate) async fn get_addition_record_indices_for_block(
        &self,
        block_digest: Digest,
    ) -> Option<HashMap<AdditionRecord, Option<u64>>> {
        let maybe_block_record = self.get_block_record(block_digest).await;

        let Some(block_record) = maybe_block_record else {
            // If genesis, get the addition records from there
            if block_digest == self.genesis_block().hash() {
                return Some(
                    self.genesis_block()
                        .body()
                        .transaction_kernel()
                        .outputs
                        .iter()
                        .enumerate()
                        .map(|(i, ar)| (*ar, Some(i as u64)))
                        .collect::<HashMap<_, _>>(),
                );
            }

            // No block record and not genesis block => block not known
            return None;
        };

        // In the common case, the block is canonical, and then it is faster to
        // read the addition records from the archival mutator set.
        let block_is_canonical = self.block_belongs_to_canonical_chain(block_digest).await;
        if block_is_canonical {
            let aocl_leaf_indices = block_record.min_aocl_index..=block_record.max_aocl_index();
            let addition_records = self
                .archival_mutator_set
                .ams()
                .aocl
                .get_leaf_range_inclusive_async(aocl_leaf_indices.clone())
                .await;
            Some(
                addition_records
                    .into_iter()
                    .map(|digest| AdditionRecord {
                        canonical_commitment: digest,
                    })
                    .zip(aocl_leaf_indices.into_iter().map(Some))
                    .collect::<HashMap<_, _>>(),
            )
        }
        // If the block is not canonical, we get the addition records from the
        // block itself. The AOC leaf indices (the values in the returned hash
        // map) will be set to `None` because AOCL leaf indices are only defined
        // for confirmed outputs.
        else {
            let block = self
                .get_block_from_block_record(block_record)
                .await
                .unwrap_or_else(|e| {
                    panic!("could not read block from database: {e}");
                });
            let transaction_addition_records = block.body().transaction_kernel.outputs.clone();
            let guesser_addition_records =
                block.guesser_fee_addition_records().unwrap_or_else(|e| {
                    panic!("stored block is invalid: {e}");
                });
            Some(
                transaction_addition_records
                    .into_iter()
                    .chain(guesser_addition_records)
                    .map(|ar| (ar, None))
                    .collect::<HashMap<_, _>>(),
            )
        }
    }

    /// Return the digests of the known blocks at a specific height
    pub(crate) async fn block_height_to_block_digests(
        &self,
        block_height: BlockHeight,
    ) -> Vec<Digest> {
        if block_height.is_genesis() {
            vec![self.genesis_block().hash()]
        } else {
            self.block_index_db
                .get(BlockIndexKey::Height(block_height))
                .await
                .map(|x| x.as_height_record())
                .unwrap_or_else(Vec::new)
        }
    }

    /// Return a boolean indicating if block belongs to most canonical chain.
    ///
    /// Returns false if either the block is not known, or if it's known but
    /// has been orphaned.
    pub(crate) async fn block_belongs_to_canonical_chain(&self, block_digest: Digest) -> bool {
        let Some(block_header) = self.get_block_header(block_digest).await else {
            return false;
        };

        let block_height: u64 = block_header.height.into();

        self.archival_block_mmr
            .ammr()
            .try_get_leaf(block_height)
            .await
            .is_some_and(|canonical_digest_at_this_height| {
                canonical_digest_at_this_height == block_digest
            })
    }

    /// Return a list of digests of the ancestors to the requested digest. Does not include the input
    /// digest. If no ancestors can be found, returns the empty list. The count is the maximum length
    /// of the returned list. E.g. if the input digest corresponds to height 2 and count is 5, the
    /// returned list will contain the digests of block 1 and block 0 (the genesis block).
    /// The input block must correspond to a known block but it can be the genesis block in which case
    /// the empty list will be returned.
    pub(crate) async fn get_ancestor_block_digests(
        &self,
        block_digest: Digest,
        mut count: usize,
    ) -> Vec<Digest> {
        let input_block_header = self.get_block_header(block_digest).await.unwrap();
        let mut parent_digest = input_block_header.prev_block_digest;
        let mut ret = vec![];
        while let Some(parent) = self.get_block_header(parent_digest).await {
            if count == 0 {
                break;
            }
            ret.push(parent_digest);
            parent_digest = parent.prev_block_digest;
            count -= 1;
        }

        ret
    }

    /// Returns the old mutator set matching the provided digest as well as the
    /// mutator set update required to go from the old state to that in the tip.
    ///
    /// # Warning
    ///
    /// This can be a very expensive function to run if it's called with a high
    /// max search depth, as it loads all the blocks in the search path into
    /// memory. A max search depth of 0 means that only the tip is checked.
    async fn mutator_set_to_tip_internal(
        &mut self,
        old_ms_digest: Digest,
        old_aocl_num_leafs: Option<u64>,
        max_search_depth: usize,
    ) -> Option<(MutatorSetAccumulator, MutatorSetUpdate)> {
        let mut search_depth = 0;
        let mut block_mutations = vec![];

        let mut haystack = self.get_tip().await;
        let mut parent = self.get_tip_parent().await;
        let old_msa = loop {
            let haystack_msa = haystack
                .mutator_set_accumulator_after()
                .expect("Block from state must have mutator set after");
            if haystack_msa.hash() == old_ms_digest {
                break haystack_msa;
            }

            search_depth += 1;

            // Notice that comparing the whole mutator set accumulator and not
            // just its hash allows us to do early return here. Parent == None
            // indicates that we've gone all the way back to genesis, with no
            // match.
            if old_aocl_num_leafs
                .is_some_and(|old_num_leafs| old_num_leafs > haystack_msa.aocl.num_leafs())
                || search_depth > max_search_depth
                || parent.is_none()
            {
                return None;
            }

            let MutatorSetUpdate {
                removals,
                additions,
            } = haystack
                .mutator_set_update()
                .expect("Block from state must have mutator set update");
            block_mutations.push((additions, removals));

            haystack = parent.unwrap();
            parent = self
                .get_block(haystack.header().prev_block_digest)
                .await
                .expect("Must succeed in reading block");
        };

        // The removal records collected above were valid for each block but
        // are in the general case not valid for the `mutator_set` which was
        // given as input to this function. In order to find the right removal
        // records, we, temporarily, roll back the state of the archival mutator
        // set. This allows us to read out MMR-authentication paths from a
        // previous state of the mutator set. It's crucial that these changes
        // are not persisted, as that would leave the archival mutator set in a
        // state incompatible with the tip.
        self.archival_mutator_set.persist().await;
        for (additions, removals) in &block_mutations {
            for rr in removals.iter().rev() {
                self.archival_mutator_set.ams_mut().revert_remove(rr).await;
            }

            for ar in additions.iter().rev() {
                self.archival_mutator_set.ams_mut().revert_add(ar).await;
            }
        }

        let (mut addition_records, mut removal_records): (
            Vec<Vec<AdditionRecord>>,
            Vec<Vec<RemovalRecord>>,
        ) = block_mutations.clone().into_iter().unzip();

        addition_records.reverse();
        removal_records.reverse();

        let addition_records = addition_records.concat();
        let mut removal_records = removal_records.concat();

        let swbf_length = self.archival_mutator_set.ams().chunks.len().await;
        for rr in &mut removal_records {
            let mut removals = vec![];
            for (chkidx, (mp, chunk)) in rr
                .target_chunks
                .chunk_indices_and_membership_proofs_and_leafs_iter_mut()
            {
                if swbf_length <= *chkidx {
                    removals.push(*chkidx);
                } else {
                    *mp = self
                        .archival_mutator_set
                        .ams()
                        .swbf_inactive
                        .prove_membership_async(*chkidx)
                        .await;
                    *chunk = self.archival_mutator_set.ams().chunks.get(*chkidx).await;
                }
            }

            for remove in removals {
                rr.target_chunks.retain(|(x, _)| *x != remove);
            }
        }

        self.archival_mutator_set.drop_unpersisted().await;

        Some((
            old_msa,
            MutatorSetUpdate::new(removal_records, addition_records),
        ))
    }

    /// Returns the old mutator set matching the provided digest as well as the
    /// mutator set update required to go from the old state to that in the tip.
    ///
    /// # Warning
    ///
    /// This can be a very expensive function to run if it's called with a high
    /// max search depth, as it loads all the blocks in the search path into
    /// memory. A max search depth of 0 means that only the tip is checked.
    pub(crate) async fn old_mutator_set_and_mutator_set_update_to_tip(
        &mut self,
        old_mutator_set_digest: Digest,
        max_search_depth: usize,
    ) -> Option<(MutatorSetAccumulator, MutatorSetUpdate)> {
        self.mutator_set_to_tip_internal(old_mutator_set_digest, None, max_search_depth)
            .await
    }

    /// Returns Some(MutatorSetUpdate) if a path could be found from tip to a
    /// block with the indicated mutator set.
    ///
    /// # Warning
    ///
    /// This can be a very expensive function to run if it's called with a high
    /// max search depth, as it loads all the blocks in the search path into
    /// memory. A max search depth of 0 means that only the tip is checked.
    pub(crate) async fn get_mutator_set_update_to_tip(
        &mut self,
        mutator_set: &MutatorSetAccumulator,
        max_search_depth: usize,
    ) -> Option<MutatorSetUpdate> {
        self.mutator_set_to_tip_internal(
            mutator_set.hash(),
            Some(mutator_set.aocl.num_leafs()),
            max_search_depth,
        )
        .await
        .map(|(_, msa)| msa)
    }

    /// Update the archival mutator set with a new block.
    ///
    /// Assumes the block in question has already been stored to the database
    /// (or else it is the genesis block). This function handles rollback of the
    /// mutator set if needed but requires that all blocks that are rolled back
    /// are present in the database. The input block is considered chain tip.
    /// All blocks stored in the database are assumed to be valid. The given
    /// `new_block` is also assumed to be valid. This function will return an
    /// error if the new block does not have a mutator set update.
    ///
    /// # Panics
    ///
    ///  - If the database does not contain rolled back blocks.
    ///  - If there is no path to the new block.
    pub async fn update_mutator_set(&mut self, new_block: &Block) -> Result<()> {
        #[cfg(test)]
        {
            // In tests you're allowed to set a genesis block with a height
            // different than zero. In such cases, this part of the archival state
            // update cannot work. So we skip it.
            if !self.genesis_block.header().height.is_genesis() {
                return Ok(());
            }
        }

        // If new block is genesis block, special case and exit early.
        if new_block.header().height.is_genesis() {
            let genesis_hash = self.genesis_block().hash();
            assert_eq!(genesis_hash, new_block.hash(), "Wrong genesis block.");

            self.archival_mutator_set.ams_mut().clear().await;
            Self::populate_archival_mutator_set_with_genesis_block(
                &mut self.archival_mutator_set,
                new_block,
            )
            .await;

            return Ok(());
        }

        // cannot get the mutator set update from new block, so abort early
        if new_block.mutator_set_update().is_err() {
            bail!("invalid block: could not get mutator set update");
        }

        let (forwards, backwards) = {
            // Get the block digest that the mutator set was most recently synced to
            let ms_block_sync_digest = self.archival_mutator_set.get_sync_label();

            // Find path from mutator set sync digest to new block. Optimize for the common case,
            // where the new block is the child block of block that the mutator set is synced to.
            let (backwards, _luca, forwards) =
                if ms_block_sync_digest == new_block.header().prev_block_digest {
                    // Trivial path
                    (vec![], ms_block_sync_digest, vec![])
                } else {
                    // Non-trivial path from current mutator set sync digest to new block
                    self.find_path(ms_block_sync_digest, new_block.header().prev_block_digest)
                        .await
                };
            let forwards = [forwards, vec![new_block.hash()]].concat();

            (forwards, backwards)
        };

        for digest in backwards {
            // Roll back mutator set
            let rollback_block = self
                .get_block(digest)
                .await
                .expect("Fetching block must succeed")
                .unwrap();

            debug!(
                "Updating mutator set: rolling back block with height {}",
                rollback_block.header().height
            );

            let MutatorSetUpdate {
                additions,
                removals,
            } = rollback_block
                .mutator_set_update()
                .expect("Block from state must have mutator set update");

            // Roll back all removal records contained in block
            for removal_record in &removals {
                self.archival_mutator_set
                    .ams_mut()
                    .revert_remove(removal_record)
                    .await;
            }

            // Roll back all addition records contained in block
            for addition_record in additions.iter().rev() {
                assert!(
                    self.archival_mutator_set
                        .ams_mut()
                        .add_is_reversible(addition_record)
                        .await,
                    "Addition record must be in sync with block being rolled back."
                );
                self.archival_mutator_set
                    .ams_mut()
                    .revert_add(addition_record)
                    .await;
            }
        }

        for digest in forwards {
            // Add block to mutator set
            let apply_forward_block = if digest == new_block.hash() {
                // Avoid reading from disk if block to be applied is the block
                // with which this function is invoked.
                new_block.to_owned()
            } else {
                self.get_block(digest)
                    .await
                    .expect("Fetching block must succeed")
                    .unwrap()
            };
            debug!(
                "Updating mutator set: adding block with height {}.  Mined: {}",
                apply_forward_block.header().height,
                apply_forward_block
                    .kernel
                    .header
                    .timestamp
                    .standard_format()
            );

            let MutatorSetUpdate {
                mut additions,
                mut removals,
            } = apply_forward_block
                .mutator_set_update()
                .expect("Block from state must have mutator set update");
            additions.reverse();
            removals.reverse();

            let mut removals_mutable = removals.iter_mut().collect::<Vec<_>>();

            // Add items, thus adding the output UTXOs to the mutator set
            while let Some(addition_record) = additions.pop() {
                // Batch-update all removal records to keep them valid after next addition
                RemovalRecord::batch_update_from_addition(
                    &mut removals_mutable,
                    &self.archival_mutator_set.ams().accumulator().await,
                );

                // Add the element to the mutator set
                self.archival_mutator_set
                    .ams_mut()
                    .add(&addition_record)
                    .await;
            }

            // Remove items, thus removing the input UTXOs from the mutator set
            self.archival_mutator_set
                .ams_mut()
                .batch_remove(removals)
                .await;
        }

        // Sanity check that archival mutator set has been updated consistently with the new block
        debug!("sanity check: was AMS updated consistently with new block?");
        assert_eq!(
            new_block
                .mutator_set_accumulator_after().unwrap()
                .hash(),
            self.archival_mutator_set.ams().hash().await,
            "Calculated archival mutator set commitment must match that from newly added block. Block Digest: {:?}", new_block.hash()
        );

        // Persist updated mutator set to disk, with sync label
        self.archival_mutator_set
            .set_sync_label(new_block.hash())
            .await;
        self.archival_mutator_set.persist().await;

        Ok(())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(super) mod tests {

    use itertools::Itertools;
    use macro_rules_attr::apply;
    use rand::random;
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::RngCore;
    use rand::SeedableRng;
    use tracing_test::traced_test;

    use super::*;
    use crate::application::config::cli_args;
    use crate::application::config::data_directory::DataDirectory;
    use crate::application::config::network::Network;
    use crate::application::database::storage::storage_vec::traits::*;
    use crate::application::loops::mine_loop::tests::make_coinbase_transaction_from_state;
    use crate::application::triton_vm_job_queue::TritonVmJobPriority;
    use crate::application::triton_vm_job_queue::TritonVmJobQueue;
    use crate::protocol::consensus::block::block_transaction::BlockTransaction;
    use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
    use crate::protocol::consensus::transaction::lock_script::LockScript;
    use crate::protocol::consensus::transaction::utxo::Utxo;
    use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
    use crate::protocol::proof_abstractions::timestamp::Timestamp;
    use crate::state::archival_state::ArchivalState;
    use crate::state::transaction::tx_creation_config::TxCreationConfig;
    use crate::state::transaction::tx_proving_capability::TxProvingCapability;
    use crate::state::wallet::address::KeyType;
    use crate::state::wallet::expected_utxo::UtxoNotifier;
    use crate::state::wallet::transaction_output::TxOutput;
    use crate::state::wallet::transaction_output::TxOutputList;
    use crate::state::wallet::wallet_entropy::WalletEntropy;
    use crate::tests::shared::archival::add_block_to_archival_state;
    use crate::tests::shared::archival::mock_genesis_archival_state;
    use crate::tests::shared::blocks::invalid_block_with_transaction;
    use crate::tests::shared::blocks::make_mock_block;
    use crate::tests::shared::files::unit_test_data_directory;
    use crate::tests::shared::globalstate::mock_genesis_global_state;
    use crate::tests::shared::mock_genesis_wallet_state;
    use crate::tests::shared_tokio_runtime;

    pub(super) async fn make_test_archival_state(network: Network) -> ArchivalState {
        let data_dir: DataDirectory = unit_test_data_directory(network).unwrap();

        let genesis_block = Block::genesis(network);
        ArchivalState::new(data_dir, genesis_block, network).await
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn initialize_archival_state_test() -> Result<()> {
        // Ensure that the archival state can be initialized without overflowing the stack
        let seed: [u8; 32] = rand::rng().random();
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let network = Network::RegTest;

        let mut archival_state0 = make_test_archival_state(network).await;

        let b = Block::genesis(network);
        let some_wallet_secret = WalletEntropy::new_random();
        let some_key = some_wallet_secret.nth_generation_spending_key_for_tests(0);

        let (block_1, _) = make_mock_block(&b, None, some_key, rng.random(), network).await;
        add_block_to_archival_state(&mut archival_state0, block_1.clone())
            .await
            .unwrap();
        let _c = archival_state0
            .get_block(block_1.hash())
            .await
            .unwrap()
            .unwrap();

        Ok(())
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn archival_state_init_test() -> Result<()> {
        // Verify that archival mutator set is populated with outputs from genesis block
        let network = Network::RegTest;
        let archival_state = make_test_archival_state(network).await;

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
    async fn archival_state_restore_test() -> Result<()> {
        let mut rng = rand::rng();
        // Verify that a restored archival mutator set is populated with the right `sync_label`
        let network = Network::Main;
        let mut archival_state = make_test_archival_state(network).await;
        let cli_args = cli_args::Args::default_with_network(network);
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
        )
        .await;
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
        let cli_args = cli_args::Args::default_with_network(network);
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
        let (block1, _) =
            make_mock_block(&genesis_block, None, alice_key, rng.random(), network).await;

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
    async fn update_mutator_set_rollback_ms_block_sync_test() -> Result<()> {
        let mut rng = rand::rng();
        let network = Network::Main;
        let (mut archival_state, _peer_db_lock, _data_dir) =
            mock_genesis_archival_state(network).await;
        let own_wallet = WalletEntropy::new_random();
        let own_key = own_wallet.nth_generation_spending_key_for_tests(0);

        // 1. Create new block 1 and store it to the DB
        let (mock_block_1a, _) = make_mock_block(
            &archival_state.genesis_block,
            None,
            own_key,
            rng.random(),
            network,
        )
        .await;
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
        )
        .await;
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
        let cli_args = cli_args::Args::default_with_network(network);
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
        let cli_args = cli_args::Args::default_with_network(network);
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
                make_mock_block(&genesis_block, None, alice_key, rng.random(), network).await;
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
        let network = Network::Main;
        let cli_args = cli_args::Args::default_with_network(network);
        let premine_rec_ws =
            mock_genesis_wallet_state(WalletEntropy::devnet_wallet(), &cli_args).await;
        let premine_rec_spending_key = premine_rec_ws.wallet_entropy.nth_generation_spending_key(0);
        let mut premine_rec = mock_genesis_global_state(
            3,
            premine_rec_ws.wallet_entropy,
            cli_args::Args {
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
            .next_unused_spending_key(KeyType::Symmetric)
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

        let (cbtx, _composer_expected_utxos) = make_coinbase_transaction_from_state(
            &premine_rec
                .global_state_lock
                .lock_guard()
                .await
                .chain
                .light_state()
                .clone(),
            &premine_rec,
            in_seven_months,
            TritonVmJobPriority::Normal.into(),
        )
        .await
        .unwrap();

        let block_tx = BlockTransaction::merge(
            cbtx.into(),
            tx_to_alice_and_bob.into(),
            Default::default(),
            TritonVmJobQueue::get_instance(),
            TritonVmJobPriority::default().into(),
            consensus_rule_set_0,
        )
        .await
        .unwrap();
        println!("Generated block transaction");

        let block_1 = Block::compose(
            &genesis_block,
            block_tx,
            in_seven_months,
            TritonVmJobQueue::get_instance(),
            TritonVmJobPriority::default().into(),
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
        assert_eq!(
            NativeCurrencyAmount::coins(10),
            alice
                .lock_guard()
                .await
                .get_wallet_status_for_tip()
                .await
                .available_confirmed(in_seven_months)
        );
        assert_eq!(
            NativeCurrencyAmount::coins(5),
            bob.lock_guard()
                .await
                .get_wallet_status_for_tip()
                .await
                .available_confirmed(in_seven_months)
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
                .available_confirmed(in_seven_months)
        );

        let after_cb_timelock_expiration = block_1.header().timestamp + Timestamp::months(37);
        assert_eq!(
            block_subsidy + NativeCurrencyAmount::coins(20 - 10 - 5 - 1),
            premine_rec
                .lock_guard()
                .await
                .get_wallet_status_for_tip()
                .await
                .available_confirmed(after_cb_timelock_expiration)
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

        // Make block_2 with tx that contains:
        // - 4 inputs: 2 from Alice and 2 from Bob
        // - 7 outputs: 2 from Alice to premine rec, 3 from Bob to premine rec, and 2 coinbases to premine rec
        let (cbtx2, expected_composer_utxos2) = make_coinbase_transaction_from_state(
            &premine_rec
                .global_state_lock
                .lock_guard()
                .await
                .chain
                .light_state()
                .clone(),
            &premine_rec,
            in_seven_months,
            TritonVmJobPriority::Normal.into(),
        )
        .await
        .unwrap();
        let block_tx2 = BlockTransaction::merge(
            cbtx2.into(),
            tx_from_alice.into(),
            Default::default(),
            TritonVmJobQueue::get_instance(),
            TritonVmJobPriority::default().into(),
            consensus_rule_set_1,
        )
        .await
        .unwrap();
        let block_tx2 = BlockTransaction::merge(
            block_tx2.into(),
            tx_from_bob.into(),
            Default::default(),
            TritonVmJobQueue::get_instance(),
            TritonVmJobPriority::default().into(),
            consensus_rule_set_1,
        )
        .await
        .unwrap();
        let block_2 = Block::compose(
            &block_1,
            block_tx2,
            in_seven_months + network.minimum_block_time(),
            TritonVmJobQueue::get_instance(),
            TritonVmJobPriority::default().into(),
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
            .available_confirmed(in_seven_months)
            .is_zero());
        assert!(bob
            .lock_guard()
            .await
            .get_wallet_status_for_tip()
            .await
            .available_confirmed(in_seven_months)
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
            let mut archival_state: ArchivalState = make_test_archival_state(network).await;

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
            let (mock_block_1, _) =
                make_mock_block(&genesis, None, own_key, rng.random(), network).await;
            add_block_to_archival_state(&mut archival_state, mock_block_1.clone())
                .await
                .unwrap();

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
                make_mock_block(&mock_block_1, None, own_key, rng.random(), network).await;
            add_block_to_archival_state(&mut archival_state, mock_block_2.clone())
                .await
                .unwrap();
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
        let mut archival_state = make_test_archival_state(network).await;

        let genesis = *archival_state.genesis_block.clone();
        let own_wallet = WalletEntropy::new_random();
        let own_key = own_wallet.nth_generation_spending_key_for_tests(0);
        let (mock_block_1, _) =
            make_mock_block(&genesis.clone(), None, own_key, rng.random(), network).await;

        // Lookup a block in an empty database, expect None to be returned
        assert!(
            archival_state
                .get_block(mock_block_1.hash())
                .await?
                .is_none(),
            "Must return none when not stored to DB"
        );

        add_block_to_archival_state(&mut archival_state, mock_block_1.clone()).await?;
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
            make_mock_block(&mock_block_1.clone(), None, own_key, rng.random(), network).await;
        add_block_to_archival_state(&mut archival_state, mock_block_2.clone()).await?;
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
            let (new_block, _) =
                make_mock_block(&last_block, None, own_key, rng.random(), network).await;
            add_block_to_archival_state(&mut archival_state, new_block.clone()).await?;
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
        let mut archival_state = make_test_archival_state(network).await;

        // Digest::default ==> no block found
        assert!(archival_state
            .get_addition_record_indices_for_block(Digest::default())
            .await
            .is_none());

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
            make_mock_block(&genesis_block.clone(), None, own_key, rng.random(), network).await;

        // apply block 1a
        archival_state.write_block_as_tip(&block_1a).await.unwrap();
        archival_state.append_to_archival_block_mmr(&block_1a).await;
        archival_state.update_mutator_set(&block_1a).await.unwrap();

        // mine block 1b
        let (block_1b, _) =
            make_mock_block(&genesis_block.clone(), None, own_key, rng.random(), network).await;

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
    async fn ms_update_to_tip_genesis() {
        let network = Network::Main;
        let mut archival_state = make_test_archival_state(network).await;
        let current_msa = archival_state
            .archival_mutator_set
            .ams()
            .accumulator()
            .await;

        for i in 0..10 {
            assert!(archival_state
                .get_mutator_set_update_to_tip(&current_msa, i)
                .await
                .unwrap()
                .is_empty());
        }
    }

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

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn ms_update_to_tip_five_blocks() {
        let network = Network::Main;
        let wallet = WalletEntropy::new_random();
        let mut rng = rand::rng();
        let mut archival_state = make_test_archival_state(network).await;
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
            .await
            .0;
            add_block_to_archival_state(&mut archival_state, next_block.clone())
                .await
                .unwrap();
            current_block = next_block;
        }

        let current_msa = current_block.mutator_set_accumulator_after().unwrap();
        for search_depth in 0..10 {
            println!("{search_depth}");
            if search_depth < 5 {
                assert!(archival_state
                    .get_mutator_set_update_to_tip(&genesis_msa, search_depth)
                    .await
                    .is_none());
            } else {
                positive_prop_ms_update_to_tip(&genesis_msa, &mut archival_state, search_depth)
                    .await;
            }
        }

        // Walking the opposite way returns None, and does not crash.
        let mut genesis_archival_state = make_test_archival_state(network).await;
        for i in 0..10 {
            assert!(genesis_archival_state
                .get_mutator_set_update_to_tip(&current_msa, i)
                .await
                .is_none());
        }
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn find_canonical_block_with_aocl_index_five_blocks() {
        let network = Network::Main;
        let wallet = WalletEntropy::new_random();
        let mut rng = rand::rng();
        let mut archival_state = make_test_archival_state(network).await;
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
            )
            .await;
            add_block_to_archival_state(&mut archival_state, next_block.clone())
                .await
                .unwrap();
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
    async fn find_canonical_block_with_aocl_index_genesis() {
        for network in [
            Network::Main,
            Network::TestnetMock,
            Network::RegTest,
            Network::Testnet(0),
            Network::Testnet(1),
        ] {
            let archival_state = make_test_archival_state(network).await;
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
            assert!(archival_state
                .canonical_block_digest_of_aocl_index(num_premine_outputs)
                .await
                .unwrap()
                .is_none());
            assert!(archival_state
                .canonical_block_digest_of_aocl_index(num_premine_outputs + 1)
                .await
                .unwrap()
                .is_none());
        }
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn find_canonical_block_with_output_genesis_block_test() {
        let network = Network::Main;
        let archival_state = make_test_archival_state(network).await;
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

    #[traced_test]
    #[test_strategy::proptest(async = "tokio")]
    async fn find_canonical_block_with_input_genesis_block_test(
        #[strategy(crate::tests::shared::strategies::absindset())]
        random_index_set: AbsoluteIndexSet,
    ) {
        let network = Network::Main;
        let archival_state = make_test_archival_state(network).await;

        assert!(archival_state
            .find_canonical_block_with_input(random_index_set, None)
            .await
            .is_none());
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn ms_update_to_tip_fork_depth_1() {
        let mut rng = rand::rng();
        let network = Network::Main;
        let wallet = WalletEntropy::new_random();
        let mut archival_state = make_test_archival_state(network).await;
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
        .await
        .0;
        let block_1b = make_mock_block(
            &genesis_block,
            None,
            compose_beneficiary,
            rng.random(),
            network,
        )
        .await
        .0;
        let block_1a_msa = &block_1a.mutator_set_accumulator_after().unwrap();
        let block_1b_msa = &block_1b.mutator_set_accumulator_after().unwrap();

        // 1a is tip
        let search_depth = 1;
        add_block_to_archival_state(&mut archival_state, block_1a.clone())
            .await
            .unwrap();
        positive_prop_ms_update_to_tip(genesis_msa, &mut archival_state, search_depth).await;
        positive_prop_ms_update_to_tip(block_1a_msa, &mut archival_state, search_depth).await;
        assert!(archival_state
            .get_mutator_set_update_to_tip(block_1b_msa, 1)
            .await
            .is_none());

        // 1b is tip
        add_block_to_archival_state(&mut archival_state, block_1b.clone())
            .await
            .unwrap();
        positive_prop_ms_update_to_tip(genesis_msa, &mut archival_state, search_depth).await;
        assert!(archival_state
            .get_mutator_set_update_to_tip(block_1a_msa, 1)
            .await
            .is_none());
        positive_prop_ms_update_to_tip(block_1b_msa, &mut archival_state, search_depth).await;
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn ms_update_to_tip_fork_depth_2() {
        let mut rng = rand::rng();
        let network = Network::Main;
        let wallet = WalletEntropy::new_random();
        let mut archival_state = make_test_archival_state(network).await;
        let genesis_block = Block::genesis(network);
        let genesis_msa = &genesis_block.mutator_set_accumulator_after().unwrap();
        let cb_beneficiary = wallet.nth_generation_spending_key_for_tests(0);

        let block_1a = make_mock_block(&genesis_block, None, cb_beneficiary, rng.random(), network)
            .await
            .0;
        let block_2a = make_mock_block(&block_1a, None, cb_beneficiary, rng.random(), network)
            .await
            .0;
        let block_1b = make_mock_block(&genesis_block, None, cb_beneficiary, rng.random(), network)
            .await
            .0;
        let block_2b = make_mock_block(&block_1b, None, cb_beneficiary, rng.random(), network)
            .await
            .0;
        let block_1a_msa = &block_1a.mutator_set_accumulator_after().unwrap();
        let block_2a_msa = &block_2a.mutator_set_accumulator_after().unwrap();
        let block_1b_msa = &block_1b.mutator_set_accumulator_after().unwrap();
        let block_2b_msa = &block_2b.mutator_set_accumulator_after().unwrap();

        // 1a is tip
        let search_depth = 10;
        add_block_to_archival_state(&mut archival_state, block_1a.clone())
            .await
            .unwrap();
        assert!(archival_state
            .get_mutator_set_update_to_tip(block_2a_msa, search_depth)
            .await
            .is_none());
        assert!(archival_state
            .get_mutator_set_update_to_tip(block_2b_msa, search_depth)
            .await
            .is_none());

        // 1b is tip
        add_block_to_archival_state(&mut archival_state, block_1b.clone())
            .await
            .unwrap();
        assert!(archival_state
            .get_mutator_set_update_to_tip(block_2a_msa, search_depth)
            .await
            .is_none());
        assert!(archival_state
            .get_mutator_set_update_to_tip(block_2b_msa, search_depth)
            .await
            .is_none());

        // 2a is tip
        add_block_to_archival_state(&mut archival_state, block_2a.clone())
            .await
            .unwrap();
        positive_prop_ms_update_to_tip(genesis_msa, &mut archival_state, search_depth).await;
        positive_prop_ms_update_to_tip(block_1a_msa, &mut archival_state, search_depth).await;
        positive_prop_ms_update_to_tip(block_2a_msa, &mut archival_state, search_depth).await;
        assert!(archival_state
            .get_mutator_set_update_to_tip(block_1b_msa, search_depth)
            .await
            .is_none());
        assert!(archival_state
            .get_mutator_set_update_to_tip(block_2b_msa, search_depth)
            .await
            .is_none());

        // 2b is tip
        add_block_to_archival_state(&mut archival_state, block_2b.clone())
            .await
            .unwrap();
        positive_prop_ms_update_to_tip(genesis_msa, &mut archival_state, search_depth).await;
        positive_prop_ms_update_to_tip(block_1b_msa, &mut archival_state, search_depth).await;
        positive_prop_ms_update_to_tip(block_2b_msa, &mut archival_state, search_depth).await;
        assert!(archival_state
            .get_mutator_set_update_to_tip(block_1a_msa, search_depth)
            .await
            .is_none());
        assert!(archival_state
            .get_mutator_set_update_to_tip(block_2a_msa, search_depth)
            .await
            .is_none());
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn find_path_simple_test() -> Result<()> {
        let mut rng = rand::rng();
        let network = Network::Main;
        let mut archival_state = make_test_archival_state(network).await;
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
            make_mock_block(&genesis.clone(), None, key, rng.random(), network).await;
        add_block_to_archival_state(&mut archival_state, mock_block_1_a.clone()).await?;

        let (mock_block_1_b, _) =
            make_mock_block(&genesis.clone(), None, key, rng.random(), network).await;
        add_block_to_archival_state(&mut archival_state, mock_block_1_b.clone()).await?;

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
            assert_eq!(backwards_expected, backwards, "\n\nbackwards digests must match expected value. Got:\n {backwards:?}\n\n, Expected from helper function:\n {backwards_expected:?}\n");

            let mut forwards_expected = archival_state
                .get_ancestor_block_digests(stop.to_owned(), forwards.len())
                .await;
            forwards_expected.reverse();
            assert_eq!(forwards_expected, forwards, "\n\nforwards digests must match expected value. Got:\n {forwards:?}\n\n, Expected from helper function:\n{forwards_expected:?}\n");
        }

        let network = Network::Main;
        let mut archival_state = make_test_archival_state(network).await;

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
        let (block1, _) = make_mock_block(&genesis.clone(), None, key, rng.random(), network).await;
        add_block_to_archival_state(&mut archival_state, block1.clone()).await?;
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
            make_mock_block(&block1.clone(), None, key, rng.random(), network).await;
        add_block_to_archival_state(&mut archival_state, mock_block_2_a.clone()).await?;
        let (mock_block_3_a, _) =
            make_mock_block(&mock_block_2_a.clone(), None, key, rng.random(), network).await;
        add_block_to_archival_state(&mut archival_state, mock_block_3_a.clone()).await?;
        let (mock_block_4_a, _) =
            make_mock_block(&mock_block_3_a.clone(), None, key, rng.random(), network).await;
        add_block_to_archival_state(&mut archival_state, mock_block_4_a.clone()).await?;
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
            make_mock_block(&block1.clone(), None, key, rng.random(), network).await;
        add_block_to_archival_state(&mut archival_state, mock_block_2_b.clone()).await?;
        let (mock_block_3_b, _) =
            make_mock_block(&mock_block_2_b.clone(), None, key, rng.random(), network).await;
        add_block_to_archival_state(&mut archival_state, mock_block_3_b.clone()).await?;
        let (mock_block_4_b, _) =
            make_mock_block(&mock_block_3_b.clone(), None, key, rng.random(), network).await;
        add_block_to_archival_state(&mut archival_state, mock_block_4_b.clone()).await?;
        let (mock_block_5_b, _) =
            make_mock_block(&mock_block_4_b.clone(), None, key, rng.random(), network).await;
        add_block_to_archival_state(&mut archival_state, mock_block_5_b.clone()).await?;
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
            make_mock_block(&mock_block_2_a.clone(), None, key, rng.random(), network).await;
        add_block_to_archival_state(&mut archival_state, mock_block_3_c.clone()).await?;
        let (mock_block_4_c, _) =
            make_mock_block(&mock_block_3_c.clone(), None, key, rng.random(), network).await;
        add_block_to_archival_state(&mut archival_state, mock_block_4_c.clone()).await?;
        let (mock_block_5_c, _) =
            make_mock_block(&mock_block_4_c.clone(), None, key, rng.random(), network).await;
        add_block_to_archival_state(&mut archival_state, mock_block_5_c.clone()).await?;
        let (mock_block_6_c, _) =
            make_mock_block(&mock_block_5_c.clone(), None, key, rng.random(), network).await;
        add_block_to_archival_state(&mut archival_state, mock_block_6_c.clone()).await?;
        let (mock_block_7_c, _) =
            make_mock_block(&mock_block_6_c.clone(), None, key, rng.random(), network).await;
        add_block_to_archival_state(&mut archival_state, mock_block_7_c.clone()).await?;
        let (mock_block_8_c, _) =
            make_mock_block(&mock_block_7_c.clone(), None, key, rng.random(), network).await;
        add_block_to_archival_state(&mut archival_state, mock_block_8_c.clone()).await?;
        let (mock_block_5_a, _) =
            make_mock_block(&mock_block_4_a.clone(), None, key, rng.random(), network).await;
        add_block_to_archival_state(&mut archival_state, mock_block_5_a.clone()).await?;
        let (mock_block_3_d, _) =
            make_mock_block(&mock_block_2_a.clone(), None, key, rng.random(), network).await;
        add_block_to_archival_state(&mut archival_state, mock_block_3_d.clone()).await?;

        let (mock_block_4_e, _) =
            make_mock_block(&mock_block_3_d.clone(), None, key, rng.random(), network).await;
        add_block_to_archival_state(&mut archival_state, mock_block_4_e.clone()).await?;
        let (mock_block_5_e, _) =
            make_mock_block(&mock_block_4_e.clone(), None, key, rng.random(), network).await;
        add_block_to_archival_state(&mut archival_state, mock_block_5_e.clone()).await?;

        let (mock_block_4_d, _) =
            make_mock_block(&mock_block_3_d.clone(), None, key, rng.random(), network).await;
        add_block_to_archival_state(&mut archival_state, mock_block_4_d.clone()).await?;
        let (mock_block_5_d, _) =
            make_mock_block(&mock_block_4_d.clone(), None, key, rng.random(), network).await;
        add_block_to_archival_state(&mut archival_state, mock_block_5_d.clone()).await?;

        // This is the most canonical block in the known set
        let (mock_block_6_d, _) =
            make_mock_block(&mock_block_5_d.clone(), None, key, rng.random(), network).await;
        add_block_to_archival_state(&mut archival_state, mock_block_6_d.clone()).await?;

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
            make_mock_block(&mock_block_5_b.clone(), None, key, rng.random(), network).await;
        add_block_to_archival_state(&mut archival_state, mock_block_6_b.clone()).await?;
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
    async fn block_belongs_to_canonical_chain_doesnt_crash_on_unknown_block() {
        let archival_state = make_test_archival_state(Network::Main).await;
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
        let archival_state = make_test_archival_state(Network::Main).await;

        let genesis = archival_state.genesis_block.clone();
        archival_state
            .get_ancestor_block_digests(genesis.kernel.header.prev_block_digest, 10)
            .await;
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn digest_of_ancestors_test() {
        let mut rng = rand::rng();
        let network = Network::Main;
        let mut archival_state = make_test_archival_state(network).await;
        let genesis = *archival_state.genesis_block.clone();
        let wallet = WalletEntropy::new_random();
        let key = wallet.nth_generation_spending_key_for_tests(0);

        assert!(archival_state
            .get_ancestor_block_digests(genesis.hash(), 10)
            .await
            .is_empty());
        assert!(archival_state
            .get_ancestor_block_digests(genesis.hash(), 1)
            .await
            .is_empty());
        assert!(archival_state
            .get_ancestor_block_digests(genesis.hash(), 0)
            .await
            .is_empty());

        // Insert blocks and verify that the same result is returned
        let (mock_block_1, _) =
            make_mock_block(&genesis.clone(), None, key, rng.random(), network).await;
        add_block_to_archival_state(&mut archival_state, mock_block_1.clone())
            .await
            .unwrap();
        let (mock_block_2, _) =
            make_mock_block(&mock_block_1.clone(), None, key, rng.random(), network).await;
        add_block_to_archival_state(&mut archival_state, mock_block_2.clone())
            .await
            .unwrap();
        let (mock_block_3, _) =
            make_mock_block(&mock_block_2.clone(), None, key, rng.random(), network).await;
        add_block_to_archival_state(&mut archival_state, mock_block_3.clone())
            .await
            .unwrap();
        let (mock_block_4, _) =
            make_mock_block(&mock_block_3.clone(), None, key, rng.random(), network).await;
        add_block_to_archival_state(&mut archival_state, mock_block_4.clone())
            .await
            .unwrap();

        assert!(archival_state
            .get_ancestor_block_digests(genesis.hash(), 10)
            .await
            .is_empty());
        assert!(archival_state
            .get_ancestor_block_digests(genesis.hash(), 1)
            .await
            .is_empty());
        assert!(archival_state
            .get_ancestor_block_digests(genesis.hash(), 0)
            .await
            .is_empty());

        // Check that ancestors of block 1 and 2 return the right values
        let ancestors_of_1 = archival_state
            .get_ancestor_block_digests(mock_block_1.hash(), 10)
            .await;
        assert_eq!(1, ancestors_of_1.len());
        assert_eq!(genesis.hash(), ancestors_of_1[0]);
        assert!(archival_state
            .get_ancestor_block_digests(mock_block_1.hash(), 0)
            .await
            .is_empty());

        let ancestors_of_2 = archival_state
            .get_ancestor_block_digests(mock_block_2.hash(), 10)
            .await;
        assert_eq!(2, ancestors_of_2.len());
        assert_eq!(mock_block_1.hash(), ancestors_of_2[0]);
        assert_eq!(genesis.hash(), ancestors_of_2[1]);
        assert!(archival_state
            .get_ancestor_block_digests(mock_block_2.hash(), 0)
            .await
            .is_empty());

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
        assert!(archival_state
            .get_ancestor_block_digests(mock_block_4.hash(), 0)
            .await
            .is_empty());
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn write_block_db_test() -> Result<()> {
        let network = Network::Main;
        let mut rng = rand::rng();
        let mut archival_state = make_test_archival_state(network).await;
        let genesis = *archival_state.genesis_block.clone();
        let wallet = WalletEntropy::new_random();
        let key = wallet.nth_generation_spending_key_for_tests(0);

        let (mock_block_1, _) =
            make_mock_block(&genesis.clone(), None, key, rng.random(), network).await;
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
            make_mock_block(&mock_block_1.clone(), None, key, rng.random(), network).await;
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
    async fn can_initialize_mutator_set_database() {
        let args: cli_args::Args = cli_args::Args::default();
        let data_dir = DataDirectory::get(args.data_dir.clone(), args.network).unwrap();
        println!("data_dir for MS initialization test: {data_dir}");
        let _rams = ArchivalState::initialize_mutator_set(&data_dir)
            .await
            .unwrap();
    }

    mod block_hash_witness {
        use super::*;
        use crate::tests::shared::blocks::invalid_empty_block;

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn stored_block_hash_witness_agrees_with_block_hash() {
            let network = Network::Main;
            let mut archival_state = make_test_archival_state(network).await;
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
    }
}
