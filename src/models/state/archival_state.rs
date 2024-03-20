use crate::prelude::twenty_first;

use crate::database::storage::storage_schema::traits::*;
use anyhow::Result;
use memmap2::MmapOptions;
use num_traits::Zero;
use std::ops::DerefMut;
use std::path::PathBuf;
use tasm_lib::twenty_first::util_types::emojihash_trait::Emojihash;
use tokio::io::AsyncSeekExt;
use tokio::io::AsyncWriteExt;
use tokio::io::SeekFrom;
use tracing::{debug, warn};
use twenty_first::amount::u32s::U32s;
use twenty_first::shared_math::digest::Digest;

use super::shared::new_block_file_is_needed;
use crate::config_models::data_directory::DataDirectory;
use crate::database::{create_db_if_missing, NeptuneLevelDb, WriteBatchAsync};
use crate::models::blockchain::block::block_header::{BlockHeader, PROOF_OF_WORK_COUNT_U32_SIZE};
use crate::models::blockchain::block::{block_height::BlockHeight, Block};
use crate::models::database::{
    BlockFileLocation, BlockIndexKey, BlockIndexValue, BlockRecord, FileRecord, LastFileRecord,
};
use crate::util_types::mmr::traits::*;
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::mutator_set_trait::*;
use crate::util_types::mutator_set::removal_record::RemovalRecord;
use crate::util_types::mutator_set::rusty_archival_mutator_set::RustyArchivalMutatorSet;

pub const BLOCK_INDEX_DB_NAME: &str = "block_index";
pub const MUTATOR_SET_DIRECTORY_NAME: &str = "mutator_set";

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
    pub block_index_db: NeptuneLevelDb<BlockIndexKey, BlockIndexValue>,

    // The genesis block is stored on the heap, as we would otherwise get stack overflows whenever we instantiate
    // this object in a spawned worker thread.
    genesis_block: Box<Block>,

    // The archival mutator set is persisted to one database that also records a sync label,
    // which corresponds to the hash of the block to which the mutator set is synced.
    pub archival_mutator_set: RustyArchivalMutatorSet,
}

// The only reason we have this `Debug` implementation is that it's required
// for some tracing/logging functionalities.
impl core::fmt::Debug for ArchivalState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArchivalState")
            .field("data_dir", &self.data_dir)
            .field("block_index_db", &self.block_index_db)
            .field("genesis_block", &self.genesis_block)
            .finish()
    }
}

impl ArchivalState {
    /// Create databases for block persistence
    pub async fn initialize_block_index_database(
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
    pub async fn initialize_mutator_set(
        data_dir: &DataDirectory,
    ) -> Result<RustyArchivalMutatorSet> {
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
                    If you suspect the database may be corrupted, consider renaming the directory {} or removing it altogether.",
                    ms_db_dir_path.display()
                );
            }
        };

        let mut archival_set = RustyArchivalMutatorSet::connect(db).await;
        archival_set.restore_or_new().await;

        Ok(archival_set)
    }

    /// Find the path connecting two blocks. Every path involves
    /// going down some number of steps and then going up some number
    /// of steps. So this function returns two lists: the list of
    /// down steps and the list of up steps.
    pub async fn find_path(
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

    pub async fn new(
        data_dir: DataDirectory,
        block_index_db: NeptuneLevelDb<BlockIndexKey, BlockIndexValue>,
        mut archival_mutator_set: RustyArchivalMutatorSet,
    ) -> Self {
        let genesis_block = Box::new(Block::genesis_block().await);

        // If archival mutator set is empty, populate it with the addition records from genesis block
        // This assumes genesis block doesn't spend anything -- which it can't so that should be OK.
        // We could have populated the archival mutator set with the genesis block UTXOs earlier in
        // the setup, but we don't have the genesis block in scope before this function, so it makes
        // sense to do it here.
        if archival_mutator_set.ams().kernel.aocl.is_empty().await {
            for addition_record in genesis_block.kernel.body.transaction.kernel.outputs.iter() {
                archival_mutator_set.ams_mut().add(addition_record).await;
            }
            let genesis_hash = genesis_block.hash();
            archival_mutator_set.set_sync_label(genesis_hash).await;
            archival_mutator_set.persist().await;
        }

        Self {
            data_dir,
            block_index_db,
            genesis_block,
            archival_mutator_set,
        }
    }

    /// Write a newly found block to database and to disk.
    pub async fn write_block(
        &mut self,
        new_block: &Block,
        current_max_pow_family: Option<U32s<PROOF_OF_WORK_COUNT_U32_SIZE>>,
    ) -> Result<()> {
        // Fetch last file record to find disk location to store block.
        // This record must exist in the DB already, unless this is the first block
        // stored on disk.
        let mut last_rec: LastFileRecord = match self
            .block_index_db
            .get(BlockIndexKey::LastFile)
            .await
            .map(|x| x.as_last_file_record())
        {
            Some(rec) => rec,
            None => LastFileRecord::default(),
        };

        // Open the file that was last used for storing a block
        let mut block_file_path = self.data_dir.block_file_path(last_rec.last_file);
        let serialized_block: Vec<u8> = bincode::serialize(new_block)?;
        let serialized_block_size: u64 = serialized_block.len() as u64;

        // file operations are async.

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
            .get(file_record_key.clone())
            .await
            .map(|x| x.as_file_record());
        let file_record_value: FileRecord = match file_record_value {
            Some(record) => record.add(serialized_block_size, &new_block.kernel.header),
            None => {
                assert!(
                    block_file.metadata().await.unwrap().len().is_zero(),
                    "If no file record exists, block file must be empty"
                );
                FileRecord::new(serialized_block_size, &new_block.kernel.header)
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

        let height_record_key = BlockIndexKey::Height(new_block.kernel.header.height);
        let mut blocks_at_same_height: Vec<Digest> =
            match self.block_index_db.get(height_record_key.clone()).await {
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
        })
        .await?;

        // Update block index database with newly stored block
        let mut block_index_entries: Vec<(BlockIndexKey, BlockIndexValue)> = vec![];
        let block_record_key: BlockIndexKey = BlockIndexKey::Block(new_block.hash());
        let block_record_value: BlockIndexValue = BlockIndexValue::Block(Box::new(BlockRecord {
            block_header: new_block.kernel.header.clone(),
            file_location: BlockFileLocation {
                file_index: last_rec.last_file,
                offset: file_offset,
                block_length: serialized_block_size as usize,
            },
        }));

        block_index_entries.push((file_record_key, BlockIndexValue::File(file_record_value)));
        block_index_entries.push((block_record_key, block_record_value));

        block_index_entries.push((BlockIndexKey::LastFile, BlockIndexValue::LastFile(last_rec)));
        blocks_at_same_height.push(new_block.hash());
        block_index_entries.push((
            height_record_key,
            BlockIndexValue::Height(blocks_at_same_height),
        ));

        // Mark block as tip if its PoW family is larger than current most canonical
        if current_max_pow_family.is_none()
            || current_max_pow_family.unwrap() < new_block.kernel.header.proof_of_work_family
        {
            block_index_entries.push((
                BlockIndexKey::BlockTipDigest,
                BlockIndexValue::BlockTipDigest(new_block.hash()),
            ));
        }

        let mut batch = WriteBatchAsync::new();
        for (k, v) in block_index_entries.into_iter() {
            batch.op_write(k, v);
        }

        self.block_index_db.batch_write(batch).await;

        Ok(())
    }

    async fn get_block_from_block_record(&self, block_record: BlockRecord) -> Result<Block> {
        // Get path of file for block
        let block_file_path: PathBuf = self
            .data_dir
            .block_file_path(block_record.file_location.file_index);

        // Open file as read-only
        let block_file: tokio::fs::File = tokio::fs::OpenOptions::new()
            .read(true)
            .open(block_file_path)
            .await
            .unwrap();

        // Read the file into memory, set the offset and length indicated in the block record
        // to avoid using more memory than needed
        // we use spawn_blocking to make the blocking mmap async-friendly.
        tokio::task::spawn_blocking(move || {
            let mmap = unsafe {
                MmapOptions::new()
                    .offset(block_record.file_location.offset)
                    .len(block_record.file_location.block_length)
                    .map(&block_file)?
            };
            let block: Block = bincode::deserialize(&mmap).unwrap();
            Ok(block)
        })
        .await?
    }

    /// return the latest block
    async fn get_latest_block_from_disk(&self) -> Result<Option<Block>> {
        let tip_digest = self.block_index_db.get(BlockIndexKey::BlockTipDigest).await;
        let tip_digest: Digest = match tip_digest {
            Some(digest) => digest.as_tip_digest(),
            None => return Ok(None),
        };

        let tip_block_record: BlockRecord = self
            .block_index_db
            .get(BlockIndexKey::Block(tip_digest))
            .await
            .unwrap()
            .as_block_record();

        let block: Block = self.get_block_from_block_record(tip_block_record).await?;

        Ok(Some(block))
    }

    /// Return latest block from database, or genesis block if no other block
    /// is known.
    pub async fn get_latest_block(&self) -> Block {
        let lookup_res_info: Option<Block> = self
            .get_latest_block_from_disk()
            .await
            .expect("Failed to read block from disk");

        match lookup_res_info {
            None => *self.genesis_block.clone(),
            Some(block) => block,
        }
    }

    pub async fn get_block_header(&self, block_digest: Digest) -> Option<BlockHeader> {
        let mut ret = self
            .block_index_db
            .get(BlockIndexKey::Block(block_digest))
            .await
            .map(|x| x.as_block_record().block_header);

        // If no block was found, check if digest is genesis digest
        if ret.is_none() && block_digest == self.genesis_block.hash() {
            ret = Some(self.genesis_block.kernel.header.clone());
        }

        ret
    }

    // Return the block with a given block digest, iff it's available in state somewhere
    pub async fn get_block(&self, block_digest: Digest) -> Result<Option<Block>> {
        let maybe_record: Option<BlockRecord> = self
            .block_index_db
            .get(BlockIndexKey::Block(block_digest))
            .await
            .map(|x| x.as_block_record());
        let record: BlockRecord = match maybe_record {
            Some(rec) => rec,
            None => {
                if self.genesis_block.hash() == block_digest {
                    return Ok(Some(*self.genesis_block.clone()));
                } else {
                    return Ok(None);
                }
            }
        };

        // Fetch block from disk
        let block = self.get_block_from_block_record(record).await?;

        Ok(Some(block))
    }

    /// Return the number of blocks with the given height
    async fn block_height_to_block_count(&self, height: BlockHeight) -> usize {
        match self
            .block_index_db
            .get(BlockIndexKey::Height(height))
            .await
            .map(|x| x.as_height_record())
        {
            Some(rec) => rec.len(),
            None => 0,
        }
    }

    /// Return the headers of the known blocks at a specific height
    pub async fn block_height_to_block_headers(
        &self,
        block_height: BlockHeight,
    ) -> Vec<BlockHeader> {
        let block_digests = self.block_height_to_block_digests(block_height).await;
        let mut block_headers = vec![];
        for block_digest in block_digests.into_iter() {
            let block = self
                .block_index_db
                .get(BlockIndexKey::Block(block_digest))
                .await
                .map(|x| x.as_block_record())
                .unwrap();
            block_headers.push(block.block_header);
        }

        block_headers
    }

    /// Return the digests of the known blocks at a specific height
    pub async fn block_height_to_block_digests(&self, block_height: BlockHeight) -> Vec<Digest> {
        self.block_index_db
            .get(BlockIndexKey::Height(block_height))
            .await
            .map(|x| x.as_height_record())
            .unwrap_or_else(Vec::new)
    }

    pub async fn get_children_block_headers(
        &self,
        parent_block_digest: Digest,
    ) -> Vec<BlockHeader> {
        // get header
        let parent_block_header = match self.get_block_header(parent_block_digest).await {
            Some(header) => header,
            None => {
                warn!("Querying for children of unknown parent block digest.");
                return vec![];
            }
        };
        // Get all blocks with height n + 1
        let blocks_from_childrens_generation: Vec<BlockHeader> = self
            .block_height_to_block_headers(parent_block_header.height.next())
            .await;

        // Filter out those that don't have the right parent
        blocks_from_childrens_generation
            .into_iter()
            .filter(|child_block_header| {
                child_block_header.prev_block_digest == parent_block_digest
            })
            .collect()
    }

    /// Get all immediate children of the given block, no grandchildren or higher-order
    /// descendants.
    pub async fn get_children_block_digests(&self, parent_block_digest: Digest) -> Vec<Digest> {
        // get header
        let parent_block_header = match self.get_block_header(parent_block_digest).await {
            Some(header) => header,
            None => {
                warn!("Querying for children of unknown parent block digest.");
                return vec![];
            }
        };
        // Get all blocks with height n + 1
        let children_digests = self
            .block_height_to_block_digests(parent_block_header.height.next())
            .await;
        let mut downstream_children = vec![];
        for child_digest in children_digests {
            let child_header =
                self
                .get_block_header(child_digest)
                .await
                .unwrap_or_else(
                    || panic!(
                        "Cannot get block header from digest, even though digest was fetched from height. Digest: {}/{}",
                        child_digest,
                        child_digest.emojihash()
                    )
                );
            if child_header.prev_block_digest == parent_block_digest {
                downstream_children.push(child_digest);
            }
        }

        downstream_children
    }

    /// Return a boolean indicating if block belongs to most canonical chain
    pub async fn block_belongs_to_canonical_chain(
        &self,
        block_digest: Digest,
        tip_digest: Digest,
    ) -> bool {
        let block_header = self
            .get_block_header(block_digest)
            .await
            .unwrap_or_else(|| {
                panic!(
                    "Could not get block header by digest: {}/{}",
                    block_digest,
                    block_digest.emojihash()
                )
            });
        let tip_header = self.get_block_header(tip_digest).await.unwrap_or_else(|| {
            panic!(
                "Could not get block header by digest: {}/{}",
                tip_digest,
                tip_digest.emojihash()
            )
        });

        // If block is tip or parent to tip, then block belongs to canonical chain
        if tip_digest == block_digest || tip_header.prev_block_digest == block_digest {
            return true;
        }

        // If block is genesis block, it belongs to the canonical chain
        if block_digest == self.genesis_block.hash() {
            return true;
        }

        // If tip header height is less than this block, or the same but with a different hash,
        // then it cannot belong to the canonical chain. Note that we already checked if digest
        // was that of tip, so it's sufficient to check if tip height is less than or equal to
        // block height.
        if tip_header.height <= block_header.height {
            return false;
        }

        // If only one block at this height is known and block height is less than or equal
        // to that of the tip, then this block must belong to the canonical chain
        if self.block_height_to_block_count(block_header.height).await == 1
            && tip_header.height >= block_header.height
        {
            return true;
        }

        // Find the path from block to tip and check if this involves stepping back
        let (backwards, _, _) = self.find_path(block_digest, tip_digest).await;

        backwards.is_empty()
    }

    /// Return a list of digests of the ancestors to the requested digest. Does not include the input
    /// digest. If no ancestors can be found, returns the empty list. The count is the maximum length
    /// of the returned list. E.g. if the input digest corresponds to height 2 and count is 5, the
    /// returned list will contain the digests of block 1 and block 0 (the genesis block).
    /// The input block must correspond to a known block but it can be the genesis block in which case
    /// the empty list will be returned.
    pub async fn get_ancestor_block_digests(
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

    /// Update the mutator set with a block after this block has been stored to the database.
    /// Handles rollback of the mutator set if needed but requires that all blocks that are
    /// rolled back are present in the DB. The input block is considered chain tip. All blocks
    /// stored in the database are assumed to be valid.
    pub async fn update_mutator_set(&mut self, new_block: &Block) -> Result<()> {
        let (forwards, backwards) = {
            // Get the block digest that the mutator set was most recently synced to
            let ms_block_sync_digest = self.archival_mutator_set.get_sync_label().await;

            // Find path from mutator set sync digest to new block. Optimize for the common case,
            // where the new block is the child block of block that the mutator set is synced to.
            let (backwards, _luca, forwards) =
                if ms_block_sync_digest == new_block.kernel.header.prev_block_digest {
                    // Trivial path
                    (vec![], ms_block_sync_digest, vec![])
                } else {
                    // Non-trivial path from current mutator set sync digest to new block
                    self.find_path(
                        ms_block_sync_digest,
                        new_block.kernel.header.prev_block_digest,
                    )
                    .await
                };
            let forwards = [forwards, vec![new_block.hash()]].concat();

            (forwards, backwards)
        };

        for digest in backwards {
            // Roll back mutator set
            let roll_back_block = self
                .get_block(digest)
                .await
                .expect("Fetching block must succeed")
                .unwrap();

            debug!(
                "Updating mutator set: rolling back block with height {}",
                roll_back_block.kernel.header.height
            );

            // Roll back all addition records contained in block
            for addition_record in roll_back_block
                .kernel
                .body
                .transaction
                .kernel
                .outputs
                .iter()
                .rev()
            {
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

            // Roll back all removal records contained in block
            for removal_record in roll_back_block.kernel.body.transaction.kernel.inputs.iter() {
                self.archival_mutator_set
                    .ams_mut()
                    .revert_remove(removal_record)
                    .await;
            }
        }

        for digest in forwards {
            // Add block to mutator set
            let apply_forward_block = if digest == new_block.hash() {
                new_block.to_owned()
            } else {
                self.get_block(digest)
                    .await
                    .expect("Fetching block must succeed")
                    .unwrap()
            };
            debug!(
                "Updating mutator set: adding block with height {}.  Mined: {}",
                apply_forward_block.kernel.header.height,
                crate::utc_timestamp_to_localtime(
                    apply_forward_block.kernel.header.timestamp.value()
                )
                .to_string()
            );

            let mut addition_records: Vec<AdditionRecord> = apply_forward_block
                .kernel
                .body
                .transaction
                .kernel
                .outputs
                .clone();
            addition_records.reverse();
            let mut removal_records = apply_forward_block
                .kernel
                .body
                .transaction
                .kernel
                .inputs
                .clone();
            removal_records.reverse();
            let mut removal_records: Vec<&mut RemovalRecord> =
                removal_records.iter_mut().collect::<Vec<_>>();

            // Add items, thus adding the output UTXOs to the mutator set
            while let Some(addition_record) = addition_records.pop() {
                // Batch-update all removal records to keep them valid after next addition
                RemovalRecord::batch_update_from_addition(
                    &mut removal_records,
                    &mut self.archival_mutator_set.ams_mut().kernel,
                )
                .await;

                // Add the element to the mutator set
                self.archival_mutator_set
                    .ams_mut()
                    .add(&addition_record)
                    .await;
            }

            // Remove items, thus removing the input UTXOs from the mutator set
            while let Some(removal_record) = removal_records.pop() {
                // Batch-update all removal records to keep them valid after next removal
                RemovalRecord::batch_update_from_remove(&mut removal_records, removal_record);

                // Remove the element from the mutator set
                self.archival_mutator_set
                    .ams_mut()
                    .remove(removal_record)
                    .await;
            }
        }

        // Sanity check that archival mutator set has been updated consistently with the new block
        debug!("sanity check: was AMS updated consistently with new block?");
        assert_eq!(
            new_block
                .kernel.body
                .mutator_set_accumulator
                .hash().await,
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
mod archival_state_tests {

    use std::time::Duration;

    use super::*;

    use crate::config_models::network::Network;
    use crate::database::storage::storage_vec::traits::*;
    use crate::models::blockchain::transaction::utxo::LockScript;
    use crate::models::blockchain::transaction::utxo::Utxo;
    use crate::models::blockchain::transaction::PublicAnnouncement;
    use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
    use crate::models::consensus::mast_hash::MastHash;
    use crate::models::state::archival_state::ArchivalState;
    use crate::models::state::global_state_tests::create_transaction_with_timestamp;
    use crate::models::state::wallet::utxo_notification_pool::UtxoNotifier;
    use crate::models::state::wallet::WalletSecret;
    use crate::models::state::UtxoReceiverData;
    use crate::tests::shared::{
        add_block, add_block_to_archival_state, get_mock_global_state, get_mock_wallet_state,
        make_mock_block_with_valid_pow, make_unit_test_archival_state, unit_test_databases,
    };
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::SeedableRng;
    use rand::{random, thread_rng, RngCore};
    use tracing_test::traced_test;

    async fn make_test_archival_state(network: Network) -> ArchivalState {
        let (block_index_db, _peer_db_lock, data_dir) = unit_test_databases(network).await.unwrap();

        let ams = ArchivalState::initialize_mutator_set(&data_dir)
            .await
            .unwrap();

        ArchivalState::new(data_dir, block_index_db, ams).await
    }

    #[traced_test]
    #[tokio::test]
    async fn initialize_archival_state_test() -> Result<()> {
        // Ensure that the archival state can be initialized without overflowing the stack
        let seed: [u8; 32] = thread_rng().gen();
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let network = Network::Alpha;

        let mut archival_state0 = make_test_archival_state(network).await;

        let b = Block::genesis_block().await;
        let some_wallet_secret = WalletSecret::new_random();
        let some_spending_key = some_wallet_secret.nth_generation_spending_key(0);
        let some_receiving_address = some_spending_key.to_address();

        let (block_1, _, _) =
            make_mock_block_with_valid_pow(&b, None, some_receiving_address, rng.gen()).await;
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
    #[tokio::test]
    async fn archival_state_init_test() -> Result<()> {
        // Verify that archival mutator set is populated with outputs from genesis block
        let archival_state = make_test_archival_state(Network::Alpha).await;

        assert_eq!(
            Block::genesis_block()
                .await
                .kernel
                .body
                .transaction
                .kernel
                .outputs
                .len() as u64,
            archival_state
                .archival_mutator_set
                .ams()
                .kernel
                .aocl
                .count_leaves()
                .await,
            "Archival mutator set must be populated with premine outputs"
        );

        assert_eq!(
            Block::genesis_block().await.hash(),
            archival_state.archival_mutator_set.get_sync_label().await,
            "AMS must be synced to genesis block after initialization from genesis block"
        );

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn archival_state_restore_test() -> Result<()> {
        let mut rng = thread_rng();
        // Verify that a restored archival mutator set is populated with the right `sync_label`
        let network = Network::Alpha;
        let mut archival_state = make_test_archival_state(network).await;
        let genesis_wallet_state =
            get_mock_wallet_state(WalletSecret::devnet_wallet(), network).await;
        let (mock_block_1, _, _) = make_mock_block_with_valid_pow(
            &archival_state.genesis_block,
            None,
            genesis_wallet_state
                .wallet_secret
                .nth_generation_spending_key(0)
                .to_address(),
            rng.gen(),
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
                .get_sync_label()
                .await,
            "sync_label of restored archival mutator set must be digest of latest block"
        );

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn update_mutator_set_db_write_test() -> Result<()> {
        let mut rng = thread_rng();
        // Verify that `update_mutator_set` writes the active window back to disk.

        let network = Network::Alpha;
        let genesis_wallet_state =
            get_mock_wallet_state(WalletSecret::devnet_wallet(), network).await;
        let wallet = genesis_wallet_state.wallet_secret;
        let own_receiving_address = wallet.nth_generation_spending_key(0).to_address();
        let genesis_receiver_global_state_lock = get_mock_global_state(network, 0, wallet).await;
        let mut genesis_receiver_global_state =
            genesis_receiver_global_state_lock.lock_guard_mut().await;

        let (mock_block_1, _, _) = make_mock_block_with_valid_pow(
            &genesis_receiver_global_state
                .chain
                .archival_state_mut()
                .genesis_block,
            None,
            own_receiving_address,
            rng.gen(),
        )
        .await;

        {
            add_block(&mut genesis_receiver_global_state, mock_block_1.clone()).await?;
            genesis_receiver_global_state
                .chain
                .archival_state_mut()
                .update_mutator_set(&mock_block_1)
                .await
                .unwrap();
            let msa = genesis_receiver_global_state
                .chain
                .archival_state_mut()
                .genesis_block
                .kernel
                .body
                .mutator_set_accumulator
                .clone();
            genesis_receiver_global_state
                .wallet_state
                .update_wallet_state_with_new_block(&msa, &mock_block_1)
                .await
                .unwrap();

            let ams_ref = &genesis_receiver_global_state
                .chain
                .archival_state()
                .archival_mutator_set;
            assert_ne!(0, ams_ref.ams().kernel.aocl.count_leaves().await);
        }

        let now = Duration::from_millis(mock_block_1.kernel.header.timestamp.value());
        let seven_months = Duration::from_millis(7 * 30 * 24 * 60 * 60 * 1000);

        // Add an input to the next block's transaction. This will add a removal record
        // to the block, and this removal record will insert indices in the Bloom filter.
        {
            let (mut mock_block_2, _, _) = make_mock_block_with_valid_pow(
                &mock_block_1,
                None,
                own_receiving_address,
                rng.gen(),
            )
            .await;
            let sender_tx = genesis_receiver_global_state
                .create_transaction(
                    vec![UtxoReceiverData {
                        public_announcement: PublicAnnouncement::default(),
                        receiver_privacy_digest: random(),
                        sender_randomness: random(),
                        utxo: Utxo {
                            coins: NeptuneCoins::new(4).to_native_coins(),
                            lock_script_hash: LockScript::anyone_can_spend().hash(),
                        },
                    }],
                    NeptuneCoins::new(2),
                    now + seven_months,
                )
                .await
                .unwrap();
            mock_block_2
                .accumulate_transaction(
                    sender_tx,
                    &mock_block_1.kernel.body.mutator_set_accumulator,
                )
                .await;

            // Remove an element from the mutator set, verify that the active window DB is updated.
            add_block(&mut genesis_receiver_global_state, mock_block_2.clone()).await?;
            genesis_receiver_global_state
                .chain
                .archival_state_mut()
                .update_mutator_set(&mock_block_2)
                .await
                .unwrap();

            let ams_ref = &genesis_receiver_global_state
                .chain
                .archival_state()
                .archival_mutator_set;
            assert_ne!(0, ams_ref.ams().kernel.swbf_active.sbf.len());
        }

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn update_mutator_set_rollback_ms_block_sync_test() -> Result<()> {
        let mut rng = thread_rng();
        let network = Network::Alpha;
        let (mut archival_state, _peer_db_lock, _data_dir) =
            make_unit_test_archival_state(network).await;
        let own_wallet = WalletSecret::new_random();
        let own_receiving_address = own_wallet.nth_generation_spending_key(0).to_address();

        // 1. Create new block 1 and store it to the DB
        let (mock_block_1a, _, _) = make_mock_block_with_valid_pow(
            &archival_state.genesis_block,
            None,
            own_receiving_address,
            rng.gen(),
        )
        .await;
        archival_state
            .write_block(
                &mock_block_1a,
                Some(mock_block_1a.kernel.header.proof_of_work_family),
            )
            .await?;

        // 2. Update mutator set with this
        archival_state
            .update_mutator_set(&mock_block_1a)
            .await
            .unwrap();

        // 3. Create competing block 1 and store it to DB
        let (mock_block_1b, _, _) = make_mock_block_with_valid_pow(
            &archival_state.genesis_block,
            None,
            own_receiving_address,
            rng.gen(),
        )
        .await;
        archival_state
            .write_block(
                &mock_block_1a,
                Some(mock_block_1b.kernel.header.proof_of_work_family),
            )
            .await?;

        // 4. Update mutator set with that
        archival_state
            .update_mutator_set(&mock_block_1b)
            .await
            .unwrap();

        // 5. Experience rollback

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn update_mutator_set_rollback_ms_block_sync_multiple_inputs_outputs_in_block_test() {
        let mut rng = thread_rng();
        // Make a rollback of one block that contains multiple inputs and outputs.
        // This test is intended to verify that rollbacks work for non-trivial
        // blocks.
        let network = Network::Alpha;
        let (mut archival_state, _peer_db_lock, _data_dir) =
            make_unit_test_archival_state(network).await;
        let genesis_wallet_state =
            get_mock_wallet_state(WalletSecret::devnet_wallet(), network).await;
        let genesis_wallet = genesis_wallet_state.wallet_secret;
        let own_receiving_address = genesis_wallet.nth_generation_spending_key(0).to_address();
        let global_state_lock = get_mock_global_state(Network::RegTest, 42, genesis_wallet).await;
        let mut num_utxos = Block::premine_utxos().len();

        // 1. Create new block 1 with one input and four outputs and store it to disk
        let (mut block_1a, _, _) = make_mock_block_with_valid_pow(
            &archival_state.genesis_block,
            None,
            own_receiving_address,
            rng.gen(),
        )
        .await;
        let genesis_block = archival_state.genesis_block.clone();
        let now = Duration::from_millis(genesis_block.kernel.header.timestamp.value());
        let seven_months = Duration::from_millis(7 * 30 * 24 * 60 * 60 * 1000);

        let one_money = NeptuneCoins::new(42).to_native_coins();
        let receiver_data = vec![
            UtxoReceiverData {
                utxo: Utxo {
                    lock_script_hash: LockScript::anyone_can_spend().hash(),
                    coins: one_money.clone(),
                },
                sender_randomness: random(),
                receiver_privacy_digest: random(),
                public_announcement: PublicAnnouncement::default(),
            },
            UtxoReceiverData {
                utxo: Utxo {
                    lock_script_hash: LockScript::anyone_can_spend().hash(),
                    coins: one_money,
                },
                sender_randomness: random(),
                receiver_privacy_digest: random(),
                public_announcement: PublicAnnouncement::default(),
            },
        ];
        let sender_tx = global_state_lock
            .lock_guard_mut()
            .await
            .create_transaction(receiver_data, NeptuneCoins::new(4), now + seven_months)
            .await
            .unwrap();

        block_1a
            .accumulate_transaction(
                sender_tx,
                &archival_state
                    .genesis_block
                    .kernel
                    .body
                    .mutator_set_accumulator,
            )
            .await;

        assert!(block_1a.is_valid(&genesis_block, now + seven_months).await);

        {
            archival_state
                .write_block(&block_1a, Some(block_1a.kernel.header.proof_of_work_family))
                .await
                .unwrap();

            // 2. Update mutator set with this
            archival_state.update_mutator_set(&block_1a).await.unwrap();

            // 3. Create competing block 1 and store it to DB
            let (mock_block_1b, _, _) = make_mock_block_with_valid_pow(
                &archival_state.genesis_block,
                None,
                own_receiving_address,
                rng.gen(),
            )
            .await;
            archival_state
                .write_block(
                    // &block_1a,
                    &mock_block_1b,
                    Some(mock_block_1b.kernel.header.proof_of_work_family),
                )
                .await
                .unwrap();
            num_utxos += mock_block_1b.body().transaction.kernel.outputs.len();

            // 4. Update mutator set with that and verify rollback
            archival_state
                .update_mutator_set(&mock_block_1b)
                .await
                .unwrap();
        }

        // 5. Verify correct rollback

        // Verify that the new state of the archival mutator set contains
        // two UTXOs and that none have been removed
        assert!(
            archival_state
                .archival_mutator_set
                .ams()
                .kernel
                .swbf_active
                .sbf
                .is_empty(),
            "Active window must be empty when no UTXOs have been spent"
        );

        assert_eq!(
            num_utxos,
            archival_state
                .archival_mutator_set
                .ams()
                .kernel
                .aocl
                .count_leaves()
                .await as usize,
            "AOCL leaf count must agree with blockchain after rollback"
        );
    }

    #[traced_test]
    #[tokio::test]
    async fn update_mutator_set_rollback_many_blocks_multiple_inputs_outputs_test() -> Result<()> {
        let mut rng = thread_rng();
        // Make a rollback of multiple blocks that contains multiple inputs and outputs.
        // This test is intended to verify that rollbacks work for non-trivial
        // blocks, also when there are many blocks that push the active window of the
        // mutator set forwards.
        let genesis_wallet_state =
            get_mock_wallet_state(WalletSecret::devnet_wallet(), Network::Alpha).await;
        let genesis_wallet = genesis_wallet_state.wallet_secret;
        let own_receiving_address = genesis_wallet.nth_generation_spending_key(0).to_address();
        let global_state_lock = get_mock_global_state(Network::RegTest, 42, genesis_wallet).await;

        let mut global_state = global_state_lock.lock_guard_mut().await;
        let genesis_block: Block = *global_state.chain.archival_state().genesis_block.to_owned();
        let mut num_utxos = Block::premine_utxos().len();
        let mut previous_block = genesis_block.clone();

        // this variable might come in handy for reporting purposes
        let mut _aocl_index_of_consumed_input = 0;

        let some_money = NeptuneCoins::new(54).to_native_coins();

        for i in 0..10 {
            // Create next block with inputs and outputs
            let (mut next_block, _, _) = make_mock_block_with_valid_pow(
                &previous_block,
                None,
                own_receiving_address,
                rng.gen(),
            )
            .await;
            let now = Duration::from_millis(next_block.kernel.header.timestamp.value());
            let seven_months = Duration::from_millis(7 * 30 * 24 * 60 * 60 * 1000);
            let receiver_data = vec![
                UtxoReceiverData {
                    utxo: Utxo {
                        lock_script_hash: LockScript::anyone_can_spend().hash(),
                        coins: some_money.clone(),
                    },
                    sender_randomness: random(),
                    receiver_privacy_digest: random(),
                    public_announcement: PublicAnnouncement::default(),
                },
                UtxoReceiverData {
                    utxo: Utxo {
                        lock_script_hash: LockScript::anyone_can_spend().hash(),
                        coins: some_money.clone(),
                    },
                    sender_randomness: random(),
                    receiver_privacy_digest: random(),
                    public_announcement: PublicAnnouncement::default(),
                },
            ];
            let sender_tx = global_state
                .create_transaction(receiver_data, NeptuneCoins::new(4), now + seven_months)
                .await
                .unwrap();

            next_block
                .accumulate_transaction(
                    sender_tx,
                    &previous_block.kernel.body.mutator_set_accumulator,
                )
                .await;

            assert!(
                next_block
                    .is_valid(&previous_block, now + seven_months)
                    .await,
                "next block ({i}) not valid for devnet"
            );

            // Store the produced block
            {
                global_state
                    .chain
                    .archival_state_mut()
                    .write_block(
                        &next_block,
                        Some(next_block.kernel.header.proof_of_work_family),
                    )
                    .await?;
                global_state
                    .chain
                    .light_state_mut()
                    .set_block(next_block.clone());

                // 2. Update mutator set with produced block
                global_state
                    .chain
                    .archival_state_mut()
                    .update_mutator_set(&next_block)
                    .await
                    .unwrap();

                // 3. Update wallet state so we can continue making transactions
                global_state
                    .wallet_state
                    .update_wallet_state_with_new_block(
                        &previous_block.kernel.body.mutator_set_accumulator,
                        &next_block,
                    )
                    .await
                    .unwrap();
            }

            // Genesis block may have a different number of outputs than the blocks produced above
            if i == 0 {
                _aocl_index_of_consumed_input +=
                    genesis_block.kernel.body.transaction.kernel.outputs.len() as u64;
            } else {
                _aocl_index_of_consumed_input +=
                    next_block.kernel.body.transaction.kernel.outputs.len() as u64;
            }

            previous_block = next_block;
        }

        {
            // 3. Create competing block 1 and store it to DB
            let (mock_block_1b, _, _) = make_mock_block_with_valid_pow(
                &genesis_block,
                None,
                own_receiving_address,
                rng.gen(),
            )
            .await;
            global_state
                .chain
                .archival_state_mut()
                .write_block(
                    &mock_block_1b,
                    Some(mock_block_1b.kernel.header.proof_of_work_family),
                )
                .await?;
            num_utxos += mock_block_1b.body().transaction.kernel.outputs.len();

            // 4. Update mutator set with that and verify rollback
            global_state
                .chain
                .archival_state_mut()
                .update_mutator_set(&mock_block_1b)
                .await
                .unwrap();
        }

        // 5. Verify correct rollback

        // Verify that the new state of the archival mutator set contains
        // two UTXOs and that none have been removed
        assert!(
            global_state
                .chain
                .archival_state()
                .archival_mutator_set
                .ams()
                .kernel
                .swbf_active
                .sbf
                .is_empty(),
            "Active window must be empty when no UTXOs have been spent"
        );

        assert_eq!(
            num_utxos,
            global_state
                .chain
                .archival_state()
                .archival_mutator_set
                .ams()
                .kernel
                .aocl
                .count_leaves().await as usize,
            "AOCL leaf count must agree with #premine allocations + #transaction outputs in all blocks, even after rollback"
        );

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn allow_consumption_of_genesis_output_test() -> Result<()> {
        let mut rng = thread_rng();
        let network = Network::RegTest;
        let genesis_wallet_state =
            get_mock_wallet_state(WalletSecret::devnet_wallet(), network).await;
        let genesis_wallet = genesis_wallet_state.wallet_secret;
        let own_receiving_address = genesis_wallet.nth_generation_spending_key(0).to_address();
        let genesis_block = Block::genesis_block().await;
        let now = Duration::from_millis(genesis_block.kernel.header.timestamp.value());
        let seven_months = Duration::from_millis(7 * 30 * 24 * 60 * 60 * 1000);
        let (mut block_1_a, _, _) =
            make_mock_block_with_valid_pow(&genesis_block, None, own_receiving_address, rng.gen())
                .await;
        let global_state_lock = get_mock_global_state(network, 42, genesis_wallet).await;

        // Verify that block_1 that only contains the coinbase output is valid
        assert!(block_1_a.has_proof_of_work(&genesis_block));
        assert!(block_1_a.is_valid(&genesis_block, now).await);

        // Add a valid input to the block transaction
        let one_money: NeptuneCoins = NeptuneCoins::new(1);
        let receiver_data = UtxoReceiverData {
            public_announcement: PublicAnnouncement::default(),
            receiver_privacy_digest: random(),
            sender_randomness: random(),
            utxo: Utxo {
                coins: one_money.to_native_coins(),
                lock_script_hash: LockScript::anyone_can_spend().hash(),
            },
        };
        let sender_tx = global_state_lock
            .lock_guard_mut()
            .await
            .create_transaction(vec![receiver_data], one_money, now + seven_months)
            .await
            .unwrap();

        block_1_a
            .accumulate_transaction(
                sender_tx,
                &genesis_block.kernel.body.mutator_set_accumulator,
            )
            .await;

        // Block with signed transaction must validate
        assert!(block_1_a.is_valid(&genesis_block, now + seven_months).await);

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn allow_multiple_inputs_and_outputs_in_block() {
        let mut rng = thread_rng();
        // Test various parts of the state update when a block contains multiple inputs and outputs
        let network = Network::Alpha;
        let genesis_wallet_state =
            get_mock_wallet_state(WalletSecret::devnet_wallet(), network).await;
        let genesis_spending_key = genesis_wallet_state
            .wallet_secret
            .nth_generation_spending_key(0);
        let genesis_state_lock =
            get_mock_global_state(network, 3, genesis_wallet_state.wallet_secret).await;

        let wallet_secret_alice = WalletSecret::new_random();
        let alice_spending_key = wallet_secret_alice.nth_generation_spending_key(0);
        let alice_state_lock = get_mock_global_state(network, 3, wallet_secret_alice).await;

        let wallet_secret_bob = WalletSecret::new_random();
        let bob_spending_key = wallet_secret_bob.nth_generation_spending_key(0);
        let bob_state_lock = get_mock_global_state(network, 3, wallet_secret_bob).await;

        let genesis_block = Block::genesis_block().await;
        let launch = Duration::from_millis(genesis_block.kernel.header.timestamp.value());
        let seven_months = Duration::from_millis(7 * 30 * 24 * 60 * 60 * 1000);

        let (mut block_1, cb_utxo, cb_output_randomness) = make_mock_block_with_valid_pow(
            &genesis_block,
            None,
            genesis_spending_key.to_address(),
            rng.gen(),
        )
        .await;

        // Send two outputs each to Alice and Bob, from genesis receiver
        let fee = NeptuneCoins::one();
        let sender_randomness: Digest = random();
        let receiver_data_for_alice = vec![
            UtxoReceiverData {
                public_announcement: PublicAnnouncement::default(),
                receiver_privacy_digest: alice_spending_key.to_address().privacy_digest,
                sender_randomness,
                utxo: Utxo {
                    lock_script_hash: alice_spending_key.to_address().lock_script().hash(),
                    coins: NeptuneCoins::new(41).to_native_coins(),
                },
            },
            UtxoReceiverData {
                public_announcement: PublicAnnouncement::default(),
                receiver_privacy_digest: alice_spending_key.to_address().privacy_digest,
                sender_randomness,
                utxo: Utxo {
                    lock_script_hash: alice_spending_key.to_address().lock_script().hash(),
                    coins: NeptuneCoins::new(59).to_native_coins(),
                },
            },
        ];
        // Two outputs for Bob
        let receiver_data_for_bob = vec![
            UtxoReceiverData {
                public_announcement: PublicAnnouncement::default(),
                receiver_privacy_digest: bob_spending_key.to_address().privacy_digest,
                sender_randomness,
                utxo: Utxo {
                    lock_script_hash: bob_spending_key.to_address().lock_script().hash(),
                    coins: NeptuneCoins::new(141).to_native_coins(),
                },
            },
            UtxoReceiverData {
                public_announcement: PublicAnnouncement::default(),
                receiver_privacy_digest: bob_spending_key.to_address().privacy_digest,
                sender_randomness,
                utxo: Utxo {
                    lock_script_hash: bob_spending_key.to_address().lock_script().hash(),
                    coins: NeptuneCoins::new(59).to_native_coins(),
                },
            },
        ];
        {
            let tx_to_alice_and_bob = create_transaction_with_timestamp(
                &genesis_state_lock,
                &[
                    receiver_data_for_alice.clone(),
                    receiver_data_for_bob.clone(),
                ]
                .concat(),
                fee,
                (launch + seven_months).as_millis() as u64,
            )
            .await
            .unwrap();

            // Absorb and verify validity
            block_1
                .accumulate_transaction(
                    tx_to_alice_and_bob,
                    &genesis_block.kernel.body.mutator_set_accumulator,
                )
                .await;
            assert!(
                block_1
                    .is_valid(&genesis_block, launch + seven_months)
                    .await
            );
        }

        println!("Accumulated transaction into block_1.");
        println!(
            "Transaction has {} inputs (removal records) and {} outputs (addition records)",
            block_1.kernel.body.transaction.kernel.inputs.len(),
            block_1.kernel.body.transaction.kernel.outputs.len()
        );

        // Update chain states
        for state_lock in [&genesis_state_lock, &alice_state_lock, &bob_state_lock] {
            let mut state = state_lock.lock_guard_mut().await;
            add_block(&mut state, block_1.clone()).await.unwrap();
            state
                .chain
                .archival_state_mut()
                .update_mutator_set(&block_1)
                .await
                .unwrap();
        }

        {
            // Update wallets
            let mut genesis_state = genesis_state_lock.lock_guard_mut().await;
            genesis_state
                .wallet_state
                .expected_utxos
                .add_expected_utxo(
                    cb_utxo,
                    cb_output_randomness,
                    genesis_spending_key.privacy_preimage,
                    UtxoNotifier::OwnMiner,
                )
                .unwrap();
            genesis_state
                .wallet_state
                .update_wallet_state_with_new_block(
                    &genesis_block.kernel.body.mutator_set_accumulator,
                    &block_1,
                )
                .await
                .unwrap();
            assert_eq!(
                3,
                genesis_state
                    .wallet_state
                    .wallet_db
                    .monitored_utxos()
                    .len().await, "Genesis receiver must have 3 UTXOs after block 1: change from transaction, coinbase from block 1, and the spent premine UTXO"
            );
        }

        {
            let mut alice_state = alice_state_lock.lock_guard_mut().await;
            for rec_data in receiver_data_for_alice {
                alice_state
                    .wallet_state
                    .expected_utxos
                    .add_expected_utxo(
                        rec_data.utxo.clone(),
                        rec_data.sender_randomness,
                        alice_spending_key.privacy_preimage,
                        UtxoNotifier::Cli,
                    )
                    .unwrap();
            }
            alice_state
                .wallet_state
                .update_wallet_state_with_new_block(
                    &genesis_block.kernel.body.mutator_set_accumulator,
                    &block_1,
                )
                .await
                .unwrap();
        }

        {
            let mut bob_state = bob_state_lock.lock_guard_mut().await;
            for rec_data in receiver_data_for_bob {
                bob_state
                    .wallet_state
                    .expected_utxos
                    .add_expected_utxo(
                        rec_data.utxo.clone(),
                        rec_data.sender_randomness,
                        bob_spending_key.privacy_preimage,
                        UtxoNotifier::Cli,
                    )
                    .unwrap();
            }
            bob_state
                .wallet_state
                .update_wallet_state_with_new_block(
                    &genesis_block.kernel.body.mutator_set_accumulator,
                    &block_1,
                )
                .await
                .unwrap();
        }

        // Now Alice should have a balance of 100 and Bob a balance of 200

        assert_eq!(
            NeptuneCoins::new(100),
            alice_state_lock
                .lock_guard()
                .await
                .get_wallet_status_for_tip()
                .await
                .synced_unspent_available_amount((launch + seven_months).as_millis() as u64)
        );
        assert_eq!(
            NeptuneCoins::new(200),
            bob_state_lock
                .lock_guard()
                .await
                .get_wallet_status_for_tip()
                .await
                .synced_unspent_available_amount((launch + seven_months).as_millis() as u64)
        );

        // Make two transactions: Alice sends two UTXOs to Genesis and Bob sends three UTXOs to genesis
        let receiver_data_from_alice = vec![
            UtxoReceiverData {
                utxo: Utxo {
                    lock_script_hash: genesis_spending_key.to_address().lock_script().hash(),
                    coins: NeptuneCoins::new(50).to_native_coins(),
                },
                sender_randomness: random(),
                receiver_privacy_digest: genesis_spending_key.to_address().privacy_digest,
                public_announcement: PublicAnnouncement::default(),
            },
            UtxoReceiverData {
                utxo: Utxo {
                    lock_script_hash: genesis_spending_key.to_address().lock_script().hash(),
                    coins: NeptuneCoins::new(49).to_native_coins(),
                },
                sender_randomness: random(),
                receiver_privacy_digest: genesis_spending_key.to_address().privacy_digest,
                public_announcement: PublicAnnouncement::default(),
            },
        ];
        let tx_from_alice = alice_state_lock
            .lock_guard_mut()
            .await
            .create_transaction(
                receiver_data_from_alice.clone(),
                NeptuneCoins::new(1),
                launch + seven_months,
            )
            .await
            .unwrap();
        let receiver_data_from_bob = vec![
            UtxoReceiverData {
                utxo: Utxo {
                    lock_script_hash: genesis_spending_key.to_address().lock_script().hash(),
                    coins: NeptuneCoins::new(50).to_native_coins(),
                },
                sender_randomness: random(),
                receiver_privacy_digest: genesis_spending_key.to_address().privacy_digest,
                public_announcement: PublicAnnouncement::default(),
            },
            UtxoReceiverData {
                utxo: Utxo {
                    lock_script_hash: genesis_spending_key.to_address().lock_script().hash(),
                    coins: NeptuneCoins::new(50).to_native_coins(),
                },
                sender_randomness: random(),
                receiver_privacy_digest: genesis_spending_key.to_address().privacy_digest,
                public_announcement: PublicAnnouncement::default(),
            },
            UtxoReceiverData {
                utxo: Utxo {
                    lock_script_hash: genesis_spending_key.to_address().lock_script().hash(),
                    coins: NeptuneCoins::new(98).to_native_coins(),
                },
                sender_randomness: random(),
                receiver_privacy_digest: genesis_spending_key.to_address().privacy_digest,
                public_announcement: PublicAnnouncement::default(),
            },
        ];
        let tx_from_bob = create_transaction_with_timestamp(
            &bob_state_lock,
            &receiver_data_from_bob.clone(),
            NeptuneCoins::new(2),
            (launch + seven_months).as_millis() as u64,
        )
        .await
        .unwrap();

        // Make block_2 with tx that contains:
        // - 4 inputs: 2 from Alice and 2 from Bob
        // - 6 outputs: 2 from Alice to Genesis, 3 from Bob to Genesis, and 1 coinbase to Genesis
        let (mut block_2, cb_utxo_block_2, cb_sender_randomness_block_2) =
            make_mock_block_with_valid_pow(
                &block_1,
                None,
                genesis_spending_key.to_address(),
                rng.gen(),
            )
            .await;
        block_2
            .accumulate_transaction(tx_from_alice, &block_1.kernel.body.mutator_set_accumulator)
            .await;
        assert_eq!(2, block_2.kernel.body.transaction.kernel.inputs.len());
        assert_eq!(3, block_2.kernel.body.transaction.kernel.outputs.len());

        block_2
            .accumulate_transaction(tx_from_bob, &block_1.kernel.body.mutator_set_accumulator)
            .await;

        // Sanity checks
        assert_eq!(4, block_2.kernel.body.transaction.kernel.inputs.len());
        assert_eq!(6, block_2.kernel.body.transaction.kernel.outputs.len());
        let now = Duration::from_millis(block_1.kernel.header.timestamp.value());
        assert!(block_2.is_valid(&block_1, now).await);

        // Update chain states
        for state_lock in [&genesis_state_lock, &alice_state_lock, &bob_state_lock] {
            let mut state = state_lock.lock_guard_mut().await;

            add_block(&mut state, block_2.clone()).await.unwrap();
            state
                .chain
                .archival_state_mut()
                .update_mutator_set(&block_2)
                .await
                .unwrap();
        }

        // Update wallets and verify that Alice and Bob's balances are zero
        alice_state_lock
            .lock_guard_mut()
            .await
            .wallet_state
            .update_wallet_state_with_new_block(
                &block_1.kernel.body.mutator_set_accumulator,
                &block_2,
            )
            .await
            .unwrap();
        bob_state_lock
            .lock_guard_mut()
            .await
            .wallet_state
            .update_wallet_state_with_new_block(
                &block_1.kernel.body.mutator_set_accumulator,
                &block_2,
            )
            .await
            .unwrap();
        assert!(alice_state_lock
            .lock_guard()
            .await
            .get_wallet_status_for_tip()
            .await
            .synced_unspent_available_amount((launch + seven_months).as_millis() as u64)
            .is_zero());
        assert!(bob_state_lock
            .lock_guard()
            .await
            .get_wallet_status_for_tip()
            .await
            .synced_unspent_available_amount((launch + seven_months).as_millis() as u64)
            .is_zero());

        // Update genesis wallet and verify that all ingoing UTXOs are recorded
        for rec_data in receiver_data_from_alice {
            genesis_state_lock
                .lock_guard_mut()
                .await
                .wallet_state
                .expected_utxos
                .add_expected_utxo(
                    rec_data.utxo.clone(),
                    rec_data.sender_randomness,
                    genesis_spending_key.privacy_preimage,
                    UtxoNotifier::Cli,
                )
                .unwrap();
        }
        for rec_data in receiver_data_from_bob {
            genesis_state_lock
                .lock_guard_mut()
                .await
                .wallet_state
                .expected_utxos
                .add_expected_utxo(
                    rec_data.utxo.clone(),
                    rec_data.sender_randomness,
                    genesis_spending_key.privacy_preimage,
                    UtxoNotifier::Cli,
                )
                .unwrap();
        }
        genesis_state_lock
            .lock_guard_mut()
            .await
            .wallet_state
            .expected_utxos
            .add_expected_utxo(
                cb_utxo_block_2,
                cb_sender_randomness_block_2,
                genesis_spending_key.privacy_preimage,
                UtxoNotifier::Cli,
            )
            .unwrap();
        genesis_state_lock
            .lock_guard_mut()
            .await
            .wallet_state
            .update_wallet_state_with_new_block(
                &block_1.kernel.body.mutator_set_accumulator,
                &block_2,
            )
            .await
            .unwrap();

        // Verify that states and wallets can be updated successfully
        assert_eq!(
            9,
            genesis_state_lock.lock_guard().await
                .wallet_state
                .wallet_db
                .monitored_utxos()
                .len().await, "Genesis receiver must have 9 UTXOs after block 2: 3 after block 1, and 6 added by block 2"
        );

        // Verify that mutator sets are updated correctly and that last block is block 2
        for state_lock in [&genesis_state_lock, &alice_state_lock, &bob_state_lock] {
            let state = state_lock.lock_guard().await;

            assert_eq!(
                block_2.kernel.body.mutator_set_accumulator,
                state
                    .chain
                    .archival_state()
                    .archival_mutator_set
                    .ams()
                    .accumulator()
                    .await,
                "AMS must be correctly updated"
            );
            assert_eq!(
                block_2,
                state.chain.archival_state().get_latest_block().await
            );
        }
    }

    #[traced_test]
    #[tokio::test]
    async fn get_latest_block_test() -> Result<()> {
        let mut rng = thread_rng();
        let network = Network::Alpha;
        let mut archival_state: ArchivalState = make_test_archival_state(network).await;

        let ret = archival_state.get_latest_block_from_disk().await?;
        assert!(
            ret.is_none(),
            "Must return None when no block is stored in DB"
        );

        // Add a block to archival state and verify that this is returned
        let own_wallet = WalletSecret::new_random();
        let own_receiving_address = own_wallet.nth_generation_spending_key(0).to_address();
        let genesis = *archival_state.genesis_block.clone();
        let (mock_block_1, _, _) =
            make_mock_block_with_valid_pow(&genesis, None, own_receiving_address, rng.gen()).await;
        add_block_to_archival_state(&mut archival_state, mock_block_1.clone()).await?;

        let ret1 = archival_state.get_latest_block_from_disk().await?;
        assert!(
            ret1.is_some(),
            "Must return a block when one is stored to DB"
        );
        assert_eq!(
            mock_block_1,
            ret1.unwrap(),
            "Returned block must match the one inserted"
        );

        // Add a 2nd block and verify that this new block is now returned
        let (mock_block_2, _, _) =
            make_mock_block_with_valid_pow(&mock_block_1, None, own_receiving_address, rng.gen())
                .await;
        add_block_to_archival_state(&mut archival_state, mock_block_2.clone()).await?;
        let ret2 = archival_state.get_latest_block_from_disk().await?;
        assert!(
            ret2.is_some(),
            "Must return a block when one is stored to DB"
        );

        assert_eq!(
            mock_block_2,
            ret2.unwrap(),
            "Returned block must match the one inserted"
        );

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn get_block_test() -> Result<()> {
        let mut rng = thread_rng();
        let network = Network::Alpha;
        let mut archival_state = make_test_archival_state(network).await;

        let genesis = *archival_state.genesis_block.clone();
        let own_wallet = WalletSecret::new_random();
        let own_receiving_address = own_wallet.nth_generation_spending_key(0).to_address();
        let (mock_block_1, _, _) = make_mock_block_with_valid_pow(
            &genesis.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        )
        .await;

        // Lookup a block in an empty database, expect None to be returned
        let ret0 = archival_state.get_block(mock_block_1.hash()).await?;
        assert!(
            ret0.is_none(),
            "Must return a block when one is stored to DB"
        );

        add_block_to_archival_state(&mut archival_state, mock_block_1.clone()).await?;
        let ret1 = archival_state.get_block(mock_block_1.hash()).await?;
        assert!(
            ret1.is_some(),
            "Must return a block when one is stored to DB"
        );
        assert_eq!(
            mock_block_1,
            ret1.unwrap(),
            "Returned block must match the one inserted"
        );

        // Inserted a new block and verify that both blocks can be found
        let (mock_block_2, _, _) = make_mock_block_with_valid_pow(
            &mock_block_1.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        )
        .await;
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
        for _ in 0..(thread_rng().next_u32() % 20) {
            let (new_block, _, _) =
                make_mock_block_with_valid_pow(&last_block, None, own_receiving_address, rng.gen())
                    .await;
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
    #[tokio::test]
    async fn find_path_simple_test() -> Result<()> {
        let mut rng = thread_rng();
        let network = Network::Alpha;
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
        let own_wallet = WalletSecret::new_random();
        let own_receiving_address = own_wallet.nth_generation_spending_key(0).to_address();
        let (mock_block_1_a, _, _) = make_mock_block_with_valid_pow(
            &genesis.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        )
        .await;
        add_block_to_archival_state(&mut archival_state, mock_block_1_a.clone()).await?;

        let (mock_block_1_b, _, _) = make_mock_block_with_valid_pow(
            &genesis.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        )
        .await;
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
    #[tokio::test]
    async fn fork_path_finding_test() -> Result<()> {
        let mut rng = thread_rng();
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

        let network = Network::Alpha;
        let mut archival_state = make_test_archival_state(network).await;

        let genesis = *archival_state.genesis_block.clone();
        assert!(
            archival_state
                .block_belongs_to_canonical_chain(
                    genesis.kernel.mast_hash(),
                    genesis.kernel.mast_hash()
                )
                .await,
            "Genesis block is always part of the canonical chain, tip"
        );

        // Insert a block that is descendant from genesis block and verify that it is canonical
        let own_wallet = WalletSecret::new_random();
        let own_receiving_address = own_wallet.nth_generation_spending_key(0).to_address();
        let (mock_block_1, _, _) = make_mock_block_with_valid_pow(
            &genesis.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        )
        .await;
        add_block_to_archival_state(&mut archival_state, mock_block_1.clone()).await?;
        assert!(
            archival_state
                .block_belongs_to_canonical_chain(
                    genesis.kernel.mast_hash(),
                    mock_block_1.kernel.mast_hash()
                )
                .await,
            "Genesis block is always part of the canonical chain, tip parent"
        );
        assert!(
            archival_state
                .block_belongs_to_canonical_chain(
                    mock_block_1.kernel.mast_hash(),
                    mock_block_1.kernel.mast_hash()
                )
                .await,
            "Tip block is always part of the canonical chain"
        );

        // Insert three more blocks and verify that all are part of the canonical chain
        let (mock_block_2_a, _, _) = make_mock_block_with_valid_pow(
            &mock_block_1.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        )
        .await;
        add_block_to_archival_state(&mut archival_state, mock_block_2_a.clone()).await?;
        let (mock_block_3_a, _, _) = make_mock_block_with_valid_pow(
            &mock_block_2_a.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        )
        .await;
        add_block_to_archival_state(&mut archival_state, mock_block_3_a.clone()).await?;
        let (mock_block_4_a, _, _) = make_mock_block_with_valid_pow(
            &mock_block_3_a.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        )
        .await;
        add_block_to_archival_state(&mut archival_state, mock_block_4_a.clone()).await?;
        for (i, block) in [
            genesis.clone(),
            mock_block_1.clone(),
            mock_block_2_a.clone(),
            mock_block_3_a.clone(),
            mock_block_4_a.clone(),
        ]
        .iter()
        .enumerate()
        {
            assert!(
                archival_state
                    .block_belongs_to_canonical_chain(
                        block.kernel.mast_hash(),
                        mock_block_4_a.kernel.mast_hash()
                    )
                    .await,
                "block {} does not belong to canonical chain",
                i
            );
            dag_walker_leash_prop(block.hash(), mock_block_4_a.hash(), &archival_state).await;
            dag_walker_leash_prop(mock_block_4_a.hash(), block.hash(), &archival_state).await;
        }

        assert!(
            archival_state
                .block_belongs_to_canonical_chain(
                    genesis.kernel.mast_hash(),
                    mock_block_4_a.kernel.mast_hash()
                )
                .await,
            "Genesis block is always part of the canonical chain, block height is four"
        );

        // Make a tree and verify that the correct parts of the tree are identified as
        // belonging to the canonical chain
        let (mock_block_2_b, _, _) = make_mock_block_with_valid_pow(
            &mock_block_1.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        )
        .await;
        add_block_to_archival_state(&mut archival_state, mock_block_2_b.clone()).await?;
        let (mock_block_3_b, _, _) = make_mock_block_with_valid_pow(
            &mock_block_2_b.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        )
        .await;
        add_block_to_archival_state(&mut archival_state, mock_block_3_b.clone()).await?;
        let (mock_block_4_b, _, _) = make_mock_block_with_valid_pow(
            &mock_block_3_b.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        )
        .await;
        add_block_to_archival_state(&mut archival_state, mock_block_4_b.clone()).await?;
        let (mock_block_5_b, _, _) = make_mock_block_with_valid_pow(
            &mock_block_4_b.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        )
        .await;
        add_block_to_archival_state(&mut archival_state, mock_block_5_b.clone()).await?;
        for (i, block) in [
            genesis.clone(),
            mock_block_1.clone(),
            mock_block_2_a.clone(),
            mock_block_3_a.clone(),
            mock_block_4_a.clone(),
        ]
        .iter()
        .enumerate()
        {
            assert!(
                archival_state
                    .block_belongs_to_canonical_chain(
                        block.kernel.mast_hash(),
                        mock_block_4_a.kernel.mast_hash()
                    )
                    .await,
                "canonical chain {} is canonical",
                i
            );
            dag_walker_leash_prop(block.hash(), mock_block_4_a.hash(), &archival_state).await;
            dag_walker_leash_prop(mock_block_4_a.hash(), block.hash(), &archival_state).await;
        }

        // These blocks do not belong to the canonical chain since block 4_a has a higher PoW family
        // value
        for (i, block) in [
            mock_block_2_b.clone(),
            mock_block_3_b.clone(),
            mock_block_4_b.clone(),
            mock_block_5_b.clone(),
        ]
        .iter()
        .enumerate()
        {
            assert!(
                !archival_state
                    .block_belongs_to_canonical_chain(
                        block.kernel.mast_hash(),
                        mock_block_4_a.kernel.mast_hash()
                    )
                    .await,
                "Stale chain {} is not canonical",
                i
            );
            dag_walker_leash_prop(block.hash(), mock_block_4_a.hash(), &archival_state).await;
            dag_walker_leash_prop(mock_block_4_a.hash(), block.hash(), &archival_state).await;
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
        let (mock_block_3_c, _, _) = make_mock_block_with_valid_pow(
            &mock_block_2_a.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        )
        .await;
        add_block_to_archival_state(&mut archival_state, mock_block_3_c.clone()).await?;
        let (mock_block_4_c, _, _) = make_mock_block_with_valid_pow(
            &mock_block_3_c.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        )
        .await;
        add_block_to_archival_state(&mut archival_state, mock_block_4_c.clone()).await?;
        let (mock_block_5_c, _, _) = make_mock_block_with_valid_pow(
            &mock_block_4_c.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        )
        .await;
        add_block_to_archival_state(&mut archival_state, mock_block_5_c.clone()).await?;
        let (mock_block_6_c, _, _) = make_mock_block_with_valid_pow(
            &mock_block_5_c.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        )
        .await;
        add_block_to_archival_state(&mut archival_state, mock_block_6_c.clone()).await?;
        let (mock_block_7_c, _, _) = make_mock_block_with_valid_pow(
            &mock_block_6_c.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        )
        .await;
        add_block_to_archival_state(&mut archival_state, mock_block_7_c.clone()).await?;
        let (mock_block_8_c, _, _) = make_mock_block_with_valid_pow(
            &mock_block_7_c.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        )
        .await;
        add_block_to_archival_state(&mut archival_state, mock_block_8_c.clone()).await?;
        let (mock_block_5_a, _, _) = make_mock_block_with_valid_pow(
            &mock_block_4_a.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        )
        .await;
        add_block_to_archival_state(&mut archival_state, mock_block_5_a.clone()).await?;
        let (mock_block_3_d, _, _) = make_mock_block_with_valid_pow(
            &mock_block_2_a.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        )
        .await;
        add_block_to_archival_state(&mut archival_state, mock_block_3_d.clone()).await?;
        let (mock_block_4_d, _, _) = make_mock_block_with_valid_pow(
            &mock_block_3_d.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        )
        .await;
        add_block_to_archival_state(&mut archival_state, mock_block_4_d.clone()).await?;
        let (mock_block_5_d, _, _) = make_mock_block_with_valid_pow(
            &mock_block_4_d.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        )
        .await;
        add_block_to_archival_state(&mut archival_state, mock_block_5_d.clone()).await?;

        // This is the most canonical block in the known set
        let (mock_block_6_d, _, _) = make_mock_block_with_valid_pow(
            &mock_block_5_d.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        )
        .await;
        add_block_to_archival_state(&mut archival_state, mock_block_6_d.clone()).await?;

        let (mock_block_4_e, _, _) = make_mock_block_with_valid_pow(
            &mock_block_3_d.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        )
        .await;
        add_block_to_archival_state(&mut archival_state, mock_block_4_e.clone()).await?;
        let (mock_block_5_e, _, _) = make_mock_block_with_valid_pow(
            &mock_block_4_e.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        )
        .await;
        add_block_to_archival_state(&mut archival_state, mock_block_5_e.clone()).await?;

        for (i, block) in [
            genesis.clone(),
            mock_block_1.clone(),
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
                    .block_belongs_to_canonical_chain(
                        block.kernel.mast_hash(),
                        mock_block_6_d.kernel.mast_hash()
                    )
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
                    .block_belongs_to_canonical_chain(
                        block.kernel.mast_hash(),
                        mock_block_6_d.kernel.mast_hash()
                    )
                    .await,
                "Stale chain {} is not canonical",
                i
            );
            dag_walker_leash_prop(mock_block_6_d.hash(), block.hash(), &archival_state).await;
            dag_walker_leash_prop(block.hash(), mock_block_6_d.hash(), &archival_state).await;
        }

        // Make a new block, 6b, canonical and verify that all checks work
        let (mock_block_6_b, _, _) = make_mock_block_with_valid_pow(
            &mock_block_5_b.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        )
        .await;
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
                    .block_belongs_to_canonical_chain(
                        block.kernel.mast_hash(),
                        mock_block_6_b.kernel.mast_hash()
                    )
                    .await,
                "Stale chain {} is not canonical",
                i
            );
            dag_walker_leash_prop(mock_block_6_b.hash(), block.hash(), &archival_state).await;
            dag_walker_leash_prop(block.hash(), mock_block_6_b.hash(), &archival_state).await;
        }

        for (i, block) in [
            &genesis,
            &mock_block_1,
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
                    .block_belongs_to_canonical_chain(
                        block.kernel.mast_hash(),
                        mock_block_6_b.kernel.mast_hash()
                    )
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
        //
        // Note that in the later test, 6b becomes the tip.
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
        assert_eq!(mock_block_1.hash(), luca, "Luca must be block 1");

        Ok(())
    }

    #[should_panic]
    #[traced_test]
    #[tokio::test]
    async fn digest_of_ancestors_panic_test() {
        let archival_state = make_test_archival_state(Network::Alpha).await;

        let genesis = archival_state.genesis_block.clone();
        archival_state
            .get_ancestor_block_digests(genesis.kernel.header.prev_block_digest, 10)
            .await;
    }

    #[traced_test]
    #[tokio::test]
    async fn digest_of_ancestors_test() {
        let mut rng = thread_rng();
        let mut archival_state = make_test_archival_state(Network::Alpha).await;
        let genesis = *archival_state.genesis_block.clone();
        let own_wallet = WalletSecret::new_random();
        let own_receiving_address = own_wallet.nth_generation_spending_key(0).to_address();

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
        let (mock_block_1, _, _) = make_mock_block_with_valid_pow(
            &genesis.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        )
        .await;
        add_block_to_archival_state(&mut archival_state, mock_block_1.clone())
            .await
            .unwrap();
        let (mock_block_2, _, _) = make_mock_block_with_valid_pow(
            &mock_block_1.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        )
        .await;
        add_block_to_archival_state(&mut archival_state, mock_block_2.clone())
            .await
            .unwrap();
        let (mock_block_3, _, _) = make_mock_block_with_valid_pow(
            &mock_block_2.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        )
        .await;
        add_block_to_archival_state(&mut archival_state, mock_block_3.clone())
            .await
            .unwrap();
        let (mock_block_4, _, _) = make_mock_block_with_valid_pow(
            &mock_block_3.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        )
        .await;
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
    #[tokio::test]
    async fn write_block_db_test() -> Result<()> {
        let mut rng = thread_rng();
        let mut archival_state = make_test_archival_state(Network::Alpha).await;
        let genesis = *archival_state.genesis_block.clone();
        let own_wallet = WalletSecret::new_random();
        let own_receiving_address = own_wallet.nth_generation_spending_key(0).to_address();

        let (mock_block_1, _, _) = make_mock_block_with_valid_pow(
            &genesis.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        )
        .await;
        archival_state
            .write_block(
                &mock_block_1,
                Some(genesis.kernel.header.proof_of_work_family),
            )
            .await?;

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
            .block_index_db
            .get(BlockIndexKey::Block(mock_block_1.hash()))
            .await
            .unwrap()
            .as_block_record();

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
        let (mock_block_2, _, _) = make_mock_block_with_valid_pow(
            &mock_block_1.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        )
        .await;
        archival_state
            .write_block(
                &mock_block_2,
                Some(mock_block_1.kernel.header.proof_of_work_family),
            )
            .await?;

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
            .block_index_db
            .get(BlockIndexKey::Block(mock_block_2.hash()))
            .await
            .unwrap()
            .as_block_record();

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
        let read_latest_block = archival_state.get_latest_block_from_disk().await?.unwrap();
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

        // Test `block_height_to_block_headers`
        let block_headers_of_height_2 =
            archival_state.block_height_to_block_headers(2.into()).await;
        assert_eq!(1, block_headers_of_height_2.len());
        assert_eq!(mock_block_2.kernel.header, block_headers_of_height_2[0]);

        // Test `get_children_blocks`
        let children_of_mock_block_1 = archival_state
            .get_children_block_headers(mock_block_1.kernel.mast_hash())
            .await;
        assert_eq!(1, children_of_mock_block_1.len());
        assert_eq!(mock_block_2.kernel.header, children_of_mock_block_1[0]);

        // Test `get_ancestor_block_digests`
        let ancestor_digests = archival_state
            .get_ancestor_block_digests(mock_block_2.hash(), 10)
            .await;
        assert_eq!(2, ancestor_digests.len());
        assert_eq!(mock_block_1.kernel.mast_hash(), ancestor_digests[0]);
        assert_eq!(genesis.kernel.mast_hash(), ancestor_digests[1]);

        Ok(())
    }

    use crate::config_models::{cli_args, data_directory::DataDirectory};

    #[traced_test]
    #[tokio::test]
    async fn can_initialize_mutator_set_database() {
        let args: cli_args::Args = cli_args::Args::default();
        let data_dir = DataDirectory::get(args.data_dir.clone(), args.network).unwrap();
        let _rams = ArchivalState::initialize_mutator_set(&data_dir)
            .await
            .unwrap();
    }
}
