use std::ops::DerefMut;
use std::path::PathBuf;

use anyhow::Result;
use memmap2::MmapOptions;
use num_traits::Zero;
use tokio::io::AsyncSeekExt;
use tokio::io::AsyncWriteExt;
use tokio::io::SeekFrom;
use tracing::debug;
use tracing::warn;
use twenty_first::math::digest::Digest;

use super::shared::new_block_file_is_needed;
use crate::config_models::data_directory::DataDirectory;
use crate::config_models::network::Network;
use crate::database::create_db_if_missing;
use crate::database::storage::storage_schema::traits::*;
use crate::database::NeptuneLevelDb;
use crate::database::WriteBatchAsync;
use crate::models::blockchain::block::block_header::BlockHeader;
use crate::models::blockchain::block::block_height::BlockHeight;
use crate::models::blockchain::block::Block;
use crate::models::database::BlockFileLocation;
use crate::models::database::BlockIndexKey;
use crate::models::database::BlockIndexValue;
use crate::models::database::BlockRecord;
use crate::models::database::FileRecord;
use crate::models::database::LastFileRecord;
use crate::prelude::twenty_first;
use crate::util_types::mutator_set::addition_record::AdditionRecord;
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
        network: Network,
    ) -> Self {
        let genesis_block = Box::new(Block::genesis_block(network));

        // If archival mutator set is empty, populate it with the addition records from genesis block
        // This assumes genesis block doesn't spend anything -- which it can't so that should be OK.
        // We could have populated the archival mutator set with the genesis block UTXOs earlier in
        // the setup, but we don't have the genesis block in scope before this function, so it makes
        // sense to do it here.
        if archival_mutator_set.ams().aocl.is_empty().await {
            for addition_record in genesis_block.kernel.body.transaction_kernel.outputs.iter() {
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

    pub fn genesis_block(&self) -> &Block {
        &self.genesis_block
    }

    /// Write a newly found block to database and to disk, and set it as tip.
    pub async fn write_block_as_tip(&mut self, new_block: &Block) -> Result<()> {
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

        // Mark block as tip
        block_index_entries.push((
            BlockIndexKey::BlockTipDigest,
            BlockIndexValue::BlockTipDigest(new_block.hash()),
        ));

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

    /// Return the latest block that was stored to disk. If no block has been stored to disk, i.e.
    /// if tip is genesis, then `None` is returned
    async fn get_tip_from_disk(&self) -> Result<Option<Block>> {
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
    pub async fn get_tip(&self) -> Block {
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
    pub async fn get_tip_parent(&self) -> Option<Block> {
        let tip_digest = self
            .block_index_db
            .get(BlockIndexKey::BlockTipDigest)
            .await?;
        let tip_digest: Digest = tip_digest.as_tip_digest();
        let tip_header = self
            .block_index_db
            .get(BlockIndexKey::Block(tip_digest))
            .await
            .map(|x| x.as_block_record().block_header)
            .expect("Indicated block must exist in block record");

        let parent = self
            .get_block(tip_header.prev_block_digest)
            .await
            .expect("Fetching indicated block must succeed");

        Some(parent.expect("Indicated block must exist"))
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

    // Return the block with a given block digest, iff it's available in state somewhere.
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

    /// Return the digest of canonical block at a specific height, or None
    pub async fn block_height_to_canonical_block_digest(
        &self,
        block_height: BlockHeight,
        tip_digest: Digest,
    ) -> Option<Digest> {
        let digests = self.block_height_to_block_digests(block_height).await;

        // note: there should only ever be 1 block at a given height that
        //       is in the canonical chain.
        //
        // note: we could do this with an async stream using equivalent of
        //       Iterator::find() but the for loop is easier to understand.
        //       see: https://stackoverflow.com/questions/74901029/rust-async-find-use-await-within-predicate
        for digest in digests.into_iter() {
            if self
                .block_belongs_to_canonical_chain(digest, tip_digest)
                .await
            {
                return Some(digest);
            }
        }
        None
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
                        "Cannot get block header from digest, even though digest was fetched from height. Digest: {}",
                        child_digest
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
            .unwrap_or_else(|| panic!("Could not get block header by digest: {}", block_digest));
        let tip_header = self
            .get_block_header(tip_digest)
            .await
            .unwrap_or_else(|| panic!("Could not get block header by digest: {}", tip_digest));

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
                .transaction_kernel
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
            for removal_record in roll_back_block.kernel.body.transaction_kernel.inputs.iter() {
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
                apply_forward_block
                    .kernel
                    .header
                    .timestamp
                    .standard_format()
            );

            let mut addition_records: Vec<AdditionRecord> = apply_forward_block
                .kernel
                .body
                .transaction_kernel
                .outputs
                .clone();
            addition_records.reverse();
            let mut removal_records = apply_forward_block
                .kernel
                .body
                .transaction_kernel
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
                    &self.archival_mutator_set.ams().accumulator().await,
                );

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
mod archival_state_tests {

    use rand::random;
    use rand::rngs::StdRng;
    use rand::thread_rng;
    use rand::Rng;
    use rand::RngCore;
    use rand::SeedableRng;
    use tracing_test::traced_test;

    use super::*;
    use crate::config_models::network::Network;
    use crate::database::storage::storage_vec::traits::*;
    use crate::models::blockchain::transaction::lock_script::LockScript;
    use crate::models::blockchain::transaction::utxo::Utxo;
    use crate::models::blockchain::transaction::PublicAnnouncement;
    use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
    use crate::models::proof_abstractions::timestamp::Timestamp;
    use crate::models::state::archival_state::ArchivalState;
    use crate::models::state::global_state_tests::create_transaction_with_timestamp;
    use crate::models::state::global_state_tests::create_transaction_with_timestamp_and_prover_capability;
    use crate::models::state::tx_proving_capability::TxProvingCapability;
    use crate::models::state::wallet::utxo_notification_pool::UtxoNotifier;
    use crate::models::state::wallet::WalletSecret;
    use crate::models::state::UtxoReceiverData;
    use crate::tests::shared::add_block_to_archival_state;
    use crate::tests::shared::make_mock_block_with_valid_pow;
    use crate::tests::shared::make_mock_transaction;
    use crate::tests::shared::mock_genesis_archival_state;
    use crate::tests::shared::mock_genesis_global_state;
    use crate::tests::shared::mock_genesis_wallet_state;
    use crate::tests::shared::unit_test_databases;

    async fn make_test_archival_state(network: Network) -> ArchivalState {
        let (block_index_db, _peer_db_lock, data_dir) = unit_test_databases(network).await.unwrap();

        let ams = ArchivalState::initialize_mutator_set(&data_dir)
            .await
            .unwrap();

        ArchivalState::new(data_dir, block_index_db, ams, network).await
    }

    #[traced_test]
    #[tokio::test]
    async fn initialize_archival_state_test() -> Result<()> {
        // Ensure that the archival state can be initialized without overflowing the stack
        let seed: [u8; 32] = thread_rng().gen();
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let network = Network::RegTest;

        let mut archival_state0 = make_test_archival_state(network).await;

        let b = Block::genesis_block(network);
        let some_wallet_secret = WalletSecret::new_random();
        let some_spending_key = some_wallet_secret.nth_generation_spending_key(0);
        let some_receiving_address = some_spending_key.to_address();

        let (block_1, _, _) =
            make_mock_block_with_valid_pow(&b, None, some_receiving_address, rng.gen());
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
        let network = Network::RegTest;
        let archival_state = make_test_archival_state(network).await;

        assert_eq!(
            Block::genesis_block(network)
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
            "Archival mutator set must be populated with premine outputs"
        );

        assert_eq!(
            Block::genesis_block(network).hash(),
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
            mock_genesis_wallet_state(WalletSecret::devnet_wallet(), network).await;
        let (mock_block_1, _, _) = make_mock_block_with_valid_pow(
            &archival_state.genesis_block,
            None,
            genesis_wallet_state
                .wallet_secret
                .nth_generation_spending_key(0)
                .to_address(),
            rng.gen(),
        );
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
            mock_genesis_wallet_state(WalletSecret::devnet_wallet(), network).await;
        let wallet = genesis_wallet_state.wallet_secret;
        let own_receiving_address = wallet.nth_generation_spending_key(0).to_address();
        let genesis_receiver_global_state_lock =
            mock_genesis_global_state(network, 0, wallet).await;
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
        );

        {
            genesis_receiver_global_state
                .set_new_tip(mock_block_1.clone())
                .await
                .unwrap();
            let ams_ref = &genesis_receiver_global_state
                .chain
                .archival_state()
                .archival_mutator_set;
            assert_ne!(0, ams_ref.ams().aocl.num_leafs().await);
        }

        let now = mock_block_1.kernel.header.timestamp;
        let seven_months = Timestamp::months(7);

        // Add an input to the next block's transaction. This will add a removal record
        // to the block, and this removal record will insert indices in the Bloom filter.
        {
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

            let mock_block_2 =
                Block::new_block_from_template(&mock_block_1, sender_tx, Timestamp::now(), None);

            // Remove an element from the mutator set, verify that the active window DB is updated.
            genesis_receiver_global_state
                .set_new_tip(mock_block_2.clone())
                .await?;

            let ams_ref = &genesis_receiver_global_state
                .chain
                .archival_state()
                .archival_mutator_set;
            assert_ne!(0, ams_ref.ams().swbf_active.sbf.len());
        }

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn update_mutator_set_rollback_ms_block_sync_test() -> Result<()> {
        let mut rng = thread_rng();
        let network = Network::Alpha;
        let (mut archival_state, _peer_db_lock, _data_dir) =
            mock_genesis_archival_state(network).await;
        let own_wallet = WalletSecret::new_random();
        let own_receiving_address = own_wallet.nth_generation_spending_key(0).to_address();

        // 1. Create new block 1 and store it to the DB
        let (mock_block_1a, _, _) = make_mock_block_with_valid_pow(
            &archival_state.genesis_block,
            None,
            own_receiving_address,
            rng.gen(),
        );
        archival_state.write_block_as_tip(&mock_block_1a).await?;

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
        );
        archival_state.write_block_as_tip(&mock_block_1a).await?;

        // 4. Update mutator set with that
        archival_state
            .update_mutator_set(&mock_block_1b)
            .await
            .unwrap();

        // 5. Experience rollback

        Ok(())
    }

    // #[traced_test]
    #[tokio::test]
    async fn update_mutator_set_rollback_ms_block_sync_multiple_inputs_outputs_in_block_test() {
        // Make a rollback of one block that contains multiple inputs and outputs.
        // This test is intended to verify that rollbacks work for non-trivial
        // blocks.

        let mut rng = thread_rng();
        let network = Network::RegTest;
        let (mut archival_state, _peer_db_lock, _data_dir) =
            mock_genesis_archival_state(network).await;
        let genesis_wallet_state =
            mock_genesis_wallet_state(WalletSecret::devnet_wallet(), network).await;
        let genesis_wallet = genesis_wallet_state.wallet_secret;
        let own_receiving_address = genesis_wallet.nth_generation_spending_key(0).to_address();
        let global_state_lock =
            mock_genesis_global_state(Network::RegTest, 42, genesis_wallet).await;
        let mut num_utxos = Block::premine_utxos(network).len();

        // 1. Create new block 1 with one input and four outputs and store it to disk
        let genesis_block = archival_state.genesis_block.clone();
        let now = genesis_block.kernel.header.timestamp;
        let seven_months = Timestamp::months(7);

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
        let (coinbase_tx, _) = global_state_lock
            .global_state_lock
            .lock_guard_mut()
            .await
            .make_coinbase_transaction(NeptuneCoins::zero(), Timestamp::now());
        let merged_tx = coinbase_tx.merge_with(sender_tx, Default::default());
        let block_1a = Block::new_block_from_template(
            &archival_state.genesis_block,
            merged_tx,
            now + seven_months,
            None,
        );

        assert!(block_1a.is_valid(&genesis_block, now + seven_months));

        {
            archival_state.write_block_as_tip(&block_1a).await.unwrap();

            // 2. Update mutator set with this
            archival_state.update_mutator_set(&block_1a).await.unwrap();

            // 3. Create competing block 1 and store it to DB
            let (mock_block_1b, _, _) = make_mock_block_with_valid_pow(
                &archival_state.genesis_block,
                None,
                own_receiving_address,
                rng.gen(),
            );
            archival_state
                .write_block_as_tip(&mock_block_1b)
                .await
                .unwrap();
            num_utxos += mock_block_1b.body().transaction_kernel.outputs.len();

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
                .aocl
                .num_leafs()
                .await as usize,
            "AOCL leaf count must agree with blockchain after rollback"
        );
    }

    #[traced_test]
    #[tokio::test]
    async fn update_mutator_set_rollback_many_blocks_multiple_inputs_outputs_test() -> Result<()> {
        // Make a rollback of multiple blocks that contains multiple inputs and outputs.
        // This test is intended to verify that rollbacks work for non-trivial
        // blocks, also when there are many blocks that push the active window of the
        // mutator set forwards.

        let network = Network::RegTest;
        let mut rng = thread_rng();
        let genesis_wallet_state =
            mock_genesis_wallet_state(WalletSecret::devnet_wallet(), network).await;
        let genesis_wallet = genesis_wallet_state.wallet_secret;
        let own_receiving_address = genesis_wallet.nth_generation_spending_key(0).to_address();
        let global_state_lock =
            mock_genesis_global_state(Network::RegTest, 42, genesis_wallet).await;

        let mut global_state = global_state_lock.lock_guard_mut().await;
        let genesis_block: Block = *global_state.chain.archival_state().genesis_block.to_owned();
        let mut num_utxos = Block::premine_utxos(network).len();
        let mut previous_block = genesis_block.clone();

        let in_seven_months = Timestamp::now() + Timestamp::months(7);

        for _ in 0..10 {
            // Create next block with inputs and outputs

            let removal_records = {
                let (_, _, rr0) = mock_item_mp_rr_for_init_msa();
                let (_, _, rr1) = mock_item_mp_rr_for_init_msa();
                vec![rr0, rr1]
            };
            let addition_records = vec![];

            let tx = make_mock_transaction(removal_records, addition_records);
            let next_block =
                Block::new_block_from_template(&previous_block, tx, in_seven_months, None);

            // 2. Update archival-mutator set with produced block
            global_state.set_new_tip(next_block.clone()).await.unwrap();

            previous_block = next_block;
        }

        {
            // 3. Create competing block 1 and treat it as new tip
            let (mock_block_1b, _, _) = make_mock_block_with_valid_pow(
                &genesis_block,
                None,
                own_receiving_address,
                rng.gen(),
            );
            num_utxos += mock_block_1b.body().transaction_kernel.outputs.len();

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
                .aocl
                .num_leafs().await as usize,
            "AOCL leaf count must agree with #premine allocations + #transaction outputs in all blocks, even after rollback"
        );

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn allow_consumption_of_genesis_output_test() -> Result<()> {
        let network = Network::Main;
        let genesis_wallet_state =
            mock_genesis_wallet_state(WalletSecret::devnet_wallet(), network).await;
        let genesis_wallet = genesis_wallet_state.wallet_secret;
        let genesis_block = Block::genesis_block(network);
        let in_seven_months = genesis_block.kernel.header.timestamp + Timestamp::months(7);
        let global_state_lock = mock_genesis_global_state(network, 42, genesis_wallet).await;
        let mut global_state = global_state_lock.lock_guard_mut().await;
        let mut rng = StdRng::seed_from_u64(87255549301u64);

        let (cbtx, _cb_expected) =
            global_state.make_coinbase_transaction(NeptuneCoins::zero(), in_seven_months);
        let one_money: NeptuneCoins = NeptuneCoins::new(1);
        let anyone_can_spend_utxo =
            Utxo::new_native_coin(LockScript::anyone_can_spend(), one_money);
        let receiver_data = UtxoReceiverData::new(anyone_can_spend_utxo, rng.gen(), rng.gen());
        let sender_tx = global_state
            .create_transaction_with_prover_capability(
                vec![receiver_data],
                one_money,
                in_seven_months,
                TxProvingCapability::SingleProof,
            )
            .await
            .unwrap();
        let block_tx = sender_tx.merge_with(cbtx, Default::default());
        let block_1 =
            Block::new_block_from_template(&genesis_block, block_tx, in_seven_months, None);

        // Verify that block_1 is valid. We don't care about PoW for this test.
        assert!(block_1.is_valid(&genesis_block, in_seven_months));

        // 3 outputs: 1 coinbase, 1 for recipient of tx, 1 for change.
        assert_eq!(3, block_1.body().transaction_kernel.outputs.len());

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn allow_multiple_inputs_and_outputs_in_block() {
        // Test various parts of the state update when a block contains multiple inputs and outputs
        let network = Network::Main;
        let genesis_wallet_state =
            mock_genesis_wallet_state(WalletSecret::devnet_wallet(), network).await;
        let genesis_spending_key = genesis_wallet_state
            .wallet_secret
            .nth_generation_spending_key(0);
        let genesis =
            mock_genesis_global_state(network, 3, genesis_wallet_state.wallet_secret).await;
        let mut rng = StdRng::seed_from_u64(41251549301u64);

        let wallet_secret_alice = WalletSecret::new_pseudorandom(rng.gen());
        let alice_spending_key = wallet_secret_alice.nth_generation_spending_key(0);
        let alice_state_lock = mock_genesis_global_state(network, 3, wallet_secret_alice).await;

        let wallet_secret_bob = WalletSecret::new_pseudorandom(rng.gen());
        let bob_spending_key = wallet_secret_bob.nth_generation_spending_key(0);
        let bob_state_lock = mock_genesis_global_state(network, 3, wallet_secret_bob).await;

        let genesis_block = Block::genesis_block(network);
        let in_seven_months = genesis_block.kernel.header.timestamp + Timestamp::months(7);

        println!("Generated initial states and genesis block");

        // Send two outputs each to Alice and Bob, from genesis receiver
        let sender_randomness: Digest = rng.gen();
        let alice_address = alice_spending_key.to_address();
        let receiver_data_for_alice = vec![
            UtxoReceiverData::new(
                Utxo::new_native_coin(alice_address.lock_script(), NeptuneCoins::new(1)),
                sender_randomness,
                alice_address.privacy_digest,
            ),
            UtxoReceiverData::new(
                Utxo::new_native_coin(alice_address.lock_script(), NeptuneCoins::new(9)),
                sender_randomness,
                alice_address.privacy_digest,
            ),
        ];
        // Two outputs for Bob
        let bob_address = bob_spending_key.to_address();

        let receiver_data_for_bob = vec![
            UtxoReceiverData::new(
                Utxo::new_native_coin(bob_address.lock_script(), NeptuneCoins::new(2)),
                sender_randomness,
                bob_address.privacy_digest,
            ),
            UtxoReceiverData::new(
                Utxo::new_native_coin(bob_address.lock_script(), NeptuneCoins::new(3)),
                sender_randomness,
                bob_address.privacy_digest,
            ),
        ];

        println!("Before tx creation");
        let fee = NeptuneCoins::new(1);
        let tx_to_alice_and_bob = create_transaction_with_timestamp_and_prover_capability(
            &genesis,
            [
                receiver_data_for_alice.clone(),
                receiver_data_for_bob.clone(),
            ]
            .concat(),
            fee,
            in_seven_months,
            TxProvingCapability::SingleProof,
        )
        .await
        .unwrap();
        println!("Generated transaction for Alice and Bob.");

        let (cbtx, cb_expected) = genesis
            .lock_guard_mut()
            .await
            .make_coinbase_transaction(NeptuneCoins::zero(), in_seven_months);
        let block_tx = cbtx.merge_with(tx_to_alice_and_bob, Default::default());
        println!("Generated block transaction");

        let block_1 =
            Block::new_block_from_template(&genesis_block, block_tx, in_seven_months, None);
        println!("Generated block");

        // Verify validity
        assert!(block_1.is_valid(&genesis_block, in_seven_months));

        println!("Accumulated transaction into block_1.");
        println!(
            "Transaction has {} inputs (removal records) and {} outputs (addition records)",
            block_1.kernel.body.transaction_kernel.inputs.len(),
            block_1.kernel.body.transaction_kernel.outputs.len()
        );

        // Expect incoming transactions
        {
            let mut genesis_state = genesis.lock_guard_mut().await;
            genesis_state
                .wallet_state
                .expected_utxos
                .add_expected_utxo(
                    cb_expected.utxo,
                    cb_expected.sender_randomness,
                    genesis_spending_key.privacy_preimage,
                    UtxoNotifier::OwnMiner,
                )
                .unwrap();
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
        }

        // Update chain states
        for state_lock in [&genesis, &alice_state_lock, &bob_state_lock] {
            let mut state = state_lock.lock_guard_mut().await;
            state.set_new_tip(block_1.clone()).await.unwrap();
        }

        {
            let genesis_state = genesis.lock_guard_mut().await;
            assert_eq!(
                3,
                genesis_state
                .wallet_state
                .wallet_db
                .monitored_utxos()
                .len().await, "Genesis receiver must have 3 UTXOs after block 1: change from transaction, coinbase from block 1, and the spent premine UTXO"
            );
        }

        // Check balances
        assert_eq!(
            NeptuneCoins::new(10),
            alice_state_lock
                .lock_guard()
                .await
                .get_wallet_status_for_tip()
                .await
                .synced_unspent_available_amount(in_seven_months)
        );
        assert_eq!(
            NeptuneCoins::new(5),
            bob_state_lock
                .lock_guard()
                .await
                .get_wallet_status_for_tip()
                .await
                .synced_unspent_available_amount(in_seven_months)
        );

        println!("Transactions were received in good order.");

        // Make two transactions: Alice sends two UTXOs to Genesis (1 + 8 coins and 1 in fee)
        // and Bob sends three UTXOs to genesis (1 + 1 + 1 and 1 in fee)
        let genesis_address = genesis_spending_key.to_address();
        let receiver_data_from_alice = vec![
            UtxoReceiverData::new(
                Utxo::new_native_coin(genesis_address.lock_script(), NeptuneCoins::new(1)),
                rng.gen(),
                genesis_address.privacy_digest,
            ),
            UtxoReceiverData::new(
                Utxo::new_native_coin(genesis_address.lock_script(), NeptuneCoins::new(8)),
                rng.gen(),
                genesis_address.privacy_digest,
            ),
        ];
        let tx_from_alice = alice_state_lock
            .lock_guard_mut()
            .await
            .create_transaction_with_prover_capability(
                receiver_data_from_alice.clone(),
                NeptuneCoins::new(1),
                in_seven_months,
                TxProvingCapability::SingleProof,
            )
            .await
            .unwrap();
        let receiver_data_from_bob = vec![
            UtxoReceiverData::new(
                Utxo::new_native_coin(genesis_address.lock_script(), NeptuneCoins::new(1)),
                rng.gen(),
                genesis_address.privacy_digest,
            ),
            UtxoReceiverData::new(
                Utxo::new_native_coin(genesis_address.lock_script(), NeptuneCoins::new(1)),
                rng.gen(),
                genesis_address.privacy_digest,
            ),
            UtxoReceiverData::new(
                Utxo::new_native_coin(genesis_address.lock_script(), NeptuneCoins::new(2)),
                rng.gen(),
                genesis_address.privacy_digest,
            ),
        ];
        let tx_from_bob = create_transaction_with_timestamp_and_prover_capability(
            &bob_state_lock,
            receiver_data_from_bob.clone(),
            NeptuneCoins::new(1),
            in_seven_months,
            TxProvingCapability::SingleProof,
        )
        .await
        .unwrap();

        println!("Generated new transaction to Alice and Bob");

        // Make block_2 with tx that contains:
        // - 4 inputs: 2 from Alice and 2 from Bob
        // - 6 outputs: 2 from Alice to Genesis, 3 from Bob to Genesis, and 1 coinbase to Genesis
        let (cbtx2, cb_expected2) = genesis
            .lock_guard()
            .await
            .make_coinbase_transaction(NeptuneCoins::zero(), in_seven_months);
        let block_tx2 = cbtx2
            .merge_with(tx_from_alice, Default::default())
            .merge_with(tx_from_bob, Default::default());
        let block_2 = Block::new_block_from_template(&block_1, block_tx2, in_seven_months, None);

        println!("Generated new block");

        // Sanity checks
        assert_eq!(4, block_2.kernel.body.transaction_kernel.inputs.len());
        assert_eq!(6, block_2.kernel.body.transaction_kernel.outputs.len());
        assert!(block_2.is_valid(&block_1, in_seven_months));

        // Expect incoming UTXOs
        for rec_data in receiver_data_from_alice
            .into_iter()
            .chain(receiver_data_from_bob)
        {
            genesis
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

        genesis
            .lock_guard_mut()
            .await
            .wallet_state
            .expected_utxos
            .add_expected_utxo(
                cb_expected2.utxo,
                cb_expected2.sender_randomness,
                genesis_spending_key.privacy_preimage,
                UtxoNotifier::OwnMiner,
            )
            .unwrap();

        // Update chain states
        for state_lock in [&genesis, &alice_state_lock, &bob_state_lock] {
            let mut state = state_lock.lock_guard_mut().await;
            state.set_new_tip(block_2.clone()).await.unwrap();
        }

        assert!(alice_state_lock
            .lock_guard()
            .await
            .get_wallet_status_for_tip()
            .await
            .synced_unspent_available_amount(in_seven_months)
            .is_zero());
        assert!(bob_state_lock
            .lock_guard()
            .await
            .get_wallet_status_for_tip()
            .await
            .synced_unspent_available_amount(in_seven_months)
            .is_zero());

        // Verify that all ingoing UTXOs are recorded in wallet of receiver of genesis UTXO
        assert_eq!(
            9,
            genesis.lock_guard().await
                .wallet_state
                .wallet_db
                .monitored_utxos()
                .len().await, "Genesis receiver must have 9 UTXOs after block 2: 3 after block 1, and 6 added by block 2"
        );

        // Verify that mutator sets are updated correctly and that last block is block 2
        for state_lock in [&genesis, &alice_state_lock, &bob_state_lock] {
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
            assert_eq!(block_2, state.chain.archival_state().get_tip().await);
            assert_eq!(
                block_1,
                state.chain.archival_state().get_tip_parent().await.unwrap()
            );
        }
    }

    #[traced_test]
    #[tokio::test]
    // Added due to clippy warning produced by `traced_test` test framework.
    #[allow(clippy::needless_return)]
    async fn get_tip_block_test() -> Result<()> {
        for network in [
            Network::Alpha,
            Network::Beta,
            Network::Main,
            Network::RegTest,
            Network::Testnet,
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
            let mut rng = thread_rng();
            let own_wallet = WalletSecret::new_random();
            let own_receiving_address = own_wallet.nth_generation_spending_key(0).to_address();
            let genesis = *archival_state.genesis_block.clone();
            let (mock_block_1, _, _) =
                make_mock_block_with_valid_pow(&genesis, None, own_receiving_address, rng.gen());
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
            let (mock_block_2, _, _) = make_mock_block_with_valid_pow(
                &mock_block_1,
                None,
                own_receiving_address,
                rng.gen(),
            );
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
        }

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
        );

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
        );
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
                make_mock_block_with_valid_pow(&last_block, None, own_receiving_address, rng.gen());
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
        );
        add_block_to_archival_state(&mut archival_state, mock_block_1_a.clone()).await?;

        let (mock_block_1_b, _, _) = make_mock_block_with_valid_pow(
            &genesis.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        );
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
                .block_belongs_to_canonical_chain(genesis.hash(), genesis.hash())
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
        );
        add_block_to_archival_state(&mut archival_state, mock_block_1.clone()).await?;
        assert!(
            archival_state
                .block_belongs_to_canonical_chain(genesis.hash(), mock_block_1.hash())
                .await,
            "Genesis block is always part of the canonical chain, tip parent"
        );
        assert!(
            archival_state
                .block_belongs_to_canonical_chain(mock_block_1.hash(), mock_block_1.hash())
                .await,
            "Tip block is always part of the canonical chain"
        );

        // Insert three more blocks and verify that all are part of the canonical chain
        let (mock_block_2_a, _, _) = make_mock_block_with_valid_pow(
            &mock_block_1.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        );
        add_block_to_archival_state(&mut archival_state, mock_block_2_a.clone()).await?;
        let (mock_block_3_a, _, _) = make_mock_block_with_valid_pow(
            &mock_block_2_a.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        );
        add_block_to_archival_state(&mut archival_state, mock_block_3_a.clone()).await?;
        let (mock_block_4_a, _, _) = make_mock_block_with_valid_pow(
            &mock_block_3_a.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        );
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
                    .block_belongs_to_canonical_chain(block.hash(), mock_block_4_a.hash())
                    .await,
                "block {} does not belong to canonical chain",
                i
            );
            dag_walker_leash_prop(block.hash(), mock_block_4_a.hash(), &archival_state).await;
            dag_walker_leash_prop(mock_block_4_a.hash(), block.hash(), &archival_state).await;
        }

        assert!(
            archival_state
                .block_belongs_to_canonical_chain(genesis.hash(), mock_block_4_a.hash())
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
        );
        add_block_to_archival_state(&mut archival_state, mock_block_2_b.clone()).await?;
        let (mock_block_3_b, _, _) = make_mock_block_with_valid_pow(
            &mock_block_2_b.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        );
        add_block_to_archival_state(&mut archival_state, mock_block_3_b.clone()).await?;
        let (mock_block_4_b, _, _) = make_mock_block_with_valid_pow(
            &mock_block_3_b.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        );
        add_block_to_archival_state(&mut archival_state, mock_block_4_b.clone()).await?;
        let (mock_block_5_b, _, _) = make_mock_block_with_valid_pow(
            &mock_block_4_b.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        );
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
                    .block_belongs_to_canonical_chain(block.hash(), mock_block_4_a.hash())
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
                    .block_belongs_to_canonical_chain(block.hash(), mock_block_4_a.hash())
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
        );
        add_block_to_archival_state(&mut archival_state, mock_block_3_c.clone()).await?;
        let (mock_block_4_c, _, _) = make_mock_block_with_valid_pow(
            &mock_block_3_c.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        );
        add_block_to_archival_state(&mut archival_state, mock_block_4_c.clone()).await?;
        let (mock_block_5_c, _, _) = make_mock_block_with_valid_pow(
            &mock_block_4_c.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        );
        add_block_to_archival_state(&mut archival_state, mock_block_5_c.clone()).await?;
        let (mock_block_6_c, _, _) = make_mock_block_with_valid_pow(
            &mock_block_5_c.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        );
        add_block_to_archival_state(&mut archival_state, mock_block_6_c.clone()).await?;
        let (mock_block_7_c, _, _) = make_mock_block_with_valid_pow(
            &mock_block_6_c.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        );
        add_block_to_archival_state(&mut archival_state, mock_block_7_c.clone()).await?;
        let (mock_block_8_c, _, _) = make_mock_block_with_valid_pow(
            &mock_block_7_c.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        );
        add_block_to_archival_state(&mut archival_state, mock_block_8_c.clone()).await?;
        let (mock_block_5_a, _, _) = make_mock_block_with_valid_pow(
            &mock_block_4_a.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        );
        add_block_to_archival_state(&mut archival_state, mock_block_5_a.clone()).await?;
        let (mock_block_3_d, _, _) = make_mock_block_with_valid_pow(
            &mock_block_2_a.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        );
        add_block_to_archival_state(&mut archival_state, mock_block_3_d.clone()).await?;
        let (mock_block_4_d, _, _) = make_mock_block_with_valid_pow(
            &mock_block_3_d.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        );
        add_block_to_archival_state(&mut archival_state, mock_block_4_d.clone()).await?;
        let (mock_block_5_d, _, _) = make_mock_block_with_valid_pow(
            &mock_block_4_d.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        );
        add_block_to_archival_state(&mut archival_state, mock_block_5_d.clone()).await?;

        // This is the most canonical block in the known set
        let (mock_block_6_d, _, _) = make_mock_block_with_valid_pow(
            &mock_block_5_d.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        );
        add_block_to_archival_state(&mut archival_state, mock_block_6_d.clone()).await?;

        let (mock_block_4_e, _, _) = make_mock_block_with_valid_pow(
            &mock_block_3_d.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        );
        add_block_to_archival_state(&mut archival_state, mock_block_4_e.clone()).await?;
        let (mock_block_5_e, _, _) = make_mock_block_with_valid_pow(
            &mock_block_4_e.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        );
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
                    .block_belongs_to_canonical_chain(block.hash(), mock_block_6_d.hash())
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
                    .block_belongs_to_canonical_chain(block.hash(), mock_block_6_d.hash())
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
        );
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
                    .block_belongs_to_canonical_chain(block.hash(), mock_block_6_b.hash())
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
                    .block_belongs_to_canonical_chain(block.hash(), mock_block_6_b.hash())
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
        );
        add_block_to_archival_state(&mut archival_state, mock_block_1.clone())
            .await
            .unwrap();
        let (mock_block_2, _, _) = make_mock_block_with_valid_pow(
            &mock_block_1.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        );
        add_block_to_archival_state(&mut archival_state, mock_block_2.clone())
            .await
            .unwrap();
        let (mock_block_3, _, _) = make_mock_block_with_valid_pow(
            &mock_block_2.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        );
        add_block_to_archival_state(&mut archival_state, mock_block_3.clone())
            .await
            .unwrap();
        let (mock_block_4, _, _) = make_mock_block_with_valid_pow(
            &mock_block_3.clone(),
            None,
            own_receiving_address,
            rng.gen(),
        );
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
        );
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
        );
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

        // Test `block_height_to_block_headers`
        let block_headers_of_height_2 =
            archival_state.block_height_to_block_headers(2.into()).await;
        assert_eq!(1, block_headers_of_height_2.len());
        assert_eq!(mock_block_2.kernel.header, block_headers_of_height_2[0]);

        // Test `get_children_blocks`
        let children_of_mock_block_1 = archival_state
            .get_children_block_headers(mock_block_1.hash())
            .await;
        assert_eq!(1, children_of_mock_block_1.len());
        assert_eq!(mock_block_2.kernel.header, children_of_mock_block_1[0]);

        // Test `get_ancestor_block_digests`
        let ancestor_digests = archival_state
            .get_ancestor_block_digests(mock_block_2.hash(), 10)
            .await;
        assert_eq!(2, ancestor_digests.len());
        assert_eq!(mock_block_1.hash(), ancestor_digests[0]);
        assert_eq!(genesis.hash(), ancestor_digests[1]);

        Ok(())
    }

    use crate::config_models::cli_args;
    use crate::config_models::data_directory::DataDirectory;
    use crate::util_types::test_shared::mutator_set::mock_item_mp_rr_for_init_msa;

    #[traced_test]
    #[tokio::test]
    async fn can_initialize_mutator_set_database() {
        let args: cli_args::Args = cli_args::Args::default();
        let data_dir = DataDirectory::get(args.data_dir.clone(), args.network).unwrap();
        println!("data_dir for MS initialization test: {data_dir}");
        let _rams = ArchivalState::initialize_mutator_set(&data_dir)
            .await
            .unwrap();
    }
}
