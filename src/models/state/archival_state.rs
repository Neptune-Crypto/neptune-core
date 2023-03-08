use anyhow::{Context, Result};
use memmap2::MmapOptions;
use num_traits::Zero;
use rusty_leveldb::DB;
use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::ops::DerefMut;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;
use tracing::debug;
use twenty_first::shared_math::rescue_prime_digest::Digest;
use twenty_first::util_types::emojihash_trait::Emojihash;

use mutator_set_tf::util_types::mutator_set::addition_record::AdditionRecord;
use mutator_set_tf::util_types::mutator_set::archival_mutator_set::ArchivalMutatorSet;
use mutator_set_tf::util_types::mutator_set::mutator_set_trait::MutatorSet;
use mutator_set_tf::util_types::mutator_set::removal_record::RemovalRecord;
use twenty_first::amount::u32s::U32s;
use twenty_first::util_types::{algebraic_hasher::AlgebraicHasher, mmr::mmr_trait::Mmr};

use super::shared::new_block_file_is_needed;
use crate::config_models::data_directory::DataDirectory;
use crate::database::leveldb::LevelDB;
use crate::database::rusty::{default_options, RustyLevelDB};
use crate::models::blockchain::block::block_header::{BlockHeader, PROOF_OF_WORK_COUNT_U32_SIZE};
use crate::models::blockchain::block::{block_height::BlockHeight, Block};
use crate::models::blockchain::shared::Hash;
use crate::models::database::{
    BlockFileLocation, BlockIndexKey, BlockIndexValue, BlockRecord, FileRecord, LastFileRecord,
    MsBlockSyncKey, MsBlockSyncValue,
};

pub const BLOCK_INDEX_DB_NAME: &str = "block_index";
pub const MUTATOR_SET_DIRECTORY_NAME: &str = "mutator_set";
pub const MS_AOCL_MMR_DB_NAME: &str = "aocl_mmr";
pub const MS_SWBF_INACTIVE_MMR_DB_NAME: &str = "swbfi_mmr";
pub const MS_SWBF_ACTIVE_DB_NAME: &str = "swbfa_mmr";
pub const MS_CHUNKS_DB_NAME: &str = "chunks";
pub const MS_BLOCK_SYNC_DB_NAME: &str = "ms_block_sync";

#[derive(Clone)]
pub struct ArchivalState {
    data_dir: DataDirectory,

    // Since this is a database, we use the tokio Mutex here.
    pub block_index_db: Arc<TokioMutex<RustyLevelDB<BlockIndexKey, BlockIndexValue>>>,

    // The genesis block is stored on the heap, as we would otherwise get stack overflows whenever we instantiate
    // this object in a spawned worker thread.
    genesis_block: Box<Block>,

    // The archival mutator set is three databases and one array that lives in memory that needs
    // to be persisted in a database. So it involves four databases where the last one is opened
    // and closed as needed and the other ones are kept open throughout the lifetime of the program.
    // The fourth database is the active window that is small enough to that we can keep it in RAM
    // but we need to persist it when the program is shut down and started again. The database of
    // the active window is not exposed outside of this module.
    pub archival_mutator_set: Arc<TokioMutex<ArchivalMutatorSet<Hash>>>,

    pub ms_block_sync_db: Arc<TokioMutex<RustyLevelDB<MsBlockSyncKey, MsBlockSyncValue>>>,
}

impl ArchivalState {
    /// Create databases for block persistence
    pub fn initialize_block_index_database(
        data_dir: &DataDirectory,
    ) -> Result<RustyLevelDB<BlockIndexKey, BlockIndexValue>> {
        let block_index_db_dir_path = data_dir.block_index_database_dir_path();
        DataDirectory::create_dir_if_not_exists(&block_index_db_dir_path)?;

        let block_index = RustyLevelDB::<BlockIndexKey, BlockIndexValue>::new(
            &block_index_db_dir_path,
            default_options(),
        )?;

        Ok(block_index)
    }

    /// Return the database for active window. This should not be public.
    /// This should be fetched when constructing the mutator set, and when persisting the state
    /// of the active window. This is factored out to a separate function because it's used
    /// multiple places.
    /// FIXME: Share `rusty_leveldb::Options` between `DB`s.
    fn active_window_db(data_dir: &DataDirectory) -> Result<DB> {
        let active_window_dir_path = data_dir.active_window_database_dir_path();
        println!("{}", active_window_dir_path.display());
        DataDirectory::create_dir_if_not_exists(&active_window_dir_path)?;
        DB::open(active_window_dir_path, default_options()).context("Opening DB for active window")
    }

    /// Initialize an `ArchivalMutatorSet` by opening or creating its databases.
    ///
    /// Additionally, return a `RustyLevelDB<MsBlockSyncKey, MsBlockSyncValue>`
    /// for synchronising the mutator set with the block index database.
    pub fn initialize_mutator_set(
        data_dir: &DataDirectory,
    ) -> Result<(
        ArchivalMutatorSet<Hash>,
        RustyLevelDB<MsBlockSyncKey, MsBlockSyncValue>,
    )> {
        let ms_db_dir_path = data_dir.mutator_set_database_dir_path();
        DataDirectory::create_dir_if_not_exists(&ms_db_dir_path)?;

        let options = rusty_leveldb::Options::default();

        let aocl_db_path = data_dir.aocl_database_dir_path();
        let aocl_mmr_db = DB::open(aocl_db_path, options.clone())?;

        let swbfi_db_path = data_dir.swbfi_database_dir_path();
        let swbf_inactive_mmr_db = DB::open(swbfi_db_path, options.clone())?;

        let chunks_db_path = data_dir.chunks_database_dir_path();
        let chunks_db = DB::open(chunks_db_path, options.clone())?;

        let active_window_db = Self::active_window_db(data_dir)?;

        let archival_set = ArchivalMutatorSet::<Hash>::new_or_restore(
            aocl_mmr_db,
            swbf_inactive_mmr_db,
            chunks_db,
            active_window_db,
        );

        let ms_block_sync_db_path = data_dir.mutator_set_block_sync_database_dir_path();
        let ms_block_sync = RustyLevelDB::new(&ms_block_sync_db_path, options)?;

        Ok((archival_set, ms_block_sync))
    }
}

// FIXME: The `Debug` for `ArchivalState` does not contain `archival_mutator_set` or `ms_block_sync_db`. Is this intentional?
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
    pub async fn new(
        data_dir: DataDirectory,
        block_index_db: Arc<TokioMutex<RustyLevelDB<BlockIndexKey, BlockIndexValue>>>,
        archival_mutator_set: Arc<TokioMutex<ArchivalMutatorSet<Hash>>>,
        ms_block_sync_db: Arc<TokioMutex<RustyLevelDB<MsBlockSyncKey, MsBlockSyncValue>>>,
    ) -> Self {
        let genesis_block = Box::new(Block::genesis_block());

        // If archival mutator set is empty, populate it with the addition records from genesis block
        // This assumes genesis block doesn't spend anything -- which it can't so that should be OK.
        // We could have populated the archival mutator set with the genesis block UTXOs earlier in
        // the setup, but we don't have the genesis block in scope before this function, so it makes
        // sense to do it here.
        {
            let mut ams_lock = archival_mutator_set.lock().await;
            let ams_is_empty = ams_lock.set_commitment.aocl.count_leaves().is_zero();
            if ams_is_empty {
                for mut addition_record in genesis_block.body.mutator_set_update.additions.clone() {
                    ams_lock.add(&mut addition_record);
                }
            }

            ams_lock.flush();
        }

        Self {
            data_dir,
            block_index_db,
            genesis_block,
            archival_mutator_set,
            ms_block_sync_db,
        }
    }

    /// Write a newly found block to database and to disk. A lock should be held over light state
    /// while this function call is executed.
    pub fn write_block(
        &self,
        new_block: Box<Block>,
        db_lock: &mut tokio::sync::MutexGuard<'_, RustyLevelDB<BlockIndexKey, BlockIndexValue>>,
        current_max_pow_family: Option<U32s<PROOF_OF_WORK_COUNT_U32_SIZE>>,
    ) -> Result<()> {
        // Fetch last file record to find disk location to store block.
        // This record must exist in the DB already, unless this is the first block
        // stored on disk.
        let mut last_rec: LastFileRecord = match db_lock
            .get(BlockIndexKey::LastFile)
            .map(|x| x.as_last_file_record())
        {
            Some(rec) => rec,
            None => LastFileRecord::default(),
        };

        // Open the file that was last used for storing a block
        let mut block_file_path = self.data_dir.block_file_path(last_rec.last_file);
        let serialized_block: Vec<u8> = bincode::serialize(&new_block)?;
        let serialized_block_size: u64 = serialized_block.len() as u64;
        let mut block_file = DataDirectory::open_ensure_parent_dir_exists(&block_file_path)?;

        // Check if we should use the last file, or we need a new one.
        if new_block_file_is_needed(&block_file, serialized_block_size) {
            last_rec = LastFileRecord {
                last_file: last_rec.last_file + 1,
            };
            block_file_path = self.data_dir.block_file_path(last_rec.last_file);
            block_file = DataDirectory::open_ensure_parent_dir_exists(&block_file_path)?;
        }

        debug!("Writing block to: {}", block_file_path.display());
        // Get associated file record from database, otherwise create it
        let file_record_key: BlockIndexKey = BlockIndexKey::File(last_rec.last_file);
        let file_record_value: Option<FileRecord> = db_lock
            .get(file_record_key.clone())
            .map(|x| x.as_file_record());
        let file_record_value: FileRecord = match file_record_value {
            Some(record) => record.add(serialized_block_size, &new_block.header),
            None => {
                assert!(
                    block_file.metadata().unwrap().len().is_zero(),
                    "If no file record exists, block file must be empty"
                );
                FileRecord::new(serialized_block_size, &new_block.header)
            }
        };

        // Make room in file for mmapping and record where block starts
        let pos = block_file.seek(SeekFrom::End(0)).unwrap();
        debug!("Size of file prior to block writing: {}", pos);
        block_file
            .seek(SeekFrom::Current(serialized_block_size as i64 - 1))
            .unwrap();
        block_file.write_all(&[0]).unwrap();
        let file_offset: u64 = block_file
            .seek(SeekFrom::Current(-(serialized_block_size as i64)))
            .unwrap();
        debug!(
            "New file size: {} bytes",
            block_file.metadata().unwrap().len()
        );

        let height_record_key = BlockIndexKey::Height(new_block.header.height);
        let mut blocks_at_same_height: Vec<Digest> = match db_lock.get(height_record_key.clone()) {
            Some(rec) => rec.as_height_record(),
            None => vec![],
        };

        // Write to file with mmap, only map relevant part of file into memory
        let mmap = unsafe {
            MmapOptions::new()
                .offset(pos)
                .len(serialized_block_size as usize)
                .map(&block_file)?
        };
        let mut mmap: memmap2::MmapMut = mmap.make_mut().unwrap();
        mmap.deref_mut()[..].copy_from_slice(&serialized_block);

        // Update block index database with newly stored block
        let mut block_index_entries: Vec<(BlockIndexKey, BlockIndexValue)> = vec![];
        let block_record_key: BlockIndexKey = BlockIndexKey::Block(new_block.hash);
        let block_record_value: BlockIndexValue = BlockIndexValue::Block(Box::new(BlockRecord {
            block_header: new_block.header.clone(),
            file_location: BlockFileLocation {
                file_index: last_rec.last_file,
                offset: file_offset,
                block_length: serialized_block_size as usize,
            },
        }));

        block_index_entries.push((file_record_key, BlockIndexValue::File(file_record_value)));
        block_index_entries.push((block_record_key, block_record_value));

        block_index_entries.push((BlockIndexKey::LastFile, BlockIndexValue::LastFile(last_rec)));
        blocks_at_same_height.push(new_block.hash);
        block_index_entries.push((
            height_record_key,
            BlockIndexValue::Height(blocks_at_same_height),
        ));

        // Mark block as tip if its PoW family is larger than current most canonical
        if current_max_pow_family.is_none()
            || current_max_pow_family.unwrap() < new_block.header.proof_of_work_family
        {
            block_index_entries.push((
                BlockIndexKey::BlockTipDigest,
                BlockIndexValue::BlockTipDigest(new_block.hash),
            ));
        }

        db_lock.batch_write(&block_index_entries);

        Ok(())
    }

    fn get_block_from_block_record(&self, block_record: BlockRecord) -> Result<Block> {
        // Get path of file for block
        let block_file_path: PathBuf = self
            .data_dir
            .block_file_path(block_record.file_location.file_index);

        // Open file as read-only
        let block_file: fs::File = fs::OpenOptions::new()
            .read(true)
            .open(block_file_path)
            .unwrap();

        // Read the file into memory, set the offset and length indicated in the block record
        // to avoid using more memory than needed
        let mmap = unsafe {
            MmapOptions::new()
                .offset(block_record.file_location.offset)
                .len(block_record.file_location.block_length)
                .map(&block_file)?
        };
        let block: Block = bincode::deserialize(&mmap).unwrap();

        Ok(block)
    }

    /// Given a mutex lock on the database, return the latest block
    fn get_latest_block_from_disk(
        &self,
        block_index_db: &mut tokio::sync::MutexGuard<RustyLevelDB<BlockIndexKey, BlockIndexValue>>,
    ) -> Result<Option<Block>> {
        let tip_digest = block_index_db.get(BlockIndexKey::BlockTipDigest);
        let tip_digest: Digest = match tip_digest {
            Some(digest) => digest.as_tip_digest(),
            None => return Ok(None),
        };

        let tip_block_record: BlockRecord = block_index_db
            .get(BlockIndexKey::Block(tip_digest))
            .unwrap()
            .as_block_record();

        let block: Block = self.get_block_from_block_record(tip_block_record)?;

        Ok(Some(block))
    }

    /// Return latest block from database, or genesis block if no other block
    /// is known.
    pub async fn get_latest_block(&self) -> Block {
        let mut dbs = self.block_index_db.lock().await;
        let lookup_res_info: Option<Block> = self
            .get_latest_block_from_disk(&mut dbs)
            .expect("Failed to read block from disk");

        match lookup_res_info {
            None => *self.genesis_block.clone(),
            Some(block) => block,
        }
    }

    pub async fn get_block_header(&self, block_digest: Digest) -> Option<BlockHeader> {
        let mut ret = self
            .block_index_db
            .lock()
            .await
            .get(BlockIndexKey::Block(block_digest))
            .map(|x| x.as_block_record().block_header);

        // If no block was found, check if digest is genesis digest
        if ret.is_none() && block_digest == self.genesis_block.hash {
            ret = Some(self.genesis_block.header.clone());
        }

        ret
    }

    // Return the block with a given block digest, iff it's available in state somewhere
    // Takes a lock on the block databases as argument.
    fn get_block_with_lock(
        &self,
        block_db_lock: &mut tokio::sync::MutexGuard<RustyLevelDB<BlockIndexKey, BlockIndexValue>>,
        block_digest: Digest,
    ) -> Option<Block> {
        let maybe_record: Option<BlockRecord> = block_db_lock
            .get(BlockIndexKey::Block(block_digest))
            .map(|x| x.as_block_record());
        let record: BlockRecord = match maybe_record {
            Some(rec) => rec,
            None => {
                if self.genesis_block.hash == block_digest {
                    return Some(*self.genesis_block.clone());
                } else {
                    return None;
                }
            }
        };

        // Fetch block from disk
        let block = self
            .get_block_from_block_record(record)
            .expect("Fetching from disk must succeed");

        Some(block)
    }

    // Return the block with a given block digest, iff it's available in state somewhere
    pub async fn get_block(&self, block_digest: Digest) -> Result<Option<Block>> {
        let maybe_record: Option<BlockRecord> = self
            .block_index_db
            .lock()
            .await
            .get(BlockIndexKey::Block(block_digest))
            .map(|x| x.as_block_record());
        let record: BlockRecord = match maybe_record {
            Some(rec) => rec,
            None => {
                if self.genesis_block.hash == block_digest {
                    return Ok(Some(*self.genesis_block.clone()));
                } else {
                    return Ok(None);
                }
            }
        };

        // Fetch block from disk
        let block = self.get_block_from_block_record(record)?;

        Ok(Some(block))
    }

    /// Return the number of blocks with the given height
    async fn block_height_to_block_count(&self, height: BlockHeight) -> usize {
        match self
            .block_index_db
            .lock()
            .await
            .get(BlockIndexKey::Height(height))
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
        let maybe_digests = self
            .block_index_db
            .lock()
            .await
            .get(BlockIndexKey::Height(block_height))
            .map(|x| x.as_height_record());

        // Note that if you do not assign the `maybe_digests` value but use the RHS expression instead,
        // you create a deadlock when the body of the `Some` branch below attempts to grab the lock.
        match maybe_digests {
            Some(block_digests) => {
                let mut block_headers = vec![];
                for block_digest in block_digests {
                    let block_header = self
                        .block_index_db
                        .lock()
                        .await
                        .get(BlockIndexKey::Block(block_digest))
                        .map(|x| x.as_block_record())
                        .unwrap();
                    block_headers.push(block_header.block_header);
                }

                block_headers
            }
            None => vec![],
        }
    }

    pub async fn get_children_blocks(&self, parent_block_header: &BlockHeader) -> Vec<BlockHeader> {
        // Get all blocks with height n + 1
        let blocks_from_childrens_generation: Vec<BlockHeader> = self
            .block_height_to_block_headers(parent_block_header.height.next())
            .await;

        // Filter out those that don't have the right parent
        let parent_block_header_digest = Hash::hash(parent_block_header);
        blocks_from_childrens_generation
            .into_iter()
            .filter(|child_block_header| {
                child_block_header.prev_block_digest == parent_block_header_digest
            })
            .collect()
    }

    /// Return a boolean indicating if block belongs to most canonical chain
    pub async fn block_belongs_to_canonical_chain(
        &self,
        block_header: &BlockHeader,
        tip_header: &BlockHeader,
    ) -> bool {
        let mut block_height: BlockHeight = block_header.height;
        // If only one block at this height is known and block height is less than or equal
        // to that of the tip, then this block must belong to the canonical chain
        if self.block_height_to_block_count(block_height).await == 1
            && tip_header.height >= block_height
        {
            return true;
        }

        // If tip header height is less than this block, or the same but with a different hash,
        // then it cannot belong to the canonical chain
        let tip_header_digest = Hash::hash(tip_header);
        if tip_header.height < block_height
            || tip_header.height == block_height && tip_header_digest != Hash::hash(block_header)
        {
            return false;
        }

        // If multiple blocks at this height is known, check all children blocks until we have one or zero blocks at a specific height
        let mut previous_generation_blocks: Vec<BlockHeader> = vec![block_header.clone()];
        let mut offspring_of_generation_x: Vec<BlockHeader> =
            self.get_children_blocks(block_header).await;
        block_height = block_height.next();
        while offspring_of_generation_x.len() > 1 && block_height < tip_header.height {
            previous_generation_blocks = offspring_of_generation_x.clone();
            let mut next_generation_offspring: Vec<BlockHeader> = vec![];
            for offspring in offspring_of_generation_x.iter() {
                next_generation_offspring.append(&mut self.get_children_blocks(offspring).await);
            }
            offspring_of_generation_x = next_generation_offspring;
            block_height = block_height.next();
        }

        if previous_generation_blocks
            .iter()
            .any(|prev_block_header| tip_header_digest == Hash::hash(prev_block_header))
        {
            return true;
        }

        if offspring_of_generation_x
            .iter()
            .any(|offspring_block_header| tip_header_digest == Hash::hash(offspring_block_header))
        {
            return true;
        }

        if block_height == tip_header.height {
            return false;
        }

        if offspring_of_generation_x.is_empty() {
            return false;
        }

        if offspring_of_generation_x.len() == 1 {
            let offspring_candidate: BlockHeader = offspring_of_generation_x[0].clone();
            let number_of_blocks_with_height = self
                .block_height_to_block_count(offspring_candidate.height)
                .await;
            if number_of_blocks_with_height == 1 {
                return true;
            } else {
                // Track backwards from tip and check if we find offspring candidate
                let mut tip_ancestor = tip_header.to_owned();
                while tip_ancestor != offspring_candidate
                    && tip_ancestor.height > offspring_candidate.height
                {
                    tip_ancestor = self
                        .get_block_header(tip_ancestor.prev_block_digest)
                        .await
                        .unwrap();
                }

                return Hash::hash(&tip_ancestor) == Hash::hash(&offspring_candidate);
            }
        }

        // This should never be hit as we above this have checked both reasons as to why the
        // while loop could stop.
        panic!("This should never happen");
    }

    /// Return a list of digests of the ancestors to the requested digest. Does not include the input
    /// digest. If no ancestors can be found, returns the empty list. The count is the maximum length
    /// of the returned list. E.g. if the input digest corresponds to height 2 and count is 5, the
    /// returned list will contain the digests of block 1 and block 0 (the genesis block).
    /// The input block must correspond to a known block but it can be the genesis block in which case
    /// the empty list will be returned. The lock on the database must be free for this method to
    /// not end in a deadlock.
    pub async fn get_ancestor_block_digests(
        &self,
        block_digest: Digest,
        mut count: usize,
    ) -> Vec<Digest> {
        let input_block_header = self.get_block_header(block_digest).await.unwrap();
        let mut parent_digest = input_block_header.prev_block_digest;
        let mut ret = vec![];
        while let Some(parent) = self.get_block_header(parent_digest).await {
            ret.push(Hash::hash(&parent));
            parent_digest = parent.prev_block_digest;
            count -= 1;
            if count == 0 {
                break;
            }
        }

        ret
    }

    pub async fn flush_active_window(&self) -> Result<()> {
        let ams_lock: tokio::sync::MutexGuard<ArchivalMutatorSet<Hash>> =
            self.archival_mutator_set.lock().await;
        // Store active window onto disk for persistence
        let active_window_db = Self::active_window_db(&self.data_dir)?;
        let _active_window_db = ams_lock
            .set_commitment
            .swbf_active
            .store_to_database(active_window_db);

        Ok(())
    }

    /// Update the mutator set with a block after this block has been stored to the database.
    /// Handles rollback of the mutator set if needed but requires that all blocks that are
    /// rolled back are present in the DB. The input block is considered chain tip.
    pub fn update_mutator_set(
        &self,
        block_db_lock: &mut tokio::sync::MutexGuard<RustyLevelDB<BlockIndexKey, BlockIndexValue>>,
        ams_lock: &mut tokio::sync::MutexGuard<ArchivalMutatorSet<Hash>>,
        ms_block_sync_lock: &mut tokio::sync::MutexGuard<
            RustyLevelDB<MsBlockSyncKey, MsBlockSyncValue>,
        >,
        new_block: &Block,
    ) -> Result<()> {
        // Get the block digest that the mutator set was most recently synced to
        let ms_block_sync_digest = if let Some(value) = ms_block_sync_lock.get(MsBlockSyncKey) {
            debug!(
                "ms_block_sync was present in database: {}",
                value.0.emojihash()
            );
            value.0
        } else {
            // first (non-genesis) block
            debug!("ms_block_sync was missing in database; using genesis.");
            assert_eq!(
                new_block.header.prev_block_digest, self.genesis_block.hash,
                "Empty ms_block_sync_db only allowed for block after genesis block"
            );
            self.genesis_block.hash
        };

        // Process roll back, if necessary.
        // Until the mutator set isn't synced with the previous block, roll back, unless we've
        // reached the genesis block in which case, we cannot roll back further.
        let mut ms_block_rollback_digest = ms_block_sync_digest;
        while ms_block_rollback_digest != new_block.header.prev_block_digest {
            // This should be impossible, but this function has crashed a lot, so we add this
            // sanity check. This would indicate an invalid block, and previous validation
            // should have caught that.
            if ms_block_rollback_digest == self.genesis_block.hash {
                panic!("Attempted to roll back genesis block in archival mutator set");
            }

            // Roll back mutator set
            // block_header_for_current_ms_state = get_current_ms_bh();
            let roll_back_block = self
                .get_block_with_lock(block_db_lock, ms_block_rollback_digest)
                .expect("Fetching block must succeed");

            debug!(
                "Updating mutator set: rolling back block with height {}",
                roll_back_block.header.height
            );

            // Roll back all addition records contained in block
            for addition_record in roll_back_block
                .body
                .mutator_set_update
                .additions
                .iter()
                .rev()
            {
                assert!(
                    ams_lock.add_is_reversible(addition_record),
                    "Addition record must be in sync with block being rolled back."
                );
                ams_lock.revert_add(addition_record);
            }

            // Roll back all removal records contained in block
            // This is done by reading out the indices from the block.
            let block_diff_indices = roll_back_block
                .body
                .mutator_set_update
                .removals
                .iter()
                .flat_map(|rr| rr.absolute_indices.to_array())
                .collect();
            debug!(
                "block_diff_indices being rolled back = {:?}",
                block_diff_indices
            );
            ams_lock.revert_remove(block_diff_indices);

            ms_block_rollback_digest = roll_back_block.header.prev_block_digest;
        }

        let mut addition_records: Vec<AdditionRecord> =
            new_block.body.mutator_set_update.additions.clone();
        addition_records.reverse();
        let mut removal_records = new_block.body.mutator_set_update.removals.clone();
        removal_records.reverse();
        let mut removal_records: Vec<&mut RemovalRecord<Hash>> =
            removal_records.iter_mut().collect::<Vec<_>>();

        // Add items, thus adding the output UTXOs to the mutator set
        while let Some(mut addition_record) = addition_records.pop() {
            // Batch-update all removal records to keep them valid after next addition
            RemovalRecord::batch_update_from_addition(
                &mut removal_records,
                &mut ams_lock.set_commitment,
            ).expect("MS removal record update from add must succeed in update_mutator_set as block should already be verified");

            // Add the element to the mutator set
            ams_lock.add(&mut addition_record);
        }

        // Remove items, thus removing the input UTXOs from the mutator set
        while let Some(removal_record) = removal_records.pop() {
            // Batch-update all removal records to keep them valid after next removal
            RemovalRecord::batch_update_from_remove(
                &mut removal_records,
                removal_record,
            ).expect("MS removal record update from remove must succeed in update_mutator_set as block should already be verified");

            // Remove the element from the mutator set
            ams_lock.remove(removal_record);
        }

        // Store active window onto disk for persistence
        let active_window_db = Self::active_window_db(&self.data_dir)?;
        let _active_window_db = ams_lock
            .set_commitment
            .swbf_active
            .store_to_database(active_window_db);

        // Sanity check that archival mutator set has been updated consistently with the new block
        debug!("sanity check: was AMS updated consistently with new block?");
        let mut new_block_copy = new_block.clone();
        assert_eq!(
            new_block_copy
                .body
                .next_mutator_set_accumulator
                .get_commitment(),
            ams_lock.get_commitment(),
            "Calculated archival mutator set commitment must match that from newly added block. Block Digest: {:?}", new_block_copy.hash
        );

        // Write synced block digest onto disk
        ms_block_sync_lock.batch_write(&[(MsBlockSyncKey, MsBlockSyncValue(new_block.hash))]);

        Ok(())
    }
}

#[cfg(test)]
mod archival_state_tests {
    use super::*;

    use mutator_set_tf::util_types::mutator_set::active_window::ActiveWindow;
    use rand::{thread_rng, RngCore};
    use rusty_leveldb::LdbIterator;
    use secp256k1::Secp256k1;
    use tracing_test::traced_test;

    use crate::config_models::network::Network;
    use crate::models::blockchain::transaction::{amount::Amount, utxo::Utxo};
    use crate::models::state::archival_state::ArchivalState;
    use crate::models::state::blockchain_state::BlockchainState;
    use crate::models::state::light_state::LightState;
    use crate::tests::shared::{
        add_block_to_archival_state, add_output_to_block, add_unsigned_input_to_block_ams,
        get_mock_wallet_state, make_mock_block, make_unit_test_archival_state, unit_test_databases,
    };

    async fn make_test_archival_state(network: Network) -> ArchivalState {
        let (block_index_db_lock, _peer_db_lock, data_dir) = unit_test_databases(network).unwrap();

        let (ams, ms_block_sync) = ArchivalState::initialize_mutator_set(&data_dir).unwrap();
        let ams_lock = Arc::new(TokioMutex::new(ams));
        let ms_block_sync_lock = Arc::new(TokioMutex::new(ms_block_sync));

        ArchivalState::new(data_dir, block_index_db_lock, ams_lock, ms_block_sync_lock).await
    }

    #[traced_test]
    #[tokio::test]
    async fn initialize_archival_state_test() -> Result<()> {
        // Ensure that the archival state can be initialized without overflowing the stack
        tokio::spawn(async move {
            let network = Network::Main;

            let archival_state0 = make_test_archival_state(network).await;
            let archival_state1 = make_test_archival_state(network).await;
            let archival_state2 = make_test_archival_state(network).await;

            let b = Block::genesis_block();
            let blockchain_state = BlockchainState {
                archival_state: Some(archival_state2),
                light_state: LightState::new(*archival_state1.genesis_block),
            };
            let (_secret_key, public_key): (secp256k1::SecretKey, secp256k1::PublicKey) =
                Secp256k1::new().generate_keypair(&mut thread_rng());
            let block_1 = make_mock_block(&b, None, public_key);
            let lock0 = blockchain_state
                .archival_state
                .as_ref()
                .unwrap()
                .block_index_db
                .lock()
                .await;
            add_block_to_archival_state(&archival_state0, block_1.clone())
                .await
                .unwrap();
            let c = archival_state0
                .get_block(block_1.hash)
                .await
                .unwrap()
                .unwrap();
            println!("genesis digest = {}", c.hash);
            drop(lock0);
        })
        .await?;

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn archival_state_init_test() -> Result<()> {
        // Verify that archival mutator set is populated with outputs from genesis block
        let archival_state = make_test_archival_state(Network::Main).await;

        assert_eq!(
            Block::genesis_block().body.transaction.outputs.len() as u128,
            archival_state
                .archival_mutator_set
                .lock()
                .await
                .set_commitment
                .aocl
                .count_leaves(),
            "Archival mutator set must be populated with premine outputs"
        );

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn update_mutator_set_db_write_test() -> Result<()> {
        // Verify that `update_mutator_set` writes the active window back to disk.

        let network = Network::Main;
        let archival_state = make_test_archival_state(network).await;
        let genesis_wallet_state = get_mock_wallet_state(None).await;
        let wallet = genesis_wallet_state.wallet;
        let data_dir = &archival_state.data_dir;

        let mock_block_1 =
            make_mock_block(&archival_state.genesis_block, None, wallet.get_public_key());

        {
            let mut block_db_lock = archival_state.block_index_db.lock().await;
            let mut ams_lock = archival_state.archival_mutator_set.lock().await;

            // Before updating the AMS, the active window DB must be empty.
            {
                let mut active_window_db_before: DB = ArchivalState::active_window_db(data_dir)?;
                assert!(active_window_db_before.new_iter().unwrap().next().is_none());
            }

            // ms_block_sync_db is empty
            let mut ms_block_sync_lock = archival_state.ms_block_sync_db.lock().await;

            archival_state.update_mutator_set(
                &mut block_db_lock,
                &mut ams_lock,
                &mut ms_block_sync_lock,
                &mock_block_1,
            )?;
        }

        // After running the AMS updater, the active window DB must be written back to disk
        // but all the values in the active window must be zero since no removal record
        // has been added yet.
        {
            let active_window_db_after_add: DB = ArchivalState::active_window_db(data_dir)?;
            let active_window =
                ActiveWindow::<Hash>::restore_from_database(active_window_db_after_add);
            assert!(
                active_window.sbf.is_empty(),
                "Active window must be empty before consuming UTXOs"
            );
        }

        // Add an input to the next block's transaction. This will add a removal record
        // to the block, and this removal record will insert indices in the Bloom filter.
        {
            let mut mock_block_2 = make_mock_block(&mock_block_1, None, wallet.get_public_key());
            let consumed_utxo = mock_block_1.body.transaction.outputs[0].0;
            let output_randomness = mock_block_1.body.transaction.outputs[0].1;
            add_unsigned_input_to_block_ams(
                &mut mock_block_2,
                consumed_utxo,
                output_randomness,
                &archival_state.archival_mutator_set,
                1,
            )
            .await;

            // Remove an element from the mutator set, verify that the active window DB is updated.
            let mut block_db_lock = archival_state.block_index_db.lock().await;
            let mut ams_lock = archival_state.archival_mutator_set.lock().await;
            let mut ms_block_sync_lock = archival_state.ms_block_sync_db.lock().await;

            archival_state.update_mutator_set(
                &mut block_db_lock,
                &mut ams_lock,
                &mut ms_block_sync_lock,
                &mock_block_2,
            )?;
        }

        // After running the MS updater with a removal record, the active window
        // that is stored on disk must contain non-zero values, i.e. the Bloom filter must not be empty.
        let active_window_db_after_remove: DB = ArchivalState::active_window_db(data_dir)?;
        let active_window =
            ActiveWindow::<Hash>::restore_from_database(active_window_db_after_remove);
        assert!(!active_window.sbf.is_empty());

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn update_mutator_set_rollback_ms_block_sync_test() -> Result<()> {
        let (archival_state, _peer_db_lock) = make_unit_test_archival_state(Network::Main).await;
        let mut block_db_lock = archival_state.block_index_db.lock().await;
        let mut ams_lock = archival_state.archival_mutator_set.lock().await;
        let mut ms_block_sync_lock = archival_state.ms_block_sync_db.lock().await;
        let (_secret_key, public_key): (secp256k1::SecretKey, secp256k1::PublicKey) =
            Secp256k1::new().generate_keypair(&mut thread_rng());

        // 1. Create new block 1 and store it to the DB
        let mock_block_1a = make_mock_block(&archival_state.genesis_block, None, public_key);
        archival_state.write_block(
            Box::new(mock_block_1a.clone()),
            &mut block_db_lock,
            Some(mock_block_1a.header.proof_of_work_family),
        )?;

        // 2. Update mutator set with this
        archival_state.update_mutator_set(
            &mut block_db_lock,
            &mut ams_lock,
            &mut ms_block_sync_lock,
            &mock_block_1a,
        )?;

        // 3. Create competing block 1 and store it to DB
        let mock_block_1b = make_mock_block(&archival_state.genesis_block, None, public_key);
        archival_state.write_block(
            Box::new(mock_block_1a.clone()),
            &mut block_db_lock,
            Some(mock_block_1b.header.proof_of_work_family),
        )?;

        // 4. Update mutator set with that
        archival_state.update_mutator_set(
            &mut block_db_lock,
            &mut ams_lock,
            &mut ms_block_sync_lock,
            &mock_block_1b,
        )?;

        // 5. Experience rollback

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn update_mutator_set_rollback_ms_block_sync_multiple_inputs_outputs_in_block_test(
    ) -> Result<()> {
        // Make a rollback of one block that contains multiple inputs and outputs.
        // This test is intended to verify that rollbacks work for non-trivial
        // blocks.
        let (archival_state, _peer_db_lock) = make_unit_test_archival_state(Network::Main).await;
        let genesis_wallet_state = get_mock_wallet_state(None).await;
        let genesis_wallet = genesis_wallet_state.wallet;

        // 1. Create new block 1 with two inputs and three outputs and store it to disk
        let mut block_1a = make_mock_block(
            &archival_state.genesis_block,
            None,
            genesis_wallet.get_public_key(),
        );
        let genesis_block = archival_state.genesis_block.clone();
        let consumed_utxo = archival_state.genesis_block.body.transaction.outputs[0].0;
        let premine_output_randomness = genesis_block.body.transaction.outputs[0].1;
        add_unsigned_input_to_block_ams(
            &mut block_1a,
            consumed_utxo,
            premine_output_randomness,
            &archival_state.archival_mutator_set,
            0,
        )
        .await;
        let output_utxo_1: Utxo = Utxo::new(
            Amount::one() + Amount::one(),
            genesis_wallet.get_public_key(),
        );
        add_output_to_block(&mut block_1a, output_utxo_1);
        let output_utxo_2: Utxo = Utxo::new(
            Amount::one() + Amount::one() + Amount::one(),
            genesis_wallet.get_public_key(),
        );
        add_output_to_block(&mut block_1a, output_utxo_2);
        block_1a.body.transaction.sign(&genesis_wallet);
        assert!(block_1a.is_valid_for_devnet(&genesis_block));

        {
            let mut block_db_lock = archival_state.block_index_db.lock().await;
            let mut ams_lock = archival_state.archival_mutator_set.lock().await;
            let mut ms_block_sync_lock = archival_state.ms_block_sync_db.lock().await;
            archival_state.write_block(
                Box::new(block_1a.clone()),
                &mut block_db_lock,
                Some(block_1a.header.proof_of_work_family),
            )?;

            // 2. Update mutator set with this
            archival_state.update_mutator_set(
                &mut block_db_lock,
                &mut ams_lock,
                &mut ms_block_sync_lock,
                &block_1a,
            )?;

            // 3. Create competing block 1 and store it to DB
            let mock_block_1b = make_mock_block(
                &archival_state.genesis_block,
                None,
                genesis_wallet.get_public_key(),
            );
            archival_state.write_block(
                Box::new(block_1a.clone()),
                &mut block_db_lock,
                Some(mock_block_1b.header.proof_of_work_family),
            )?;

            // 4. Update mutator set with that and verify rollback
            archival_state.update_mutator_set(
                &mut block_db_lock,
                &mut ams_lock,
                &mut ms_block_sync_lock,
                &mock_block_1b,
            )?;
        }

        // 5. Verify correct rollback

        // Verify that the new state of the archival mutator set contains
        // two UTXOs and that none have been removed
        assert!(
            archival_state
                .archival_mutator_set
                .lock()
                .await
                .set_commitment
                .swbf_active
                .sbf
                .is_empty(),
            "Active window must be empty when no UTXOs have been spent"
        );

        assert_eq!(
            2,
            archival_state
                .archival_mutator_set
                .lock()
                .await
                .set_commitment
                .aocl
                .count_leaves(),
            "AOCL leaf count must be 2 after two blocks containing only coinbase transactions"
        );

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn update_mutator_set_rollback_many_blocks_multiple_inputs_outputs_test() -> Result<()> {
        // Make a rollback of multiple blocks that contains multiple inputs and outputs.
        // This test is intended to verify that rollbacks work for non-trivial
        // blocks, also when there are many blocks that push the active window of the
        // mutator set forwards.
        let (archival_state, _peer_db_lock) = make_unit_test_archival_state(Network::Main).await;
        let genesis_wallet_state = get_mock_wallet_state(None).await;
        let genesis_wallet = genesis_wallet_state.wallet;

        let genesis_block: Block = *archival_state.genesis_block.to_owned();
        let mut consumed_utxo = genesis_block.body.transaction.outputs[0].0;
        let mut output_randomness = genesis_block.body.transaction.outputs[0].1;
        let mut previous_block = genesis_block;
        let mut aocl_index_of_consumed_input = 0;

        for i in 0..10 {
            // Create next block with inputs and outputs
            let mut next_block =
                make_mock_block(&previous_block, None, genesis_wallet.get_public_key());
            add_unsigned_input_to_block_ams(
                &mut next_block,
                consumed_utxo,
                output_randomness,
                &archival_state.archival_mutator_set,
                aocl_index_of_consumed_input,
            )
            .await;
            let output_utxo_1: Utxo = Utxo::new(
                Amount::one() + Amount::one(),
                genesis_wallet.get_public_key(),
            );
            add_output_to_block(&mut next_block, output_utxo_1);
            let output_utxo_2: Utxo = Utxo::new(
                Amount::one() + Amount::one() + Amount::one(),
                genesis_wallet.get_public_key(),
            );
            add_output_to_block(&mut next_block, output_utxo_2);
            next_block.body.transaction.sign(&genesis_wallet);
            assert!(next_block.is_valid_for_devnet(&previous_block));

            // Store the produced block
            {
                let mut block_db_lock = archival_state.block_index_db.lock().await;
                let mut ams_lock = archival_state.archival_mutator_set.lock().await;
                let mut ms_block_sync_lock = archival_state.ms_block_sync_db.lock().await;
                archival_state.write_block(
                    Box::new(next_block.clone()),
                    &mut block_db_lock,
                    Some(next_block.header.proof_of_work_family),
                )?;

                // 2. Update mutator set with produced block
                archival_state.update_mutator_set(
                    &mut block_db_lock,
                    &mut ams_lock,
                    &mut ms_block_sync_lock,
                    &next_block,
                )?;
            }

            consumed_utxo = next_block.body.transaction.outputs[0].0;
            output_randomness = next_block.body.transaction.outputs[0].1;

            // Genesis block may have a different number of outputs than the blocks produced above
            if i == 0 {
                aocl_index_of_consumed_input += archival_state
                    .genesis_block
                    .body
                    .mutator_set_update
                    .additions
                    .len() as u128;
            } else {
                aocl_index_of_consumed_input +=
                    next_block.body.mutator_set_update.additions.len() as u128;
            }

            previous_block = next_block;
        }

        {
            // 3. Create competing block 1 and store it to DB
            let mock_block_1b = make_mock_block(
                &archival_state.genesis_block,
                None,
                genesis_wallet.get_public_key(),
            );
            let mut block_db_lock = archival_state.block_index_db.lock().await;
            let mut ams_lock = archival_state.archival_mutator_set.lock().await;
            let mut ms_block_sync_lock = archival_state.ms_block_sync_db.lock().await;
            archival_state.write_block(
                Box::new(mock_block_1b.clone()),
                &mut block_db_lock,
                Some(mock_block_1b.header.proof_of_work_family),
            )?;

            // 4. Update mutator set with that and verify rollback
            archival_state.update_mutator_set(
                &mut block_db_lock,
                &mut ams_lock,
                &mut ms_block_sync_lock,
                &mock_block_1b,
            )?;
        }

        // 5. Verify correct rollback

        // Verify that the new state of the archival mutator set contains
        // two UTXOs and that none have been removed
        assert!(
            archival_state
                .archival_mutator_set
                .lock()
                .await
                .set_commitment
                .swbf_active
                .sbf
                .is_empty(),
            "Active window must be empty when no UTXOs have been spent"
        );

        assert_eq!(
            2,
            archival_state
                .archival_mutator_set
                .lock()
                .await
                .set_commitment
                .aocl
                .count_leaves(),
            "AOCL leaf count must be 2 after two blocks containing only coinbase transactions"
        );

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn allow_consumption_of_genesis_output_test() -> Result<()> {
        let (archival_state, _peer_db_lock) = make_unit_test_archival_state(Network::Main).await;
        let genesis_wallet_state = get_mock_wallet_state(None).await;
        let genesis_wallet = genesis_wallet_state.wallet;
        let mut block_1_a = make_mock_block(
            &archival_state.genesis_block,
            None,
            genesis_wallet.get_public_key(),
        );

        // Verify that block_1 that only contains the coinbase output is valid
        assert!(block_1_a.archival_is_valid(&archival_state.genesis_block));

        // Add a valid input to the block transaction
        let genesis_block = archival_state.genesis_block.clone();
        let consumed_utxo = archival_state.genesis_block.body.transaction.outputs[0].0;
        let premine_output_randomness = genesis_block.body.transaction.outputs[0].1;
        add_unsigned_input_to_block_ams(
            &mut block_1_a,
            consumed_utxo,
            premine_output_randomness,
            &archival_state.archival_mutator_set,
            0,
        )
        .await;

        // Unsigned input must fail to validate
        assert!(!block_1_a.archival_is_valid(&archival_state.genesis_block));

        // Sign the transaction with a valid key and verify
        block_1_a.body.transaction.sign(&genesis_wallet);

        // Block with signed transaction must validate
        assert!(block_1_a.archival_is_valid(&archival_state.genesis_block));

        // Verify that we store this block and that we can update the mutator set with it
        {
            // Before updating, the active window must be empty
            let mut db_bc_lock = archival_state.block_index_db.lock().await;
            let mut ams_lock = archival_state.archival_mutator_set.lock().await;
            assert!(ams_lock.set_commitment.swbf_active.sbf.is_empty());

            // Write the block to disk
            archival_state.write_block(
                Box::new(block_1_a.clone()),
                &mut db_bc_lock,
                Some(genesis_block.header.proof_of_work_family),
            )?;

            // Update the mutator set
            let mut ms_block_sync_lock = archival_state.ms_block_sync_db.lock().await;
            archival_state.update_mutator_set(
                &mut db_bc_lock,
                &mut ams_lock,
                &mut ms_block_sync_lock,
                &block_1_a,
            )?;

            // Verify that the active window is not empty as a removal record has inserted indices into the Bloom filter
            assert!(!ams_lock.set_commitment.swbf_active.sbf.is_empty());

            // Verify that a block containing a removal record `block_1_a` can be reverted
            let block_1_b = make_mock_block(
                &genesis_block,
                Some(1000.into()),
                genesis_wallet.get_public_key(),
            );
            archival_state.write_block(
                Box::new(block_1_b.clone()),
                &mut db_bc_lock,
                Some(genesis_block.header.proof_of_work_family),
            )?;
            archival_state.update_mutator_set(
                &mut db_bc_lock,
                &mut ams_lock,
                &mut ms_block_sync_lock,
                &block_1_b,
            )?;

            // Verify that the active window is empty after reverting the removal record
            assert!(ams_lock.set_commitment.swbf_active.sbf.is_empty());
        }

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn allow_mutliple_inputs_and_outputs_in_block() -> Result<()> {
        let (archival_state, _peer_db_lock) = make_unit_test_archival_state(Network::Main).await;
        let genesis_wallet_state = get_mock_wallet_state(None).await;
        let genesis_wallet = genesis_wallet_state.wallet;
        let mut block_1 = make_mock_block(
            &archival_state.genesis_block,
            None,
            genesis_wallet.get_public_key(),
        );

        // Add a valid input to the block transaction
        let genesis_block = archival_state.genesis_block.clone();
        let consumed_utxo = archival_state.genesis_block.body.transaction.outputs[0].0;
        let premine_output_randomness = genesis_block.body.transaction.outputs[0].1;
        add_unsigned_input_to_block_ams(
            &mut block_1,
            consumed_utxo,
            premine_output_randomness,
            &archival_state.archival_mutator_set,
            0,
        )
        .await;

        // Sign and verify validity
        block_1.body.transaction.sign(&genesis_wallet);
        assert!(block_1.is_valid_for_devnet(&genesis_block));

        // Add one output to the block's transaction
        let output_utxo_0: Utxo = Utxo::new(Amount::one(), genesis_wallet.get_public_key());
        add_output_to_block(&mut block_1, output_utxo_0);

        // Sign the transaction
        block_1.body.transaction.sign(&genesis_wallet);
        assert!(block_1.is_valid_for_devnet(&genesis_block));

        // Add two more outputs and verify validity
        // Add one output to the block's transaction
        let output_utxo_1: Utxo = Utxo::new(
            Amount::one() + Amount::one(),
            genesis_wallet.get_public_key(),
        );
        add_output_to_block(&mut block_1, output_utxo_1);
        let output_utxo_2: Utxo = Utxo::new(
            Amount::one() + Amount::one() + Amount::one(),
            genesis_wallet.get_public_key(),
        );
        add_output_to_block(&mut block_1, output_utxo_2);

        // Sign the transaction and verify validity
        block_1.body.transaction.sign(&genesis_wallet);
        assert!(block_1.is_valid_for_devnet(&genesis_block));

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn get_latest_block_test() -> Result<()> {
        let archival_state: ArchivalState = make_test_archival_state(Network::Main).await;

        let mut db_lock_0 = archival_state.block_index_db.lock().await;
        let ret = archival_state.get_latest_block_from_disk(&mut db_lock_0)?;
        assert!(
            ret.is_none(),
            "Must return None when no block is stored in DB"
        );
        drop(db_lock_0);

        // Add a block to archival state and verify that this is returned
        let (_secret_key, public_key): (secp256k1::SecretKey, secp256k1::PublicKey) =
            Secp256k1::new().generate_keypair(&mut thread_rng());
        let genesis = *archival_state.genesis_block.clone();
        let mock_block_1 = make_mock_block(&genesis, None, public_key);
        add_block_to_archival_state(&archival_state, mock_block_1.clone()).await?;

        let mut db_lock_1 = archival_state.block_index_db.lock().await;
        let ret1 = archival_state.get_latest_block_from_disk(&mut db_lock_1)?;
        assert!(
            ret1.is_some(),
            "Must return a block when one is stored to DB"
        );
        assert_eq!(
            mock_block_1,
            ret1.unwrap(),
            "Returned block must match the one inserted"
        );
        drop(db_lock_1);

        // Add a 2nd block and verify that this new block is now returned
        let mock_block_2 = make_mock_block(&mock_block_1, None, public_key);
        add_block_to_archival_state(&archival_state, mock_block_2.clone()).await?;
        let mut db_lock_2 = archival_state.block_index_db.lock().await;
        let ret2 = archival_state.get_latest_block_from_disk(&mut db_lock_2)?;
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
        let archival_state = make_test_archival_state(Network::Main).await;

        let genesis = *archival_state.genesis_block.clone();
        let (_secret_key, public_key): (secp256k1::SecretKey, secp256k1::PublicKey) =
            Secp256k1::new().generate_keypair(&mut thread_rng());
        let mock_block_1 = make_mock_block(&genesis.clone(), None, public_key);

        // Lookup a block in an empty database, expect None to be returned
        let ret0 = archival_state.get_block(mock_block_1.hash).await?;
        assert!(
            ret0.is_none(),
            "Must return a block when one is stored to DB"
        );

        add_block_to_archival_state(&archival_state, mock_block_1.clone()).await?;
        let ret1 = archival_state.get_block(mock_block_1.hash).await?;
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
        let mock_block_2 = make_mock_block(
            &mock_block_1.clone(),
            Some(mock_block_1.header.proof_of_work_family),
            public_key,
        );
        add_block_to_archival_state(&archival_state, mock_block_2.clone()).await?;
        let fetched2 = archival_state.get_block(mock_block_2.hash).await?.unwrap();
        println!("\n\nheight2: {}\n\n", fetched2.header.height);
        assert_eq!(
            mock_block_2, fetched2,
            "Returned block must match the one inserted"
        );
        let fetched1 = archival_state.get_block(mock_block_1.hash).await?.unwrap();
        println!("\n\nheight1: {}\n\n", fetched1.header.height);
        assert_eq!(
            mock_block_1, fetched1,
            "Returned block must match the one inserted"
        );

        // Insert N new blocks and verify that they can all be fetched
        let mut last_block = mock_block_2.clone();
        let mut blocks = vec![genesis, mock_block_1, mock_block_2];
        for _ in 0..(thread_rng().next_u32() % 20) {
            let new_block = make_mock_block(&last_block, None, public_key);
            add_block_to_archival_state(&archival_state, new_block.clone()).await?;
            blocks.push(new_block.clone());
            last_block = new_block;
        }

        for block in blocks {
            assert_eq!(block, archival_state.get_block(block.hash).await?.unwrap());
        }

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn block_belongs_to_canonical_chain_test() -> Result<()> {
        let archival_state = make_test_archival_state(Network::Main).await;

        let genesis = *archival_state.genesis_block.clone();
        assert!(
            archival_state
                .block_belongs_to_canonical_chain(&genesis.header, &genesis.header)
                .await,
            "Genesis block is always part of the canonical chain, tip"
        );

        // Insert a block that is descendant from genesis block and verify that it is canonical
        let (_secret_key, public_key): (secp256k1::SecretKey, secp256k1::PublicKey) =
            Secp256k1::new().generate_keypair(&mut thread_rng());
        let mock_block_1 = make_mock_block(&genesis.clone(), None, public_key);
        add_block_to_archival_state(&archival_state, mock_block_1.clone()).await?;
        assert!(
            archival_state
                .block_belongs_to_canonical_chain(&genesis.header, &mock_block_1.header)
                .await,
            "Genesis block is always part of the canonical chain, tip parent"
        );
        assert!(
            archival_state
                .block_belongs_to_canonical_chain(&mock_block_1.header, &mock_block_1.header)
                .await,
            "Tip block is always part of the canonical chain"
        );

        // Insert three more blocks and verify that all are part of the canonical chain
        let mock_block_2_a = make_mock_block(&mock_block_1.clone(), None, public_key);
        add_block_to_archival_state(&archival_state, mock_block_2_a.clone()).await?;
        let mock_block_3_a = make_mock_block(&mock_block_2_a.clone(), None, public_key);
        add_block_to_archival_state(&archival_state, mock_block_3_a.clone()).await?;
        let mock_block_4_a = make_mock_block(
            &mock_block_3_a.clone(),
            Some(U32s::new([5000, 0, 0, 0, 0])),
            public_key,
        );
        add_block_to_archival_state(&archival_state, mock_block_4_a.clone()).await?;
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
                    .block_belongs_to_canonical_chain(&block.header, &mock_block_4_a.header)
                    .await,
                "only chain {} is canonical",
                i
            );
        }

        // Make a tree and verify that the correct parts of the tree are identified as
        // belonging to the canonical chain
        let mock_block_2_b = make_mock_block(&mock_block_1.clone(), None, public_key);
        add_block_to_archival_state(&archival_state, mock_block_2_b.clone()).await?;
        let mock_block_3_b = make_mock_block(&mock_block_2_b.clone(), None, public_key);
        add_block_to_archival_state(&archival_state, mock_block_3_b.clone()).await?;
        let mock_block_4_b = make_mock_block(&mock_block_3_b.clone(), None, public_key);
        add_block_to_archival_state(&archival_state, mock_block_4_b.clone()).await?;
        let mock_block_5_b = make_mock_block(
            &mock_block_4_b.clone(),
            Some(U32s::new([200000, 0, 0, 0, 0])),
            public_key,
        );
        add_block_to_archival_state(&archival_state, mock_block_5_b.clone()).await?;
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
                    .block_belongs_to_canonical_chain(&block.header, &mock_block_4_a.header)
                    .await,
                "canonical chain {} is canonical",
                i
            );
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
                    .block_belongs_to_canonical_chain(&block.header, &mock_block_4_a.header)
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
        //   gen<----1<----2a<---3d<----4d<----5d<-----6d
        //            \            \
        //             \            \---4e<----5e
        //              \
        //               \
        //                \2b<---3b<----4b<----5b ((<--6b)) (added in test later)
        //
        // Note that in the later test, 6b becomes the tip.

        let mock_block_3_c = make_mock_block(&mock_block_2_a.clone(), None, public_key);
        add_block_to_archival_state(&archival_state, mock_block_3_c.clone()).await?;
        let mock_block_4_c = make_mock_block(&mock_block_3_c.clone(), None, public_key);
        add_block_to_archival_state(&archival_state, mock_block_4_c.clone()).await?;
        let mock_block_5_c = make_mock_block(&mock_block_4_c.clone(), None, public_key);
        add_block_to_archival_state(&archival_state, mock_block_5_c.clone()).await?;
        let mock_block_6_c = make_mock_block(&mock_block_5_c.clone(), None, public_key);
        add_block_to_archival_state(&archival_state, mock_block_6_c.clone()).await?;
        let mock_block_7_c = make_mock_block(&mock_block_6_c.clone(), None, public_key);
        add_block_to_archival_state(&archival_state, mock_block_7_c.clone()).await?;
        let mock_block_8_c = make_mock_block(&mock_block_7_c.clone(), None, public_key);
        add_block_to_archival_state(&archival_state, mock_block_8_c.clone()).await?;
        let mock_block_5_a = make_mock_block(&mock_block_4_a.clone(), None, public_key);
        add_block_to_archival_state(&archival_state, mock_block_5_a.clone()).await?;
        let mock_block_3_d = make_mock_block(
            &mock_block_2_a.clone(),
            Some(U32s::new([1000, 0, 0, 0, 0])),
            public_key,
        );
        add_block_to_archival_state(&archival_state, mock_block_3_d.clone()).await?;
        let mock_block_4_d = make_mock_block(
            &mock_block_3_d.clone(),
            Some(U32s::new([2000, 0, 0, 0, 0])),
            public_key,
        );
        add_block_to_archival_state(&archival_state, mock_block_4_d.clone()).await?;
        let mock_block_5_d = make_mock_block(
            &mock_block_4_d.clone(),
            Some(U32s::new([20000, 0, 0, 0, 0])),
            public_key,
        );
        add_block_to_archival_state(&archival_state, mock_block_5_d.clone()).await?;

        // This is the most canonical block in the known set
        let mock_block_6_d = make_mock_block(
            &mock_block_5_d.clone(),
            Some(U32s::new([2000, 0, 0, 0, 0])),
            public_key,
        );
        add_block_to_archival_state(&archival_state, mock_block_6_d.clone()).await?;

        let mock_block_4_e = make_mock_block(
            &mock_block_3_d.clone(),
            Some(U32s::new([2006, 0, 0, 0, 0])),
            public_key,
        );
        add_block_to_archival_state(&archival_state, mock_block_4_e.clone()).await?;
        let mock_block_5_e = make_mock_block(
            &mock_block_3_d.clone(),
            Some(U32s::new([2002, 0, 0, 0, 0])),
            public_key,
        );
        add_block_to_archival_state(&archival_state, mock_block_5_e.clone()).await?;

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
                    .block_belongs_to_canonical_chain(&block.header, &mock_block_6_d.header)
                    .await,
                "canonical chain {} is canonical, complicated",
                i
            );
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
                    .block_belongs_to_canonical_chain(&block.header, &mock_block_6_d.header)
                    .await,
                "Stale chain {} is not canonical",
                i
            );
        }

        // Make a new block, 6b, canonical and verify that all checks work
        let mock_block_6_b = make_mock_block(
            &mock_block_5_b.clone(),
            Some(U32s::new([200000002, 2, 0, 0, 0])),
            public_key,
        );
        add_block_to_archival_state(&archival_state, mock_block_6_b.clone()).await?;
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
                    .block_belongs_to_canonical_chain(&block.header, &mock_block_6_b.header)
                    .await,
                "Stale chain {} is not canonical",
                i
            );
        }

        for (i, block) in [
            genesis,
            mock_block_1,
            mock_block_2_b,
            mock_block_3_b,
            mock_block_4_b,
            mock_block_5_b,
            mock_block_6_b.clone(),
        ]
        .iter()
        .enumerate()
        {
            assert!(
                archival_state
                    .block_belongs_to_canonical_chain(&block.header, &mock_block_6_b.header)
                    .await,
                "canonical chain {} is canonical, complicated",
                i
            );
        }

        Ok(())
    }

    #[should_panic]
    #[traced_test]
    #[tokio::test]
    async fn digest_of_ancestors_panic_test() {
        let archival_state = make_test_archival_state(Network::Main).await;

        let genesis = archival_state.genesis_block.clone();
        archival_state
            .get_ancestor_block_digests(genesis.header.prev_block_digest, 10)
            .await;
    }

    #[traced_test]
    #[tokio::test]
    async fn digest_of_ancestors_test() -> Result<()> {
        let archival_state = make_test_archival_state(Network::Main).await;
        let genesis = *archival_state.genesis_block.clone();

        assert!(archival_state
            .get_ancestor_block_digests(genesis.hash, 10)
            .await
            .is_empty());
        assert!(archival_state
            .get_ancestor_block_digests(genesis.hash, 1)
            .await
            .is_empty());

        // Insert blocks and verify that the same result is returned
        let (_secret_key, public_key): (secp256k1::SecretKey, secp256k1::PublicKey) =
            Secp256k1::new().generate_keypair(&mut thread_rng());
        let mock_block_1 = make_mock_block(&genesis.clone(), None, public_key);
        add_block_to_archival_state(&archival_state, mock_block_1.clone()).await?;
        let mock_block_2 = make_mock_block(&mock_block_1.clone(), None, public_key);
        add_block_to_archival_state(&archival_state, mock_block_2.clone()).await?;
        let mock_block_3 = make_mock_block(&mock_block_2.clone(), None, public_key);
        add_block_to_archival_state(&archival_state, mock_block_3.clone()).await?;
        let mock_block_4 = make_mock_block(&mock_block_3.clone(), None, public_key);
        add_block_to_archival_state(&archival_state, mock_block_4.clone()).await?;

        assert!(archival_state
            .get_ancestor_block_digests(genesis.hash, 10)
            .await
            .is_empty());
        assert!(archival_state
            .get_ancestor_block_digests(genesis.hash, 1)
            .await
            .is_empty());

        // Check that ancestors of block 1 and 2 return the right values
        let ancestors_of_1 = archival_state
            .get_ancestor_block_digests(mock_block_1.hash, 10)
            .await;
        assert_eq!(1, ancestors_of_1.len());
        assert_eq!(genesis.hash, ancestors_of_1[0]);

        let ancestors_of_2 = archival_state
            .get_ancestor_block_digests(mock_block_2.hash, 10)
            .await;
        assert_eq!(2, ancestors_of_2.len());
        assert_eq!(mock_block_1.hash, ancestors_of_2[0]);
        assert_eq!(genesis.hash, ancestors_of_2[1]);

        // Verify that max length is respected
        let ancestors_of_4_long = archival_state
            .get_ancestor_block_digests(mock_block_4.hash, 10)
            .await;
        assert_eq!(4, ancestors_of_4_long.len());
        assert_eq!(mock_block_3.hash, ancestors_of_4_long[0]);
        assert_eq!(mock_block_2.hash, ancestors_of_4_long[1]);
        assert_eq!(mock_block_1.hash, ancestors_of_4_long[2]);
        assert_eq!(genesis.hash, ancestors_of_4_long[3]);
        let ancestors_of_4_short = archival_state
            .get_ancestor_block_digests(mock_block_4.hash, 2)
            .await;
        assert_eq!(2, ancestors_of_4_short.len());
        assert_eq!(mock_block_3.hash, ancestors_of_4_short[0]);
        assert_eq!(mock_block_2.hash, ancestors_of_4_short[1]);

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn write_block_db_test() -> Result<()> {
        let archival_state = make_test_archival_state(Network::Main).await;
        let genesis = *archival_state.genesis_block.clone();
        let (_secret_key, public_key): (secp256k1::SecretKey, secp256k1::PublicKey) =
            Secp256k1::new().generate_keypair(&mut thread_rng());
        let mock_block_1 = make_mock_block(&genesis.clone(), None, public_key);
        let mut db_lock = archival_state.block_index_db.lock().await;
        archival_state.write_block(
            Box::new(mock_block_1.clone()),
            &mut db_lock,
            Some(genesis.header.proof_of_work_family),
        )?;

        // Verify that `LastFile` value is stored correctly
        let read_last_file: LastFileRecord = db_lock
            .get(BlockIndexKey::LastFile)
            .unwrap()
            .as_last_file_record();

        assert_eq!(0, read_last_file.last_file);

        // Verify that `Height` value is stored correctly
        {
            let expected_height: u64 = 1;
            let blocks_with_height_1: Vec<Digest> = db_lock
                .get(BlockIndexKey::Height(expected_height.into()))
                .unwrap()
                .as_height_record();

            assert_eq!(1, blocks_with_height_1.len());
            assert_eq!(mock_block_1.hash, blocks_with_height_1[0]);
        }

        // Verify that `File` value is stored correctly
        let expected_file: u32 = read_last_file.last_file;
        let last_file_record_1: FileRecord = db_lock
            .get(BlockIndexKey::File(expected_file))
            .unwrap()
            .as_file_record();

        assert_eq!(1, last_file_record_1.blocks_in_file_count);

        let expected_block_len_1 = bincode::serialize(&mock_block_1).unwrap().len();
        assert_eq!(expected_block_len_1, last_file_record_1.file_size as usize);
        assert_eq!(
            mock_block_1.header.height,
            last_file_record_1.min_block_height
        );
        assert_eq!(
            mock_block_1.header.height,
            last_file_record_1.max_block_height
        );

        // Verify that `BlockTipDigest` is stored correctly
        let tip_digest: Digest = db_lock
            .get(BlockIndexKey::BlockTipDigest)
            .unwrap()
            .as_tip_digest();

        assert_eq!(mock_block_1.hash, tip_digest);

        // Verify that `Block` is stored correctly
        let actual_block: BlockRecord = db_lock
            .get(BlockIndexKey::Block(mock_block_1.hash))
            .unwrap()
            .as_block_record();

        assert_eq!(mock_block_1.header, actual_block.block_header);
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
        let mock_block_2 = make_mock_block(&mock_block_1.clone(), None, public_key);
        archival_state.write_block(
            Box::new(mock_block_2.clone()),
            &mut db_lock,
            Some(mock_block_1.header.proof_of_work_family),
        )?;

        // Verify that `LastFile` value is updated correctly, unchanged
        let read_last_file_2: LastFileRecord = db_lock
            .get(BlockIndexKey::LastFile)
            .unwrap()
            .as_last_file_record();
        assert_eq!(0, read_last_file.last_file);

        // Verify that `Height` value is updated correctly
        {
            let blocks_with_height_1: Vec<Digest> = db_lock
                .get(BlockIndexKey::Height(1.into()))
                .unwrap()
                .as_height_record();
            assert_eq!(1, blocks_with_height_1.len());
            assert_eq!(mock_block_1.hash, blocks_with_height_1[0]);
        }

        {
            let blocks_with_height_2: Vec<Digest> = db_lock
                .get(BlockIndexKey::Height(2.into()))
                .unwrap()
                .as_height_record();
            assert_eq!(1, blocks_with_height_2.len());
            assert_eq!(mock_block_2.hash, blocks_with_height_2[0]);
        }
        // Verify that `File` value is updated correctly
        let expected_file_2: u32 = read_last_file.last_file;
        let last_file_record_2: FileRecord = db_lock
            .get(BlockIndexKey::File(expected_file_2))
            .unwrap()
            .as_file_record();
        assert_eq!(2, last_file_record_2.blocks_in_file_count);
        let expected_block_len_2 = bincode::serialize(&mock_block_2).unwrap().len();
        assert_eq!(
            expected_block_len_1 + expected_block_len_2,
            last_file_record_2.file_size as usize
        );
        assert_eq!(
            mock_block_1.header.height,
            last_file_record_2.min_block_height
        );
        assert_eq!(
            mock_block_2.header.height,
            last_file_record_2.max_block_height
        );

        // Verify that `BlockTipDigest` is updated correctly
        let tip_digest_2: Digest = db_lock
            .get(BlockIndexKey::BlockTipDigest)
            .unwrap()
            .as_tip_digest();
        assert_eq!(mock_block_2.hash, tip_digest_2);

        // Verify that `Block` is stored correctly
        let actual_block_record_2: BlockRecord = db_lock
            .get(BlockIndexKey::Block(mock_block_2.hash))
            .unwrap()
            .as_block_record();

        assert_eq!(mock_block_2.header, actual_block_record_2.block_header);
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
        let read_latest_block = archival_state
            .get_latest_block_from_disk(&mut db_lock)?
            .unwrap();
        assert_eq!(mock_block_2, read_latest_block);

        // Test `get_block_from_block_record`
        let block_from_block_record = archival_state
            .get_block_from_block_record(actual_block_record_2)
            .unwrap();
        assert_eq!(mock_block_2, block_from_block_record);
        assert_eq!(mock_block_2.hash, block_from_block_record.hash);

        // Test `get_block_header`
        drop(db_lock);
        let block_header_2 = archival_state
            .get_block_header(mock_block_2.hash)
            .await
            .unwrap();
        assert_eq!(mock_block_2.header, block_header_2);

        // Test `block_height_to_block_headers`
        let block_headers_of_height_2 =
            archival_state.block_height_to_block_headers(2.into()).await;
        assert_eq!(1, block_headers_of_height_2.len());
        assert_eq!(mock_block_2.header, block_headers_of_height_2[0]);

        // Test `get_children_blocks`
        let children_of_mock_block_1 = archival_state
            .get_children_blocks(&mock_block_1.header)
            .await;
        assert_eq!(1, children_of_mock_block_1.len());
        assert_eq!(mock_block_2.header, children_of_mock_block_1[0]);

        // Test `get_ancestor_block_digests`
        let ancestor_digests = archival_state
            .get_ancestor_block_digests(mock_block_2.hash, 10)
            .await;
        assert_eq!(2, ancestor_digests.len());
        assert_eq!(Hash::hash(&mock_block_1.header), ancestor_digests[0]);
        assert_eq!(Hash::hash(&genesis.header), ancestor_digests[1]);

        Ok(())
    }
}
