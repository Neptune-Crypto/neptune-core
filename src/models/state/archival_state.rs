use anyhow::Result;
use memmap2::MmapOptions;
use mutator_set_tf::util_types::mutator_set::archival_mutator_set::ArchivalMutatorSet;
use num_traits::Zero;
use rusty_leveldb::DB;
use std::{
    fs,
    io::{Seek, SeekFrom, Write},
    net::IpAddr,
    ops::DerefMut,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::Mutex as TokioMutex;
use tracing::debug;
use twenty_first::amount::u32s::U32s;

use super::shared::{get_block_file_path, new_block_file_is_needed};
use crate::{
    database::{leveldb::LevelDB, rusty::RustyLevelDB},
    models::{
        blockchain::{
            block::{
                block_header::{BlockHeader, PROOF_OF_WORK_COUNT_U32_SIZE},
                block_height::BlockHeight,
                Block,
            },
            digest::{Digest, Hashable},
            shared::Hash,
        },
        database::{
            BlockDatabases, BlockFileLocation, BlockIndexKey, BlockIndexValue, BlockRecord,
            FileRecord, LastFileRecord, PeerDatabases,
        },
        peer::PeerStanding,
    },
};

const BLOCK_INDEX_DB_NAME: &str = "block_index";
const BANNED_IPS_DB_NAME: &str = "banned_ips";
const DATABASE_DIRECTORY_ROOT_NAME: &str = "databases";
const MUTATOR_SET_DIRECTORY_NAME: &str = "mutator_set";
const MS_AOCL_MMR_DB_NAME: &str = "aocl_mmr";
const MS_SWBF_INACTIVE_MMR_DB_NAME: &str = "swbfi_mmr";
const MS_SWBF_ACTIVE_DB_NAME: &str = "swbfa_mmr";
const MS_CHUNKS_DB_NAME: &str = "chunks";

#[derive(Clone)]
pub struct ArchivalState {
    // Since this is a database, we use the tokio Mutex here.
    pub block_databases: Arc<TokioMutex<BlockDatabases>>,

    root_data_dir: PathBuf,

    // The genesis block is stored on the heap, as we would otherwise get stack overflows whenever we instantiate
    // this object in a spawned worker thread.
    genesis_block: Box<Block>,

    pub archival_mutator_set: Arc<TokioMutex<ArchivalMutatorSet<Hash>>>,
}

impl ArchivalState {
    // TODO: This function belongs in NetworkState
    /// Create databases for peer standings
    pub fn initialize_peer_databases(root_path: &Path) -> Result<PeerDatabases> {
        let mut path = root_path.to_owned();
        path.push(DATABASE_DIRECTORY_ROOT_NAME);

        // Create root directory for all databases if it does not exist
        std::fs::create_dir_all(path.clone()).unwrap_or_else(|_| {
            panic!(
                "Failed to create database directory in {}",
                path.to_string_lossy()
            )
        });

        let banned_peers = RustyLevelDB::<IpAddr, PeerStanding>::new(&path, BANNED_IPS_DB_NAME)?;
        Ok(PeerDatabases {
            peer_standings: banned_peers,
        })
    }

    /// Create databases for block persistence
    pub fn initialize_block_databases(root_path: &Path) -> Result<BlockDatabases> {
        let mut path = root_path.to_owned();
        path.push(DATABASE_DIRECTORY_ROOT_NAME);

        // Create root directory for all databases if it does not exist
        std::fs::create_dir_all(path.clone()).unwrap_or_else(|_| {
            panic!(
                "Failed to create database directory in {}",
                path.to_string_lossy()
            )
        });

        let block_index =
            RustyLevelDB::<BlockIndexKey, BlockIndexValue>::new(&path, BLOCK_INDEX_DB_NAME)?;

        Ok(BlockDatabases { block_index })
    }

    /// Return the database for active window. This should not be public.
    /// This should be fetched when constructing the mutator set, and when persisting the state
    /// of the active window.
    fn active_window_db(ms_db_path: &Path) -> Result<DB> {
        let mut path = ms_db_path.to_owned();
        path.push(MS_SWBF_ACTIVE_DB_NAME);
        Ok(DB::open(path, rusty_leveldb::Options::default())?)
    }

    /// Returns archival mutator set and database for active window
    pub fn initialize_mutator_set(root_path: &Path) -> Result<ArchivalMutatorSet<Hash>> {
        let mut path = root_path.to_owned();
        path.push(DATABASE_DIRECTORY_ROOT_NAME);
        path.push(MUTATOR_SET_DIRECTORY_NAME);

        // Create root directory for all databases if it does not exist
        std::fs::create_dir_all(path.clone()).unwrap_or_else(|_| {
            panic!(
                "Failed to create database directory in {}",
                path.to_string_lossy()
            )
        });

        let options = rusty_leveldb::Options::default();

        let mut aocl_db_path = path.clone();
        aocl_db_path.push(MS_AOCL_MMR_DB_NAME);
        let aocl_mmr_db = DB::open(aocl_db_path, options.clone())?;

        let mut swbfi_db_path = path.clone();
        swbfi_db_path.push(MS_SWBF_INACTIVE_MMR_DB_NAME);
        let swbf_inactive_mmr_db = DB::open(swbfi_db_path, options.clone())?;

        let mut chunks_db_path = path.clone();
        chunks_db_path.push(MS_CHUNKS_DB_NAME);
        let chunks_db = DB::open(chunks_db_path, options)?;

        let active_window_db = Self::active_window_db(&path)?;

        let archival_set: ArchivalMutatorSet<Hash> = ArchivalMutatorSet::new_or_restore(
            aocl_mmr_db,
            swbf_inactive_mmr_db,
            chunks_db,
            active_window_db,
        );

        Ok(archival_set)
    }
}

impl core::fmt::Debug for ArchivalState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArchivalState")
            .field("block_databases", &self.block_databases)
            .field("root_data_dir", &self.root_data_dir)
            .field("genesis_block", &self.genesis_block)
            .finish()
    }
}

impl ArchivalState {
    pub fn new(
        initial_block_databases: Arc<TokioMutex<BlockDatabases>>,
        archival_mutator_set: Arc<TokioMutex<ArchivalMutatorSet<Hash>>>,
        root_data_dir: PathBuf,
    ) -> Self {
        Self {
            block_databases: initial_block_databases,
            root_data_dir,
            genesis_block: Box::new(Block::genesis_block()),
            archival_mutator_set,
        }
    }

    /// Write a newly found block to database and to disk. A lock should be held over light state
    /// while this function call is executed.
    pub fn write_block(
        &self,
        new_block: Box<Block>,
        db_lock: &mut tokio::sync::MutexGuard<'_, BlockDatabases>,
        current_max_pow_family: Option<U32s<PROOF_OF_WORK_COUNT_U32_SIZE>>,
    ) -> Result<()> {
        // Fetch last file record to find disk location to store block.
        // This record must exist in the DB already, unless this is the first block
        // stored on disk.
        let mut last_rec: LastFileRecord = match db_lock
            .block_index
            .get(BlockIndexKey::LastFile)
            .map(|x| x.as_last_file_record())
        {
            Some(rec) => rec,
            None => LastFileRecord::default(),
        };

        // Open the file that was last used for storing a block
        let mut block_file_path =
            get_block_file_path(self.root_data_dir.clone(), last_rec.last_file);
        let serialized_block: Vec<u8> = bincode::serialize(&new_block).unwrap();
        let serialized_block_size: u64 = serialized_block.len() as u64;
        let mut block_file: fs::File = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(block_file_path.clone())
            .unwrap();

        // Check if we should use the last file, or we need a new one.
        if new_block_file_is_needed(&block_file, serialized_block_size) {
            last_rec = LastFileRecord {
                last_file: last_rec.last_file + 1,
            };
            block_file_path = get_block_file_path(self.root_data_dir.clone(), last_rec.last_file);
            block_file = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(block_file_path.clone())
                .unwrap();
        }

        debug!("Writing block to: {}", block_file_path.display());
        // Get associated file record from database, otherwise create it
        let file_record_key: BlockIndexKey = BlockIndexKey::File(last_rec.last_file);
        let file_record_value: Option<FileRecord> = db_lock
            .block_index
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
        let mut blocks_at_same_height: Vec<Digest> =
            match db_lock.block_index.get(height_record_key.clone()) {
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
            tx_count: new_block.body.transactions.len() as u32,
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

        db_lock.block_index.batch_write(&block_index_entries);

        Ok(())
    }

    fn get_block_from_block_record(&self, block_record: BlockRecord) -> Result<Block> {
        // Get path of file for block
        let block_file_path: PathBuf = get_block_file_path(
            self.root_data_dir.clone(),
            block_record.file_location.file_index,
        );

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
        databases: &mut tokio::sync::MutexGuard<BlockDatabases>,
    ) -> Result<Option<Block>> {
        let tip_digest = databases.block_index.get(BlockIndexKey::BlockTipDigest);
        let tip_digest: Digest = match tip_digest {
            Some(digest) => digest.as_tip_digest(),
            None => return Ok(None),
        };

        let tip_block_record: BlockRecord = databases
            .block_index
            .get(BlockIndexKey::Block(tip_digest))
            .unwrap()
            .as_block_record();

        let block: Block = self.get_block_from_block_record(tip_block_record)?;

        Ok(Some(block))
    }

    /// Return latest block from database, or genesis block if no other block
    /// is known.
    pub async fn get_latest_block(&self) -> Block {
        let mut dbs = self.block_databases.lock().await;
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
            .block_databases
            .lock()
            .await
            .block_index
            .get(BlockIndexKey::Block(block_digest))
            .map(|x| x.as_block_record().block_header);

        // If no block was found, check if digest is genesis digest
        if ret.is_none() && block_digest == self.genesis_block.hash {
            ret = Some(self.genesis_block.header.clone());
        }

        ret
    }

    // Return the block with a given block digest, iff it's available in state somewhere
    pub async fn get_block(&self, block_digest: Digest) -> Result<Option<Block>> {
        let maybe_record: Option<BlockRecord> = self
            .block_databases
            .lock()
            .await
            .block_index
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
            .block_databases
            .lock()
            .await
            .block_index
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
            .block_databases
            .lock()
            .await
            .block_index
            .get(BlockIndexKey::Height(block_height))
            .map(|x| x.as_height_record());

        // Note that if you do not assign the `maybe_digests` value but use the RHS expression instead,
        // you create a deadlock when the body of the `Some` branch below attempts to grab the lock.
        match maybe_digests {
            Some(block_digests) => {
                let mut block_headers = vec![];
                for block_digest in block_digests {
                    let block_header = self
                        .block_databases
                        .lock()
                        .await
                        .block_index
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

    pub async fn get_children_blocks(&self, block_header: &BlockHeader) -> Vec<BlockHeader> {
        // Get all blocks with height n + 1
        let blocks_from_childrens_generation: Vec<BlockHeader> = self
            .block_height_to_block_headers(block_header.height.next())
            .await;

        // Filter out those that don't have the right parent
        blocks_from_childrens_generation
            .into_iter()
            .filter(|x| x.prev_block_digest == block_header.hash())
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
        if tip_header.height < block_height
            || tip_header.height == block_height && tip_header.hash() != block_header.hash()
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
            .any(|x| x.hash() == tip_header.hash())
        {
            return true;
        }

        if offspring_of_generation_x
            .iter()
            .any(|x| x.hash() == tip_header.hash())
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
            if self
                .block_height_to_block_count(offspring_candidate.height)
                .await
                == 1
            {
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

                return tip_ancestor.hash() == offspring_candidate.hash();
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
            ret.push(parent.hash());
            parent_digest = parent.prev_block_digest;
            count -= 1;
            if count == 0 {
                break;
            }
        }

        ret
    }
}

#[cfg(test)]
mod archival_state_tests {
    use super::*;

    use rand::{thread_rng, RngCore};
    use tracing_test::traced_test;

    use crate::{
        config_models::network::Network,
        models::state::{blockchain_state::BlockchainState, light_state::LightState},
        tests::shared::{add_block_to_archival_state, databases, make_mock_block},
    };

    #[traced_test]
    #[tokio::test]
    async fn initialize_archival_state_test() -> Result<()> {
        // Ensure that the archival state can be initialized without overflowing the stack
        tokio::spawn(async move {
            let (block_databases_0, _, data_dir_0) = databases(Network::Main).unwrap();
            let ams0 = ArchivalState::initialize_mutator_set(&data_dir_0).unwrap();
            let ams0 = Arc::new(TokioMutex::new(ams0));
            let archival_state0 = ArchivalState::new(block_databases_0, ams0, data_dir_0);

            let (block_databases_1, _, data_dir_1) = databases(Network::Main).unwrap();
            let ams1 = ArchivalState::initialize_mutator_set(&data_dir_1).unwrap();
            let ams1 = Arc::new(TokioMutex::new(ams1));
            let _archival_state1 = ArchivalState::new(block_databases_1, ams1, data_dir_1);

            let (block_databases_2, _, data_dir_2) = databases(Network::Main).unwrap();
            let ams2 = ArchivalState::initialize_mutator_set(&data_dir_2).unwrap();
            let ams2 = Arc::new(TokioMutex::new(ams2));
            let archival_state2 = ArchivalState::new(block_databases_2, ams2, data_dir_2);

            let b = Block::genesis_block();
            let blockchain_state = BlockchainState {
                archival_state: Some(archival_state2),
                light_state: LightState::new(_archival_state1.genesis_block.header),
            };
            let block_1 = make_mock_block(&b, None);
            let lock0 = blockchain_state
                .archival_state
                .as_ref()
                .unwrap()
                .block_databases
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
    async fn get_latest_block_test() -> Result<()> {
        let (block_databases, _, root_data_dir_path) = databases(Network::Main).unwrap();
        println!("root_data_dir_path = {:?}", root_data_dir_path);
        let ams = ArchivalState::initialize_mutator_set(&root_data_dir_path).unwrap();
        let ams = Arc::new(TokioMutex::new(ams));
        let archival_state = ArchivalState::new(block_databases.clone(), ams, root_data_dir_path);
        let mut db_lock_0 = block_databases.lock().await;
        let ret = archival_state.get_latest_block_from_disk(&mut db_lock_0)?;
        assert!(
            ret.is_none(),
            "Must return None when no block is stored in DB"
        );
        drop(db_lock_0);

        // Add a block to archival state and verify that this is returned
        let genesis = *archival_state.genesis_block.clone();
        let mock_block_1 = make_mock_block(&genesis.clone(), None);
        add_block_to_archival_state(&archival_state, mock_block_1.clone()).await?;
        let mut db_lock_1 = block_databases.lock().await;
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
        let mock_block_2 = make_mock_block(&mock_block_1, None);
        add_block_to_archival_state(&archival_state, mock_block_2.clone()).await?;
        let mut db_lock_2 = block_databases.lock().await;
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
        let (block_databases, _, root_data_dir_path) = databases(Network::Main).unwrap();
        let ams = ArchivalState::initialize_mutator_set(&root_data_dir_path).unwrap();
        let ams = Arc::new(TokioMutex::new(ams));
        let archival_state = ArchivalState::new(block_databases.clone(), ams, root_data_dir_path);
        let genesis = *archival_state.genesis_block.clone();
        let mock_block_1 = make_mock_block(&genesis.clone(), None);

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
            let new_block = make_mock_block(&last_block, None);
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
        let (block_databases, _, root_data_dir_path) = databases(Network::Main).unwrap();
        let ams = ArchivalState::initialize_mutator_set(&root_data_dir_path).unwrap();
        let ams = Arc::new(TokioMutex::new(ams));
        let archival_state = ArchivalState::new(block_databases.clone(), ams, root_data_dir_path);
        let genesis = *archival_state.genesis_block.clone();
        assert!(
            archival_state
                .block_belongs_to_canonical_chain(&genesis.header, &genesis.header)
                .await,
            "Genesis block is always part of the canonical chain, tip"
        );

        // Insert a block that is descendant from genesis block and verify that it is canonical
        let mock_block_1 = make_mock_block(&genesis.clone(), None);
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
        let mock_block_2_a = make_mock_block(&mock_block_1.clone(), None);
        add_block_to_archival_state(&archival_state, mock_block_2_a.clone()).await?;
        let mock_block_3_a = make_mock_block(&mock_block_2_a.clone(), None);
        add_block_to_archival_state(&archival_state, mock_block_3_a.clone()).await?;
        let mock_block_4_a =
            make_mock_block(&mock_block_3_a.clone(), Some(U32s::new([5000, 0, 0, 0, 0])));
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
        let mock_block_2_b = make_mock_block(&mock_block_1.clone(), None);
        add_block_to_archival_state(&archival_state, mock_block_2_b.clone()).await?;
        let mock_block_3_b = make_mock_block(&mock_block_2_b.clone(), None);
        add_block_to_archival_state(&archival_state, mock_block_3_b.clone()).await?;
        let mock_block_4_b = make_mock_block(&mock_block_3_b.clone(), None);
        add_block_to_archival_state(&archival_state, mock_block_4_b.clone()).await?;
        let mock_block_5_b = make_mock_block(
            &mock_block_4_b.clone(),
            Some(U32s::new([200000, 0, 0, 0, 0])),
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

        let mock_block_3_c = make_mock_block(&mock_block_2_a.clone(), None);
        add_block_to_archival_state(&archival_state, mock_block_3_c.clone()).await?;
        let mock_block_4_c = make_mock_block(&mock_block_3_c.clone(), None);
        add_block_to_archival_state(&archival_state, mock_block_4_c.clone()).await?;
        let mock_block_5_c = make_mock_block(&mock_block_4_c.clone(), None);
        add_block_to_archival_state(&archival_state, mock_block_5_c.clone()).await?;
        let mock_block_6_c = make_mock_block(&mock_block_5_c.clone(), None);
        add_block_to_archival_state(&archival_state, mock_block_6_c.clone()).await?;
        let mock_block_7_c = make_mock_block(&mock_block_6_c.clone(), None);
        add_block_to_archival_state(&archival_state, mock_block_7_c.clone()).await?;
        let mock_block_8_c = make_mock_block(&mock_block_7_c.clone(), None);
        add_block_to_archival_state(&archival_state, mock_block_8_c.clone()).await?;
        let mock_block_5_a = make_mock_block(&mock_block_4_a.clone(), None);
        add_block_to_archival_state(&archival_state, mock_block_5_a.clone()).await?;
        let mock_block_3_d =
            make_mock_block(&mock_block_2_a.clone(), Some(U32s::new([1000, 0, 0, 0, 0])));
        add_block_to_archival_state(&archival_state, mock_block_3_d.clone()).await?;
        let mock_block_4_d =
            make_mock_block(&mock_block_3_d.clone(), Some(U32s::new([2000, 0, 0, 0, 0])));
        add_block_to_archival_state(&archival_state, mock_block_4_d.clone()).await?;
        let mock_block_5_d = make_mock_block(
            &mock_block_4_d.clone(),
            Some(U32s::new([20000, 0, 0, 0, 0])),
        );
        add_block_to_archival_state(&archival_state, mock_block_5_d.clone()).await?;

        // This is the most canonical block in the known set
        let mock_block_6_d =
            make_mock_block(&mock_block_5_d.clone(), Some(U32s::new([2000, 0, 0, 0, 0])));
        add_block_to_archival_state(&archival_state, mock_block_6_d.clone()).await?;

        let mock_block_4_e =
            make_mock_block(&mock_block_3_d.clone(), Some(U32s::new([2006, 0, 0, 0, 0])));
        add_block_to_archival_state(&archival_state, mock_block_4_e.clone()).await?;
        let mock_block_5_e =
            make_mock_block(&mock_block_3_d.clone(), Some(U32s::new([2002, 0, 0, 0, 0])));
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
        let (block_databases, _, root_data_dir_path) = databases(Network::Main).unwrap();
        let ams = ArchivalState::initialize_mutator_set(&root_data_dir_path).unwrap();
        let ams = Arc::new(TokioMutex::new(ams));
        let archival_state = ArchivalState::new(block_databases.clone(), ams, root_data_dir_path);
        let genesis = archival_state.genesis_block.clone();
        archival_state
            .get_ancestor_block_digests(genesis.header.prev_block_digest, 10)
            .await;
    }

    #[traced_test]
    #[tokio::test]
    async fn digest_of_ancestors_test() -> Result<()> {
        let (block_databases, _, root_data_dir_path) = databases(Network::Main).unwrap();
        let ams = ArchivalState::initialize_mutator_set(&root_data_dir_path).unwrap();
        let ams = Arc::new(TokioMutex::new(ams));
        let archival_state = ArchivalState::new(block_databases.clone(), ams, root_data_dir_path);
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
        let mock_block_1 = make_mock_block(&genesis.clone(), None);
        add_block_to_archival_state(&archival_state, mock_block_1.clone()).await?;
        let mock_block_2 = make_mock_block(&mock_block_1.clone(), None);
        add_block_to_archival_state(&archival_state, mock_block_2.clone()).await?;
        let mock_block_3 = make_mock_block(&mock_block_2.clone(), None);
        add_block_to_archival_state(&archival_state, mock_block_3.clone()).await?;
        let mock_block_4 = make_mock_block(&mock_block_3.clone(), None);
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
        let (block_databases, _, root_data_dir_path) = databases(Network::Main).unwrap();
        let ams = ArchivalState::initialize_mutator_set(&root_data_dir_path).unwrap();
        let ams = Arc::new(TokioMutex::new(ams));
        let archival_state = ArchivalState::new(block_databases.clone(), ams, root_data_dir_path);
        let genesis = *archival_state.genesis_block.clone();
        let mock_block_1 = make_mock_block(&genesis.clone(), None);
        let mut db_lock = archival_state.block_databases.lock().await;
        archival_state.write_block(
            Box::new(mock_block_1.clone()),
            &mut db_lock,
            Some(genesis.header.proof_of_work_family),
        )?;

        // Verify that `LastFile` value is stored correctly
        let read_last_file: LastFileRecord = db_lock
            .block_index
            .get(BlockIndexKey::LastFile)
            .unwrap()
            .as_last_file_record();

        assert_eq!(0, read_last_file.last_file);

        // Verify that `Height` value is stored correctly
        {
            let expected_height: u64 = 1;
            let blocks_with_height_1: Vec<Digest> = db_lock
                .block_index
                .get(BlockIndexKey::Height(expected_height.into()))
                .unwrap()
                .as_height_record();

            assert_eq!(1, blocks_with_height_1.len());
            assert_eq!(mock_block_1.hash, blocks_with_height_1[0]);
        }

        // Verify that `File` value is stored correctly
        let expected_file: u32 = read_last_file.last_file;
        let last_file_record_1: FileRecord = db_lock
            .block_index
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
            .block_index
            .get(BlockIndexKey::BlockTipDigest)
            .unwrap()
            .as_tip_digest();

        assert_eq!(mock_block_1.hash, tip_digest);

        // Verify that `Block` is stored correctly
        let actual_block: BlockRecord = db_lock
            .block_index
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
        let mock_block_2 = make_mock_block(&mock_block_1.clone(), None);
        archival_state.write_block(
            Box::new(mock_block_2.clone()),
            &mut db_lock,
            Some(mock_block_1.header.proof_of_work_family),
        )?;

        // Verify that `LastFile` value is updated correctly, unchanged
        let read_last_file_2: LastFileRecord = db_lock
            .block_index
            .get(BlockIndexKey::LastFile)
            .unwrap()
            .as_last_file_record();
        assert_eq!(0, read_last_file.last_file);

        // Verify that `Height` value is updated correctly
        {
            let blocks_with_height_1: Vec<Digest> = db_lock
                .block_index
                .get(BlockIndexKey::Height(1.into()))
                .unwrap()
                .as_height_record();
            assert_eq!(1, blocks_with_height_1.len());
            assert_eq!(mock_block_1.hash, blocks_with_height_1[0]);
        }

        {
            let blocks_with_height_2: Vec<Digest> = db_lock
                .block_index
                .get(BlockIndexKey::Height(2.into()))
                .unwrap()
                .as_height_record();
            assert_eq!(1, blocks_with_height_2.len());
            assert_eq!(mock_block_2.hash, blocks_with_height_2[0]);
        }
        // Verify that `File` value is updated correctly
        let expected_file_2: u32 = read_last_file.last_file;
        let last_file_record_2: FileRecord = db_lock
            .block_index
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
            .block_index
            .get(BlockIndexKey::BlockTipDigest)
            .unwrap()
            .as_tip_digest();
        assert_eq!(mock_block_2.hash, tip_digest_2);

        // Verify that `Block` is stored correctly
        let actual_block_record_2: BlockRecord = db_lock
            .block_index
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
        assert_eq!(mock_block_1.header.hash(), ancestor_digests[0]);
        assert_eq!(genesis.header.hash(), ancestor_digests[1]);

        Ok(())
    }
}
