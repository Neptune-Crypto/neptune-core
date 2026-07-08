use std::collections::BTreeSet;
use std::collections::HashMap;
use std::collections::HashSet;
use std::ops::DerefMut;
use std::path::PathBuf;

use anyhow::Result;
use anyhow::bail;
use anyhow::ensure;
use itertools::Itertools;
use memmap2::MmapOptions;
use neptune_consensus::block::Block;
use neptune_consensus::block::INITIAL_BLOCK_SUBSIDY;
use neptune_consensus::block::PREMINE_MAX_SIZE;
use neptune_consensus::block::block_header::BlockHeader;
use neptune_consensus::block::block_header::BlockHeaderWithBlockHashWitness;
use neptune_consensus::block::block_header::HeaderToBlockHashWitness;
use neptune_consensus::block::block_kernel::BlockKernel;
use neptune_consensus::block::mutator_set_update::MutatorSetUpdate;
use neptune_consensus::proof_abstractions::verifier::CHECKPOINT_MAIN;
use neptune_consensus::proof_abstractions::verifier::CHECKPOINT_TESTNET_0;
use neptune_consensus::proof_abstractions::verifier::cache_true_claims;
use neptune_consensus::transaction::lock_script::LockScript;
use neptune_consensus::transaction::transaction_kernel::TransactionKernelProxy;
use neptune_consensus::transaction::utxo::Utxo;
use neptune_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use neptune_database::NeptuneLevelDb;
use neptune_database::WriteBatchAsync;
use neptune_database::create_db_if_missing;
use neptune_database::storage::storage_schema::traits::*;
use neptune_database::storage::storage_vec::traits::StorageVecBase;
use neptune_mutator_set::addition_record::AdditionRecord;
use neptune_mutator_set::commit;
use neptune_mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use neptune_mutator_set::removal_record::RemovalRecord;
use neptune_mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
use neptune_mutator_set::rusty_archival_mutator_set::RustyArchivalMutatorSet;
use neptune_primitives::block_height::BLOCKS_PER_GENERATION;
use neptune_primitives::block_height::BlockHeight;
use neptune_primitives::block_height::NUM_BLOCKS_SKIPPED_BECAUSE_REBOOT;
use neptune_primitives::data_directory::DataDirectory;
use neptune_primitives::network::Network;
use num_traits::CheckedSub;
use num_traits::Zero;
use tasm_lib::prelude::Tip5;
use tasm_lib::triton_vm::prelude::BFieldElement;
use tasm_lib::triton_vm::proof::Claim;
use tasm_lib::twenty_first::bfe_array;
use tasm_lib::twenty_first::prelude::Mmr;
use tasm_lib::twenty_first::tip5::digest::Digest;
use tokio::io::AsyncSeekExt;
use tokio::io::AsyncWriteExt;
use tokio::io::SeekFrom;
use tracing::debug;
#[cfg(any(test, feature = "test-helpers"))]
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::block_index::BlockFileLocation;
use crate::block_index::BlockIndexKey;
use crate::block_index::BlockIndexValue;
use crate::block_index::BlockRecord;
use crate::block_index::FileRecord;
use crate::block_index::LastFileRecord;
use crate::rusty_archival_block_mmr::RustyArchivalBlockMmr;
use crate::rusty_utxo_index::RustyUtxoIndex;
use crate::shared::new_block_file_is_needed;

/// Provides interface to historic blockchain data which consists of
///  * block-data stored in individual files (append-only)
///  * block-index database stored in levelDB
///  * mutator set stored in LevelDB,
///
/// all file operations are async, or async-friendly.
///       see <https://github.com/Neptune-Crypto/neptune-core/issues/75>
pub struct ArchivalState {
    pub(crate) data_dir: DataDirectory,

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
    // this object in a spawned worker task.
    pub genesis_block: Box<Block>,

    // The archival mutator set is persisted to one database that also records a sync label,
    // which corresponds to the hash of the block to which the mutator set is synced.
    pub archival_mutator_set: RustyArchivalMutatorSet,

    /// Archival-MMR of the block digests belonging to the canonical chain.
    pub archival_block_mmr: RustyArchivalBlockMmr,

    /// Mapping from block digest to a list of (flag, receiver_id) pairs for all
    /// announcement in the block, and other indexing data related to historical
    /// blocks. This index is only maintained if the node has been started with
    /// the CLI flag `--utxo-index`, which implies that this value is Some(T).
    /// If the node is not started with this flag, this value is `None`.
    pub utxo_index: Option<RustyUtxoIndex>,

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
            .field("archival_block_mmr", &self.archival_block_mmr)
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
    pub(crate) async fn initialize_mutator_set(
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

    pub async fn new(
        data_dir: DataDirectory,
        genesis_block: Block,
        utxo_index: bool,
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

        let utxo_index = if utxo_index {
            let mut utxo_index = RustyUtxoIndex::initialize(&data_dir)
                .await
                .expect("Must be able to initialize utxo index database");

            if utxo_index.is_empty().await {
                utxo_index.index_block(&genesis_block).await;
            }
            debug!("UTXO index populated");
            Some(utxo_index)
        } else {
            None
        };

        // Populate true claims cache with block claims from checkpoint.
        // network provided by caller
        Self::accept_checkpoint(network).await;
        debug!("Accepted checkpoint");

        let genesis_block = Box::new(genesis_block);
        Self {
            data_dir,
            block_index_db,
            genesis_block,
            archival_mutator_set,
            archival_block_mmr,
            network,
            utxo_index,
        }
    }

    pub fn genesis_block(&self) -> &Block {
        &self.genesis_block
    }

    /// Return the number of files used to store the raw blocks.
    #[cfg(any(test, feature = "test-helpers"))]
    pub async fn num_block_files(&self) -> u32 {
        let last_rec = self
            .block_index_db
            .get(BlockIndexKey::LastFile)
            .await
            .map(|x| x.as_last_file_record())
            .unwrap_or_default();
        last_rec.last_file + 1
    }

    /// Return the directory in which the raw blocks are stored.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn block_dir_path(&self) -> PathBuf {
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

    pub(crate) async fn write_block_internal(
        &mut self,
        block: &Block,
        is_canonical_tip: bool,
    ) -> Result<()> {
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

    /// Update all of archival state with a new block which is set as tip.
    ///
    /// May also be used to set the tip back to any earlier block, including the
    /// genesis block. However, a path from the current tip to the new tip must
    /// be known.
    ///
    /// Performs no validation.
    ///
    /// # Panics
    ///
    /// - If the new tip does not have a mutator set update.
    /// - If databases are in an inconsistent state.
    pub async fn set_new_tip(&mut self, block: &Block) -> Result<()> {
        self.write_block_as_tip(block).await?;
        self.append_to_archival_block_mmr(block).await;
        self.update_mutator_set(block).await?;
        self.update_utxo_index(block).await;

        Ok(())
    }

    /// Ensure internal consistency of archival state.
    ///
    /// Ensure that the entire archival state is consistent with the tip defined
    /// by the block index database and the block it points to on disk.
    ///
    /// This method is only intended to be run on startup. It is intended to
    /// be used to recover from a non-graceful shutdown of the node.
    ///
    /// It can fix an inconsistent archival state which can be produced for
    /// example if the node is shut down after the block index database has been
    /// updated and the block written to disk but before the rest of the
    /// archival state update is finished.
    pub async fn recover(&mut self) -> Result<()> {
        let tip = self.get_tip().await;

        // Since the sub-parts of the archival state handles reorganizations,
        // all we have to do is to call the tip updater again. Then all parts
        // will agree with the block index database.
        self.set_new_tip(&tip).await
    }

    /// Write a newly found block to database and to disk, without setting it as
    /// tip.
    ///
    /// If block was already written to database, then this is a nop as the old
    /// database entries and block stored on disk are considered valid.
    pub async fn write_block_not_tip(&mut self, block: &Block) -> Result<()> {
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
        #[cfg(any(test, feature = "test-helpers"))]
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
            self.archival_block_mmr
                .ammr()
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

    /// Apply a new block to the UTXO index. Does nothing if no UTXO index is
    /// maintained by this archival state.
    ///
    /// This method handles reorganizations, but all predecessors of this block
    /// must be known and stored in the block index database for it to work.
    /// Reorganizations leaves ophaned blocks in the index though. So this must
    /// be accounted for when reading from the index.
    ///
    /// # Panics
    /// - If any of the predecessor blocks have not been applied to the block
    ///   index database.
    async fn update_utxo_index(&mut self, new_block: &Block) {
        if self.utxo_index.is_none() {
            return;
        }

        let current_sync = self.utxo_index.as_ref().unwrap().sync_label().await;
        let new_block_hash = new_block.hash();

        // Index all not-yet-indexed blocks preceding the new block. In the
        // common case, where the new block is the direct descendant of the
        // block that was previously applied, only one block will be processed
        // here. This path-finding logic allows for an efficient common-case
        // processing, and an effcient "catchup" behavior where the UTXO index
        // is many block behind the rest of the archival state.
        let (_, _, missing_blocks) = self.find_path(current_sync, new_block_hash).await;

        // Inform user if this will take a long time.
        let num_missing_blocks = missing_blocks.len();
        debug!("Applying {num_missing_blocks} missing blocks to UTXO index.");
        let process_many_blocks = num_missing_blocks > 10;
        if process_many_blocks {
            info!(
                "Applying {num_missing_blocks} missing blocks to UTXO index. This may take a while."
            )
        }

        for (i, missing) in missing_blocks.into_iter().enumerate() {
            if process_many_blocks && i.is_multiple_of(100) {
                info!("Processed {i}/{num_missing_blocks} blocks for UTXO index")
            }

            // This optimization means that we don't have to read the full
            // blocks from disk in case it was already processed.
            if self
                .utxo_index
                .as_ref()
                .unwrap()
                .block_was_indexed(missing)
                .await
            {
                continue;
            }

            if missing == new_block_hash {
                // Avoid reading the new block from disk if it's already in
                // memory.
                self.utxo_index
                    .as_mut()
                    .unwrap()
                    .index_block(new_block)
                    .await;
            } else {
                let missing = self
                    .get_block(missing)
                    .await
                    .expect("Fetching block must succeed")
                    .expect("missing block must exist before processed by UTXO index");
                self.utxo_index
                    .as_mut()
                    .unwrap()
                    .index_block(&missing)
                    .await;
            }
        }

        if process_many_blocks {
            info!("Done updating UTXO index")
        } else {
            debug!("Done updating UTXO index");
        }
    }

    pub(crate) async fn get_block_from_block_record(
        &self,
        block_record: BlockRecord,
    ) -> Result<Block> {
        let block_file_path: PathBuf = self
            .data_dir
            .block_file_path(block_record.file_location.file_index);

        tokio::task::spawn_blocking(move || {
            let block_file = std::fs::File::open(&block_file_path)
                .map_err(|e| anyhow::anyhow!("IO Error while reading '{}': {e}.", block_file_path.to_string_lossy()))?;

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
    pub(crate) async fn get_tip_from_disk(&self) -> Result<Option<Block>> {
        let tip_block_record = self.tip_block_record().await;
        let Some(tip_block_record) = tip_block_record else {
            return Ok(None);
        };

        let block: Block = self.get_block_from_block_record(tip_block_record).await?;

        Ok(Some(block))
    }

    /// Return the canonical block digest and block height of the block in
    /// which an AOCL leaf with specified index is contained.
    async fn canonical_block_info_of_aocl_index(
        &self,
        aocl_leaf_index: u64,
    ) -> Result<Option<(Digest, BlockHeight)>> {
        // Is AOCL leaf contained in genesis block? Special-case this, as
        // genesis block does not have a block record.
        let genesis_tx: TransactionKernelProxy =
            self.genesis_block.body().transaction_kernel.clone().into();
        if aocl_leaf_index < genesis_tx.outputs.len().try_into().unwrap() {
            return Ok(Some((self.genesis_block.hash(), BlockHeight::genesis())));
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
        let tip_height = record.block_header.height;

        // Is AOCL leaf index after current tip?
        if aocl_leaf_index > record.max_aocl_index() {
            return Ok(None);
        }

        let mut min_block_height = BlockHeight::genesis().next();
        let mut max_block_height = record.block_header.height;

        // Do binary search to find block
        // invariant: min_block_height <= record.block_header.height && record.block_header.height <= max_block_height
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
                return Ok(Some((block_hash, record.block_header.height)));
            };

            let new_guess_height = BlockHeight::arithmetic_mean(min_block_height, max_block_height);
            debug!(
                "canonical_block_digest_of_aocl_index: binary search on [{}:{}] -- new guess is {} (/{})",
                min_block_height, max_block_height, new_guess_height, tip_height
            );
            block_hash = self
                .archival_block_mmr
                .ammr()
                .get_leaf_async(new_guess_height.into())
                .await;
            record = self.get_block_record(block_hash).await.unwrap();
        }
    }

    /// Return the block digest of the block in which an AOCL leaf with
    /// specified index is contained.
    pub async fn canonical_block_digest_of_aocl_index(
        &self,
        aocl_leaf_index: u64,
    ) -> Result<Option<Digest>> {
        Ok(self
            .canonical_block_info_of_aocl_index(aocl_leaf_index)
            .await?
            .map(|(block_digest, _)| block_digest))
    }

    /// Returns some block info about all blocks in which the UTXO, identified
    /// by its absolute indices, could have originated.
    ///
    /// The fuzzy timestamp of the absolute index set is used to calculate the
    /// range of blocks in which the UTXO could have been mined.
    ///
    /// Only blocks on the current canonical chain are considered.
    ///
    /// Never loads a block from disk, so performance is good.
    pub async fn utxo_origin_blocks_from_absolute_index_sets(
        &self,
        absolute_index_sets: impl IntoIterator<Item = AbsoluteIndexSet>,
    ) -> Result<Vec<(Digest, BlockHeader, u64, u64)>> {
        let num_aocl_leafs = self.archival_mutator_set.ams().aocl.num_leafs().await;

        if num_aocl_leafs == 0 {
            return Ok(vec![]);
        }

        let last_aocl_index = num_aocl_leafs - 1;
        let mut block_heights = BTreeSet::new();
        for absolute_index_set in absolute_index_sets {
            let (range_start, range_end) = absolute_index_set.aocl_range()?;

            if range_start > last_aocl_index {
                continue;
            }

            let capped_range_end = std::cmp::min(range_end, last_aocl_index);
            let Some((_, start_block_height)) =
                self.canonical_block_info_of_aocl_index(range_start).await?
            else {
                continue;
            };
            let Some((_, end_block_height)) = self
                .canonical_block_info_of_aocl_index(capped_range_end)
                .await?
            else {
                continue;
            };

            for height in start_block_height.value()..=end_block_height.value() {
                block_heights.insert(BlockHeight::from(height));
            }
        }

        let mut block_infos = Vec::with_capacity(block_heights.len());
        for height in block_heights {
            let block_hash = self
                .archival_block_mmr
                .ammr()
                .try_get_leaf(height.value())
                .await
                .expect("Canonical block height must have a block digest");
            let (header, min_aocl_index, max_aocl_index) =
                if block_hash == self.genesis_block.hash() {
                    (
                        *self.genesis_block.header(),
                        0,
                        self.genesis_block.body().max_aocl_leaf_index(),
                    )
                } else {
                    let record = self
                        .get_block_record(block_hash)
                        .await
                        .expect("Block record of canonical hash must exist");
                    (
                        record.block_header,
                        record.min_aocl_index,
                        record.max_aocl_index(),
                    )
                };

            block_infos.push((block_hash, header, min_aocl_index, max_aocl_index));
        }

        Ok(block_infos)
    }

    /// Returns the 1st block containing this addition record. Returns
    /// `None` if no canonical block with this output is known.
    ///
    /// searches max `max_search_depth` from tip for a matching transaction
    /// output. Unless the node maintain a UTXO index in which case all blocks
    /// are searched and this parameter is ignored.
    ///
    /// If `max_search_depth` is set to `None`, then all blocks are searched
    /// until a match is found. A `max_search_depth` of `Some(0)` will only
    /// consider the tip.
    pub async fn find_canonical_block_with_output(
        &self,
        output: AdditionRecord,
        max_search_depth: Option<u64>,
    ) -> Option<Block> {
        let block_hash = self
            .find_canonical_block_hash_with_output(output, max_search_depth)
            .await?;
        Some(
            self.get_block(block_hash)
                .await
                .expect("Database reading of block must succeed")
                .expect("Block reported to contain addition record must exist"),
        )
    }

    /// Returns the 1st block hash containing this addition record. Returns
    /// `None` if no canonical block with this output is known.
    ///
    /// searches max `max_search_depth` from tip for a matching transaction
    /// output. Unless the node maintain a UTXO index in which case all blocks
    /// are searched and this parameter is ignored.
    ///
    /// If `max_search_depth` is set to `None`, then all blocks are searched
    /// until a match is found. A `max_search_depth` of `Some(0)` will only
    /// consider the tip.
    ///
    /// Never loads blocks from disk, so performance should be good.
    pub(crate) async fn find_canonical_block_hash_with_output(
        &self,
        output: AdditionRecord,
        max_search_depth: Option<u64>,
    ) -> Option<Digest> {
        let block_heights = match &self.utxo_index {
            Some(utxo_index) => {
                let heights = utxo_index
                    .blocks_by_addition_record(output)
                    .await
                    .into_iter()
                    .map(|x| x.value())
                    .sorted_unstable();
                itertools::Either::Left(heights)
            }
            None => {
                let tip_height = self.tip_header().await.height.value();

                let end = match max_search_depth {
                    Some(num) => tip_height.saturating_sub(num),
                    None => 0,
                };

                let heights = (end..=tip_height).rev();
                itertools::Either::Right(heights)
            }
        };

        for block_height in block_heights {
            let (addition_records, block_hash) = self
                .addition_record_indices_for_block_by_height(block_height)
                .await
                .expect("Block height from UTXO index must be known");

            if addition_records.contains_key(&output) {
                return Some(block_hash);
            }
        }

        None
    }

    /// Returns the block containing this input. Returns `None` if no canonical
    /// block with this input is known.
    ///
    /// searches max `max_search_depth` from tip for a matching transaction
    /// input.
    ///
    /// searches max `max_search_depth` from tip for a matching transaction
    /// input. Unless the node maintain a UTXO index in which case all blocks
    /// are searched and this parameter is ignored.
    pub async fn find_canonical_block_with_input(
        &self,
        input: AbsoluteIndexSet,
        max_search_depth: Option<u64>,
    ) -> Option<Block> {
        let block_heights = match &self.utxo_index {
            Some(utxo_index) => {
                let heights = utxo_index
                    .block_by_index_set(&input)
                    .await
                    .into_iter()
                    .map(|x| x.value())
                    .sorted_unstable();
                itertools::Either::Left(heights)
            }
            None => {
                let tip_height = self.tip_header().await.height.value();

                let end = match max_search_depth {
                    Some(num) => tip_height.saturating_sub(num),
                    None => 0,
                };

                let heights = (end..=tip_height).rev();
                itertools::Either::Right(heights)
            }
        };

        for block_height in block_heights {
            let block = self
                .canonical_block_by_height(block_height.into())
                .await
                .expect("Canonical block with in-range height must exist");
            if block
                .body()
                .transaction_kernel
                .inputs
                .iter()
                .any(|rr| rr.absolute_indices == input)
            {
                return Some(block);
            }
        }

        None
    }

    /// Return all block heights of blocks belonging to the canonical chain
    /// containing any of the requested addition records.
    ///
    /// Never loads the entire block from disk. Only reads from the database, so
    /// performace should be good.
    ///
    /// Only works if a UTXO index is maintained.
    pub async fn addition_records_to_block_height(
        &self,
        addition_records: HashSet<AdditionRecord>,
    ) -> Result<HashSet<BlockHeight>> {
        ensure!(
            self.utxo_index.is_some(),
            "Only works a UTXO index is maintained."
        );

        let mut ret = HashSet::new();
        for addition_record in addition_records {
            let maybe_matching_blocks = self
                .utxo_index
                .as_ref()
                .unwrap()
                .blocks_by_addition_record(addition_record)
                .await;

            // Verify reported block height matches a block in the canonical
            // chain.
            // An addition record can (theoretically) be present in mutiple
            // blocks, and even multiple times in the same block. This loop
            // handles that case. Common case is that returned list has length
            // zero or one.
            for height in maybe_matching_blocks {
                let (actual_ars_in_canonical_block, _) = self
                    .addition_record_indices_for_block_by_height(height.into())
                    .await
                    .expect("Height reported by UTXO index must be known by archival state");
                if actual_ars_in_canonical_block.contains_key(&addition_record) {
                    ret.insert(height);
                }
            }
        }

        Ok(ret)
    }

    /// Return all block heights of blocks belonging to the canonical chain
    /// containing any of the requested absolute index sets.
    ///
    /// Never loads the entire block from disk. Only reads from the database, so
    /// performace should be good.
    ///
    /// Only works if a UTXO index is maintained.
    pub async fn absolute_index_sets_to_block_heights(
        &self,
        absolute_index_sets: HashSet<AbsoluteIndexSet>,
    ) -> Result<HashSet<BlockHeight>> {
        ensure!(
            self.utxo_index.is_some(),
            "Only works a UTXO index is maintained."
        );

        let mut ret = HashSet::new();
        for index_set in absolute_index_sets {
            let maybe_matching_block = self
                .utxo_index
                .as_ref()
                .unwrap()
                .block_by_index_set(&index_set)
                .await;

            let Some(maybe_matching_block) = maybe_matching_block else {
                continue;
            };

            // No use to add same block height twice.
            if ret.contains(&maybe_matching_block) {
                continue;
            }

            // Verify that the block height in question has not been reorganized
            // out of canonicity.
            let Some(block_hash) = self
                .archival_block_mmr
                .ammr()
                .try_get_leaf(maybe_matching_block.into())
                .await
            else {
                // Reorganization to shorter chain. Very unlikely.
                continue;
            };

            let block_index_set_digests = self
                .utxo_index
                .as_ref()
                .unwrap()
                .index_set_digests(block_hash)
                .await
                .expect("Canonical block must have been indexed by UTXO index");

            let index_set_digest = Tip5::hash(&index_set);
            if block_index_set_digests.contains(&index_set_digest) {
                ret.insert(maybe_matching_block);
            }
        }

        Ok(ret)
    }

    /// Return the block heights for blocks matching *all* elements in the
    /// specified input/output lists, for blocks belonging to the canonical
    /// chain. Will not return block heights were e.g. only one of the outputs
    /// was included if more than one output is included in the outputs list.
    ///
    /// Can return multiple blocks in the case where blocks are selected only
    /// based on addition records and multiple blocks contain the same addition
    /// records.
    ///
    /// Only works if a UTXO index is maintained, otherwise an error is
    /// returned.
    ///
    /// # Panics
    /// - If no filtering is applied, i.e. if both input and output lists are
    ///   empty.
    pub async fn canonical_block_heights_with_puts(
        &self,
        absolute_index_sets: HashSet<AbsoluteIndexSet>,
        addition_records: HashSet<AdditionRecord>,
    ) -> Result<HashSet<BlockHeight>> {
        ensure!(
            self.utxo_index.is_some(),
            "Only works a UTXO index is maintained."
        );

        assert!(
            !addition_records.is_empty() || !absolute_index_sets.is_empty(),
            "No filtering was applied"
        );

        let mut block_matches: Option<HashSet<BlockHeight>> = None;
        for index_set in absolute_index_sets {
            let block_heights = self
                .absolute_index_sets_to_block_heights(HashSet::from([index_set]))
                .await
                .expect("Utxo index namespace can only be active when UTXO index is present");

            match block_matches {
                Some(bmatches) => {
                    block_matches = Some(bmatches.intersection(&block_heights).copied().collect());
                }
                None => {
                    block_matches = Some(block_heights);
                }
            }
        }

        for addition_record in addition_records {
            let block_heights = self
                .addition_records_to_block_height(HashSet::from([addition_record]))
                .await
                .expect("Utxo index namespace can only be active when UTXO index is present");

            match block_matches {
                Some(bmatches) => {
                    block_matches = Some(bmatches.intersection(&block_heights).copied().collect());
                }
                None => {
                    block_matches = Some(block_heights);
                }
            }
        }

        Ok(block_matches.expect("At least one filtering criteria was set"))
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

    /// Return the header of tip, without loading a whole block from disk.
    pub(crate) async fn tip_header(&self) -> BlockHeader {
        let tip_digest = self
            .block_index_db
            .get(BlockIndexKey::BlockTipDigest)
            .await
            .unwrap_or_else(|| BlockIndexValue::BlockTipDigest(self.genesis_block().hash()))
            .as_tip_digest();

        self.get_block_header(tip_digest)
            .await
            .expect("Header must be known for tip.")
    }

    /// Return parent of tip block. Returns `None` iff tip is genesis block.
    pub async fn get_tip_parent(&self) -> Option<Block> {
        let tip_header = self.tip_header().await;
        if tip_header.height.is_genesis() {
            return None;
        }

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
    pub async fn get_block_header(&self, block_digest: Digest) -> Option<BlockHeader> {
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
    pub async fn block_header_with_hash_witness(
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
    pub(crate) async fn get_block_record(&self, block_digest: Digest) -> Option<BlockRecord> {
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
    pub async fn get_block(&self, block_digest: Digest) -> Result<Option<Block>> {
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

    /// Return the (block kernel, proof leaf) as identified by block hash.
    ///
    /// The proof leaf is the MAST hash leaf of the proof that is used to
    /// calculate the block hash.
    ///
    /// Return:
    ///  - `Ok(Some((block, None)))` in case of success where the returned block
    ///    *is* the genesis block.
    ///  - `Ok(Some((block, Some(proof_leaf))))` in case of success where the
    ///    returned block is *not* the genesis block.
    ///  - `Ok(None)` if the block does not live in archival state.
    ///  - `Err(_)` if there was a problem reading from archival state.
    pub async fn get_block_kernel_with_proof_digest(
        &self,
        block_digest: Digest,
    ) -> Result<Option<(BlockKernel, Option<Digest>)>> {
        let maybe_record = self.get_block_record(block_digest).await;
        let Some(record) = maybe_record else {
            let maybe_genesis_block =
                (self.genesis_block.hash() == block_digest).then_some(*self.genesis_block.clone());
            let maybe_genesis_block =
                maybe_genesis_block.map(|genesis| (genesis.kernel.clone(), None));
            return Ok(maybe_genesis_block);
        };

        // Fetch block from disk
        let block = self.get_block_from_block_record(record).await?;

        // Perf: avoid recalculating the proof leaf. Just read it from the
        // block record.
        Ok(Some((
            block.kernel.clone(),
            Some(record.block_hash_witness.proof_leaf()),
        )))
    }

    /// Return the canonical block with the given height. None if no height of
    /// this block is known yet.
    pub async fn canonical_block_by_height(&self, block_height: BlockHeight) -> Option<Block> {
        let block_hash = self
            .archival_block_mmr
            .ammr()
            .try_get_leaf(block_height.value())
            .await?;
        Some(
            self.get_block(block_hash)
                .await
                .expect("Block loading must work")
                .expect("Canonical block with in-range height must exist"),
        )
    }

    /// Return the guesser rewards for the specified block belonging to the
    /// canonical chain, as `(addition record, AOCL index)` pairs. Can be used
    /// to check if a wallet has already registered guesser reward UTXOs.
    ///
    /// Returns none if no block of the specified height belonging to the
    /// canonical chain is known.
    ///
    /// Perf: Does not read block from disk.
    ///
    /// # Panics
    ///
    ///  - If the database is corrupted.
    pub async fn guesser_reward_addition_records_for_block(
        &self,
        block_height: u64,
    ) -> Option<Vec<(AdditionRecord, u64)>> {
        if block_height == BlockHeight::genesis().value() {
            return Some(vec![]);
        }

        let Some(block_hash) = self
            .archival_block_mmr
            .ammr()
            .try_get_leaf(block_height)
            .await
        else {
            warn!(
                "Attempted to get addition records for block height {block_height} which is not known."
            );
            return None;
        };

        let block_record = self
            .get_block_record(block_hash)
            .await
            .expect("Must know block record of canonical and non-genesis block");

        // The protocol dictates that the timelocked UTXO comes first, then the
        // liquid.
        let leaf_index_timelocked = block_record.max_aocl_index() - 1;
        let addition_record_timelocked = self
            .archival_mutator_set
            .ams()
            .aocl
            .get_leaf_async(leaf_index_timelocked)
            .await;

        let leaf_index_liquid = block_record.max_aocl_index();
        let addition_record_liquid = self
            .archival_mutator_set
            .ams()
            .aocl
            .get_leaf_async(leaf_index_liquid)
            .await;

        Some(vec![
            (
                AdditionRecord::new(addition_record_timelocked),
                leaf_index_timelocked,
            ),
            (
                AdditionRecord::new(addition_record_liquid),
                leaf_index_liquid,
            ),
        ])
    }

    /// Returns a [`HashMap`] of [`AdditionRecord`] to  AOCL leaf indices for
    /// all outputs in a given block, including guesser rewards.  Also returns
    /// the block hash. Returns `None` if no block at the specified height is
    /// known. AOCL leaf indices have list type since a block can contain the
    /// same addition record multiple times.
    ///
    /// Never loads the entire block from disk. Only reads from the database, so
    /// performace should be good.
    ///
    /// # Panics
    ///
    ///  - If the database is corrupted.
    pub async fn addition_record_indices_for_block_by_height(
        &self,
        block_height: u64,
    ) -> Option<(HashMap<AdditionRecord, Vec<u64>>, Digest)> {
        let (aocl_leaf_indices, block_hash) = if block_height == BlockHeight::genesis().value() {
            // Special-case for genesis block since it has no block record.
            let num_outputs_in_genesis: u64 = self
                .genesis_block()
                .body()
                .transaction_kernel()
                .outputs
                .len()
                .try_into()
                .expect("Can always convert usize to u64");
            let range = 0u64..=(num_outputs_in_genesis - 1);
            (range, self.genesis_block().hash())
        } else {
            let Some(block_hash) = self
                .archival_block_mmr
                .ammr()
                .try_get_leaf(block_height)
                .await
            else {
                warn!(
                    "Attempted to get addition records for block height {block_height} which is not known."
                );
                return None;
            };

            let block_record = self
                .get_block_record(block_hash)
                .await
                .expect("Must know block record of canonical and non-genesis block");

            let range = block_record.min_aocl_index..=block_record.max_aocl_index();
            (range, block_hash)
        };

        // Getting all leafs in a batch-read operation was benchmarked to be
        // faster than getting each leaf individually. So batch-reading of leafs
        // was chosen here.
        let addition_records = self
            .archival_mutator_set
            .ams()
            .aocl
            .get_leaf_range_inclusive_async(aocl_leaf_indices.clone())
            .await;
        let mut ret = HashMap::new();
        for (ar, leaf_index) in addition_records.into_iter().zip_eq(aocl_leaf_indices) {
            let addition_record = AdditionRecord::new(ar);
            ret.entry(addition_record)
                .and_modify(|e: &mut Vec<u64>| e.push(leaf_index))
                .or_insert(vec![leaf_index]);
        }

        Some((ret, block_hash))
    }

    /// Returns a [`HashMap`] of [`AdditionRecord`] to [`Option`] of AOCL leaf
    /// index (`u64`) for all outputs in a given block. If the block is not
    /// canonical, the indices are all `None`, and conversely, if the block is
    /// canonical then the indices point into the current mutator set AOCL.
    /// If the block does not live in the archival state, return `None`.
    ///
    /// If the block is canonical this method never loads the entire blocks from
    /// disk. So in that case, it is guaranteed to perform well.
    ///
    /// # Panics
    ///
    ///  - If the block is not canonical, was stored, and reading it from disk
    ///    fails.
    ///  - If the block is not canonical, was stored, and is invalid.
    pub async fn get_addition_record_indices_for_block(
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

    /// Returns true iff the (block height, block hash) pair represents a block
    /// in the canonical chain.
    ///
    /// Returns false if the block has a higher height than the current tip.
    /// Canonicity is defined as all direct ancestors of the current tip.
    pub async fn is_canonical_block(&self, block_hash: Digest, block_height: BlockHeight) -> bool {
        let block_height: u64 = block_height.into();
        self.archival_block_mmr
            .ammr()
            .try_get_leaf(block_height)
            .await
            .is_some_and(|canonical_digest_at_this_height| {
                canonical_digest_at_this_height == block_hash
            })
    }

    /// Return a boolean indicating if block belongs to most canonical chain.
    ///
    /// Returns false if either the block is not known, or if it's known but
    /// has been orphaned.
    pub async fn block_belongs_to_canonical_chain(&self, block_digest: Digest) -> bool {
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
    pub async fn old_mutator_set_and_mutator_set_update_to_tip(
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
    pub async fn get_mutator_set_update_to_tip(
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
    // Public bc used in benchmarks.
    #[doc(hidden)]
    pub async fn update_mutator_set(&mut self, new_block: &Block) -> Result<()> {
        #[cfg(any(test, feature = "test-helpers"))]
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
            new_block.mutator_set_accumulator_after().unwrap().hash(),
            self.archival_mutator_set.ams().hash().await,
            "Calculated archival mutator set commitment must match that from newly added block. Block Digest: {:?}",
            new_block.hash()
        );

        // Persist updated mutator set to disk, with sync label
        self.archival_mutator_set
            .set_sync_label(new_block.hash())
            .await;
        self.archival_mutator_set.persist().await;

        Ok(())
    }

    /// Compute the circulating supply heuristically, measured in Neptune coins.
    ///
    /// This number counts (all):
    ///  - the premine
    ///  - the redemption claims fund (because of reboot)
    ///  - all liquid mined coins up until this block height
    ///  - mined time-locked coins provided that the time-lock has expired.
    ///
    /// It does not count coins that were mined and whose time-lock is still
    /// active.
    ///
    /// Also, the amounts of known burn events are taken into account.
    ///
    /// The heuristic comes from three simplifications:
    ///  1. We assume that every block that was mined did in fact mine the
    ///     maximum allowable coinbase amount, whereas in fact miners are
    ///     allowed to mint less than the subsidy.
    ///  2. We assume that time-locked coins expire exactly one full generation
    ///     after they are minted, when in fact they expire based on timestamps
    ///     and not based on block heights.
    ///  3. We assume all known burns are accounted for, whereas there might be
    ///     more.
    pub async fn circulating_supply(&self) -> NativeCurrencyAmount {
        let premine = PREMINE_MAX_SIZE;
        let claims_pool = INITIAL_BLOCK_SUBSIDY
            .scalar_mul(u32::try_from(NUM_BLOCKS_SKIPPED_BECAUSE_REBOOT).unwrap());

        let block_height = self.get_tip().await.header().height;
        let mined_liquid = Block::mined_immediately_liquid_supply(block_height);
        let mined_released = Block::mined_timelocked_and_released_supply(block_height);

        let burned = self.burned_supply().await;

        debug!("premine: {premine}");
        debug!("claims pool: {claims_pool}");
        debug!("mined liquid: {mined_liquid}");
        debug!("mined released: {mined_released}");
        debug!("burned: {burned}");

        (premine + claims_pool + mined_liquid + mined_released)
            .checked_sub(&burned)
            .unwrap_or(NativeCurrencyAmount::zero())
    }

    /// Compute the asymptotical supply of the limit heuristically, measured in
    /// Neptune coins.
    ///
    /// This number counts (all):
    ///  - the premine
    ///  - the redemption claims fund (because of reboot)
    ///  - all mined coins, liquid or time-locked, between genesis and the last nau.
    ///
    /// Also, the amounts of known burn events are taken into account.
    pub async fn max_supply(&self) -> NativeCurrencyAmount {
        let premine = PREMINE_MAX_SIZE;
        let claims_pool = INITIAL_BLOCK_SUBSIDY
            .scalar_mul(u32::try_from(NUM_BLOCKS_SKIPPED_BECAUSE_REBOOT).unwrap());

        let block_height = BlockHeight::from(BLOCKS_PER_GENERATION * 130);
        let mined = Block::mined_supply(block_height);

        let burned = self.burned_supply().await;

        debug!("premine: {premine}");
        debug!("claims pool: {claims_pool}");
        debug!("mined: {mined}");
        debug!("burned: {burned}");

        (premine + claims_pool + mined)
            .checked_sub(&burned)
            .unwrap_or(NativeCurrencyAmount::zero())
    }

    /// Compute the total amount of all coins burned, according to all known
    /// burn events.
    pub async fn burned_supply(&self) -> NativeCurrencyAmount {
        let mut burned = NativeCurrencyAmount::zero();
        for utxo in self.authentic_burns().await {
            burned += utxo.get_native_currency_amount();
        }
        burned
    }

    /// Produce a list of verified burned UTXOs.
    ///
    /// Start from the suggestion of [`Self::known_burns`] and verify them
    /// against the given state.
    pub(crate) async fn authentic_burns(&self) -> Vec<Utxo> {
        let mut authentic_burns = vec![];

        let known_burns = Self::known_burns();

        debug!("Validating {} known burns.", known_burns.len());

        for (
            block_height,
            output_index,
            amount,
            lock_script_hash,
            sender_randomness,
            receiver_digest,
        ) in Self::known_burns()
        {
            // Verify that lock script hash is that of burn lock script or that
            // receiver digest is all-zeros (either suffices).
            if receiver_digest != Digest::new(bfe_array![0;5])
                && lock_script_hash != LockScript::burn().hash()
            {
                debug!(
                    "Burn {}/{} could not be validated because the receiver \
                    digest =/= (0,0,0,0,0) and the lock script hash does not \
                    agree with the burn lock script.",
                    block_height, output_index
                );
                continue;
            }

            // Get block.
            let candidate_block_digests = self.block_height_to_block_digests(block_height).await;
            let mut canonical_block_digest = Digest::default();
            for candidate_block_digest in candidate_block_digests {
                if self
                    .block_belongs_to_canonical_chain(candidate_block_digest)
                    .await
                {
                    canonical_block_digest = candidate_block_digest;
                }
            }
            let Ok(Some(block)) = self.get_block(canonical_block_digest).await else {
                debug!(
                    "Burn {}/{} could not be validated because no block with \
                    digest {canonical_block_digest:x} was found.",
                    block_height, output_index
                );
                continue;
            };

            // Get output.
            let Some(&output) = block.body().transaction_kernel.outputs.get(output_index) else {
                debug!(
                    "Burn {}/{} could not be validated because referenced \
                    block does not contain any outputs with the given index \
                    {output_index}.",
                    block_height, output_index
                );
                continue;
            };

            // Re-create UTXO.
            let utxo = Utxo::new_native_currency(lock_script_hash, amount);

            // Re-create addition record.
            let addition_record = commit(Tip5::hash(&utxo), sender_randomness, receiver_digest);

            // On match, append UTXOs to running list.
            if output == addition_record {
                debug!(
                    "UTXO {block_height}/{output_index} ({:x}) with {} coins were burned.",
                    addition_record.canonical_commitment,
                    utxo.get_native_currency_amount()
                );
                authentic_burns.push(utxo);
            } else if block
                .body()
                .transaction_kernel
                .outputs
                .contains(&addition_record)
            {
                let correct_index = block
                    .body()
                    .transaction_kernel
                    .outputs
                    .iter()
                    .enumerate()
                    .find(|(_i, d)| **d == addition_record)
                    .map(|(i, _d)| i)
                    .unwrap();
                warn!(
                    "UTXO {:x} was burned but index is not {output_index} but {correct_index}. Fix the code, dummy! ;-)",
                    addition_record.canonical_commitment
                );
                authentic_burns.push(utxo);
            } else {
                debug!(
                    "Burn {}/{} could not be validated because referenced \
                    output does not agree with recreated addition record.",
                    block_height, output_index
                );
                debug!(
                    "Addition record {block_height}/{output_index}: {:x}",
                    output.canonical_commitment
                );
                debug!(
                    "Re-created digest: {:x}",
                    addition_record.canonical_commitment
                );
            }
        }

        authentic_burns
    }

    /// Return a list of "known" burn events.
    ///
    /// The list is given as a vector of (block-height, output-index, amount,
    /// lock-script-hash, sender_randomness, receiver_digest) tuples.
    ///
    /// Note that this list is not definite since, in theory, a deep
    /// reorganization could undo these burns.
    pub(crate) fn known_burns() -> Vec<(
        BlockHeight,
        usize,
        NativeCurrencyAmount,
        Digest,
        Digest,
        Digest,
    )> {
        vec![
            (
                BlockHeight::from(16452),
                1,
                NativeCurrencyAmount::coins_from_str("0.10396").unwrap(),
                // Since we don't know the lock script hash of this UTXO, we
                // actually can't authenticate the amount in this burn.
                Digest::try_from_hex("00000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap(),
                Digest::try_from_hex("00000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap(),
                Digest::try_from_hex("00000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap(),
            ),
            (
                BlockHeight::from(16815),
                1,
                NativeCurrencyAmount::coins_from_str("0.10000").unwrap(),
                LockScript::burn().hash(),
                Digest::try_from_hex("01000000000000000200000000000000030000000000000004000000000000000500000000000000").unwrap(),
                Digest::try_from_hex("00000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap(),
            ),
            (
                BlockHeight::from(16999),
                3,
                NativeCurrencyAmount::coins_from_str("1526640.00000").unwrap(),
                LockScript::burn().hash(),
                Digest::try_from_hex("01000000000000000200000000000000030000000000000004000000000000000500000000000000").unwrap(),
                Digest::try_from_hex("00000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap(),
            ),
        ]
    }

    /// Populate the true claims cache with the claims derived from the blocks
    /// defined by the checkpoint as valid.
    pub async fn accept_checkpoint(network: Network) {
        let checkpoint = match network {
            Network::Main => CHECKPOINT_MAIN,
            Network::Testnet(0) => CHECKPOINT_TESTNET_0,
            _ => return,
        };

        // Parse checkpoint.
        let historical_block_claims = checkpoint
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                if line.is_empty() {
                    return None;
                }
                line.split_once(' ').map(|(_, hex)| hex.trim())
            })
            .map(|h| hex::decode(h).unwrap())
            .map(|b| bincode::deserialize::<Claim>(&b).unwrap())
            .collect_vec();

        // Populate true claims cache
        cache_true_claims(historical_block_claims).await;
    }
}

/// Test-support consistency checks for [`ArchivalState`].
#[cfg(any(test, feature = "test-helpers"))]
impl ArchivalState {
    pub(crate) async fn is_consistent(&self, expected_tip: &Block) -> bool {
        let expected_tip_digest = expected_tip.hash();

        if expected_tip_digest != self.get_tip().await.hash() {
            error!("Archival state must have expected tip");
            return false;
        }

        if expected_tip_digest != self.archival_mutator_set.get_sync_label() {
            error!("Archival state must have expected sync-label");
            return false;
        }

        let expected_msa = expected_tip.mutator_set_accumulator_after().unwrap();
        let msa_from_archive = self.archival_mutator_set.ams().accumulator().await;
        if expected_msa != msa_from_archive {
            error!("Archival mutator set must match that in expected tip");
            return false;
        }

        if expected_msa.hash() != msa_from_archive.hash() {
            error!("Archival mutator set hash must match that in expected tip");
            return false;
        }

        if expected_tip_digest
            != self
                .get_block(expected_tip_digest)
                .await
                .unwrap()
                .unwrap()
                .hash()
        {
            error!("Expected block must be found in stored state");
            return false;
        }

        if expected_tip_digest
            != self
                .archival_block_mmr
                .ammr()
                .get_latest_leaf()
                .await
                .unwrap()
        {
            error!("Latest leaf in archival block MMR must match expected block");
            return false;
        }

        {
            let mut expected_archival_block_mmr_value =
                expected_tip.body().block_mmr_accumulator.clone();
            expected_archival_block_mmr_value.append(expected_tip_digest);
            if expected_archival_block_mmr_value
                != self.archival_block_mmr.ammr().to_accumulator_async().await
            {
                error!("archival block-MMR must match that in tip after adding tip digest");
                return false;
            }
        }

        if let Some(utxo_index) = &self.utxo_index
            && !utxo_index.block_was_indexed(expected_tip_digest).await
        {
            error!("UTXO index has not processed tip");
            return false;
        }

        true
    }

    pub async fn assert_consistent(&self, expected_tip: &Block) {
        assert!(self.is_consistent(expected_tip).await);
    }
}

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
        use crate::rusty_utxo_index::*;

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
