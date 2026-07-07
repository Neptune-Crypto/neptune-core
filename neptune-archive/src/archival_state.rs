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
use num_traits::CheckedSub;
use num_traits::Zero;
use tasm_lib::prelude::Tip5;
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

pub mod import_blocks_from_files;
pub mod rusty_utxo_index;

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
use tasm_lib::triton_vm::prelude::BFieldElement;

use crate::archival_state::rusty_utxo_index::RustyUtxoIndex;
use crate::block_index::BlockFileLocation;
use crate::block_index::BlockIndexKey;
use crate::block_index::BlockIndexValue;
use crate::block_index::BlockRecord;
use crate::block_index::FileRecord;
use crate::block_index::LastFileRecord;
use crate::rusty_archival_block_mmr::RustyArchivalBlockMmr;
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
