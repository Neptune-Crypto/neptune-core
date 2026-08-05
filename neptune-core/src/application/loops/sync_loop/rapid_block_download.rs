use std::collections::HashMap;
use std::path::PathBuf;

use neptune_consensus::block::Block;
use neptune_primitives::block_height::BlockHeight;
use neptune_primitives::network::Network;
use rand::rng;
use rand::RngCore;
use tasm_lib::twenty_first::prelude::Mmr;
use tasm_lib::twenty_first::prelude::MmrMembershipProof;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
use tokio::fs;

use crate::application::loops::sync_loop::SynchronizationBitMask;

/// Truncate an MMR authentication path to one relative to an MMR with fewer
/// leafs.
///
/// The entries of an MMR authentication path are append-invariant: appending
/// leafs to the MMR only ever extends the path. So the path for a leaf
/// relative to a smaller MMR is a prefix of the path relative to a larger one
/// — provided the smaller MMR is a prefix of the larger, which this function
/// cannot check. The caller must verify the returned path against the peaks
/// of the target MMR before relying on, or sharing, it.
///
/// Returns `None` if the target MMR does not contain the leaf, or if it
/// requires a longer path than the given one — which happens when the path's
/// own MMR is the smaller one.
pub(crate) fn truncate_auth_path(
    auth_path: &MmrMembershipProof,
    leaf_index: u64,
    target_num_leafs: u64,
) -> Option<MmrMembershipProof> {
    if leaf_index >= target_num_leafs {
        return None;
    }

    let target_len = (leaf_index ^ target_num_leafs).ilog2() as usize;
    if target_len > auth_path.authentication_path.len() {
        return None;
    }

    Some(MmrMembershipProof::new(
        auth_path.authentication_path[..target_len].to_vec(),
    ))
}

/// The state of a rapid block download process.
///
/// Blocks can come in asynchronously and out of order. We need to keep track
/// of which blocks we already processed before starting the rapid block
/// download process, which blocks we received in the course of running the
/// process, and which blocks we have yet to receive.
#[derive(Debug, Clone)]
pub(crate) struct RapidBlockDownload {
    block_storage_dir: PathBuf,
    coverage: SynchronizationBitMask,
    index_to_filename: HashMap<u64, PathBuf>,

    target_height: BlockHeight,

    /// User-specified sync directory, if any.
    sync_dir: Option<PathBuf>,

    network: Network,
}

impl RapidBlockDownload {
    /// The base directory for unprocessed blocks.
    ///
    /// Either take the `sync_dir` supplied by the user or, if none, ask the OS for a storage directory. The "base" indicates that the blocks are actually stored in a random subdirectory of this one -- random so as to avoid collisions.
    fn base_storage_dir(sync_dir: &Option<PathBuf>, network: Network) -> PathBuf {
        if let Some(dir) = sync_dir {
            dir.clone()
        } else {
            let suffix = format!(
                "rapid-block-download-{}-{network}/",
                whoami::username().unwrap_or("".to_string())
            );
            std::env::temp_dir().join(suffix)
        }
    }

    /// The target block height we are syncing to.
    pub(crate) fn target(&self) -> BlockHeight {
        self.target_height
    }

    /// Set up a [`RapidBlockDownload`] state.
    pub(crate) async fn new(
        target_height: BlockHeight,
        resume_if_possible: bool,
        sync_dir: Option<PathBuf>,
        network: Network,
    ) -> Result<Self, RapidBlockDownloadError> {
        let storage_dir =
            match Self::try_resume_directory(resume_if_possible, &sync_dir, network).await {
                Some(d) => d,
                None => {
                    tracing::debug!(
                        "No existing storage directory for syncing found, creating new one."
                    );
                    let storage_dir = Self::base_storage_dir(&sync_dir, network)
                        .join(format!("{}/", rng().next_u64()));
                    tokio::fs::create_dir_all(&storage_dir)
                        .await
                        .map_err(|e| RapidBlockDownloadError::IO(e.to_string()))?;
                    storage_dir
                }
            };

        let mut index_to_filename = HashMap::new();
        let mut coverage = SynchronizationBitMask::new(1, target_height.next().value());

        // Read and process all the files in the storage directory.
        // There is only something to iterate over if we are resuming from an
        // aborted state.
        let mut number_blocks_recovered = 0;
        let mut entry_iterator = fs::read_dir(&storage_dir)
            .await
            .map_err(|e| RapidBlockDownloadError::IO(e.to_string()))?;
        while let Some(entry) = entry_iterator
            .next_entry()
            .await
            .map_err(|e| RapidBlockDownloadError::IO(e.to_string()))?
        {
            if let Ok((block, _auth_path)) =
                Self::load_entry(&entry.path()).await.inspect_err(|e| {
                    tracing::warn!(
                        "Could not read Block from file '{}': {e}",
                        entry.path().to_string_lossy()
                    );
                })
            {
                let height = block.header().height.value();
                if height >= coverage.upper_bound {
                    coverage = coverage.expand(height + 1);
                }
                coverage.set(height);
                index_to_filename.insert(height, entry.path());
                number_blocks_recovered += 1;
            }
        }
        if number_blocks_recovered != 0 {
            tracing::info!(
                "Resuming sync from previous state with {number_blocks_recovered} stored blocks."
            );
        }

        Ok(Self {
            block_storage_dir: storage_dir,
            coverage,
            index_to_filename,
            target_height,
            sync_dir,
            network,
        })
    }

    /// Return the directory used by a previous Rapid Block Download run, if
    /// it was aborted.
    ///
    /// If it was aborted, the files should still be there. No need to download
    /// them again.
    async fn try_resume_directory(
        resume_if_possible: bool,
        sync_dir: &Option<PathBuf>,
        network: Network,
    ) -> Option<PathBuf> {
        if !resume_if_possible {
            return None;
        }

        let base_dir = Self::base_storage_dir(sync_dir, network);
        let mut info = tokio::fs::read_dir(&base_dir)
            .await
            .inspect_err(|e| {
                // Failure to read the directory is a benign error. Likely means
                // that there was no aborted sync to resume from.
                tracing::info!(
                    "Cannot resume sync because directory {} cannot be read: {e}",
                    base_dir.to_string_lossy()
                );
            })
            .ok()?;

        let Some(first_entry) = info
            .next_entry()
            .await
            .inspect_err(|e| {
                // Failure to read the directory is a benign error, but there is
                // no reason why this one would be triggered as opposed to the
                // previous one. Better to log a message just in case.
                tracing::warn!(
                    "Cannot resume sync because directory {} cannot be read: {e}",
                    base_dir.to_string_lossy()
                );
            })
            .ok()?
        else {
            // Empty storage dir. Fishy because it should have been removed by
            // clean up.
            tracing::warn!(
                "Cannot resume sync because directory {} is empty.",
                base_dir.to_string_lossy()
            );
            return None;
        };

        let file_name = first_entry.file_name();
        let file_name_as_string = file_name
            .clone()
            .into_string()
            .unwrap_or_else(|e| format!("{e:?}"))
            .to_string();

        let metadata = first_entry
            .metadata()
            .await
            .inspect_err(|e| {
                // First entry exists but cannot get metadata. Error.
                tracing::warn!(
                    "Cannot resume sync because cannot get metadata of first entry '{}' in directory {}. Error: {e}",
                    file_name_as_string,
                    base_dir.to_string_lossy()
                );
            })
            .ok()?;

        if !metadata.is_dir() {
            tracing::warn!(
                "Cannot resume sync because first entry '{}' in directory {} is not a directory.",
                file_name_as_string,
                base_dir.to_string_lossy()
            );
            return None;
        }

        let directory = base_dir.join(file_name);
        tracing::info!(
            "Resuming sync from directory {}.",
            directory.to_string_lossy()
        );
        Some(directory)
    }

    /// Delete the storage directory and its contents.
    pub(crate) async fn clean_up(&self) -> Result<(), Vec<PathBuf>> {
        let mut error_directories = vec![];
        if let Err(e) = tokio::fs::remove_dir_all(self.block_storage_dir.clone()).await {
            tracing::error!(
                "failed to remove storage directory '{}' for rapid block download: {e}",
                self.block_storage_dir.clone().to_string_lossy()
            );
            error_directories.push(self.block_storage_dir.clone());
        }
        let base = Self::base_storage_dir(&self.sync_dir, self.network);
        if let Err(e) = tokio::fs::remove_dir(&base).await {
            tracing::warn!(
                "failed to remove storage directory '{}' for rapid block download: {e}",
                base.to_string_lossy()
            );
            error_directories.push(base);
        }

        if error_directories.is_empty() {
            Ok(())
        } else {
            Err(error_directories)
        }
    }

    /// Add one new block to the chain, effectively setting a new tip digest and
    /// bumping the counter by one.
    ///
    /// # Panics
    ///
    ///  - If the height of the new block does not equal current tip height plus
    ///    one.
    pub(crate) async fn extend_chain(
        &mut self,
        new_block: &Block,
    ) -> Result<(), RapidBlockDownloadError> {
        let new_block_height = new_block.header().height;
        assert_eq!(self.target_height.next(), new_block_height);

        self.coverage = self.coverage.clone().expand(new_block_height.value() + 1);

        // Blocks extending the chain lie beyond any sync anchor, so no
        // authentication path can exist for them.
        self.receive_block(new_block, None).await?;

        self.target_height = self.target_height.next();

        Ok(())
    }

    /// Get the file name for the block.
    fn file_name(&self, block: &Block) -> PathBuf {
        self.block_storage_dir.join(block.hash().to_hex())
    }

    /// Store the block in the storage directory and mark it as received, if it
    /// wasn't received already.
    ///
    /// The authentication path, if one is given, must have been verified to
    /// prove the block's membership in the chain being synced towards.
    // TODO: A block arriving *with* an authentication path for a height that
    // was first received without one does not upgrade the stored entry.
    pub(crate) async fn receive_block(
        &mut self,
        block: &Block,
        auth_path: Option<&MmrMembershipProof>,
    ) -> Result<(), RapidBlockDownloadError> {
        if !self.coverage.contains(block.header().height.value()) {
            let file_name = self.file_name(block);
            self.store_entry(block, auth_path, &file_name).await?;

            self.index_to_filename
                .insert(block.header().height.value(), file_name);
            self.coverage.set(block.header().height.value());
        }

        Ok(())
    }

    /// Store the block and its optional authentication path in the storage
    /// directory.
    async fn store_entry(
        &self,
        block: &Block,
        auth_path: Option<&MmrMembershipProof>,
        file_name: &PathBuf,
    ) -> Result<(), RapidBlockDownloadError> {
        let data = bincode::serialize(&(block, auth_path))
            .map_err(|e| RapidBlockDownloadError::Serialization(e.to_string()))?;
        tokio::fs::write(file_name, data)
            .await
            .map_err(|e| RapidBlockDownloadError::IO(e.to_string()))
    }

    /// Load a block and its optional authentication path from the storage
    /// directory.
    async fn load_entry(
        file_name: &PathBuf,
    ) -> Result<(Block, Option<MmrMembershipProof>), RapidBlockDownloadError> {
        let data = tokio::fs::read(file_name)
            .await
            .map_err(|e| RapidBlockDownloadError::IO(e.to_string()))?;
        let entry = bincode::deserialize(&data)
            .map_err(|e| RapidBlockDownloadError::Serialization(e.to_string()))?;
        Ok(entry)
    }

    /// Read a block from the storage directory.
    pub(crate) async fn get_received_block(
        &self,
        height: BlockHeight,
    ) -> Result<Block, RapidBlockDownloadError> {
        self.get_received_entry(height)
            .await
            .map(|(block, _)| block)
    }

    /// Read a block from the storage directory, along with an authentication
    /// path relative to the given anchor.
    ///
    /// The stored authentication path is relative to the anchor of the sync
    /// process that received the block, which is generally not the requester's
    /// anchor. The stored path is therefore truncated to the requester's anchor
    /// and verified against it. `Ok(None)` is returned if no authentication
    /// path against this anchor could be made.
    pub(crate) async fn get_authenticated_block(
        &self,
        height: BlockHeight,
        anchor: &MmrAccumulator,
    ) -> Result<Option<(Block, MmrMembershipProof)>, RapidBlockDownloadError> {
        let (block, stored_auth_path) = self.get_received_entry(height).await?;

        let auth_path = stored_auth_path
            .and_then(|stored| truncate_auth_path(&stored, height.value(), anchor.num_leafs()))
            .filter(|truncated| {
                truncated.verify(
                    height.value(),
                    block.hash(),
                    &anchor.peaks(),
                    anchor.num_leafs(),
                )
            });

        Ok(auth_path.map(|auth_path| (block, auth_path)))
    }

    /// Read a block and its stored authentication path, if any, from the
    /// storage directory.
    async fn get_received_entry(
        &self,
        height: BlockHeight,
    ) -> Result<(Block, Option<MmrMembershipProof>), RapidBlockDownloadError> {
        let file_name = self
            .index_to_filename
            .get(&height.value())
            .ok_or(RapidBlockDownloadError::NotReceived(height))?;

        Self::load_entry(file_name)
            .await
            .map_err(|e| RapidBlockDownloadError::IO(e.to_string()))
    }

    /// Un-bind a height: throw away the block stored there and mark the height
    /// as not received, so that it gets requested again.
    ///
    /// Blocks are stored before anything can be established about their place
    /// in the chain -- that only becomes checkable once the chain reaches them.
    /// So the height a block occupies is not a claim we can verify up front,
    /// and binding it permanently lets one peer deny the whole sync by winning
    /// the race for a single height. This is how that binding is undone.
    pub(crate) async fn reject_block(&mut self, height: BlockHeight) {
        if let Some(file_name) = self.index_to_filename.remove(&height.value()) {
            if let Err(e) = tokio::fs::remove_file(&file_name).await {
                tracing::warn!(
                    "Could not delete rejected block at height {height} from '{}': {e}. \
                    Not critical.",
                    file_name.to_string_lossy()
                );
            }
        }
        self.coverage.unset(height.value());
    }

    /// Get the [`SynchronizationBitMask`] corresponding to covered blocks
    /// (blocks we have, whether cached or in the database). The complement of
    /// this bit mask indicates which blocks we do not yet have.
    pub(crate) fn coverage(&self) -> SynchronizationBitMask {
        self.coverage.clone()
    }

    /// Determine whether all blocks have been received.
    pub(crate) fn is_complete(&self) -> bool {
        self.coverage.is_complete()
    }

    /// Determine whether the given block was received already.
    pub(crate) fn have_received(&self, block_height: BlockHeight) -> bool {
        self.coverage.contains(block_height.value())
    }

    /// Delete the block from the storage dir.
    ///
    /// Saves disk / RAM space. However, according to the bit mask, the block
    /// is there. So things go wrong if you ask for the block (which the bit
    /// mask says is there) and it was deleted. Be careful not to do that.
    pub(crate) async fn delete_block(
        &self,
        height: BlockHeight,
    ) -> Result<(), RapidBlockDownloadError> {
        let file_name = self
            .index_to_filename
            .get(&height.value())
            .ok_or(RapidBlockDownloadError::NotReceived(height))?;
        tokio::fs::remove_file(file_name)
            .await
            .map_err(|e| RapidBlockDownloadError::IO(e.to_string()))?;
        Ok(())
    }

    /// Synchronizes the rapid block download state to the new tip.
    pub(crate) fn fast_forward(&mut self, new_tip_height: BlockHeight) {
        if new_tip_height.value() >= self.coverage.upper_bound {
            self.coverage = self.coverage.clone().expand(new_tip_height.value() + 1);
        }
        if new_tip_height.value() >= self.coverage.lower_bound {
            self.coverage
                .set_range(self.coverage.lower_bound, new_tip_height.value());
        }
    }
}

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub(crate) enum RapidBlockDownloadError {
    #[error("I/O error: {0}")]
    IO(String),
    #[error("Block {0} not received")]
    NotReceived(BlockHeight),
    #[error("Serialization error: {0}")]
    Serialization(String),
}

#[cfg(test)]
mod tests {
    use itertools::Itertools;
    use macro_rules_attr::apply;
    use rand::rng;
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::RngCore;
    use rand::SeedableRng;
    use tasm_lib::prelude::Digest;

    use super::*;
    use crate::tests::shared::files::unit_test_path;
    use crate::tests::shared_tokio_runtime;

    /// Build an MMR over the given leafs while tracking the authentication
    /// path of one of the leafs. Returns the tracked path, relative to the full
    /// MMR, along with the accumulator as it looked after each append:
    /// `snapshots[m]` holds `m` leafs.
    fn mmr_with_tracked_leaf(
        leafs: &[Digest],
        tracked_index: u64,
    ) -> (MmrMembershipProof, Vec<MmrAccumulator>) {
        let mut mmra = MmrAccumulator::new_from_leafs(vec![]);
        let mut tracked: Option<MmrMembershipProof> = None;
        let mut snapshots = vec![mmra.clone()];
        for (i, leaf) in leafs.iter().enumerate() {
            if let Some(mp) = &mut tracked {
                MmrMembershipProof::batch_update_from_append(
                    &mut [mp],
                    &[tracked_index],
                    mmra.num_leafs(),
                    *leaf,
                    &mmra.peaks(),
                );
            }
            let mp = mmra.append(*leaf);
            if i as u64 == tracked_index {
                tracked = Some(mp);
            }
            snapshots.push(mmra.clone());
        }

        (tracked.unwrap(), snapshots)
    }

    #[test]
    fn truncate_auth_path_yields_valid_paths_for_all_prefix_anchors() {
        let mut rng = StdRng::seed_from_u64(0x1717);
        let num_leafs = 130u64;
        let leafs = (0..num_leafs).map(|_| rng.random::<Digest>()).collect_vec();

        for tracked_index in [0u64, 1, 63, 64, 100, num_leafs - 1] {
            let (full_path, snapshots) = mmr_with_tracked_leaf(&leafs, tracked_index);

            // The full path truncates to a valid path for every prefix MMR
            // that contains the leaf.
            for m in (tracked_index + 1)..=num_leafs {
                let truncated = truncate_auth_path(&full_path, tracked_index, m).unwrap();
                assert!(truncated.verify(
                    tracked_index,
                    leafs[tracked_index as usize],
                    &snapshots[m as usize].peaks(),
                    m,
                ));
            }

            // Prefixes not containing the leaf yield nothing.
            assert!(truncate_auth_path(&full_path, tracked_index, tracked_index).is_none());
        }

        // A path relative to a small MMR cannot be stretched to a larger MMR
        // that requires a longer path.
        let (short_path, _) = mmr_with_tracked_leaf(&leafs[..2], 0);
        assert!(truncate_auth_path(&short_path, 0, num_leafs).is_none());
    }

    #[apply(shared_tokio_runtime)]
    async fn authenticated_blocks_are_served_relative_to_the_requester_anchor() {
        let network = Network::Main;
        let mut rng = rng();
        let target_height = 129u64;
        let block_height = 100u64;
        let mut block = rng.random::<Block>();
        block.set_header_height(block_height.into());

        // The chain being synced towards: random block digests, except at the
        // stored block's own height.
        let num_leafs = target_height + 1;
        let mut leafs = (0..num_leafs).map(|_| rng.random::<Digest>()).collect_vec();
        leafs[block_height as usize] = block.hash();
        let (auth_path, snapshots) = mmr_with_tracked_leaf(&leafs, block_height);
        let own_anchor = snapshots[num_leafs as usize].clone();

        let mut download = RapidBlockDownload::new(
            BlockHeight::from(target_height),
            false,
            Some(unit_test_path()),
            network,
        )
        .await
        .unwrap();
        download
            .receive_block(&block, Some(&auth_path))
            .await
            .unwrap();

        // A requester with the same anchor gets the stored path.
        let (served_block, served_path) = download
            .get_authenticated_block(block_height.into(), &own_anchor)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(block.hash(), served_block.hash());
        assert!(served_path.verify(
            block_height,
            block.hash(),
            &own_anchor.peaks(),
            own_anchor.num_leafs(),
        ));

        // A requester whose anchor is a smaller prefix of the same chain gets
        // a truncated path, valid relative to their anchor.
        for smaller_num_leafs in [block_height + 1, 110] {
            let smaller_anchor = &snapshots[smaller_num_leafs as usize];
            let (_, truncated_path) = download
                .get_authenticated_block(block_height.into(), smaller_anchor)
                .await
                .unwrap()
                .unwrap();
            assert!(truncated_path.verify(
                block_height,
                block.hash(),
                &smaller_anchor.peaks(),
                smaller_anchor.num_leafs(),
            ));
        }

        // A requester syncing towards a different chain gets nothing.
        let forked_anchor = MmrAccumulator::new_from_leafs(
            (0..num_leafs).map(|_| rng.random::<Digest>()).collect_vec(),
        );
        let forked_anchor_entry = download
            .get_authenticated_block(block_height.into(), &forked_anchor)
            .await
            .unwrap();
        assert!(forked_anchor_entry.is_none());

        // A block stored without a path cannot be served authenticated, but
        // is still available plain.
        let mut pathless_block = rng.random::<Block>();
        pathless_block.set_header_height(BlockHeight::from(50u64));
        download.receive_block(&pathless_block, None).await.unwrap();
        let pathless_block_entry = download
            .get_authenticated_block(BlockHeight::from(50u64), &own_anchor)
            .await
            .unwrap();
        assert!(pathless_block_entry.is_none());
        assert_eq!(
            pathless_block.hash(),
            download
                .get_received_block(BlockHeight::from(50u64))
                .await
                .unwrap()
                .hash()
        );

        let _ = download.clean_up().await;
    }

    #[apply(shared_tokio_runtime)]
    async fn legacy_block_files_are_skipped_on_resume() {
        let network = Network::Main;
        let mut rng = rng();
        let sync_dir = unit_test_path();
        let target = BlockHeight::from(100u64);

        // A first download stores one block in the current format. A file in
        // the legacy format — a bare block, without the option of an
        // authentication path — is planted next to it.
        let mut first_download =
            RapidBlockDownload::new(target, false, Some(sync_dir.clone()), network)
                .await
                .unwrap();
        let mut stored_block = rng.random::<Block>();
        stored_block.set_header_height(BlockHeight::from(7u64));
        first_download
            .receive_block(&stored_block, None)
            .await
            .unwrap();

        let mut legacy_block = rng.random::<Block>();
        legacy_block.set_header_height(BlockHeight::from(9u64));
        tokio::fs::write(
            first_download
                .block_storage_dir
                .join(legacy_block.hash().to_hex()),
            bincode::serialize(&legacy_block).unwrap(),
        )
        .await
        .unwrap();

        // On resume, the current-format block is recovered and the legacy
        // file is skipped, so that height gets downloaded again.
        let resumed_download = RapidBlockDownload::new(target, true, Some(sync_dir), network)
            .await
            .unwrap();
        assert!(resumed_download.have_received(BlockHeight::from(7u64)));
        assert!(!resumed_download.have_received(BlockHeight::from(9u64)));

        let _ = resumed_download.clean_up().await;
    }

    /// A rejected block must free its height slot, so that the height is asked
    /// for again and the download counts as unfinished.
    #[apply(shared_tokio_runtime)]
    async fn rejected_block_frees_its_height_slot() {
        let network = Network::Main;
        let mut rng = rng();
        let tip_height = 100_u64;
        let target = BlockHeight::from(tip_height + 1);
        let mut rapid_block_download =
            RapidBlockDownload::new(target, false, Some(unit_test_path()), network)
                .await
                .unwrap();
        rapid_block_download.fast_forward(BlockHeight::from(tip_height));

        // The one outstanding height gets filled, completing the download.
        let mut block = rng.random::<Block>();
        block.set_header_height(target);
        rapid_block_download
            .receive_block(&block, None)
            .await
            .unwrap();
        assert!(rapid_block_download.have_received(target));
        assert!(rapid_block_download.is_complete());

        // Rejecting it puts the height back on the to-do list.
        rapid_block_download.reject_block(target).await;
        assert!(!rapid_block_download.have_received(target));
        assert!(!rapid_block_download.is_complete());
        assert!(rapid_block_download
            .coverage()
            .to_vec_complement()
            .contains(&target.value()));

        // And the height can be filled again, by a different block.
        let mut replacement = rng.random::<Block>();
        replacement.set_header_height(target);
        rapid_block_download
            .receive_block(&replacement, None)
            .await
            .unwrap();
        assert_eq!(
            replacement.hash(),
            rapid_block_download
                .get_received_block(target)
                .await
                .unwrap()
                .hash()
        );

        let _ = rapid_block_download.clean_up().await;
    }

    #[apply(shared_tokio_runtime)]
    async fn can_get_stored_block_iff_received() {
        let mut rng = rng();
        let mut tip = rng.random::<Block>();
        let high = 200;
        tip.set_header_height(high.into());
        let mut rapid_block_download = RapidBlockDownload::new(
            BlockHeight::from(high),
            false,
            Some(unit_test_path()),
            Network::Main,
        )
        .await
        .unwrap();

        // receive 10 blocks
        let mut received_heights = vec![];
        for _ in 0..10 {
            let height = rng.random_range(1..high);
            received_heights.push(height);
            let mut block = rng.random::<Block>();
            block.set_header_height(BlockHeight::from(height));
            if let Err(e) = rapid_block_download.receive_block(&block, None).await {
                panic!("Could not receive block {height}: {e}");
            }

            println!("received block {height} in good order.");
        }

        // get ith
        for _ in 0..100 {
            let index = BlockHeight::from(
                received_heights[rng.random_range(0usize..received_heights.len())],
            );
            match rapid_block_download.get_received_block(index).await {
                Ok(_) => (),
                Err(e) => panic!("Could not get block {index}! {e}"),
            }
        }

        // fail to get jth
        for _ in 0..100 {
            let seed = rng.next_u64();
            let mut inner_rng = StdRng::seed_from_u64(seed);
            let jndex =
                BlockHeight::from(rapid_block_download.coverage().sample(inner_rng.random()));
            assert!(!rapid_block_download.coverage().contains(jndex.value()));
            assert_eq!(
                rapid_block_download
                    .get_received_block(jndex)
                    .await
                    .unwrap_err(),
                RapidBlockDownloadError::NotReceived(jndex),
            );
        }

        let _ = rapid_block_download.clean_up().await;
    }

    #[apply(shared_tokio_runtime)]
    async fn can_make_complete_by_receiving_all_blocks() {
        let mut rng = rng();
        let mut tip = rng.random::<Block>();
        let high = 200;
        tip.set_header_height(high.into());
        let mut rapid_block_download = RapidBlockDownload::new(
            BlockHeight::from(high),
            false,
            Some(unit_test_path()),
            Network::Main,
        )
        .await
        .unwrap();

        // receive all blocks in random order
        let mut blocks_remaining = (1..=high).map(BlockHeight::from).collect_vec();
        while !blocks_remaining.is_empty() {
            let i = rng.random_range(0usize..blocks_remaining.len());
            let height = blocks_remaining.swap_remove(i);

            // verify that we are not finished yet
            assert!(!rapid_block_download.is_complete());

            let mut block = rng.random::<Block>();
            block.set_header_height(height);
            let _ = rapid_block_download.receive_block(&block, None).await;
        }

        // verify that we are finished
        assert!(rapid_block_download.is_complete());

        let _ = rapid_block_download.clean_up().await;
    }

    #[tracing_test::traced_test]
    #[apply(shared_tokio_runtime)]
    async fn can_resume_block_download_from_saved_incomplete_state() {
        let network = Network::Main;
        let mut rng = rng();
        let mut tip = rng.random::<Block>();
        let low = 100;
        let high = 200;
        tip.set_header_height(high.into());

        // Shared by both download states, so that the second can resume from
        // the first.
        let sync_dir = unit_test_path();

        let mut rapid_block_download_a = RapidBlockDownload::new(
            BlockHeight::from(high),
            false,
            Some(sync_dir.clone()),
            network,
        )
        .await
        .unwrap();
        rapid_block_download_a.fast_forward(BlockHeight::from(low));

        // receive half the blocks in random order
        let mut blocks_remaining = ((low + 1)..=high).map(BlockHeight::from).collect_vec();
        for _ in 0..((high - low) / 2) {
            let i = rng.random_range(0usize..blocks_remaining.len());
            let height = blocks_remaining.swap_remove(i);

            // verify that we are not finished yet
            assert!(!rapid_block_download_a.is_complete());

            let mut block = rng.random::<Block>();
            block.set_header_height(height);
            let _ = rapid_block_download_a.receive_block(&block, None).await;
        }

        assert!(!rapid_block_download_a.is_complete());

        // setup new rapid block download state
        let mut rapid_block_download_b =
            RapidBlockDownload::new(BlockHeight::from(high), true, Some(sync_dir), network)
                .await
                .unwrap();
        rapid_block_download_b.fast_forward(BlockHeight::from(low));
        assert!(!rapid_block_download_b.is_complete());

        assert!(!blocks_remaining.is_empty());

        // complete block download with second download state
        while !blocks_remaining.is_empty() {
            let i = rng.random_range(0usize..blocks_remaining.len());
            let height = blocks_remaining.swap_remove(i);

            // verify that we are not finished yet
            assert!(!rapid_block_download_b.is_complete());

            let mut block = rng.random::<Block>();
            block.set_header_height(height);
            let _ = rapid_block_download_b.receive_block(&block, None).await;
        }

        // verify that we are finished
        assert!(
            rapid_block_download_b.is_complete(),
            "missing blocks: {}",
            rapid_block_download_b.coverage.sample(rng.random())
        );

        let _ = rapid_block_download_b.clean_up().await;
    }

    /// Test that the RapidBlockDownload can resume from a directory of saved
    /// blocks that spans a larger distance than the one we are syncing to.
    ///
    /// This unit test triggers edge cases that are possible but very unlikely
    /// to occur benignly in practice. For instance, if you sync from server A,
    /// abort the sync, reconnect, and then sync from server B which itself is
    /// not fully synced yet. In this case you will end up using B's tip as the
    /// sync anchor, but there may be descendants of this tip in the sync dir.
    #[tracing_test::traced_test]
    #[apply(shared_tokio_runtime)]
    async fn can_resume_block_download_from_saved_overcomplete_state() {
        let network = Network::Main;
        let mut rng = rng();
        let mut tip = rng.random::<Block>();
        let low = 100;
        let first_high = 250;
        let second_high = 200;
        tip.set_header_height(first_high.into());

        // Shared by both download states, so that the second can resume from
        // the first.
        let sync_dir = unit_test_path();

        let mut rapid_block_download_a = RapidBlockDownload::new(
            BlockHeight::from(first_high),
            false,
            Some(sync_dir.clone()),
            network,
        )
        .await
        .unwrap();
        rapid_block_download_a.fast_forward(BlockHeight::from(low));

        // receive all the blocks in random order
        for i in low..first_high {
            let mut block = rng.random::<Block>();
            let height = BlockHeight::from(i);
            block.set_header_height(height);
            let _ = rapid_block_download_a.receive_block(&block, None).await;
        }

        // setup new rapid block download state
        let mut rapid_block_download_b = RapidBlockDownload::new(
            BlockHeight::from(second_high),
            true,
            Some(sync_dir),
            network,
        )
        .await
        .unwrap();
        rapid_block_download_b.fast_forward(BlockHeight::from(low));
        assert!(rapid_block_download_b.is_complete());

        // verify that we are finished
        assert!(rapid_block_download_b.is_complete(),);

        let _ = rapid_block_download_b.clean_up().await;
    }

    #[apply(shared_tokio_runtime)]
    async fn can_receive_same_block_twice() {
        let mut rng = rng();
        let high = 200;
        let mut rapid_block_download = RapidBlockDownload::new(
            BlockHeight::from(high),
            false,
            Some(unit_test_path()),
            Network::Main,
        )
        .await
        .unwrap();

        // receive all blocks in random order, with repetitions
        let mut blocks_remaining = (1..=high).map(BlockHeight::from).collect_vec();
        let mut blocks_received = vec![];
        while !blocks_remaining.is_empty() {
            if rng.random_bool(0.5f64) && !blocks_received.is_empty() {
                let i = rng.random_range(0usize..blocks_remaining.len());
                let mut block = rng.random::<Block>();
                block.set_header_height(blocks_remaining[i]);
                let _ = rapid_block_download.receive_block(&block, None).await;
            } else {
                let i = rng.random_range(0usize..blocks_remaining.len());
                let height = blocks_remaining.swap_remove(i);
                blocks_received.push(height);

                let mut block = rng.random::<Block>();
                block.set_header_height(height);
                let _ = rapid_block_download.receive_block(&block, None).await;
            };
        }

        // verify that we are finished
        assert!(rapid_block_download.is_complete());

        let _ = rapid_block_download.clean_up().await;
    }

    #[apply(shared_tokio_runtime)]
    async fn can_track_new_tip() {
        let mut outer_rng = rng();
        for seed in [17711521671747587153]
            .into_iter()
            .chain((0..10).map(|_| outer_rng.next_u64()))
        {
            println!("seed: {seed}");
            let mut rng = StdRng::seed_from_u64(seed);
            let mut high = 200;
            let mut rapid_block_download = RapidBlockDownload::new(
                BlockHeight::from(high),
                false,
                Some(unit_test_path()),
                Network::Main,
            )
            .await
            .unwrap();

            // receive all blocks in random order, with repetitions
            let mut blocks_remaining = (1..=high).map(BlockHeight::from).collect_vec();
            let mut blocks_received = vec![];
            while !blocks_remaining.is_empty() {
                if rng.random_bool(0.5f64) && blocks_received.len() % 5 == 0 {
                    high += 1;
                    let height = BlockHeight::from(high);
                    let mut block = rng.random::<Block>();
                    block.set_header_height(height);
                    let extend_result = rapid_block_download.extend_chain(&block).await;
                    assert!(extend_result.is_ok());
                    continue;
                }
                let height = if rng.random_bool(0.5f64) && !blocks_received.is_empty() {
                    let i = rng.random_range(0usize..blocks_remaining.len());
                    blocks_remaining[i]
                } else {
                    let i = rng.random_range(0usize..blocks_remaining.len());
                    let height = blocks_remaining.swap_remove(i);
                    blocks_received.push(height);
                    height
                };

                let mut block = rng.random::<Block>();
                block.set_header_height(height);
                let _ = rapid_block_download.receive_block(&block, None).await;
            }

            // verify that we are finished
            assert!(rapid_block_download.is_complete());

            let _ = rapid_block_download.clean_up().await;
        }
    }
}
