use std::collections::HashMap;
use std::path::PathBuf;

use rand::rng;
use rand::RngCore;
use tokio::fs;

use crate::api::export::BlockHeight;
use crate::application::loops::sync_loop::SynchronizationBitMask;
use crate::protocol::consensus::block::Block;

/// The state of a rapid block download process.
///
/// Blocks can come in asynchronously and out of order. We need to keep track
/// of which blocks we already processed before starting the rapid block
/// download process, which blocks we received in the course of running the
/// process, and which blocks we have yet to receive.
#[derive(Debug, Clone)]
pub(crate) struct RapidBlockDownload {
    temp_directory: PathBuf,
    coverage: SynchronizationBitMask,
    index_to_filename: HashMap<u64, PathBuf>,

    target_height: BlockHeight,
}

impl RapidBlockDownload {
    fn temp_dir() -> PathBuf {
        let suffix = "rapid-block-download/";
        std::env::temp_dir().join(suffix)
    }

    /// The target block height we are syncing to.
    pub(crate) fn target(&self) -> BlockHeight {
        self.target_height
    }

    /// Set up a [`RapidBlockDownload`] state.
    pub(crate) async fn new(
        highest_block_already_processed: BlockHeight,
        target_height: BlockHeight,
        resume_if_possible: bool,
    ) -> Result<Self, RapidBlockDownloadError> {
        let temp_directory = match Self::try_resume_directory(resume_if_possible).await {
            Some(d) => d,
            None => {
                let temp_directory = Self::temp_dir().join(format!("{}/", rng().next_u64()));
                tokio::fs::create_dir_all(&temp_directory)
                    .await
                    .map_err(|e| RapidBlockDownloadError::IO(e.to_string()))?;
                temp_directory
            }
        };

        let mut index_to_filename = HashMap::new();
        let mut coverage = SynchronizationBitMask::new(
            highest_block_already_processed.value() + 1,
            target_height.next().value(),
        );

        // Read and process all the files in the temp directory.
        // There is only something to iterate over if we are resuming from an
        // aborted state.
        let mut number_blocks_recovered = 0;
        let mut entry_iterator = fs::read_dir(&temp_directory)
            .await
            .map_err(|e| RapidBlockDownloadError::IO(e.to_string()))?;
        while let Some(entry) = entry_iterator
            .next_entry()
            .await
            .map_err(|e| RapidBlockDownloadError::IO(e.to_string()))?
        {
            if let Ok(block) = Self::load_block(&entry.path()).await.inspect_err(|e| {
                tracing::warn!(
                    "Could not read Block from file '{}': {e}",
                    entry.path().to_string_lossy()
                );
            }) {
                coverage.set(block.header().height.value());
                index_to_filename.insert(block.header().height.value(), entry.path());
                number_blocks_recovered += 1;
            }
        }
        if number_blocks_recovered != 0 {
            tracing::info!(
                "Resuming sync from previous state with {number_blocks_recovered} stored blocks."
            );
        }

        Ok(Self {
            temp_directory,
            coverage,
            index_to_filename,
            target_height,
        })
    }

    /// Return the directory used by a previous Rapid Block Download run, if
    /// it was aborted.
    ///
    /// If it was aborted, the files should still be there. No need to download
    /// them again.
    async fn try_resume_directory(resume_if_possible: bool) -> Option<PathBuf> {
        if !resume_if_possible {
            return None;
        }

        let temp_dir = Self::temp_dir();
        let mut info = tokio::fs::read_dir(&temp_dir)
            .await
            .inspect_err(|e| {
                // Failure to read the directory is a benign error. Likely means
                // that there was no aborted sync to resume from.
                tracing::info!(
                    "Cannot resume sync because directory {} cannot be read: {e}",
                    temp_dir.to_string_lossy()
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
                    temp_dir.to_string_lossy()
                );
            })
            .ok()?
        else {
            // Empty temp dir. Fishy because it should have been removed by
            // clean up.
            tracing::warn!(
                "Cannot resume sync because directory {} is empty.",
                temp_dir.to_string_lossy()
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
                    temp_dir.to_string_lossy()
                );
            })
            .ok()?;

        if !metadata.is_dir() {
            tracing::warn!(
                "Cannot resume sync because first entry '{}' in directory {} is not a directory.",
                file_name_as_string,
                temp_dir.to_string_lossy()
            );
            return None;
        }

        let directory = temp_dir.join(file_name);
        tracing::info!(
            "Resuming sync from directory {}.",
            directory.to_string_lossy()
        );
        Some(directory)
    }

    /// Delete the temp directory and its contents.
    pub(crate) async fn clean_up(&self) {
        if let Err(e) = tokio::fs::remove_dir_all(self.temp_directory.clone()).await {
            tracing::error!(
                "failed to remove temporary directory '{}' for rapid block download: {e}",
                self.temp_directory.clone().to_string_lossy()
            );
        }
        if let Err(e) = tokio::fs::remove_dir(Self::temp_dir()).await {
            tracing::warn!(
                "failed to remove temporary directory '{}' for rapid block download: {e}",
                Self::temp_dir().to_string_lossy()
            );
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

        self.receive_block(new_block).await?;

        self.target_height = self.target_height.next();

        Ok(())
    }

    /// Get the file name for the block.
    fn file_name(&self, block: &Block) -> PathBuf {
        self.temp_directory.join(block.hash().to_hex())
    }

    /// Store the block in the temp directory and mark it as received.
    pub(crate) async fn receive_block(
        &mut self,
        block: &Block,
    ) -> Result<(), RapidBlockDownloadError> {
        let file_name = self.file_name(block);
        self.store_block(block, &file_name).await?;

        self.index_to_filename
            .insert(block.header().height.value(), file_name);

        self.coverage.set(block.header().height.value());

        Ok(())
    }

    /// Store the block in the temp directory.
    async fn store_block(
        &self,
        block: &Block,
        file_name: &PathBuf,
    ) -> Result<(), RapidBlockDownloadError> {
        let data = bincode::serialize(block)
            .map_err(|e| RapidBlockDownloadError::Serialization(e.to_string()))?;
        tokio::fs::write(file_name, data)
            .await
            .map_err(|e| RapidBlockDownloadError::IO(e.to_string()))
    }

    /// Load the block from the temp directory.
    async fn load_block(file_name: &PathBuf) -> Result<Block, RapidBlockDownloadError> {
        let data = tokio::fs::read(file_name)
            .await
            .map_err(|e| RapidBlockDownloadError::IO(e.to_string()))?;
        let block = bincode::deserialize(&data)
            .map_err(|e| RapidBlockDownloadError::Serialization(e.to_string()))?;
        Ok(block)
    }

    /// Sample a block height among blocks we still need to download.
    ///
    /// If we have already downloaded all the blocks we need, this function
    /// returns `None`. Otherwise, it returns the sampled block height but
    /// wrapped in a `Some`.
    pub(crate) fn sample_missing_block_height(&self, seed: [u8; 32]) -> Option<BlockHeight> {
        if self.coverage().is_complete() {
            None
        } else {
            Some(self.coverage().sample(seed).into())
        }
    }

    /// Read a block from the temp directory.
    pub(crate) async fn get_received_block(
        &self,
        height: BlockHeight,
    ) -> Result<Block, RapidBlockDownloadError> {
        let file_name = self
            .index_to_filename
            .get(&height.value())
            .ok_or(RapidBlockDownloadError::NotReceived(height))?;

        let block = Self::load_block(file_name)
            .await
            .map_err(|e| RapidBlockDownloadError::IO(e.to_string()))?;

        Ok(block)
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

    /// Delete the block from the temp dir.
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
    use crate::tests::shared_tokio_runtime;
    use itertools::Itertools;
    use macro_rules_attr::apply;
    use rand::rng;
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::RngCore;
    use rand::SeedableRng;

    use super::*;

    #[apply(shared_tokio_runtime)]
    async fn can_get_stored_block_iff_received() {
        let mut rng = rng();
        let mut tip = rng.random::<Block>();
        let low = 100;
        let high = 200;
        tip.set_header_height(high.into());
        let mut rapid_block_download =
            RapidBlockDownload::new(low.into(), BlockHeight::from(high), false)
                .await
                .unwrap();

        // receive 10 blocks
        let mut received_heights = vec![];
        for _ in 0..10 {
            let height = rng.random_range(low..high);
            received_heights.push(height);
            let mut block = rng.random::<Block>();
            block.set_header_height(BlockHeight::from(height));
            let _ = rapid_block_download.receive_block(&block).await;
        }

        // get ith
        for _ in 0..100 {
            let index = BlockHeight::from(
                received_heights[rng.random_range(0usize..received_heights.len())],
            );
            assert!(rapid_block_download.get_received_block(index).await.is_ok());
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

        // clean up
        rapid_block_download.clean_up().await;
    }

    #[apply(shared_tokio_runtime)]
    async fn can_make_complete_by_receiving_all_blocks() {
        let mut rng = rng();
        let mut tip = rng.random::<Block>();
        let low = 100;
        let high = 200;
        tip.set_header_height(high.into());
        let mut rapid_block_download =
            RapidBlockDownload::new(low.into(), BlockHeight::from(high), false)
                .await
                .unwrap();

        // receive all blocks in random order
        let mut blocks_remaining = ((low + 1)..=high).map(BlockHeight::from).collect_vec();
        while !blocks_remaining.is_empty() {
            let i = rng.random_range(0usize..blocks_remaining.len());
            let height = blocks_remaining.swap_remove(i);

            // verify that we are not finished yet
            assert!(!rapid_block_download.is_complete());

            let mut block = rng.random::<Block>();
            block.set_header_height(height);
            let _ = rapid_block_download.receive_block(&block).await;
        }

        // verify that we are finished
        assert!(rapid_block_download.is_complete());

        // clean up
        rapid_block_download.clean_up().await;
    }

    #[ignore = "cannot run in parallel with other tests"]
    #[tracing_test::traced_test]
    #[apply(shared_tokio_runtime)]
    async fn can_resume_block_download_from_saved_state() {
        let mut rng = rng();
        let mut tip = rng.random::<Block>();
        let low = 100;
        let high = 200;
        tip.set_header_height(high.into());

        let mut rapid_block_download_a =
            RapidBlockDownload::new(low.into(), BlockHeight::from(high), false)
                .await
                .unwrap();

        // receive half the blocks in random order
        let mut blocks_remaining = ((low + 1)..=high).map(BlockHeight::from).collect_vec();
        for _ in 0..((high - low) / 2) {
            let i = rng.random_range(0usize..blocks_remaining.len());
            let height = blocks_remaining.swap_remove(i);

            // verify that we are not finished yet
            assert!(!rapid_block_download_a.is_complete());

            let mut block = rng.random::<Block>();
            block.set_header_height(height);
            let _ = rapid_block_download_a.receive_block(&block).await;
        }

        assert!(!rapid_block_download_a.is_complete());

        // setup new rapid block download state
        let mut rapid_block_download_b =
            RapidBlockDownload::new(low.into(), BlockHeight::from(high), true)
                .await
                .unwrap();
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
            let _ = rapid_block_download_b.receive_block(&block).await;
        }

        // verify that we are finished
        assert!(
            rapid_block_download_b.is_complete(),
            "missing blocks: {}",
            rapid_block_download_b.coverage.sample(rng.random())
        );

        // clean up
        rapid_block_download_b.clean_up().await;
    }

    #[apply(shared_tokio_runtime)]
    async fn can_receive_same_block_twice() {
        let mut rng = rng();
        let low = 100;
        let high = 200;
        let mut rapid_block_download =
            RapidBlockDownload::new(low.into(), BlockHeight::from(high), false)
                .await
                .unwrap();

        // receive all blocks in random order, with repetitions
        let mut blocks_remaining = ((low + 1)..=high).map(BlockHeight::from).collect_vec();
        let mut blocks_received = vec![];
        while !blocks_remaining.is_empty() {
            if rng.random_bool(0.5f64) && !blocks_received.is_empty() {
                let i = rng.random_range(0usize..blocks_remaining.len());
                let mut block = rng.random::<Block>();
                block.set_header_height(blocks_remaining[i]);
                let _ = rapid_block_download.receive_block(&block).await;
            } else {
                let i = rng.random_range(0usize..blocks_remaining.len());
                let height = blocks_remaining.swap_remove(i);
                blocks_received.push(height);

                let mut block = rng.random::<Block>();
                block.set_header_height(height);
                let _ = rapid_block_download.receive_block(&block).await;
            };
        }

        // verify that we are finished
        assert!(rapid_block_download.is_complete());

        // clean up
        rapid_block_download.clean_up().await;
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
            let low = 100;
            let mut high = 200;
            let mut rapid_block_download =
                RapidBlockDownload::new(low.into(), BlockHeight::from(high), false)
                    .await
                    .unwrap();

            // receive all blocks in random order, with repetitions
            let mut blocks_remaining = ((low + 1)..=high).map(BlockHeight::from).collect_vec();
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
                let _ = rapid_block_download.receive_block(&block).await;
            }

            // verify that we are finished
            assert!(rapid_block_download.is_complete());

            // clean up
            rapid_block_download.clean_up().await;
        }
    }
}
