use std::collections::HashMap;
use std::path::PathBuf;

use rand::rng;
use rand::RngCore;
use tasm_lib::prelude::Digest;

use crate::api::export::BlockHeight;
use crate::application::loops::sync_loop::bit_mask::BitMask;
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
    coverage: BitMask,
    index_to_filename: HashMap<u64, PathBuf>,

    target_digest: Digest,
    target_height: BlockHeight,
}

impl RapidBlockDownload {
    fn temp_dir() -> PathBuf {
        let suffix = "rapid-block-download/";
        std::env::temp_dir().join(suffix)
    }
    /// Set up a [`RapidBlockDownload`] state.
    pub(crate) async fn new(
        highest_block_already_processed: BlockHeight,
        target: &Block,
    ) -> Result<Self, RapidBlockDownloadError> {
        let temp_directory = Self::temp_dir().join(format!("{}/", rng().next_u64()));
        let _ = tokio::fs::create_dir_all(&temp_directory)
            .await
            .map_err(|e| RapidBlockDownloadError::IO(e.to_string()))?;

        let index_to_filename = HashMap::new();
        let target_height = target.header().height;
        let mut coverage = BitMask::new(target_height.next().value());
        coverage.set_range(0, highest_block_already_processed.value());
        let target_digest = target.hash();

        Ok(Self {
            temp_directory,
            coverage,
            index_to_filename,
            target_digest,
            target_height,
        })
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
    async fn extend_chain(&mut self, new_block: &Block) -> Result<(), RapidBlockDownloadError> {
        let new_block_height = new_block.header().height;
        assert_eq!(self.target_height.next(), new_block_height);

        self.coverage = self.coverage.clone().expand(new_block_height.value() + 1);

        self.receive_block(new_block).await?;

        self.target_digest = new_block.hash();
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
    async fn load_block(&self, file_name: &PathBuf) -> Result<Block, RapidBlockDownloadError> {
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
            Some(self.coverage().sample(false, seed).into())
        }
    }

    /// Read a block from the temp directory.
    async fn get_received_block(
        &self,
        height: BlockHeight,
    ) -> Result<Block, RapidBlockDownloadError> {
        let file_name = self
            .index_to_filename
            .get(&height.value())
            .ok_or(RapidBlockDownloadError::NotReceived(height))?;

        let block = self
            .load_block(file_name)
            .await
            .map_err(|e| RapidBlockDownloadError::IO(e.to_string()))?;

        Ok(block)
    }

    /// Get the [`BitMask`] corresponding to covered blocks (blocks we have,
    /// whether cached or in the database). The complement of this bit mask
    /// indicates which blocks we do not yet have.
    fn coverage(&self) -> BitMask {
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

    /// Load the block from disk, delete the file, and return the block.
    pub(crate) async fn get_and_free(
        &self,
        height: BlockHeight,
    ) -> Result<Block, RapidBlockDownloadError> {
        let block = self.get_received_block(height).await?;

        if let Err(e) = self.delete_block(height).await {
            tracing::warn!("Could not delete block {height} from temp dir: {e}");
        }

        Ok(block)
    }

    /// Delete the block from the temp dir.
    ///
    /// Saves disk / RAM space. However, according to the bit mask, the block
    /// is there. So things go wrong if you ask for the block (which the bit
    /// mask says is there) and it was deleted. Be careful not to do that.
    async fn delete_block(&self, height: BlockHeight) -> Result<(), RapidBlockDownloadError> {
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
        let mut rapid_block_download = RapidBlockDownload::new(low.into(), &tip).await.unwrap();

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
            let jndex = BlockHeight::from(
                rapid_block_download
                    .coverage()
                    .sample(false, inner_rng.random()),
            );
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
        let mut rapid_block_download = RapidBlockDownload::new(low.into(), &tip).await.unwrap();

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

    #[apply(shared_tokio_runtime)]
    async fn can_receive_same_block_twice() {
        let mut rng = rng();
        let mut tip = rng.random::<Block>();
        let low = 100;
        let high = 200;
        tip.set_header_height(high.into());
        let mut rapid_block_download = RapidBlockDownload::new(low.into(), &tip).await.unwrap();

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
            let mut tip = rng.random::<Block>();
            let low = 100;
            let mut high = 200;
            tip.set_header_height(high.into());
            let mut rapid_block_download = RapidBlockDownload::new(low.into(), &tip).await.unwrap();

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
