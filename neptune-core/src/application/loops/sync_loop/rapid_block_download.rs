use std::collections::HashMap;
use std::path::PathBuf;

use serde::Deserialize;
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

    tip_digest: Digest,
    tip_height: BlockHeight,
}

impl RapidBlockDownload {
    /// Set up a [`RapidBlockDownload`] state.
    async fn new(
        highest_block_already_processed: BlockHeight,
        tip: &Block,
    ) -> Result<Self, RapidBlockDownloadError> {
        let suffix = "rapid-block-download/";
        let temp_directory = std::env::temp_dir().join(suffix);
        tokio::fs::create_dir(&temp_directory)
            .await
            .map_err(|e| RapidBlockDownloadError::IO(e.to_string()));

        let index_to_filename = HashMap::new();
        let tip_height = tip.header().height;
        let mut coverage = BitMask::new(tip_height.next().value());
        coverage.set_range(0, highest_block_already_processed.value());
        let tip_digest = tip.hash();

        Ok(Self {
            temp_directory,
            coverage,
            index_to_filename,
            tip_digest,
            tip_height,
        })
    }

    /// Delete the temp directory and its contents.
    async fn clean_up(&self) {
        if let Err(e) = tokio::fs::remove_dir_all(self.temp_directory.clone()).await {
            tracing::error!("failed to remove temporary directory for rapid block download: {e}");
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
        assert_eq!(self.tip_height.next(), new_block_height);

        self.receive_block(new_block).await?;

        self.tip_digest = new_block.hash();
        self.tip_height = self.tip_height.next();

        Ok(())
    }

    /// Get the file name for the block.
    fn file_name(&self, block: &Block) -> PathBuf {
        block.hash().to_hex().into()
    }

    /// Store the block in the temp directory and mark it as received.
    async fn receive_block(&mut self, block: &Block) -> Result<(), RapidBlockDownloadError> {
        let file_name = self.file_name(block);
        self.store_block(block, &file_name).await?;

        self.index_to_filename
            .insert(block.header().height.value(), file_name);

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
    fn sample_missing_block_height(&self, seed: [u8; 32]) -> Option<BlockHeight> {
        if self.coverage().is_complete() {
            None
        } else {
            Some(self.coverage().sample(false, seed).into())
        }
    }

    /// Read a block from the temp directory.
    async fn get_block(&self, height: BlockHeight) -> Result<Block, RapidBlockDownloadError> {
        let file_name = self
            .index_to_filename
            .get(&height.value())
            .ok_or(RapidBlockDownloadError::NotReceived(height.value()))?;

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
}

#[derive(Debug, Clone, thiserror::Error)]
enum RapidBlockDownloadError {
    #[error("I/O error: {0}")]
    IO(String),
    #[error("Block {0} not received")]
    NotReceived(u64),
    #[error("Serialization error: {0}")]
    Serialization(String),
}

#[cfg(test)]
mod tests {
    use rand::rng;
    use rand::Rng;

    use super::*;

    #[tokio::test]
    async fn can_get_stored_block() {
        let mut rng = rng();
        let mut tip = rng.random::<Block>();
        tip.set_header_height(200.into());
        let mut rapid_block_download = RapidBlockDownload::new(100.into(), tip);

        todo!()
    }

    #[tokio::test]
    async fn cannot_get_unstored_block() {}

    #[tokio::test]
    async fn can_make_complete_by_receiving_all_blocks() {}

    #[tokio::test]
    async fn can_receive_same_block_twice() {}
}
