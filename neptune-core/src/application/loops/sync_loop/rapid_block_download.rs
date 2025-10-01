use std::collections::HashMap;
use std::path::PathBuf;

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
    fn new(highest_block_already_processed: BlockHeight, tip: &Block) -> Self {
        todo!()
    }

    /// Add one new block to the chain, effectively setting a new tip digest and
    /// bumping the counter by one.
    ///
    /// # Panics
    ///
    ///  - If the height of the new block does not equal current tip height plus
    ///    one.
    async fn extend_chain(&mut self, new_block: &Block) {}

    /// Store the block in the temp directory and mark it as received.
    async fn receive_block(&mut self, block: Block) {}

    /// Sample a block height among blocks we still need to download.
    ///
    /// If we have already downloaded all the blocks we need, this function
    /// returns `None`. Otherwise, it returns the sampled block height but
    /// wrapped in a `Some`.
    fn sample_missing_block_height(&self, seed: [u8; 32]) -> Option<BlockHeight> {
        todo!()
    }

    /// Read a block from the temp directory.
    async fn get_block(&self, height: BlockHeight) -> Block {
        todo!()
    }

    /// Get the [`BitMask`] corresponding to covered blocks (blocks we have,
    /// whether cached or in the database). The complement of this bit mask
    /// indicates which blocks we do not yet have.
    fn coverage(&self) -> BitMask {
        self.coverage.clone()
    }
}
