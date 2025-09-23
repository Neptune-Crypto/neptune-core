use std::path::PathBuf;

use crate::api::export::BlockHeight;
use crate::application::loops::sync_loop::bit_mask::BitMask;

#[derive(Debug, Clone)]
pub(crate) struct RapidBlockDownload {
    temp_directory: PathBuf,
    missing: Vec<u32>,
    already_downloaded: Vec<u32>,
    initial_offset: u64,
    max_index: u64,
}

impl RapidBlockDownload {
    fn new(missing_blocks: Vec<BlockHeight>) -> Self {
        todo!()
    }

    fn snapshot(&self) -> BitMask {
        todo!()
    }
}
