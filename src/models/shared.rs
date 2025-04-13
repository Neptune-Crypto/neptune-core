use serde::Deserialize;
use serde::Serialize;
use tasm_lib::twenty_first::tip5::digest::Digest;

use super::blockchain::block::block_height::BlockHeight;
use super::blockchain::block::Block;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LatestBlockInfo {
    pub height: BlockHeight,
    pub hash: Digest,
}

impl From<&Block> for LatestBlockInfo {
    fn from(b: &Block) -> Self {
        Self {
            hash: b.hash(),
            height: b.kernel.header.height,
        }
    }
}

impl From<Block> for LatestBlockInfo {
    fn from(b: Block) -> Self {
        Self {
            hash: b.hash(),
            height: b.kernel.header.height,
        }
    }
}

pub const SIZE_20MB_IN_BYTES: usize = 20_000_000;
