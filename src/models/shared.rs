use serde::{Deserialize, Serialize};

use super::blockchain::{
    block::{block_height::BlockHeight, Block},
    digest::Digest,
};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LatestBlockInfo {
    pub height: BlockHeight,
    pub hash: Digest,
}

impl From<&Block> for LatestBlockInfo {
    fn from(b: &Block) -> Self {
        Self {
            hash: b.hash,
            height: b.header.height,
        }
    }
}

impl From<Block> for LatestBlockInfo {
    fn from(b: Block) -> Self {
        Self {
            hash: b.hash,
            height: b.header.height,
        }
    }
}

pub const SIZE_1MB_IN_BYTES: usize = 1_000_000;
pub const SIZE_1GB_IN_BYTES: usize = 1_000_000_000;
