use serde::{Deserialize, Serialize};

use super::blockchain::{
    block::{block_height::BlockHeight, Block},
    digest::Digest,
};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
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
