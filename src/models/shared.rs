use crate::prelude::twenty_first;

use serde::{Deserialize, Serialize};

use twenty_first::shared_math::digest::Digest;

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

pub const SIZE_20MB_IN_BYTES: usize = 20_000_000;
