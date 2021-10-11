use serde::{Deserialize, Serialize};

use super::blockchain::{BlockHash, BlockHeight};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
pub struct LatestBlockInfo {
    pub height: BlockHeight,
    pub hash: BlockHash,
}

impl LatestBlockInfo {
    pub fn new(hash: BlockHash, height: BlockHeight) -> Self {
        LatestBlockInfo { hash, height }
    }
}
