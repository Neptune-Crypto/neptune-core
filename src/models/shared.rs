use serde::{Deserialize, Serialize};

use super::blockchain::{block::BlockHeight, digest::Digest};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
pub struct LatestBlockInfo {
    pub height: BlockHeight,
    pub hash: Digest,
}

impl LatestBlockInfo {
    pub fn new(hash: Digest, height: BlockHeight) -> Self {
        LatestBlockInfo { hash, height }
    }
}
