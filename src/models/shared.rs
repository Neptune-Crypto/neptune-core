use serde::{Deserialize, Serialize};

use super::blockchain::{block::BlockHeight, digest::KeyableDigest};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
pub struct LatestBlockInfo {
    pub height: BlockHeight,
    pub hash: KeyableDigest,
}

impl LatestBlockInfo {
    pub fn new(hash: KeyableDigest, height: BlockHeight) -> Self {
        LatestBlockInfo { hash, height }
    }
}
