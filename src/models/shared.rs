use serde::{Deserialize, Serialize};

use super::blockchain::{block::BlockHeight, digest::RescuePrimeDigest};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
pub struct LatestBlockInfo {
    pub height: BlockHeight,
    pub hash: RescuePrimeDigest,
}

impl LatestBlockInfo {
    pub fn new(hash: RescuePrimeDigest, height: BlockHeight) -> Self {
        LatestBlockInfo { hash, height }
    }
}
