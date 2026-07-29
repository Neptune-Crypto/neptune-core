use std::collections::VecDeque;

use serde::Deserialize;
use serde::Serialize;

/// Wire counterpart of `SynchronizationBitMask`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransferSyncBitMask {
    // inclusive
    pub lower_bound: u64,

    // exclusive
    pub upper_bound: u64,

    pub limbs: VecDeque<u32>,
}
