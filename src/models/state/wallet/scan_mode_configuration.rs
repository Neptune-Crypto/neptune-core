use std::ops::RangeInclusive;

use crate::models::blockchain::block::block_height::BlockHeight;
use crate::models::blockchain::block::Block;

/// Configuration settings for Scan Mode.
///
/// When scan mode is active, an extra step is performed by the wallet state
/// when updating the wallet state with a new block. This extra step checks to
/// see if the incoming block has a height captured by the target range and if
/// so, scans the block for public announcements that can be decrypted by
/// *future* keys, meaning keys that are derived deterministically from the
/// wallet secret seed but with future derivation indices. If an incoming
/// message is observed, the derivation index counter is updated accordingly.
/// The number of future indices to scan for is a tunable parameter.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ScanModeConfiguration {
    num_future_keys: usize,
    first_block_height: BlockHeight,
    last_block_height: Option<BlockHeight>,
}

impl Default for ScanModeConfiguration {
    fn default() -> Self {
        Self {
            num_future_keys: 25,
            first_block_height: BlockHeight::genesis(),
            last_block_height: None,
        }
    }
}

impl ScanModeConfiguration {
    /// Constructor for `ScanModeConfiguration`.
    ///
    /// Best used in conjuction with constructor-helpers
    /// [`Self::for_future_keys`] and [`Self::blocks`], *e.g.*:
    ///
    /// ```notest
    /// let config = ScanModeConfiguration::scan().blocks(1..=2).for_future_keys(3);
    /// ```
    pub(crate) fn scan() -> Self {
        Default::default()
    }

    /// Constructor-helper for setting the number of future keys to scan for.
    pub(crate) fn for_many_future_keys(mut self, num_future_keys: usize) -> Self {
        self.num_future_keys = num_future_keys;
        self
    }

    /// Constructor-helper for setting the range of blocks to scan.
    pub(crate) fn blocks<T: Into<u64> + Copy>(mut self, block_heights: RangeInclusive<T>) -> Self {
        let first_height: u64 = block_heights.start().to_owned().into();
        let last_height: u64 = block_heights.end().to_owned().into();
        self.first_block_height = BlockHeight::from(first_height);
        self.last_block_height = Some(BlockHeight::from(last_height));
        self
    }

    /// Determine whether to scan a block given its height.
    pub(crate) fn block_height_is_in_range(&self, block_height: BlockHeight) -> bool {
        self.first_block_height <= block_height
            && self.last_block_height.is_none_or(|lbh| lbh >= block_height)
    }

    /// Determine whether to scan the given block.
    pub(crate) fn block_is_in_range(&self, block: &Block) -> bool {
        let block_height = block.header().height;
        self.block_height_is_in_range(block_height)
    }

    /// How many future keys to scan for.
    pub(crate) fn num_future_keys(&self) -> usize {
        self.num_future_keys
    }

    pub(crate) fn default_num_future_keys() -> usize {
        Self::default().num_future_keys()
    }
}
