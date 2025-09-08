use std::ops::RangeInclusive;

use crate::protocol::consensus::block::block_height::BlockHeight;
use crate::protocol::consensus::block::Block;

/// Configuration settings for Scan Mode.
///
/// When scan mode is active, an extra step is performed by the wallet state
/// when updating the wallet state with a new block. This extra step checks to
/// see if the incoming block has a height captured by the target range and if
/// so, scans the block for announcements that can be decrypted by
/// *future* keys, meaning keys that are derived deterministically from the
/// wallet secret seed but with future derivation indices. If an incoming
/// message is observed, the derivation index counter is updated accordingly.
/// The number of future indices to scan for is a tunable parameter.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct ScanModeConfiguration {
    num_future_keys: usize,
    first_block_height: BlockHeight,
    last_block_height: Option<BlockHeight>,

    /// Relates to the attempted recovery of composer rewards, assuming the user
    ///  - remembers what they set the guesser fraction to, and
    ///  - lost incoming_randomness.dat, and
    ///  - migrated the wallet (or corrupted the wallet database), and
    ///  - did not use on-chain notifications for the composer (or used the
    ///    default settings before on-chain notifications were set as default).
    ///
    /// Under those conditions, this field will identify composer UTXOs that are
    /// lost otherwise.
    maybe_guesser_fraction: Option<f64>,
}

impl Default for ScanModeConfiguration {
    fn default() -> Self {
        Self {
            num_future_keys: 25,
            first_block_height: BlockHeight::genesis(),
            last_block_height: None,
            maybe_guesser_fraction: None,
        }
    }
}

impl ScanModeConfiguration {
    /// Constructor for `ScanModeConfiguration`.
    ///
    /// Best used in conjunction with constructor-helpers
    /// [`Self::for_many_future_keys`] and [`Self::blocks`], *e.g.*:
    ///
    /// ```notest
    /// let config = ScanModeConfiguration::scan().blocks(1..=2).for_many_future_keys(3);
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

        // note: `From<u64> for BlockHeight` clamps large values to
        // `BFieldElement::MAX` rather than wrapping round.
        self.first_block_height = BlockHeight::from(first_height);
        self.last_block_height = Some(BlockHeight::from(last_height));
        self
    }

    /// Set the guesser fraction to `Some` value.
    pub(crate) fn set_guesser_fraction(&mut self, fraction: f64) {
        self.maybe_guesser_fraction = Some(fraction);
    }

    /// Determine whether to scan a block given its height.
    ///
    /// Marked `pub(crate)` for testing. Not part of the API. Use
    /// [`Self::block_is_in_range`] instead.
    #[doc(hidden)]
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

    pub(crate) fn maybe_guesser_fraction(&self) -> Option<f64> {
        self.maybe_guesser_fraction
    }
}
