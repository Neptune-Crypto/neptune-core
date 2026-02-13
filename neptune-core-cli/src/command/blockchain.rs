use clap::Parser;
use neptune_cash::protocol::consensus::block::block_selector::BlockSelector;

/// Blockchain Command -- a command related to the state of the blockchain.
#[derive(Debug, Clone, Parser)]
pub(crate) enum BlockchainCommand {
    /// retrieve network that neptune-core is running on
    Network,

    /// retrieve current block height
    BlockHeight,

    /// retrieve information about a block
    BlockInfo {
        /// one of: `genesis, tip, height/<n>, digest/<hex>`
        block_selector: BlockSelector,
    },

    /// retrieve block digests for a given block height
    BlockDigestsByHeight {
        height: u64,
    },

    /// retrieve digest/hash of newest block
    TipDigest,
    LatestTipDigests {
        n: usize,
    },

    /// retrieve digests of newest n blocks
    TipHeader,

    /// retrieve block-header of any block
    Header {
        /// one of: `genesis, tip, height/<n>, digest/<hex>`
        block_selector: BlockSelector,
    },
}
