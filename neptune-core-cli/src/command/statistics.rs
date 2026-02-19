use clap::Parser;
use neptune_cash::protocol::consensus::block::block_selector::BlockSelector;

/// Statistics Command -- a command computing and showing statistics related to
/// the blockchain.
#[derive(Debug, Clone, Parser)]
pub(crate) enum StatisticsCommand {
    /// Show block intervals in milliseconds, in reverse chronological order.
    BlockIntervals {
        last_block: BlockSelector,
        max_num_blocks: Option<usize>,
    },

    /// Show difficulties for a list of blocks.
    BlockDifficulties {
        last_block: BlockSelector,
        max_num_blocks: Option<usize>,
    },

    /// Shows the circulating supply of Neptune coins.
    ///
    /// "Circulating" means "not time-locked" or "time-locked but with an
    /// expired release date".
    ///
    /// This number is computed rapidly but heuristically:
    ///  - It assumes that every block mined minted the maximum allowable
    ///    coinbase.
    ///  - It assumes that time-locks expire after exactly 160815 blocks,
    ///    corresponding to one generation.
    ///  - It assumes all burns are known.
    CirculatingSupply,

    /// Shows the asymptotical limit on the supply of Neptune coins.
    ///
    /// This number is computed rapidly but heuristically:
    ///  - It assumes that every block mined in the past or to be mined in the
    ///    future mints the maximum allowable coinbase.
    ///  - It assumes that all burns are known (even future ones).
    MaxSupply,

    /// Shows the total supply of Neptune coins that were burned.
    BurnedSupply,
}
