use std::str::FromStr;

use clap::Parser;
use neptune_primitives::block_selector::BlockSelector;

use crate::parser::hex_digest::HexDigest;

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

    /// retrieve the status of an addition record: whether it was mined into a
    /// canonical block, is sitting in the mempool, or is unknown
    AdditionRecordStatus {
        /// the addition record's canonical commitment, as hex
        #[arg(value_parser = HexDigest::from_str)]
        addition_record: HexDigest,

        /// how many blocks to search back from the tip. Searches all blocks
        /// when omitted. Ignored by nodes that maintain a UTXO index.
        #[arg(long)]
        max_search_depth: Option<u64>,
    },

    /// Validate all historical canonical blocks (again).
    RevalidateHistory {
        first: Option<u64>,
        last: Option<u64>,
    },
}
