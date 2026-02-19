use std::path::PathBuf;

use clap::Parser;
use neptune_cash::api::export::TransactionKernelId;

/// Mining Command -- a command related to the process of finding new blocks.
#[derive(Debug, Clone, Parser)]
pub(crate) enum MiningCommand {
    /// get information about the current best block proposal
    BestBlockProposal,

    /// pause mining
    PauseMiner,

    /// resume mining
    RestartMiner,

    /// set coinbase distribution for the next locally produced block proposal
    SetCoinbaseDistribution {
        #[clap(long, value_parser)]
        file: PathBuf,
    },

    /// Reset coinbase distribution to reward own wallet, with amount specified
    /// in CLI arguments.
    UnsetCoinbaseDistribution,

    /// Broadcast a block proposal notification
    BroadcastBlockProposal,

    /// Upgrade the specified transaction. Transaction must be either unsynced
    /// or not have a Single Proof for this to work.
    Upgrade { tx_kernel_id: TransactionKernelId },

    /******** RegTest Mode ********/
    /// mine a series of blocks to the node's wallet. (regtest network only)
    MineBlocksToWallet {
        /// number of blocks to mine
        #[clap(default_value = "1")]
        num_blocks: u32,
    },
}
