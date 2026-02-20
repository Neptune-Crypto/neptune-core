use clap::Parser;

/// Describes the kind of data the `rescan` command will search for.
//
// In this context, *quarry* means "the thing being pursued" and emphasizes
// that we are hunting for specific transaction inputs or outputs within a
// given block range, not the blocks themselves.
#[derive(Debug, Clone, Parser)]
pub(crate) enum RescanQuarry {
    /// Rescan the range of blocks for announced UTXOs.
    ///
    /// Specifically, this method searches for incoming UTXOs with a
    /// notification sent to the given address (full or abbreviated) or, if none
    /// is set, to all addresses registered by the node's wallet.
    ///
    /// This command does not require the node to maintain a UTXO index, but is
    /// faster if it does.
    ///
    /// The first block height of the range is mandatory. The last block height
    /// is optional: if not set, the range will contain just the one block.
    #[command(override_usage = "neptune-cli rescan announced <FIRST> [LAST] [OPTIONS]")]
    Announced {
        #[arg(display_order = 1)]
        first: u64,
        #[arg(display_order = 2)]
        last: Option<u64>,
        #[clap(long, display_order = 3)]
        address: Option<String>,
    },

    /// Rescan the range of blocks for UTXOs that were registered as expected.
    ///
    /// This command works regardless of UTXO index status.
    ///
    /// The first block height of the range is mandatory. The last block height
    /// is optional: if not set, the range will contain just the one block.
    Expected { first: u64, last: Option<u64> },

    /// Rescan all monitored UTXOs for expenditures.
    ///
    /// Can be used to rebuild a transaction history if the node maintains a
    /// UTXO index. If expenditures are observed but no UTXO index is maintained
    /// the monitored UTXO is marked as spent without information of when it was
    /// spent.
    Outgoing,

    /// Rescan the range of blocks for guesser rewards.
    ///
    /// Useful if the node's wallet seed was used to guess on correct proof-of-
    /// work solutions in the past but the corresponding wallet state was
    /// somehow lost. This command works regardless of UTXO index status.
    ///
    /// The first block height of the range is mandatory. The last block height
    /// is optional: if not set, the range will contain just the one block.
    GuesserRewards { first: u64, last: Option<u64> },
}
