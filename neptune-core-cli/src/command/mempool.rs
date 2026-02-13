use clap::Parser;

/// Mempool Command -- a command related to the mempool (where transactions go
/// before they are confirmed).
#[derive(Debug, Clone, Parser)]
pub(crate) enum MempoolCommand {
    /// retrieve count of transactions in the mempool
    MempoolTxCount,

    /// retrieve size of mempool in bytes (in RAM)
    MempoolSize,

    /// list mempool transaction IDs
    ListMempoolTransactionIds,

    /// Delete all transactions from the mempool.
    ClearMempool,

    /// Broadcast transaction notifications for all transactions in mempool.
    BroadcastMempoolTransactions,
}
