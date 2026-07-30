use clap::Parser;
use neptune_mempool::transaction_kernel_id::TransactionKernelId;

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

    /// retrieve the addition records in a mempool transaction, one per line
    MempoolTxOutputs {
        /// the transaction's kernel ID, as hex
        txid: TransactionKernelId,
    },

    /// Delete all transactions from the mempool.
    ClearMempool,

    /// Broadcast transaction notifications for all transactions in mempool.
    BroadcastMempoolTransactions,
}
