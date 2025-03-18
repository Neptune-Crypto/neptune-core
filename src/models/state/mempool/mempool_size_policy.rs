use crate::config_models::cli_args::Args;

#[derive(Debug, Clone, Copy)]
pub(super) struct MempoolSizePolicy {
    /// Maximum size in number of bytes this data structure may take up in
    /// memory.
    pub(super) max_total_size: usize,

    /// Maximum number of inputs per transaction allowed in this mempool.
    ///
    /// Also limits the pairs of single-proof backed transactions that are
    /// returned for potential proof upgrading as well as the list of
    /// transactions returned for block inclusion in such a way that the sum of
    /// inputs in the returned transactions will never exceed this limit.
    pub(super) max_num_inputs_per_transaction: usize,

    /// If set, represents the maximum number of transactions allowed in the
    /// mempool.
    pub(super) max_length: Option<usize>,
}

impl MempoolSizePolicy {
    pub(super) fn new(cli_args: &Args) -> Self {
        Self {
            max_total_size: cli_args.max_mempool_size.0.try_into().unwrap(),
            max_num_inputs_per_transaction: cli_args.max_num_inputs_per_tx,
            max_length: cli_args.max_mempool_num_tx,
        }
    }
}
