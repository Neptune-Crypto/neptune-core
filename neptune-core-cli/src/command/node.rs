use std::str::FromStr;

use clap::Parser;

use crate::parser::hex_digest::HexDigest;

/// Node Command -- a command for generic node management.
#[derive(Debug, Clone, Parser)]
pub(crate) enum NodeCommand {
    /// shutdown neptune-core
    Shutdown,

    /// pause processing of new transaction data. Prevents new blocks, new
    /// block proposals, and new transactions from being received.
    Freeze,

    /// If state updates have been paused, resumes them. Otherwise does nothing.
    Unfreeze,

    /// Set the tip of the blockchain state to a stored block, identified by its
    /// hash.
    ///
    /// Note: this command does not freeze the state, meaning that after its
    /// invocation it will automatically synchronize to a new canonical block
    /// when it appears on the network. To avoid this behavior, use this command
    /// in conjunction with `freeze` (before) and `unfreeze` (after).
    SetTip {
        #[arg(value_parser = HexDigest::from_str)]
        digest: HexDigest,
    },
}
