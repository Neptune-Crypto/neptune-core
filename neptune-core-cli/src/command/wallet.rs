use clap::Parser;
use neptune_cash::api::export::Network;

use crate::models::claim_utxo::ClaimUtxoFormat;

/// Wallet Command -- a command related to spending keys, receiving addresses,
/// UTXO management, funds under management, etc.
#[derive(Debug, Clone, Parser)]
pub(crate) enum WalletCommand {
    /// Retrieve number of confirmations since last balance change.
    Confirmations,

    /// retrieve confirmed balance (excludes time-locked utxos)
    ConfirmedAvailableBalance,

    /// retrieve unconfirmed balance (includes unconfirmed transactions, excludes time-locked utxos)
    UnconfirmedAvailableBalance,

    /// Export wallet status information.
    ///
    /// Available formats:
    ///  - `--json`: Raw JSON (default)
    ///  - `--table`: Table
    ///
    WalletStatus {
        #[arg(long)]
        json: bool,
        #[arg(long)]
        table: bool,
    },

    /// retrieves number of utxos the wallet expects to receive.
    NumExpectedUtxos,

    /// Get next unused generation receiving address
    NextReceivingAddress,

    /// Get the nth generation receiving address.
    ///
    /// Ignoring the ones that have been generated in the past; re-generate them
    /// if necessary. Do not increment any counters or modify state in any way.
    NthReceivingAddress {
        index: usize,

        #[clap(long, default_value_t)]
        network: Network,
    },

    /// Get a static generation receiving address, for premine recipients.
    ///
    /// This command is an alias for `nth-receiving-address 0`. It will be
    /// disabled after mainnet launch.
    PremineReceivingAddress {
        #[clap(long, default_value_t)]
        network: Network,
    },

    /// list known coins
    ListCoins,

    /// claim an off-chain utxo-transfer.
    ClaimUtxo {
        #[clap(subcommand)]
        format: ClaimUtxoFormat,

        /// Indicates how many blocks to look back in case the UTXO was already
        /// mined.
        max_search_depth: Option<u64>,
    },

    /// Rescan the selected (inclusive) range of blocks for announced, incoming
    /// UTXOs to all addresses registered by the client's wallet. Requires the
    /// client to be launched with the UTXO index activated.
    RescanAnnounced { first: u64, last: u64 },

    /// Rescan the selected (inclusive) range of blocks for UTXOs that were
    /// registered as expected. Works regardless of UTXO index status.
    RescanExpected { first: u64, last: u64 },

    /// Rescan the selected (inclusive) range of blocks for spent UTXOs. Useful
    /// to rebuild transaction history. Requires the client to be launched with
    /// the UTXO index activated.
    RescanOutgoing { first: u64, last: u64 },

    /// Rescan the selected (inclusive) range of blocks for guesser rewards.
    /// Useful if the client's seed has been used to guess on correct proof-of-
    /// work solutions in the past but wallet state was somehow lost. Works
    /// regardless of UTXO index status.
    RescanGuesserRewards { first: u64, last: u64 },

    /// prune monitored utxos from abandoned chains
    PruneAbandonedMonitoredUtxos,

    /// generate a new wallet
    GenerateWallet {
        #[clap(long, default_value_t)]
        network: Network,
    },

    /// displays path to wallet secrets file
    WhichWallet {
        #[clap(long, default_value_t)]
        network: Network,
    },

    /// export mnemonic seed phrase
    ExportSeedPhrase {
        #[clap(long, default_value_t)]
        network: Network,
    },

    /// import mnemonic seed phrase
    ImportSeedPhrase {
        #[clap(long, default_value_t)]
        network: Network,
    },

    /// Combine shares from a t-out-of-n Shamir secret sharing scheme; reproduce
    /// the original secret and save it as a wallet secret.
    ShamirCombine {
        t: usize,

        #[clap(long, default_value_t)]
        network: Network,
    },

    /// Share the wallet secret using a t-out-of-n Shamir secret sharing scheme.
    ShamirShare {
        t: usize,
        n: usize,

        #[clap(long, default_value_t)]
        network: Network,
    },
}
