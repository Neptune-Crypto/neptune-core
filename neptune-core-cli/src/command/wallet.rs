pub(crate) mod quarry;

use clap::Parser;
use neptune_cash::api::export::KeyType;
use neptune_cash::api::export::Network;

use crate::command::wallet::quarry::RescanQuarry;
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

    /// Rescan a single block or a range of blocks for transactions that may
    /// have been missed due to reorgs or moving keys across machines.
    ///
    /// If for whatever reason something goes wrong in the course of scanning
    /// blocks for incoming or outgoing UTXOs, some input or output may be
    /// missed and the wallet will report a incorrect balance as a result. In
    /// this case, this family of commands can be used to force the node to look
    /// again at a specific block or block range.
    ///
    /// The first block height of the range is mandatory. The last block height
    /// is optional: if not set, the range will contain just the one block.
    Rescan {
        #[clap(subcommand)]
        quarry: RescanQuarry,
    },

    //     /// address to which the UTXO was supposedly sent
    //     #[clap(long)]
    //     address: String,
    // },
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

    /// Get the current key derivation index for the given key type.
    GetDerivationIndex { key_type: KeyType },

    /// Set the derivation index for the given key type to the given value.
    SetDerivationIndex {
        key_type: KeyType,
        derivation_index: u64,
    },

    /// Given a receiving address derived by this wallet, find the associated
    /// derivation index.
    ///
    /// This command does not require a connection to neptune-core; it reads the
    /// wallet directly. Also, this command iterates until a match is found;
    /// if the given address does not come from the current wallet then this
    /// command will run indefinitely and the user must manually abort it.
    ///
    /// Usage: `neptune-cli index-of <address>`
    IndexOf {
        address: String,

        #[clap(long, default_value_t)]
        network: Network,
    },
}
