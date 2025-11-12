use std::net::IpAddr;
use std::net::SocketAddr;
use std::num::NonZero;
use std::ops::RangeInclusive;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;

use bytesize::ByteSize;
use clap::builder::RangedI64ValueParser;
use clap::builder::TypedValueParser;
use clap::Parser;
use itertools::Itertools;
use num_traits::Zero;
use sysinfo::System;
use tracing::error;

use super::fee_notification_policy::FeeNotificationPolicy;
use super::network::Network;
use crate::application::config::triton_vm_env_vars::TritonVmEnvVars;
use crate::application::config::tx_upgrade_filter::TxUpgradeFilter;
use crate::application::json_rpc::core::api::ops::Namespace;
use crate::application::triton_vm_job_queue::TritonVmJobPriority;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::protocol::peer::transfer_transaction::TransactionProofQuality;
use crate::protocol::proof_abstractions::tasm::program::TritonVmProofJobOptions;
use crate::protocol::proof_abstractions::tasm::prover_job::ProverJobSettings;
use crate::state::mining::block_proposal::BlockProposalRejectError;
use crate::state::transaction::tx_proving_capability::TxProvingCapability;
use crate::state::wallet::scan_mode_configuration::ScanModeConfiguration;

const MAX_NUM_INPUTS_FOR_PC_BACKED_TXS: u64 = 200;

/// The `neptune-core` command-line program starts a Neptune node.
#[derive(Parser, Debug, Clone)]
#[clap(author, version, about)]
pub struct Args {
    /// The data directory that contains the wallet and blockchain state
    ///
    /// The default varies by operating system, and includes the network, e.g.
    ///
    /// Linux:   /home/alice/.config/neptune/core/main
    ///
    /// Windows: C:\Users\Alice\AppData\Roaming\neptune\core\main
    ///
    /// macOS:   /Users/Alice/Library/Application Support/neptune/main
    #[clap(long, value_name = "DIR")]
    pub data_dir: Option<PathBuf>,

    /// A directory holding block data that can be used to bootstrap the state
    /// to speedup the initial block download.
    #[clap(long, value_name = "DIR")]
    pub import_blocks_from_directory: Option<PathBuf>,

    /// The number of blocks between each database flush during block-importing.
    ///
    /// A value of 0 disables automatic flushing during block-importing.
    /// Lower non-zero values flush more frequently, reducing memory usage but
    /// increasing I/O overhead. Higher values reduce flush frequency and I/O,
    /// but increase memory usage. If you run into memory issues during block-
    /// import, consider lowering this value.
    #[clap(long, default_value = "250")]
    pub(crate) import_block_flush_period: usize,

    /// Set this to disable block validation for a faster block-import.
    #[clap(long)]
    pub disable_validation_in_block_import: bool,

    /// Execute command when the best block changes (%s in cmd is replaced by
    /// block hash).
    ///
    /// A process is spawned to execute the command. The command's exit value
    /// is not checked. The process is spawned as a "fire and forget" process,
    /// meaning that the node software continues and does not wait for the
    /// spawned process to finish.
    ///
    /// If external command cannot be started, the entire node is stopped.
    ///
    /// Anything after the 1st space is interpreted as an argument. So the file
    /// used here may not contain spaces.
    pub(crate) block_notify: Option<String>,

    /// Ban connections to this node from IP address.
    ///
    /// This node can still make outgoing connections to IP address.
    ///
    /// To do this, see `--peer`.
    ///
    /// E.g.: --ban 1.2.3.4 --ban 5.6.7.8
    #[clap(long, value_name = "IP")]
    pub(crate) ban: Vec<IpAddr>,

    /// The threshold at which a peer's standing is considered “bad”. Current
    /// connections to peers in bad standing are terminated. Connection attempts
    /// from peers in bad standing are refused.
    ///
    /// For a list of reasons that cause bad standing, see
    /// [NegativePeerSanction](crate::protocol::peer::NegativePeerSanction).
    #[clap(
        long,
        default_value = "1000",
        value_name = "VALUE",
        value_parser = clap::value_parser!(u16).range(1..),
    )]
    pub(crate) peer_tolerance: u16,

    /// Only connect to the peers specified by --peer.
    /// When this flag is set, peer discovery is disabled and incoming
    /// connections from unlisted peers are rejected.
    #[arg(long)]
    pub restrict_peers_to_list: bool,

    /// Maximum number of peers to accept connections from.
    ///
    /// Will not prevent outgoing connections made with `--peer`.
    /// Set this value to 0 to refuse all incoming connections.
    #[clap(
        long,
        default_value = "10",
        value_name = "COUNT",
        value_parser = clap::value_parser!(u16).map(|u| usize::from(u)),
    )]
    pub(crate) max_num_peers: usize,

    /// Maximum number of peers to accept from each IP address.
    ///
    /// Multiple nodes can run on the same IP address which would either mean
    /// that multiple nodes run on the same machine, or multiple machines are
    /// on the same network that uses Network Address Translation and has one
    /// public IP.
    #[clap(long)]
    pub(crate) max_connections_per_ip: Option<usize>,

    /// Handshake timeout in seconds.
    ///
    /// The timeout used for all messages received and sent during the handshake
    /// protocol for incoming connections. Can be lowered if the client is
    /// attacked by many connection attempts. Can be raised if client is running
    /// on a machine with a bad internet connection.
    #[clap(long, default_value = "4", value_name = "SECONDS")]
    pub(crate) handshake_timeout: u8,

    /// Whether to act as bootstrapper node.
    ///
    /// Bootstrapper nodes ensure that the maximum number of peers is never
    /// reached by disconnecting from existing peers when the maximum is about
    /// to be reached. As a result, they will respond with high likelihood to
    /// incoming connection requests -- in contrast to regular nodes, which
    /// refuse incoming connections when the max is reached.
    #[clap(long)]
    pub(crate) bootstrap: bool,

    /// If this flag is set, the node will refuse to initiate a transaction.
    /// This flag makes sense for machines whose resources are dedicated to
    /// composing, and which must do so in a regular and predictable manner,
    /// undisrupted by transaction initiation tasks. To spend funds from the
    /// wallet of a node where this flag is set, either restart it and drop the
    /// flag, or else copy the wallet file to another machine.
    #[clap(long, alias = "notx")]
    pub(crate) no_transaction_initiation: bool,

    /// Specify environment variables for Triton VM for a given (log2 of) the
    /// padded height. Can be used to control the environment variables
    /// `TVM_LDE_TRACE` and `RAYON_NUM_THREADS` as a function of the proof's
    /// padded height. These environment variable affect Triton VM's performance
    /// and RAM consumption. For very high padded heights, you can use this
    /// value to guarantee that RAM consumption is limited such that the proof
    /// can be produced. These environment variables are only seen by the
    /// spawned Triton VM instances, not by neptune-core.
    ///
    /// Syntax: <log_2(padded height)>:'<key_0>=<value_0> <key_1>=<value_1> ...'
    ///
    /// Example:
    ///  --triton-vm-env-vars='24:"RAYON_NUM_THREADS=90 TVM_LDE_TRACE=no_cache",25:"RAYON_NUM_THREADS=45 TVM_LDE_TRACE=no_cache"'
    #[clap(long, default_value = "")]
    pub triton_vm_env_vars: TritonVmEnvVars,

    /// Whether to expend computational resources on upgrading proofs for 3rd
    /// party transactions, i.e. for transactions that this node is not party
    /// to. This is the 1st step of three-step mining. Transaction fees can be
    /// collected through this process. Note that upgrading transaction proofs
    /// involves the computationally expensive task of producing STARK proofs.
    /// You should have plenty of cores and probably at least 128 GB of RAM.
    #[clap(long)]
    pub(crate) tx_proof_upgrading: bool,

    /// If [`Self::tx_proof_upgrading`] is set, only upgrade transactions that
    /// match this filter. Syntax: `--tx-upgrade-filter <divisor>:<remainder>`
    ///
    /// Only upgrade transactions where txid % divisor == remainder.
    /// Example: `--tx-upgrade-filter 4:2`
    ///
    /// Setting the filter to e.g. '4:2' means that this node will on average
    /// only upgrade one out of four transactions. Specifically those whose
    /// txid modulo 4 is 2.
    ///
    /// Can be used to avoid duplicate work where multiple machines upgrade the
    /// same transaction. Useful if the same entity controls multiple nodes that
    /// all do transaction proof upgrading. If this flag is not set that
    /// corresponds to the "1:0" filter, a filter that matches on all
    /// transactions.
    #[arg(long, default_value = "1:0")]
    pub(crate) tx_upgrade_filter: TxUpgradeFilter,

    /// Determines the fraction of the transaction fee consumed by this node as
    /// a reward either for upgrading transaction proofs. Ignored unless
    /// proof upgrading is activated.
    #[clap(long, default_value = "0.6", value_parser = fraction_validator)]
    pub(crate) gobbling_fraction: f64,

    /// Determines the minimum fee to take as a reward for upgrading 3rd party
    /// transaction proofs. Foreign transactions where a fee below this
    /// threshold cannot be collected by proof upgrading will not be upgraded.
    #[clap(long, default_value = "0.01", value_parser = NativeCurrencyAmount::coins_from_str)]
    pub(crate) min_gobbling_fee: NativeCurrencyAmount,

    /// Minimum fee value for ProofCollection-backed transaction per input.
    ///
    /// Transactions with fees lower than this will not be requested from
    /// peers, will not be inserted into the mempool, and will not be
    /// relayed to peers.
    ///
    /// The value is per input. So the fee must be at least this value times
    /// the number of inputs in the transaction for the transaction to be
    /// relayed to peers.
    #[clap(long, default_value = "0.0005", value_parser = NativeCurrencyAmount::coins_from_str)]
    pub(crate) min_relay_pctx_fee_per_input: NativeCurrencyAmount,

    /// Whether to produce block proposals, which is the 2nd step of three-step
    /// mining. Note that composing block proposals involves the computationally
    /// expensive task of producing STARK proofs. You should have plenty of
    /// cores and probably at least 128 GB of RAM.
    #[clap(long)]
    pub(crate) compose: bool,

    /// When compsing, the maximum number of single proof backed transactions
    /// that will be merged from the mempool.
    ///
    /// Increasing this beyond the default value of 1 will slow down
    /// composition.
    #[clap(long, default_value = "1")]
    pub(crate) max_num_compose_mergers: NonZero<usize>,

    /// By default, a composer will share block proposals with all peers. If
    /// this flag is set, the composer will *not* share their block proposals.
    #[clap(long)]
    pub(crate) secret_compositions: bool,

    /// If set, node will only accept block proposals from these IP addresses.
    ///
    /// Multiple IP address can be set in which case the node will accept
    /// block proposals from any node connected from an IP in this list. Apart
    /// from ignoring all other block proposals, this argument does not change
    /// the proposal-selection behavior, meaning that the node will still pick
    /// the most favorable block proposal in terms of guesser rewards, as long
    /// as they are shared from any of these IPs.
    ///
    /// Example: `--whitelisted-composer=8.8.8.8 --whitelisted-composer=8.8.4.4`
    ///          `--whitelisted-composer=2001:db8:3333:4444:5555:6666:7777:8888`
    #[clap(long = "whitelisted-composer")]
    pub(crate) whitelisted_composers: Vec<IpAddr>,

    /// If set, all composition from peers will be ignored.
    #[clap(long)]
    pub(crate) ignore_foreign_compositions: bool,

    /// Regulates the fraction of the block subsidy that a composer sends to the
    /// guesser.
    /// Value must be between 0 and 1.
    ///
    /// The remainder goes to the composer. This flag is ignored if the
    /// `compose` flag is not set.
    #[clap(long, default_value = "0.5", value_parser = fraction_validator)]
    pub guesser_fraction: f64,

    /// The minimum fraction that a guesser will require from the composer
    /// before they start guessing. Block proposals with a guesser fraction
    /// below this number will not cause guessing to start.
    ///
    /// Only applies to external block proposals. Own block proposals will
    /// always be guessed on if both composition and guessing is set.
    #[clap(long, default_value = "0.5", value_parser = fraction_validator)]
    pub(crate) minimum_guesser_fraction: f64,

    /// If guessing has already started, and a new proposal comes in, the new
    /// proposal will be guessed on only if it exceeds the previous proposal
    /// with this fraction. Ideally this fraction should be set to the value of
    /// 1 - BTI' / (BTI' - PPT), where BTI' is block target interval minus
    /// proving time minus preprocessing time, and PPT is preprocessing time.
    /// This value will optimize guesser rewards. On a Threadrippper 7995wx this
    /// value is 16.7 %. On weaker CPUs, this value should be set higher.
    #[clap(long, default_value = "0.17", value_parser = fraction_validator)]
    pub(crate) minimum_guesser_improvement_fraction: f64,

    /// Whether to engage in guess-nonce-and-hash, which is the 3rd step in
    /// three-step mining. If this flag is set and the `compose` flag is not
    /// set, then the client will rely on block proposals from other nodes. In
    /// this case, it will always pick the most profitable block proposal.
    ///
    /// If this flag is set and the `compose` flag is set, then the client will
    /// always guess on their own block proposal.
    #[clap(long)]
    pub(crate) guess: bool,

    /// Set the number of threads to use while guessing. When no value is set,
    /// the number is set to the number of available cores.
    #[clap(long)]
    pub(crate) guesser_threads: Option<usize>,

    /// Whether to keep the UTXO notifications for composer fees and
    /// proof-upgrader fees off chain.
    ///
    /// Composers and proof-upgraders can gobble a portion of the fee of
    /// transactions they work on, by directing it to an output only they can
    /// spend. By default, an announcement is added to the transaction to
    /// enable the composer or proof-upgrader to recover such UTXOs after
    /// restoring the wallet from seed phrase. This announcement is
    /// encryped by default under a symmetric key.
    ///
    /// Valid options:
    ///
    ///  - `on-chain-symmetric` (default) On-chain backups using symmetric key
    ///    ciphertexts.
    ///
    ///  - `on-chain-generation` On-chain backups using generation addresses,
    ///    which means that public key encryption is used instead. Note that
    ///    public key ciphertexts are significantly larger (and thus take up
    ///    more blockchain space) than symmetric ciphertexts.
    ///
    ///  - `off-chain` Avoid on-chain backups. Saves blockchain space, but risks
    ///    loss of funds. Enable only if you know what you are doing.
    ///
    /// This flag does not apply to guesser fees because those UTXOs are
    /// generated automatically.
    #[clap(long, default_value = "on-chain-symmetric", value_parser = FeeNotificationPolicy::parse)]
    pub(crate) fee_notification: FeeNotificationPolicy,

    /// Prune the mempool when it exceeds this size in RAM.
    ///
    /// Units: B (bytes), K (kilobytes), M (megabytes), G (gigabytes)
    ///
    /// E.g. --max-mempool-size 500M
    #[clap(long, default_value = "1G", value_name = "SIZE")]
    pub(crate) max_mempool_size: ByteSize,

    /// Port on which to listen for peer connections.
    #[clap(long, default_value = "9798", value_name = "PORT")]
    pub peer_port: u16,

    /// Port on which to listen for RPC connections.
    #[clap(long, default_value = "9799", value_name = "PORT")]
    pub rpc_port: u16,

    /// IP on which to listen for peer connections. Will default to all network interfaces, IPv4 and IPv6.
    #[clap(short, long, default_value = "::")]
    pub peer_listen_addr: IpAddr,

    /// Maximum number of blocks that the client can catch up to without going
    /// into sync mode.
    ///
    /// Default: 1000.
    ///
    /// The process running this program should have access to enough RAM: at
    /// least the number of blocks set by this argument multiplied with the max
    /// block size (around 2 MB). Probably 1.5 to 2 times that amount for good
    /// margin.
    // Notice that the minimum value here may not be less than
    // [SYNC_CHALLENGE_POW_WITNESS_LENGTH](crate::models::peer::SYNC_CHALLENGE_POW_WITNESS_LENGTH)
    // as that would prevent going into sync mode.
    #[clap(long, default_value = "1000", value_parser(RangedI64ValueParser::<usize>::new().range(10..100000)))]
    pub(crate) sync_mode_threshold: usize,

    /// IPs of nodes to connect to, e.g.: --peer 8.8.8.8:9798 --peer 8.8.4.4:1337.
    #[structopt(long = "peer")]
    pub peers: Vec<SocketAddr>,

    /// Specify network, `main`, `alpha`, `beta`, `testnet`, or `regtest`
    #[structopt(long, default_value = "main", short)]
    pub network: Network,

    /// Max number of membership proofs stored per owned UTXO
    #[structopt(long, default_value = "3")]
    pub(crate) number_of_mps_per_utxo: usize,

    /// Configure how complicated proofs this machine is capable of producing.
    /// If no value is set, this parameter is estimated. For privacy, this level
    /// must not be set to [`TxProvingCapability::LockScript`], as this leaks
    /// information about amounts and input/output UTXOs.
    ///
    /// Proving the lockscripts is mandatory, since this is what prevents others
    /// from spending your coins.
    ///
    /// e.g. `--tx-proving-capability=singleproof` or
    /// `--tx-proving-capability=proofcollection`.
    #[clap(long)]
    pub tx_proving_capability: Option<TxProvingCapability>,

    /// Cache for the proving capability. If the above parameter is not set, we
    /// want to estimate proving capability and afterwards reuse the result from
    /// previous estimations. This argument cannot be set from CLI, so clap
    /// ignores it.
    #[clap(skip)]
    pub(crate) tx_proving_capability_cache: OnceLock<TxProvingCapability>,

    /// Enable tokio tracing for consumption by the tokio-console application
    /// note: this will attempt to connect to localhost:6669
    #[structopt(long, name = "tokio-console", default_value = "false")]
    pub tokio_console: bool,

    /// Sets the max program complexity limit for proof creation in Triton VM.
    ///
    /// Triton VM's prover complexity is a function of something called padded height
    /// which is always a power of two. A basic proof has a complexity of 2^11.
    /// A powerful machine in 2024 with 128 CPU cores can handle a padded height of 2^23.
    ///
    /// This limit can be increased to 2^24 if the [Self::triton_vm_env_vars]
    /// argument is used to decrease RAM consumption at these bigger proof
    /// sizes.
    ///
    /// if the limit is reached while mining, a warning is logged and mining will pause.
    /// non-mining operations may panic and halt neptune-core
    ///
    /// no limit is applied if unset.
    #[structopt(long, short, value_parser = clap::value_parser!(u8).range(10..32))]
    pub max_log2_padded_height_for_proofs: Option<u8>,

    /// Sets the maximum number of proofs in a `ProofCollection` that can be
    /// recursively combined into a `SingleProof` by this machine. I.e. how big
    /// STARK proofs this machine can produce.
    #[clap(long, default_value = "16")]
    pub(crate) max_num_proofs: usize,

    /// Disables the cookie_hint RPC API
    ///
    /// client software can ask for a cookie hint to automatically determine the
    /// root data directory used by a running node, which enables loading a
    /// cookie file for authentication.
    ///
    /// Exposing the data directory leaks some privacy. Disable to prevent.
    #[clap(long)]
    pub disable_cookie_hint: bool,

    /// The duration (in seconds) during which new connection attempts from peers
    /// are ignored after a connection to them was closed.
    ///
    /// Does not affect abnormally closed connections. For example, if a connection
    /// is dropped due to networking issues, an immediate reconnection attempt is
    /// not affected by this cooldown.
    //
    // The default should be larger than the default interval between peer discovery
    // to meaningfully suppress rapid reconnection attempts.
    #[clap(long, default_value = "1800", value_parser = duration_from_seconds_str)]
    pub reconnect_cooldown: Duration,

    /// Scan incoming blocks for inbound transactions.
    ///
    /// Keys are generated deterministically from the secret seed and a
    /// derivation index, and a counter recording the most recently used index
    /// is stored. By default, incoming blocks are scanned for inbound
    /// transactions tied to any key derived from indices smaller than this
    /// counter.
    ///
    /// However, this counter can be lost, for instance after importing the
    /// secret seed onto a new machine. In such cases, this subcommand will
    /// instruct the client to scan incoming blocks for transactions tied to
    /// future derivation indices --
    /// [`ScanModeConfiguration`]`::default().num_future_keys()` by default, but
    /// this parameter can be adjusted with the `--scan-keys` subcommand.
    ///
    /// The argument to this subcommand is the range of blocks where this extra-
    /// ordinary scanning step takes place. If no argument is supplied, the step
    /// takes place for every incoming block.
    ///
    /// Examples:
    ///  - `neptune-core --scan-blocks ..` (scan all blocks; this is the
    ///    default)
    ///  - `neptune-core --scan-blocks ..1337` (everything up to 1337)
    ///  - `neptune-core --scan-blocks 1337..` (1337 and everything after)
    ///  - `neptune-core --scan-blocks 13..=37` (13, 37, and everything in
    ///    between)
    ///  - `neptune-core --scan-blocks 13:37` (python index ranges also work)
    //
    // Everything above should constitute the help documentation for this
    // command, with the exception of the concrete value for the default number
    // of future indices. To present the user with that piece of information,
    // we override this docstring by setting `long_help`, which allows us to
    // invoke `format!` and embed the integer.
    #[clap(long, value_parser = parse_range, action = clap::ArgAction::Set,
        num_args = 0..=1, long_help = format!(
            "\
    Keys are generated deterministically from the secret seed and a\n\
    derivation index, and a counter recording the most recently used index\n\
    is stored. By default, incoming blocks are scanned for inbound\n\
    transactions tied to any key derived from indices smaller than this\n\
    counter.\n\
    \n\
    However, this counter can be lost, for instance after importing the\n\
    secret seed onto a new machine. In such cases, this subcommand will\n\
    instruct the client to scan incoming blocks for transactions tied to\n\
    future derivation indices -- {} by default, but this parameter can be\n\
    adjusted with the `--scan-keys` subcommand.\n\
    \n\
    The argument to this subcommand is the range of blocks where this extra-\n\
    ordinary scanning step takes place. If no argument is supplied, the step\n\
    takes place for every incoming block.\n\
    \n\
    Examples: \n\
     - `neptune-core --scan-blocks ..` (scan all blocks; this is the default)\n\
     - `neptune-core --scan-blocks ..1337` (everything up to 1337)\n\
     - `neptune-core --scan-blocks 1337..` (1337 and everything after)\n\
     - `neptune-core --scan-blocks 13..=37` (13, 37, and everything in\n\
       between)\n\
     - `neptune-core --scan-blocks 13:37` (python index ranges also work)",
    ScanModeConfiguration::default().num_future_keys()
        ))]
    pub(crate) scan_blocks: Option<RangeInclusive<u64>>,

    /// Scan incoming blocks for inbound transactions.
    ///
    /// Keys are generated deterministically from the secret seed and a
    /// derivation index, and a counter recording the most recently used index
    /// is stored. By default, incoming blocks are scanned for inbound
    /// transactions tied to any key derived from indices smaller than this
    /// counter.
    ///
    /// However, this counter can be lost, for instance after importing the
    /// secret seed onto a new machine. In such cases, this subcommand will
    /// instruct the client to scan incoming blocks for transactions tied to the
    /// next k derivation indices, where k is the argument supplied.
    ///
    /// When this flag is set, by default all blocks will be scanned. The
    /// subcommand `--scan-blocks` can be used to restrict the range of blocks
    /// that undergo this scan.
    ///
    /// Example: `neptune-core --scan-keys 42`
    #[clap(long)]
    pub(crate) scan_keys: Option<usize>,

    /// Enable JSON/HTTP RPC.
    /// You can optionally specify an address and port (default: 127.0.0.1:9797).
    /// If not given, RPC is disabled.
    #[clap(
        long,
        default_missing_value = "127.0.0.1:9797",
        num_args = 0..=1,
        value_name = "ADDR"
    )]
    pub listen_rpc: Option<SocketAddr>,

    /// RPC modules to enable.
    /// Specifies which sets of RPC methods are exposed (e.g., node or chain).
    /// By default, both "node" and "chain" modules are enabled.
    #[clap(
        long,
        value_parser = clap::value_parser!(Namespace),
        use_value_delimiter = true,
        default_value = "Node,Chain",
        value_name = "NAMESPACES"
    )]
    pub rpc_modules: Vec<Namespace>,

    /// Enable unsafe RPC methods over all transports (e.g., HTTP).
    ///
    /// WARNING: Enabling this exposes dangerous RPC behavior and should only be used in
    /// isolated, controlled environments.
    ///
    /// This may result in:
    /// - Denial of Service (DoS) by triggering heavy or expensive computations.
    /// - Exposure of internal node state or metrics that could aid an attacker.
    /// - Misconfigurations leading to unexpected or unsafe behavior.
    #[clap(long)]
    pub unsafe_rpc: bool,
}

impl Default for Args {
    fn default() -> Self {
        let empty: Vec<String> = vec![];
        Self::parse_from(empty)
    }
}

fn fraction_validator(s: &str) -> Result<f64, String> {
    let value = s
        .parse::<f64>()
        .map_err(|_| format!("`{s}` isn't a valid float"))?;
    if (0.0..=1.0).contains(&value) {
        Ok(value)
    } else {
        Err(format!("Fraction must be between 0 and 1, got {value}"))
    }
}

fn duration_from_seconds_str(s: &str) -> Result<Duration, std::num::ParseIntError> {
    Ok(Duration::from_secs(s.parse()?))
}

/// Parses strings that represent ranges of non-negative integers, in either
/// rust or python (index-range) format.
///
/// Disallows empty ranges.
fn parse_range(unparsed_range: &str) -> Result<RangeInclusive<u64>, String> {
    if unparsed_range.is_empty() {
        return Ok(0..=u64::MAX);
    }

    let range_parts = if unparsed_range.contains("..") {
        unparsed_range.split("..")
    } else {
        unparsed_range.split(":")
    };

    let Some((start, end)) = range_parts.collect_tuple() else {
        let error_message = format!(
            "Invalid range: \"{unparsed_range}\". \
            Syntax: `start..end`, `start..=end`, or `start:end`"
        );
        return Err(error_message);
    };

    let start = start
        .is_empty()
        .then_some(Ok(0))
        .or_else(|| Some(start.parse()))
        .unwrap()
        .map_err(|e| format!("Invalid start \"{start}\" in range \"{unparsed_range}\": {e:?}"))?;

    let end = if end.is_empty() {
        u64::MAX
    } else {
        let format_error =
            |e| format!("Invalid end \"{end}\" in range \"{unparsed_range}\": {e:?}");
        if let Some(end_inclusive) = end.strip_prefix('=') {
            end_inclusive.parse().map_err(format_error)?
        } else {
            end.parse::<u64>()
                .map_err(format_error)?
                .checked_sub(1)
                .ok_or_else(|| format!("Range upper bound \"{end}\" is invalid when excluded"))?
        }
    };

    if start > end {
        return Err(format!(
            "Range \"{unparsed_range}\" is invalid: lower bound exceeds upper bound"
        ));
    }

    Ok(start..=end)
}

impl Args {
    /// Indicates if all incoming peer connections are disallowed.
    pub(crate) fn disallow_all_incoming_peer_connections(&self) -> bool {
        self.max_num_peers.is_zero()
    }

    /// Return the port that peer can connect on. None if incoming connections
    /// are disallowed.
    pub(crate) fn own_listen_port(&self) -> Option<u16> {
        if self.disallow_all_incoming_peer_connections() {
            None
        } else {
            Some(self.peer_port)
        }
    }

    /// Whether to engage in mining (composing or guessing or both)
    pub(crate) fn mine(&self) -> bool {
        self.guess || self.compose
    }

    pub(crate) fn proof_job_options(
        &self,
        job_priority: TritonVmJobPriority,
    ) -> TritonVmProofJobOptions {
        TritonVmProofJobOptions {
            job_priority,
            job_settings: ProverJobSettings::from(self),
            cancel_job_rx: None,
        }
    }

    /// Get the proving capability CLI argument or estimate it if it is not set.
    /// Cache the result so we don't estimate more than once.
    pub fn proving_capability(&self) -> TxProvingCapability {
        *self.tx_proving_capability_cache.get_or_init(|| {
            if let Some(proving_capability) = self.tx_proving_capability {
                proving_capability
            } else if self.compose {
                TxProvingCapability::SingleProof
            } else {
                Self::estimate_proving_capability()
            }
        })
    }

    /// Check if block proposal should be accepted from this IP address.
    pub(crate) fn accept_block_proposal_from(
        &self,
        ip_address: IpAddr,
    ) -> Result<(), BlockProposalRejectError> {
        if self.ignore_foreign_compositions {
            return Err(BlockProposalRejectError::IgnoreAllForeign);
        }

        let ip_address = match ip_address {
            IpAddr::V4(_) => ip_address,
            IpAddr::V6(v6) => match v6.to_ipv4() {
                Some(v4) => std::net::IpAddr::V4(v4),
                None => ip_address,
            },
        };
        if !self.whitelisted_composers.is_empty()
            && !self.whitelisted_composers.contains(&ip_address)
        {
            return Err(BlockProposalRejectError::NotWhiteListed);
        }

        Ok(())
    }

    fn estimate_proving_capability() -> TxProvingCapability {
        const SINGLE_PROOF_CORE_REQ: usize = 19;
        // see https://github.com/Neptune-Crypto/neptune-core/issues/426
        const SINGLE_PROOF_MEMORY_USAGE: u64 = (1u64 << 30) * 120;

        const PROOF_COLLECTION_CORE_REQ: usize = 2;
        const PROOF_COLLECTION_MEMORY_USAGE: u64 = (1u64 << 30) * 16;

        let s = System::new_all();
        let total_memory = s.total_memory();
        assert!(
            !total_memory.is_zero(),
            "Total memory reported illegal value of 0"
        );

        let physical_core_count = s.physical_core_count().unwrap_or(1);

        if total_memory > SINGLE_PROOF_MEMORY_USAGE && physical_core_count > SINGLE_PROOF_CORE_REQ {
            TxProvingCapability::SingleProof
        } else if total_memory > PROOF_COLLECTION_MEMORY_USAGE
            && physical_core_count > PROOF_COLLECTION_CORE_REQ
        {
            TxProvingCapability::ProofCollection
        } else {
            TxProvingCapability::PrimitiveWitness
        }
    }

    /// creates a `TritonVmProofJobOptions` from cli args.
    pub fn as_proof_job_options(&self) -> TritonVmProofJobOptions {
        self.into()
    }

    /// Check if a transaction should be inserted into the mempool and relayed
    /// to peers. Proofcollection-backed transactions that pay too small fees
    /// are not relayed.
    pub(crate) fn relay_transaction(
        &self,
        num_inputs: u64,
        tx_fee: NativeCurrencyAmount,
        proof_quality: TransactionProofQuality,
    ) -> bool {
        match proof_quality {
            TransactionProofQuality::ProofCollection => {
                if num_inputs > MAX_NUM_INPUTS_FOR_PC_BACKED_TXS {
                    return false;
                }

                let num_inputs: u32 = num_inputs
                    .try_into()
                    .expect("Already checked that number of inputs was not too high.");

                let Some(min_fee) = self
                    .min_relay_pctx_fee_per_input
                    .checked_scalar_mul(num_inputs)
                else {
                    error!("Multiplication overflowed in fee calculation. This should not happen.");
                    return false;
                };

                tx_fee >= min_fee
            }
            // For now, all single proof txs are relayed. A threshold value
            // could be set here too though.
            TransactionProofQuality::SingleProof => true,
        }
    }
}

impl From<&Args> for ProverJobSettings {
    fn from(cli: &Args) -> Self {
        let triton_vm_env_vars: TritonVmEnvVars = cli.triton_vm_env_vars.clone();
        Self {
            max_log2_padded_height_for_proofs: cli.max_log2_padded_height_for_proofs,
            network: cli.network,
            tx_proving_capability: cli.proving_capability(),
            proof_type: cli.proving_capability().into(),
            triton_vm_env_vars,
        }
    }
}

impl From<&Args> for TritonVmProofJobOptions {
    fn from(cli: &Args) -> Self {
        Self {
            job_priority: Default::default(),
            job_settings: ProverJobSettings::from(cli),
            cancel_job_rx: None,
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::net::Ipv6Addr;
    use std::ops::RangeBounds;

    use super::*;
    use crate::protocol::consensus::transaction::transaction_proof::TransactionProofType;

    // extra methods for tests.
    impl Args {
        pub(crate) fn default_with_network(network: Network) -> Self {
            Self {
                network,
                ..Default::default()
            }
        }

        pub(crate) fn proof_job_options_prooftype(
            &self,
            proof_type: TransactionProofType,
        ) -> TritonVmProofJobOptions {
            let mut options: TritonVmProofJobOptions = self.into();
            options.job_settings.proof_type = proof_type;
            options
        }

        pub(crate) fn proof_job_options_primitive_witness(&self) -> TritonVmProofJobOptions {
            self.proof_job_options_prooftype(TransactionProofType::PrimitiveWitness)
        }
    }

    #[test]
    fn default_args_test() {
        let default_args = Args::default();

        assert_eq!(1000, default_args.peer_tolerance);
        assert_eq!(10, default_args.max_num_peers);
        assert_eq!(9798, default_args.peer_port);
        assert_eq!(9799, default_args.rpc_port);
        assert_eq!(
            IpAddr::from(Ipv6Addr::UNSPECIFIED),
            default_args.peer_listen_addr
        );
        assert_eq!(1, default_args.max_num_compose_mergers.get());
        assert_eq!(TxUpgradeFilter::match_all(), default_args.tx_upgrade_filter);
    }

    #[test]
    fn max_peers_0_means_no_incoming_connections() {
        let args = Args {
            max_num_peers: 0,
            ..Default::default()
        };
        assert!(args.disallow_all_incoming_peer_connections());
    }

    #[test]
    fn estimate_own_proving_capability() {
        // doubles as a no-crash test
        println!("{}", Args::estimate_proving_capability());
    }

    #[test]
    fn cli_args_can_differ_about_proving_capability() {
        let a = Args {
            tx_proving_capability: Some(TxProvingCapability::ProofCollection),
            ..Default::default()
        };
        let b = Args {
            tx_proving_capability: Some(TxProvingCapability::SingleProof),
            ..Default::default()
        };
        assert_ne!(a.proving_capability(), b.proving_capability());
    }

    #[test]
    fn cli_args_default_network_agrees_with_enum_default() {
        assert_eq!(Args::default().network, Network::default());
    }

    #[test]
    fn relay_transaction_unit_test() {
        let cli = Args::default();
        assert!(
            !cli.relay_transaction(
                1,
                NativeCurrencyAmount::zero(),
                TransactionProofQuality::ProofCollection
            ),
            "proof-collection backed transaction not paying fee is not relayed"
        );
        assert!(
            cli.relay_transaction(
                1,
                NativeCurrencyAmount::coins(1),
                TransactionProofQuality::ProofCollection
            ),
            "proof-collection backed transaction paying a high fee is relayed"
        );
        assert!(
            cli.relay_transaction(
                1,
                NativeCurrencyAmount::coins(1),
                TransactionProofQuality::SingleProof
            ),
            "single-proof backed transaction paying a high fee is relayed"
        );
        assert!(
            !cli.relay_transaction(
                300,
                NativeCurrencyAmount::coins(1000),
                TransactionProofQuality::ProofCollection
            ),
            "proof-collection transaction with too many inputs is never relayed."
        );
        assert!(
            !cli.relay_transaction(
                u64::MAX,
                NativeCurrencyAmount::coins(1000),
                TransactionProofQuality::ProofCollection
            ),
            "No crash on overflow"
        );
    }

    #[test]
    fn test_parse_range() {
        macro_rules! assert_range_eq {
            ($left:expr, $right:expr) => {{
                let left = $left;
                let right = $right;
                assert_eq!(
                    left.start_bound(),
                    right.start_bound(),
                    "Range start values are not equal"
                );
                match (left.end_bound(), right.end_bound()) {
                    (std::ops::Bound::Excluded(a), std::ops::Bound::Included(b)) => {
                        assert_eq!(a, &(b + 1))
                    }
                    (std::ops::Bound::Included(a), std::ops::Bound::Excluded(b)) => {
                        assert_eq!(&(a + 1), b)
                    }
                    (a, b) => assert_eq!(a, b),
                }
            }};
        }

        assert_range_eq!(5u64..10, parse_range("5..10").unwrap());
        assert_range_eq!(5u64..=5, parse_range("5..=5").unwrap());
        assert_range_eq!(5u64..=10, parse_range("5..=10").unwrap());
        assert_range_eq!(0..10u64, parse_range("..10").unwrap());
        assert_range_eq!(0..=10u64, parse_range("..=10").unwrap());
        assert_range_eq!(5u64..=u64::MAX, parse_range("5..").unwrap());
        assert_range_eq!(0u64..=u64::MAX, parse_range("..").unwrap());

        assert_range_eq!(5u64..10, parse_range("5:10").unwrap());
        assert_range_eq!(5u64..=u64::MAX, parse_range("5:").unwrap());
        assert_range_eq!(0u64..10, parse_range(":10").unwrap());
        assert_range_eq!(0u64..=u64::MAX, parse_range(":").unwrap());
    }
}
