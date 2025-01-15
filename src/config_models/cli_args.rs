use std::net::IpAddr;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;

use bytesize::ByteSize;
use clap::builder::RangedI64ValueParser;
use clap::Parser;
use num_traits::Zero;
use sysinfo::System;

use super::network::Network;
use crate::job_queue::triton_vm::TritonVmJobPriority;
use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
use crate::models::proof_abstractions::tasm::program::TritonVmProofJobOptions;
use crate::models::proof_abstractions::tasm::prover_job::ProverJobSettings;
use crate::models::state::tx_proving_capability::TxProvingCapability;

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
    pub(crate) data_dir: Option<PathBuf>,

    /// Ban connections to this node from IP address.
    ///
    /// This node can still make outgoing connections to IP address.
    ///
    /// To do this, see `--peers`.
    ///
    /// E.g.: --ban 1.2.3.4 --ban 5.6.7.8
    #[clap(long, value_name = "IP")]
    pub(crate) ban: Vec<IpAddr>,

    /// Refuse connection if peer is in bad standing.
    ///
    /// This sets the threshold for when a peer should be automatically refused.
    /// The default is set to 1000.
    ///
    /// For a list of reasons that cause bad standing, see [PeerSanctionReason](crate::models::peer::PeerSanctionReason).
    #[clap(long, default_value = "1000", value_name = "VALUE")]
    pub(crate) peer_tolerance: u16,

    /// Maximum number of peers to accept connections from.
    ///
    /// Will not prevent outgoing connections made with `--peers`.
    /// Set this value to 0 to refuse all incoming connections.
    #[clap(long, default_value = "10", value_name = "COUNT")]
    pub(crate) max_num_peers: u16,

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

    /// Whether to produce block proposals, which is the first step of two-step
    /// mining. Note that composing block proposals involves the computationally
    /// expensive task of producing STARK proofs. You should have plenty of
    /// cores and probably at least 128 GB of RAM.
    #[clap(long)]
    pub(crate) compose: bool,

    /// Whether to engage in guess-nonce-and-hash, which is the second step in
    /// two-step mining. If this flag is set and the `compose` flag is not set,
    /// then the client will rely on block proposals from other nodes. In this
    /// case, it will always pick the most profitable block proposal.
    ///
    /// If this flag is set and the `compose` flag is set, then the client will
    /// always guess on their own block proposal.
    #[clap(long)]
    pub(crate) guess: bool,

    /// By default, a composer will share block proposals with all peers. If
    /// this flag is set, the composer will *not* share their block proposals.
    #[clap(long)]
    pub(crate) secret_compositions: bool,

    /// Regulates the fraction of the block subsidy that goes to the guesser.
    /// Value must be between 0 and 1.
    ///
    /// The remainder goes to the composer. This flag is ignored if the
    /// `compose` flag is not set.
    #[clap(long, default_value = "0.5", value_parser = fraction_validator)]
    pub(crate) guesser_fraction: f64,

    /// Whether to sleep between nonce-guesses. Useful if you do not want to
    /// dedicate all your CPU power.
    #[clap(long)]
    pub(crate) sleepy_guessing: bool,

    /// Set the number of threads to use while guessing. When no value is set,
    /// the number is set to the number of available cores.
    #[clap(long)]
    pub(crate) guesser_threads: Option<usize>,

    /// Determines the fraction of the transaction fee consumed by this node as
    /// a reward either for upgrading a `ProofCollection` to `SingleProof`, or
    /// for merging two `SingleProof`s.
    #[clap(long, default_value = "0.2", value_parser = fraction_validator)]
    pub(crate) gobbling_fraction: f64,

    /// Determines the minimum fee to take as a reward for upgrading foreign
    /// transaction proofs. Foreign transactions where a fee below this
    /// threshold cannot be collected by proof upgrading will not be upgraded.
    #[clap(long, default_value = "0.01")]
    pub(crate) min_gobbling_fee: NeptuneCoins,

    /// Prune the mempool when it exceeds this size in RAM.
    ///
    /// Units: B (bytes), K (kilobytes), M (megabytes), G (gigabytes)
    ///
    /// E.g. --max-mempool-size 500M
    #[clap(long, default_value = "1G", value_name = "SIZE")]
    pub(crate) max_mempool_size: ByteSize,

    /// Maximum number of transactions permitted in the mempool.
    ///
    /// If too much time is spent updating transaction proofs, this
    /// value can be capped.
    ///
    /// E.g. --max-mempool-num-tx=4
    #[clap(long)]
    pub(crate) max_mempool_num_tx: Option<usize>,

    /// Port on which to listen for peer connections.
    #[clap(long, default_value = "9798", value_name = "PORT")]
    pub(crate) peer_port: u16,

    /// Port on which to listen for RPC connections.
    #[clap(long, default_value = "9799", value_name = "PORT")]
    pub(crate) rpc_port: u16,

    /// IP on which to listen for peer connections. Will default to all network interfaces, IPv4 and IPv6.
    #[clap(short, long, default_value = "::")]
    pub(crate) listen_addr: IpAddr,

    /// Max number of blocks that the client can catch up to before going into syncing mode.
    ///
    /// The process running this program should have access to at least the number of blocks
    /// in this field multiplied with the max block size amounts of RAM. Probably 1.5 to 2 times
    /// that amount.
    #[clap(long, default_value = "1000", value_parser(RangedI64ValueParser::<usize>::new().range(2..100000)))]
    pub(crate) max_number_of_blocks_before_syncing: usize,

    /// IPs of nodes to connect to, e.g.: --peers 8.8.8.8:9798 --peers 8.8.4.4:1337.
    #[structopt(long)]
    pub(crate) peers: Vec<SocketAddr>,

    /// Specify network, `alpha`, `beta`, `testnet`, or `regtest`
    #[structopt(long, default_value = "beta", short)]
    pub(crate) network: Network,

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
    pub(crate) tx_proving_capability: Option<TxProvingCapability>,

    /// Cache for the proving capability. If the above parameter is not set, we
    /// want to estimate proving capability and afterwards reuse the result from
    /// previous estimations. This argument cannot be set from CLI, so clap
    /// ignores it.
    #[clap(skip)]
    pub(crate) tx_proving_capability_cache: OnceLock<TxProvingCapability>,

    /// The number of seconds between each attempt to upgrade transactions in
    /// the mempool to proofs of a higher quality. Will only run if the machine
    /// on which the client runs is powerful enough to produce `SingleProof`s.
    ///
    /// Set to 0 to never perform this task.
    #[structopt(long, default_value = "1800")]
    pub(crate) tx_proof_upgrade_interval: u64,

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
    /// For such a machine, one would set a limit of 23.
    ///
    /// if the limit is reached while mining, a warning is logged and mining will pause.
    /// non-mining operations may panic and halt neptune-core
    ///
    /// no limit is applied if unset.
    #[structopt(long, short, value_parser = clap::value_parser!(u8).range(10..32))]
    pub(crate) max_log2_padded_height_for_proofs: Option<u8>,

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

impl Args {
    #[cfg(test)]
    pub(crate) fn default_with_network(network: Network) -> Self {
        Self {
            network,
            ..Default::default()
        }
    }

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

    /// Returns how often we should attempt to upgrade transaction proofs.
    pub(crate) fn tx_upgrade_interval(&self) -> Option<Duration> {
        match self.tx_proof_upgrade_interval {
            0 => None,
            n => Some(Duration::from_secs(n)),
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
            job_settings: ProverJobSettings {
                max_log2_padded_height_for_proofs: self.max_log2_padded_height_for_proofs,
            },
        }
    }

    /// Get the proving capability CLI argument or estimate it if it is not set.
    /// Cache the result so we don't estimate more than once.
    pub(crate) fn proving_capability(&self) -> TxProvingCapability {
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

    fn estimate_proving_capability() -> TxProvingCapability {
        const SINGLE_PROOF_CORE_REQ: usize = 19;
        const SINGLE_PROOF_MEMORY_USAGE: u64 = (1u64 << 30) * 128;
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
            TxProvingCapability::LockScript
        }
    }
}

#[cfg(test)]
mod cli_args_tests {
    use std::net::Ipv6Addr;

    use super::*;

    #[test]
    fn default_args_test() {
        let default_args = Args::default();

        assert_eq!(1000, default_args.peer_tolerance);
        assert_eq!(10, default_args.max_num_peers);
        assert_eq!(9798, default_args.peer_port);
        assert_eq!(9799, default_args.rpc_port);
        assert_eq!(
            IpAddr::from(Ipv6Addr::UNSPECIFIED),
            default_args.listen_addr
        );
        assert_eq!(None, default_args.max_mempool_num_tx);
        assert_eq!(1800, default_args.tx_proof_upgrade_interval);
    }

    #[test]
    fn sane_tx_upgrade_interval_value() {
        let args = Args {
            tx_proof_upgrade_interval: 900,
            ..Default::default()
        };
        assert_eq!(900, args.tx_upgrade_interval().unwrap().as_secs());
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
}
