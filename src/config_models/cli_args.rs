use std::net::IpAddr;
use std::net::SocketAddr;
use std::path::PathBuf;

use bytesize::ByteSize;
use clap::builder::RangedI64ValueParser;
use clap::Parser;
use num_traits::Zero;

use super::network::Network;
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
    pub data_dir: Option<PathBuf>,

    /// Ban connections to this node from IP address.
    ///
    /// This node can still make outgoing connections to IP address.
    ///
    /// To do this, see `--peers`.
    ///
    /// E.g.: --ban 1.2.3.4 --ban 5.6.7.8
    #[clap(long, value_name = "IP")]
    pub ban: Vec<IpAddr>,

    /// Refuse connection if peer is in bad standing.
    ///
    /// This sets the threshold for when a peer should be automatically refused.
    ///
    /// For a list of reasons that cause bad standing, see [PeerSanctionReason](crate::models::peer::PeerSanctionReason).
    #[clap(long, default_value = "100", value_name = "VALUE")]
    pub peer_tolerance: u16,

    /// Maximum number of peers to accept connections from.
    ///
    /// Will not prevent outgoing connections made with `--peers`.
    /// Set this value to 0 to refuse all incoming connections.
    #[clap(long, default_value = "10", value_name = "COUNT")]
    pub max_peers: u16,

    /// Should this node participate in competitive mining?
    ///
    /// Mining is disabled by default.
    #[clap(long)]
    pub mine: bool,

    /// If mining, use all available CPU power. Ignored if mine flag not set.
    #[clap(long)]
    pub unrestricted_mining: bool,

    /// Prune the mempool when it exceeds this size in RAM.
    ///
    /// Units: B (bytes), K (kilobytes), M (megabytes), G (gigabytes)
    ///
    /// E.g. --max-mempool-size 500M
    #[clap(long, default_value = "1G", value_name = "SIZE")]
    pub max_mempool_size: ByteSize,

    /// Maximum number of transactions permitted in the mempool.
    ///
    /// If too much time is spent updating transaction proofs, this
    /// value can be capped.
    ///
    /// E.g. --max-mempool-num-tx=4
    #[clap(long)]
    pub max_mempool_num_tx: Option<usize>,

    /// Port on which to listen for peer connections.
    #[clap(long, default_value = "9798", value_name = "PORT")]
    pub peer_port: u16,

    /// Port on which to listen for RPC connections.
    #[clap(long, default_value = "9799", value_name = "PORT")]
    pub rpc_port: u16,

    /// IP on which to listen for peer connections. Will default to all network interfaces, IPv4 and IPv6.
    #[clap(short, long, default_value = "::")]
    pub listen_addr: IpAddr,

    /// Max number of blocks that the client can catch up to before going into syncing mode.
    ///
    /// The process running this program should have access to at least the number of blocks
    /// in this field multiplied with the max block size amounts of RAM. Probably 1.5 to 2 times
    /// that amount.
    #[clap(long, default_value = "100", value_parser(RangedI64ValueParser::<usize>::new().range(2..100000)))]
    pub max_number_of_blocks_before_syncing: usize,

    /// IPs of nodes to connect to, e.g.: --peers 8.8.8.8:9798 --peers 8.8.4.4:1337.
    #[structopt(long)]
    pub peers: Vec<SocketAddr>,

    /// Specify network, `alpha`, `testnet`, or `regtest`
    #[structopt(long, short, default_value = "alpha")]
    pub network: Network,

    /// Max number of membership proofs stored per owned UTXO
    #[structopt(long, default_value = "3")]
    pub number_of_mps_per_utxo: usize,

    /// Configure how complicated proofs this machine is capable of producing.
    /// If no value is set, this parameter is estimated. For privacy, this level
    /// must not be set to [`TxProvingCapability::LockScript`], as this leaks
    /// information about amounts and input/output UTXOs.
    /// Proving the lockscripts is mandatory, since this is what prevents others
    /// from spending your coins.
    /// e.g. `--tx-proving-capability=singleproof` or
    /// `--tx-proving-capability=proofcollection`.
    #[clap(long)]
    pub tx_proving_capability: Option<TxProvingCapability>,

    /// Enable tokio tracing for consumption by the tokio-console application
    /// note: this will attempt to connect to localhost:6669
    #[structopt(long, name = "tokio-console", default_value = "false")]
    pub tokio_console: bool,
}

impl Default for Args {
    fn default() -> Self {
        let empty: Vec<String> = vec![];
        Self::parse_from(empty)
    }
}

impl Args {
    /// Indicates if all incoming peer connections are disallowed.
    pub(crate) fn disallow_all_incoming_peer_connections(&self) -> bool {
        self.max_peers.is_zero()
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
}

#[cfg(test)]
mod cli_args_tests {
    use std::net::Ipv6Addr;

    use super::*;

    #[test]
    fn default_args_test() {
        let default_args = Args::default();

        assert_eq!(100, default_args.peer_tolerance);
        assert_eq!(10, default_args.max_peers);
        assert_eq!(9798, default_args.peer_port);
        assert_eq!(9799, default_args.rpc_port);
        assert_eq!(
            IpAddr::from(Ipv6Addr::UNSPECIFIED),
            default_args.listen_addr
        );
        assert_eq!(None, default_args.max_mempool_num_tx);
    }

    #[test]
    fn max_peers_0_means_no_incoming_connections() {
        let args = Args {
            max_peers: 0,
            ..Default::default()
        };
        assert!(args.disallow_all_incoming_peer_connections());
    }
}
