use super::network::Network;
use bytesize::ByteSize;
use clap::builder::RangedI64ValueParser;
use clap::Parser;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

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
    /// For a list of reasons that cause bad standing, see <MISSING>.
    #[clap(long, default_value = "50", value_name = "VALUE")]
    pub peer_tolerance: u16,

    /// Maximum number of peers to accept connections from.
    ///
    /// Will not prevent outgoing connections made with `--peers`.
    #[clap(long, default_value = "8", value_name = "COUNT")]
    pub max_peers: u16,

    /// Should this node participate in competitive mining?
    ///
    /// Mining is disabled by default.
    #[clap(long)]
    pub mine: bool,

    /// Prune the mempool when it exceeds this size in RAM.
    ///
    /// Units: B (bytes), K (kilobytes), M (megabytes), G (gigabytes)
    ///
    /// E.g. --max-mempool-size 500M
    #[clap(long, default_value = "1G", value_name = "SIZE")]
    pub max_mempool_size: ByteSize,

    /// Prune the pool of UTXO notification when it exceeds this size in RAM.
    ///
    /// Units: B (bytes), K (kilobytes), M (megabytes), G (gigabytes)
    ///
    /// E.g. --max-utxo-notification-size 50M
    #[clap(long, default_value = "10M", value_name = "SIZE")]
    pub max_utxo_notification_size: ByteSize,

    /// Port on which to listen for peer connections.
    #[clap(long, default_value = "9798", value_name = "PORT")]
    pub peer_port: u16,

    /// Port on which to listen for RPC connections.
    #[clap(long, default_value = "9799", value_name = "PORT")]
    pub rpc_port: u16,

    /// IP on which to listen for peer connections.
    #[clap(short, long, default_value = "127.0.0.1")]
    pub listen_addr: IpAddr,

    /// Max number of blocks that the client can catch up to before going into syncing mode.
    ///
    /// The process running this program should have access to at least the number of blocks
    /// in this field multiplied with the max block size amounts of RAM. Probably 1.5 to 2 times
    /// that amount.
    /// #[clap(value_parser(RangedI64ValueParser::new().range(foo..bar)))]
    #[clap(long, default_value = "500", value_parser(RangedI64ValueParser::<usize>::new().range(10..100000)))]
    pub max_number_of_blocks_before_syncing: usize,

    /// IPs of nodes to connect to, e.g.: --peers 8.8.8.8:9798 --peers 8.8.4.4:1337.
    #[structopt(long)]
    pub peers: Vec<SocketAddr>,

    /// Specify network, `main`, `testnet`, or `regtest`
    #[structopt(long, short, default_value = "main")]
    pub network: Network,

    /// Max number of membership proofs stored per owned UTXO
    #[structopt(long, default_value = "3")]
    pub number_of_mps_per_utxo: usize,
}

impl Args {
    pub fn get_own_listen_address(&self) -> Option<SocketAddr> {
        // TODO: Should this function return Option<SocketAddr> or SocketAddr?
        Some(SocketAddr::new(self.listen_addr, self.peer_port))
    }
}

impl Default for Args {
    fn default() -> Self {
        let empty: Vec<String> = vec![];
        Self::parse_from(empty)
    }
}

#[cfg(test)]
mod cli_args_tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn default_args_test() {
        let default_args = Args::default();

        assert_eq!(50, default_args.peer_tolerance);
        assert_eq!(8, default_args.max_peers);
        assert_eq!(9798, default_args.peer_port);
        assert_eq!(9799, default_args.rpc_port);
        assert_eq!(Ipv4Addr::new(127, 0, 0, 1), default_args.listen_addr);
    }
}
