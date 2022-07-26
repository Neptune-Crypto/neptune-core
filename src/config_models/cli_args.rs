use super::network::Network;
use clap::builder::RangedI64ValueParser;
use clap::Parser;
use std::net::{IpAddr, SocketAddr};

/// Decalarative specification of command-line arguments
#[derive(Parser, Debug, Clone)]
#[clap(author, version, about)]
pub struct Args {
    /// List IP addresses to ban connections from. You can still make outgoing connections to these IPs by setting the `peers` argument.
    /// E.g.: --ban 1.2.3.4 --ban 5.6.7.8.
    #[clap(long)]
    pub ban: Vec<std::net::IpAddr>,

    /// Set threshhold for autobanning peers.
    #[clap(long, default_value = "50")]
    pub peer_tolerance: u16,

    /// Set maximum number of peers, will not prevent outgoing connections as specified in the `peers` argument.
    #[clap(long, default_value = "8")]
    pub max_peers: u16,

    /// Set mining argument to participate in competitive mining.
    #[clap(long)]
    pub mine: bool,

    /// Port on which to listen for peer connections.
    #[clap(long, default_value = "9798")]
    pub peer_port: u16,

    /// Port on which to listen for RPC connections.
    #[clap(long, default_value = "9799")]
    pub rpc_port: u16,

    // TODO: Should this value be Option<IpAddr> instead?
    /// IP on which to listen for peer connections.
    #[clap(short, long, default_value = "127.0.0.1")]
    pub listen_addr: IpAddr,

    /// Max number of blocks that the client can catch up to before going into syncing mode.
    /// The process running this program should have access to at least the number of blocks
    /// in this field multiplied with the max block size amounts of RAM. Probably 1.5 to 2 times
    /// that amount.
    /// #[clap(value_parser(RangedI64ValueParser::new().range(foo..bar)))]
    #[clap(long, default_value = "500", value_parser(RangedI64ValueParser::<usize>::new().range(10..100000)))]
    pub max_number_of_blocks_before_syncing: usize,

    /// IPs of nodes to connect to, e.g.: --peers 8.8.8.8:9798 --peers 8.8.4.4:1337.
    #[structopt(long)]
    pub peers: Vec<std::net::SocketAddr>,

    /// Specify network, `main`, `testnet`, or `regtest`
    #[structopt(long, short, default_value = "main")]
    pub network: Network,
}

impl Args {
    pub fn get_own_listen_address(&self) -> Option<SocketAddr> {
        // TODO: Should this function return Option<SocketAddr> or SocketAddr?
        Some(SocketAddr::new(self.listen_addr, self.peer_port))
    }
}
