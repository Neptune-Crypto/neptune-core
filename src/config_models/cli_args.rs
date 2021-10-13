use super::network::Network;
use std::net::IpAddr;
use structopt::StructOpt;

/// Decalarative specification of command-line arguments
/// See the [structopt
/// documentation](https://docs.rs/structopt/0.3.21/structopt) for more
/// information.
#[derive(Debug, StructOpt)]
#[structopt(name = "neptune-core", about = "A Sea of Freedom")]
pub struct Args {
    /// Set maximum number of peers, will not prevent outgoing connections as specified in the `peers` argument.
    #[structopt(long, default_value = "8")]
    pub max_peers: u16,

    /// Set mining argument to participate in competitive mining.
    #[structopt(short, long)]
    pub mine: bool,

    /// Port on which to listen for connections.
    #[structopt(long, default_value = "9798")]
    pub port: u16,

    /// IP on which to listen for peer connections.
    #[structopt(short, long, default_value = "127.0.0.1")]
    pub listen_addr: IpAddr,

    /// IPs of nodes to connect to, e.g.: --peers 8.8.8.8:9798 --peers 8.8.4.4:1337.
    #[structopt(long)]
    pub peers: Vec<std::net::SocketAddr>,

    /// Specify network, `main`, `testnet`, or `regtest`
    #[structopt(long, short, default_value = "main")]
    pub network: Network,
}
