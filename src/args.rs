use std::net::IpAddr;
use structopt::StructOpt;

/// See the [structopt
/// documentation](https://docs.rs/structopt/0.3.21/structopt) for more
/// information.
#[derive(Debug, StructOpt)]
#[structopt(name = "neptune-core", about = "A Sea of Freedom")]
pub struct Args {
    /// Set mining argument to participate in competitive mining
    #[structopt(short, long)]
    pub mine: bool,

    /// Port on which to listen for connections
    #[structopt(short, long, default_value = "9798")]
    pub port: u16,

    /// IP on which to listen for connections
    #[structopt(short, long, default_value = "127.0.0.1")]
    pub listen_addr: IpAddr,

    /// IPs of nodes to connect to, e.g.: --node-ips 8.8.8.8 --node-ips 8.8.4.4
    #[structopt(short, long)]
    pub node_ips: Vec<std::net::IpAddr>,

    /// Set this argument to connect to testnet
    #[structopt(long)]
    pub testnet: bool,
}
