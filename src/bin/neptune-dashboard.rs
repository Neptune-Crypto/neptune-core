/// A simple example demonstrating how to handle user input. This is
/// a bit out of the scope of the library as it does not provide any
/// input handling out of the box. However, it may helps some to get
/// started.
///
/// This is a very simple example:
///   * A input box always focused. Every character you type is registered
///   here
///   * Pressing Backspace erases a character
///   * Pressing Enter pushes the current input in the history of previous
///   messages
///
use anyhow::{bail, Result};
use clap::Parser;

use dashboard_src::dashboard_app::DashboardApp;
use neptune_core::{config_models::network::Network, rpc_server::RPCClient};
use std::net::{Ipv4Addr, SocketAddr};
use tarpc::{client, context};
use tokio_serde::formats::Json;

pub mod dashboard_src;

#[derive(Debug, Parser, Clone)]
#[clap(name = "neptune-dashboard", about = "Terminal user interface")]
pub struct Config {
    /// Sets the server address to connect to.
    #[clap(long, default_value = "9799", value_name = "PORT")]
    port: u16,
    #[structopt(long, short, default_value = "main")]
    pub network: Network,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Create connection to RPC server
    let args: Config = Config::parse();
    let server_socket = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), args.port);
    let transport = tarpc::serde_transport::tcp::connect(server_socket, Json::default).await;
    let transport = match transport {
        Ok(transp) => transp,
        Err(err) => {
            eprintln!("{err}");
            bail!("Connection to neptune-core failed. Is a node running?");
        }
    };
    let client = RPCClient::new(client::Config::default(), transport).spawn();

    // Block height functions as our ping endpoint
    let ping = client.block_height(context::current()).await;
    match ping {
        Ok(_pong) => {}
        Err(err) => {
            eprintln!("{err}");
            bail!("Could not ping neptune-core. Do configurations match?");
        }
    }

    // run app until quit
    let res = DashboardApp::run(client, args).await;

    match res {
        Err(err) => {
            println!("{:?}", err);
        }
        Ok(output) => {
            print!("{}", output);
        }
    }

    Ok(())
}
