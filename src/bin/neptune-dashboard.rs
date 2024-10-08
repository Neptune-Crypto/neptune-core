use std::net::Ipv4Addr;
use std::net::SocketAddr;

use anyhow::bail;
use anyhow::Result;
use clap::Parser;
use dashboard_src::dashboard_app::DashboardApp;
use neptune_core::rpc_server::RPCClient;
use tarpc::client;
use tarpc::context;
use tarpc::tokio_serde::formats::Json;

pub mod dashboard_src;

#[derive(Debug, Parser, Clone)]
#[clap(name = "neptune-dashboard", about = "Terminal user interface")]
pub struct Config {
    /// Sets the server address to connect to.
    #[clap(long, default_value = "9799", value_name = "PORT")]
    port: u16,
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
            bail!(
                "Connection to neptune-core failed. Is a node running?  Or is the client still \
                starting up?"
            );
        }
    };
    let client = RPCClient::new(client::Config::default(), transport).spawn();

    // Read what network the client is running and ensure that client is up and running
    let network = match client.network(context::current()).await {
        Ok(nw) => nw,
        Err(err) => {
            eprintln!("{err}");
            bail!(
                "Could not ping neptune-core. Do configurations match? Or is the client still \
                starting up?"
            );
        }
    };

    let listen_addr_for_peers = match client
        .own_listen_address_for_peers(context::current())
        .await
    {
        Ok(la) => la,
        Err(err) => {
            eprintln!("{err}");
            bail!("Could not get listen address from client.");
        }
    };

    // run app until quit
    let res = DashboardApp::run(client, network, listen_addr_for_peers).await;

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
