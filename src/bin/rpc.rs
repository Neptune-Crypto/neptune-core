use anyhow::Result;
use neptune_core::rpc::RPCClient;
use std::net::SocketAddr;
use structopt::StructOpt;
use tarpc::{client, context, tokio_serde::formats::Json};
use tracing_subscriber::{EnvFilter, FmtSubscriber};

#[derive(Debug, StructOpt)]
enum Command {
    BlockHeight,
    GetPeerInfo,
}

#[derive(Debug, StructOpt)]
#[structopt(name = "neptune-core-rpc", about = "An RPC client")]
struct Config {
    /// Sets the server address to connect to.
    #[structopt(long)]
    server_addr: SocketAddr,
    #[structopt(subcommand)]
    command: Command,
}

#[paw::main]
#[tokio::main]
async fn main(args: Config) -> Result<()> {
    let subscriber = FmtSubscriber::builder()
        .with_timer(tracing_subscriber::fmt::time::UtcTime::rfc_3339())
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_thread_ids(true)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .map_err(|_err| eprintln!("Unable to set global default subscriber"))
        .expect("Failed to set log subscriber");

    let transport = tarpc::serde_transport::tcp::connect(args.server_addr, Json::default);

    let client = RPCClient::new(client::Config::default(), transport.await?).spawn();

    match args.command {
        Command::BlockHeight => {
            let block_height = client.block_height(context::current()).await?;
            tracing::info!("Block height: {}", block_height);
        }
        Command::GetPeerInfo => {
            let peers = client.get_peer_info(context::current()).await?;
            tracing::info!("{} connected peers", peers.len());
            tracing::info!("{}", serde_json::to_string(&peers)?);
        }
    }

    Ok(())
}
