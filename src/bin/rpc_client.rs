use anyhow::Result;
use clap::Parser;
use neptune_core::rpc_server::RPCClient;
use std::net::IpAddr;
use std::net::SocketAddr;
use tarpc::{client, context, tokio_serde::formats::Json};
use tracing::info_span;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

#[derive(Debug, Parser)]
enum Command {
    BlockHeight,
    GetPeerInfo,
    Head,
    ClearAllStandings,
    ClearIpStanding { ip: IpAddr },
    Send { send_argument: String },
}

#[derive(Debug, Parser)]
#[clap(name = "neptune-core-rpc", about = "An RPC client")]
struct Config {
    /// Sets the server address to connect to.
    #[clap(long)]
    server_addr: SocketAddr,
    #[clap(subcommand)]
    command: Command,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Config = Config::from_args();
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
        Command::Head => {
            let head_hash = client.head(context::current()).await?;
            tracing::info!("{}", head_hash);
        }
        Command::ClearAllStandings => {
            client.clear_all_standings(context::current()).await?;
            tracing::info!("Cleared all standings.");
        }
        Command::ClearIpStanding { ip } => {
            client.clear_ip_standing(context::current(), ip).await?;
            tracing::info!("Cleared standing of {}", ip);
        }
        Command::Send { send_argument } => {
            // Only proceed if the input string is valid JSON
            let _v: Vec<serde_json::Value> = info_span!("Validating TXSPEC object as JSON")
                .in_scope(|| serde_json::from_str(&send_argument))?;

            client
                .send(context::current(), send_argument.clone())
                .await?;
            tracing::debug!("Send-command issued with argument: {}.", send_argument);
        }
    }

    Ok(())
}
