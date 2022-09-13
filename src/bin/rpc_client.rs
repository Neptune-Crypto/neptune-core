use anyhow::Result;
use clap::Parser;
use neptune_core::models::blockchain::transaction::utxo::Utxo;
use neptune_core::rpc_server::RPCClient;
use num_bigint::BigUint;
use std::net::IpAddr;
use std::net::SocketAddr;
use tarpc::{client, context, tokio_serde::formats::Json};
use tracing_subscriber::{EnvFilter, FmtSubscriber};

#[derive(Debug, Parser)]
enum Command {
    BlockHeight,
    GetPeerInfo,
    Head,
    Heads { n: usize },
    ClearAllStandings,
    ClearIpStanding { ip: IpAddr },
    Send { unparsed_send_argument: String },
    Shutdown,
    Balance,
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
            println!("Block height: {}", block_height);
        }
        Command::GetPeerInfo => {
            let peers = client.get_peer_info(context::current()).await?;
            println!("{} connected peers", peers.len());
            println!("{}", serde_json::to_string(&peers)?);
        }
        Command::Head => {
            let head_hash = client.head(context::current()).await?;
            println!("{}", head_hash);
        }
        Command::Heads { n } => {
            let head_hashes = client.heads(context::current(), n).await?;
            for hash in head_hashes {
                println!("{}", hash);
            }
        }
        Command::ClearAllStandings => {
            client.clear_all_standings(context::current()).await?;
            println!("Cleared all standings.");
        }
        Command::ClearIpStanding { ip } => {
            client.clear_ip_standing(context::current(), ip).await?;
            println!("Cleared standing of {}", ip);
        }
        Command::Send {
            unparsed_send_argument,
        } => {
            // Parse on client
            let utxos = tracing::debug_span!("Parsing TxSpec")
                .in_scope(|| serde_json::from_str::<Vec<Utxo>>(&unparsed_send_argument))
                .unwrap();

            client.send(context::current(), utxos.clone()).await?;
            println!("Send-command issued with argument: {:?}.", utxos);
        }
        Command::Shutdown => {
            println!("Sending shutdown-command.");
            client.shutdown(context::current()).await?;
            println!("Shutdown-command completed successfully.");
        }

        Command::Balance => {
            println!("Sending balance-command.");
            let balance: BigUint = client.get_balance(context::current()).await?.into();
            println!("Balance received:");
            println!("{}", balance);
        }
    }

    Ok(())
}
