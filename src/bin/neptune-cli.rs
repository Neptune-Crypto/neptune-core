use anyhow::Result;
use clap::Parser;

use neptune_core::config_models::network::Network;
use neptune_core::models::blockchain::transaction::amount::Amount;
use neptune_core::models::state::wallet::address::generation_address;
use num_bigint::BigUint;
use std::net::IpAddr;
use std::net::SocketAddr;
use tarpc::{client, context, tokio_serde::formats::Json};

use neptune_core::models::state::wallet::wallet_status::WalletStatus;
use neptune_core::rpc_server::RPCClient;
use twenty_first::shared_math::digest::Digest;

#[derive(Debug, Parser)]
enum Command {
    BlockHeight,
    GetPeerInfo,
    Head,
    Heads {
        n: usize,
    },
    GetHeader {
        hash: Digest,
    },
    ClearAllStandings,
    ClearIpStanding {
        ip: IpAddr,
    },
    Send {
        amount: Amount,
        address: String,
        fee: Amount,
    },
    Shutdown,
    SyncedBalance,
    WalletStatus,
    GetReceivingAddress,
    MempoolTxCount,
    MempoolSize,
    PruneAbandonedMonitoredUtxos,
}

#[derive(Debug, Parser)]
#[clap(name = "neptune-cli", about = "An RPC client")]
struct Config {
    /// Sets the server address to connect to.
    #[clap(long, default_value = "127.0.0.1:9799")]
    server_addr: SocketAddr,

    #[clap(subcommand)]
    command: Command,

    #[structopt(long, short, default_value = "alpha")]
    pub network: Network,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Config = Config::parse();
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
        Command::GetHeader { hash } => {
            let res = client.get_header(context::current(), hash).await?;
            if res.is_none() {
                println!("Block did not exist in database.");
            } else {
                println!("{}", res.unwrap());
            }
        }
        Command::Head => {
            let head_hash = client.head(context::current()).await?;
            println!("{}", head_hash);
        }
        Command::Heads { n } => {
            if n > 0 {
                let head_hashes = client.heads(context::current(), n).await?;
                for hash in head_hashes {
                    println!("{}", hash);
                }
            } else {
                println!("You asked for zero hashes, so here they are:");
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
            amount,
            address,
            fee,
        } => {
            // Parse on client
            let receiving_address =
                generation_address::ReceivingAddress::from_bech32m(address.clone(), args.network)?;

            client
                .send(context::current(), amount, receiving_address, fee)
                .await?;
            println!("Send-command issues. Recipient: {address}; amount: {amount}");
        }
        Command::Shutdown => {
            println!("Sending shutdown-command.");
            client.shutdown(context::current()).await?;
            println!("Shutdown-command completed successfully.");
        }

        Command::SyncedBalance => {
            let balance: BigUint = client
                .get_synced_balance(context::current())
                .await?
                .0
                .into();
            println!("{}", balance);
        }

        Command::WalletStatus => {
            let wallet_status: WalletStatus = client.get_wallet_status(context::current()).await?;
            println!("{}", wallet_status)
        }

        Command::GetReceivingAddress => {
            let rec_addr: generation_address::ReceivingAddress =
                client.get_receiving_address(context::current()).await?;
            println!("{}", rec_addr.to_bech32m(args.network).unwrap())
        }

        Command::MempoolTxCount => {
            let count: usize = client.get_mempool_tx_count(context::current()).await?;
            println!("{}", count);
        }

        Command::MempoolSize => {
            let size_in_bytes: usize = client.get_mempool_size(context::current()).await?;
            println!("{} bytes", size_in_bytes);
        }

        Command::PruneAbandonedMonitoredUtxos => {
            let prunt_res_count = client
                .prune_abandoned_monitored_utxos(context::current())
                .await?;
            println!("{prunt_res_count} monitored UTXOs marked as abandoned");
        }
    }

    Ok(())
}
