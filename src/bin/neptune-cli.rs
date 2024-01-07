use anyhow::{bail, Result};
use clap::{CommandFactory, Parser};
use clap_complete::{generate, Shell};

use neptune_core::config_models::network::Network;
use neptune_core::models::blockchain::transaction::amount::Amount;
use neptune_core::models::state::wallet::address::generation_address;
use std::net::IpAddr;
use std::net::SocketAddr;
use tarpc::{client, context, tokio_serde::formats::Json};

use neptune_core::models::state::wallet::wallet_status::WalletStatus;
use neptune_core::rpc_server::RPCClient;
use std::io::stdout;
use twenty_first::shared_math::digest::Digest;

#[derive(Debug, Parser)]
enum Command {
    /// Dump shell completions.
    Completions,

    /******** READ STATE ********/
    Network,
    OwnListenAddressForPeers,
    OwnInstanceId,
    BlockHeight,
    Confirmations,
    PeerInfo,
    AllSanctionedPeers,
    TipDigest,
    LatestTipDigests {
        n: usize,
    },
    TipHeader,
    Header {
        hash: Digest,
    },
    SyncedBalance,
    WalletStatus,
    OwnReceivingAddress,
    MempoolTxCount,
    MempoolSize,

    /******** CHANGE STATE ********/
    Shutdown,
    ClearAllStandings,
    ClearStandingByIp {
        ip: IpAddr,
    },
    Send {
        amount: Amount,
        address: String,
        fee: Amount,
    },
    PauseMiner,
    RestartMiner,
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

    // Check for completions command before establishing server connection.
    if let Command::Completions = args.command {
        if let Some(shell) = Shell::from_env() {
            generate(shell, &mut Config::command(), "neptune-cli", &mut stdout());
            return Ok(());
        } else {
            bail!("Unknown shell.  Shell completions not available.")
        }
    }

    let transport = tarpc::serde_transport::tcp::connect(args.server_addr, Json::default);
    let client = RPCClient::new(client::Config::default(), transport.await?).spawn();
    let ctx = context::current();

    match args.command {
        Command::Completions => {} // handled before server connection.

        /******** READ STATE ********/
        Command::Network => {
            let network = client.network(ctx).await?;
            println!("{network}")
        }
        Command::OwnListenAddressForPeers => {
            let own_listen_addres = client.own_listen_address_for_peers(ctx).await?;
            match own_listen_addres {
                Some(addr) => println!("{addr}"),
                None => println!("No listen address configured"),
            }
        }
        Command::OwnInstanceId => {
            let val = client.own_instance_id(ctx).await?;
            println!("{val}")
        }
        Command::BlockHeight => {
            let block_height = client.block_height(ctx).await?;
            println!("Block height: {}", block_height)
        }
        Command::Confirmations => {
            let val = client.confirmations(ctx).await?;
            match val {
                Some(confs) => println!("{confs}"),
                None => println!("Wallet has not received any ingoing transactions yet"),
            }
        }
        Command::PeerInfo => {
            let peers = client.peer_info(ctx).await?;
            println!("{} connected peers", peers.len());
            println!("{}", serde_json::to_string(&peers)?);
        }
        Command::AllSanctionedPeers => {
            let peer_sanctions = client.all_sanctioned_peers(ctx).await?;
            for (ip, sanction) in peer_sanctions {
                let standing = sanction.standing;
                let latest_sanction_str = match sanction.latest_sanction {
                    Some(sanction) => sanction.to_string(),
                    None => String::default(),
                };
                println!(
                    "{ip}\nstanding: {standing}\nlatest sanction: {} \n\n",
                    latest_sanction_str
                );
            }
        }
        Command::TipDigest => {
            let head_hash = client.tip_digest(ctx).await?;
            println!("{}", head_hash);
        }
        Command::LatestTipDigests { n } => {
            let head_hashes = client.latest_tip_digests(ctx, n).await?;
            for hash in head_hashes {
                println!("{hash}");
            }
        }
        Command::TipHeader => {
            let val = client.tip_header(ctx).await?;
            println!("{val}")
        }
        Command::Header { hash } => {
            let res = client.header(ctx, hash).await?;
            if res.is_none() {
                println!("Block did not exist in database.");
            } else {
                println!("{}", res.unwrap());
            }
        }
        Command::SyncedBalance => {
            let val = client.synced_balance(ctx).await?;
            println!("{val}");
        }
        Command::WalletStatus => {
            let wallet_status: WalletStatus = client.wallet_status(ctx).await?;
            println!("{}", wallet_status)
        }
        Command::OwnReceivingAddress => {
            let rec_addr: generation_address::ReceivingAddress =
                client.own_receiving_address(ctx).await?;
            println!("{}", rec_addr.to_bech32m(args.network).unwrap())
        }
        Command::MempoolTxCount => {
            let count: usize = client.mempool_tx_count(ctx).await?;
            println!("{}", count);
        }
        Command::MempoolSize => {
            let size_in_bytes: usize = client.mempool_size(ctx).await?;
            println!("{} bytes", size_in_bytes);
        }

        /******** CHANGE STATE ********/
        Command::Shutdown => {
            println!("Sending shutdown-command.");
            client.shutdown(ctx).await?;
            println!("Shutdown-command completed successfully.");
        }
        Command::ClearAllStandings => {
            client.clear_all_standings(ctx).await?;
            println!("Cleared all standings.");
        }
        Command::ClearStandingByIp { ip } => {
            client.clear_standing_by_ip(ctx, ip).await?;
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

            client.send(ctx, amount, receiving_address, fee).await?;
            println!("Send-command issues. Recipient: {address}; amount: {amount}");
        }
        Command::PauseMiner => {
            println!("Sending command to pause miner.");
            client.pause_miner(ctx).await?;
            println!("Command completed successfully");
        }
        Command::RestartMiner => {
            println!("Sending command to restart miner.");
            client.restart_miner(ctx).await?;
            println!("Command completed successfully");
        }

        Command::PruneAbandonedMonitoredUtxos => {
            let prunt_res_count = client.prune_abandoned_monitored_utxos(ctx).await?;
            println!("{prunt_res_count} monitored UTXOs marked as abandoned");
        }
    }

    Ok(())
}
