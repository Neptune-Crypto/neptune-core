use anyhow::{bail, Result};
use clap::{CommandFactory, Parser};
use clap_complete::{generate, Shell};
use neptune_core::config_models::data_directory::DataDirectory;
use neptune_core::config_models::network::Network;
use neptune_core::models::blockchain::block::block_selector::BlockSelector;
use neptune_core::models::blockchain::transaction::UtxoNotifyMethod;
use neptune_core::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
use neptune_core::models::state::wallet::address::KeyType;
use neptune_core::models::state::wallet::address::ReceivingAddressType;
use neptune_core::models::state::wallet::coin_with_possible_timelock::CoinWithPossibleTimeLock;
use neptune_core::models::state::wallet::wallet_status::WalletStatus;
use neptune_core::models::state::wallet::WalletSecret;
use neptune_core::rpc_server::RPCClient;
use std::io;
use std::io::stdout;
use std::io::Write;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::str::FromStr;
use tarpc::{client, context, tokio_serde::formats::Json};

// for parsing SendToMany <output> arguments.
#[derive(Debug, Clone)]
struct TransactionOutput {
    address: String,
    amount: NeptuneCoins,
}

/// We impl FromStr deserialization so that clap can parse the --outputs arg of
/// send-to-many command.
///
/// We do not bother with serialization via `impl Display` because that is
/// not presently needed and would just be unused code.
impl FromStr for TransactionOutput {
    type Err = anyhow::Error;

    /// parses address:amount into TransactionOutput{address, amount}
    ///
    /// This is used by the outputs arg of send-to-many command.
    /// Usage looks like:
    ///
    ///     <OUTPUTS>...  format: address:amount address:amount ...
    ///
    /// So each output is space delimited and the two fields are
    /// colon delimted.
    ///
    /// This format was chosen because it should be simple for humans
    /// to generate on the command-line.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts = s.split(':').collect::<Vec<_>>();

        if parts.len() != 2 {
            anyhow::bail!("Invalid transaction output.  missing :")
        }

        Ok(Self {
            address: parts[0].to_string(),
            amount: NeptuneCoins::from_str(parts[1])?,
        })
    }
}

impl TransactionOutput {
    pub fn to_receiving_address_amount_tuple(
        &self,
        network: Network,
    ) -> Result<(ReceivingAddressType, NeptuneCoins)> {
        Ok((
            ReceivingAddressType::from_bech32m(&self.address, network)?,
            self.amount,
        ))
    }
}

#[derive(Debug, Parser)]
enum Command {
    /// Dump shell completions.
    Completions,

    /******** READ STATE ********/
    Network,
    OwnListenAddressForPeers,
    OwnInstanceId,
    BlockHeight,
    BlockInfo {
        /// one of: `genesis, tip, height/<n>, digest/<hex>`
        block_selector: BlockSelector,
    },
    Confirmations,
    PeerInfo,
    AllSanctionedPeers,
    TipDigest,
    LatestTipDigests {
        n: usize,
    },
    TipHeader,
    Header {
        /// one of: `genesis, tip, height/<n>, digest/<hex>`
        block_selector: BlockSelector,
    },
    SyncedBalance,
    WalletStatus,
    OwnReceivingAddress,
    ListCoins,
    MempoolTxCount,
    MempoolSize,

    /******** CHANGE STATE ********/
    Shutdown,
    ClearAllStandings,
    ClearStandingByIp {
        ip: IpAddr,
    },
    Send {
        amount: NeptuneCoins,
        address: String,
        fee: NeptuneCoins,
    },
    SendToMany {
        /// format: address:amount address:amount ...
        #[clap(value_parser, num_args = 1.., required=true, value_delimiter = ' ')]
        outputs: Vec<TransactionOutput>,
        fee: NeptuneCoins,
    },
    PauseMiner,
    RestartMiner,
    PruneAbandonedMonitoredUtxos,

    /******** WALLET ********/
    GenerateWallet {
        #[clap(long, default_value_t=Network::default())]
        network: Network,
    },
    WhichWallet {
        #[clap(long, default_value_t=Network::default())]
        network: Network,
    },
    ExportSeedPhrase {
        #[clap(long, default_value_t=Network::default())]
        network: Network,
    },
    ImportSeedPhrase {
        #[clap(long, default_value_t=Network::default())]
        network: Network,
    },
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

    // Handle commands that don't require a server
    match args.command {
        Command::Completions => {
            if let Some(shell) = Shell::from_env() {
                generate(shell, &mut Config::command(), "neptune-cli", &mut stdout());
                return Ok(());
            } else {
                bail!("Unknown shell.  Shell completions not available.")
            }
        }
        Command::WhichWallet { network } => {
            // The root path is where both the wallet and all databases are stored
            let data_dir = DataDirectory::get(None, network)?;

            // Get wallet object, create various wallet secret files
            let wallet_dir = data_dir.wallet_directory_path();
            let wallet_file = WalletSecret::wallet_secret_path(&wallet_dir);
            if !wallet_file.exists() {
                println!("No wallet file found at {}.", wallet_file.display());
            } else {
                println!("{}", wallet_file.display());
            }
            return Ok(());
        }
        Command::GenerateWallet { network } => {
            // The root path is where both the wallet and all databases are stored
            let data_dir = DataDirectory::get(None, network)?;

            // Get wallet object, create various wallet secret files
            let wallet_dir = data_dir.wallet_directory_path();
            DataDirectory::create_dir_if_not_exists(&wallet_dir).await?;

            let (_, secret_file_paths) =
                WalletSecret::read_from_file_or_create(&wallet_dir).unwrap();

            println!(
                "Wallet stored in: {}\nMake sure you also see this path if you run the neptune-core client",
                secret_file_paths.wallet_secret_path.display()
            );

            println!(
                "To display the seed phrase, run `{} export-seed-phrase`.",
                std::env::args().next().unwrap()
            );

            return Ok(());
        }
        Command::ImportSeedPhrase { network } => {
            // The root path is where both the wallet and all databases are stored
            let data_dir = DataDirectory::get(None, network)?;
            let wallet_dir = data_dir.wallet_directory_path();
            let wallet_file = WalletSecret::wallet_secret_path(&wallet_dir);

            // if the wallet file already exists,
            if wallet_file.exists() {
                println!(
                    "Cannot import seed phrase; wallet file {} already exists. Move it to another location (or remove it) to import a seed phrase.",
                    wallet_file.display()
                );
                return Ok(());
            }

            // read seed phrase from user input
            println!("Importing seed phrase. Please enter words:");
            let mut phrase = vec![];
            let mut i = 1;
            loop {
                print!("{}. ", i);
                io::stdout().flush()?;
                let mut buffer = "".to_string();
                std::io::stdin()
                    .read_line(&mut buffer)
                    .expect("Cannot accept user input.");
                let word = buffer.trim();
                if bip39::Language::English
                    .wordlist()
                    .get_words_by_prefix("")
                    .iter()
                    .any(|s| *s == word)
                {
                    phrase.push(word.to_string());
                    i += 1;
                    if i > 18 {
                        break;
                    }
                } else {
                    println!("Did not recognize word \"{}\"; please try again.", word);
                }
            }
            let wallet_secret = match WalletSecret::from_phrase(&phrase) {
                Err(_) => {
                    println!("Invalid seed phrase. Please try again.");
                    return Ok(());
                }
                Ok(ws) => ws,
            };

            // wallet file does not exist yet, so create it and save
            println!("Saving wallet to disk at {} ...", wallet_file.display());
            DataDirectory::create_dir_if_not_exists(&wallet_dir).await?;
            match wallet_secret.save_to_disk(&wallet_file) {
                Err(e) => {
                    println!("Could not save imported wallet to disk.");
                    println!("Error:");
                    println!("{e}");
                }
                Ok(_) => {
                    println!("Success.");
                }
            }

            return Ok(());
        }
        Command::ExportSeedPhrase { network } => {
            // The root path is where both the wallet and all databases are stored
            let data_dir = DataDirectory::get(None, network)?;

            // Get wallet object, create various wallet secret files
            let wallet_dir = data_dir.wallet_directory_path();
            let wallet_file = WalletSecret::wallet_secret_path(&wallet_dir);
            if !wallet_file.exists() {
                println!(
                    "Cannot export seed phrase because there is no wallet.dat file to export from."
                );
                println!("Generate one using `neptune-cli generate-wallet` or `neptune-wallet-gen`, or import a seed phrase using `neptune-cli import-seed-phrase`.");
                return Ok(());
            }
            let wallet_secret = match WalletSecret::read_from_file(&wallet_file) {
                Err(e) => {
                    println!("Could not export seed phrase.");
                    println!("Error:");
                    println!("{e}");
                    return Ok(());
                }
                Ok(result) => result,
            };
            for (i, word) in wallet_secret.to_phrase().into_iter().enumerate() {
                println!("{}. {word}", i + 1);
            }
            return Ok(());
        }
        _ => {}
    }

    // all other operations need a connection to the server
    let transport = tarpc::serde_transport::tcp::connect(args.server_addr, Json::default);
    let client = RPCClient::new(client::Config::default(), transport.await?).spawn();
    let ctx = context::current();

    match args.command {
        Command::Completions
        | Command::GenerateWallet { .. }
        | Command::WhichWallet { .. }
        | Command::ExportSeedPhrase { .. }
        | Command::ImportSeedPhrase { .. } => unreachable!("Case should be handled earlier."),

        /******** READ STATE ********/
        Command::ListCoins => {
            let list = client.list_own_coins(ctx).await?;
            println!("{}", CoinWithPossibleTimeLock::report(&list));
        }
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
        Command::BlockInfo { block_selector } => {
            let data = client.block_info(ctx, block_selector).await?;
            match data {
                Some(block_info) => println!("{}", block_info),
                None => println!("Not found"),
            }
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
            let head_hash = client
                .block_digest(ctx, BlockSelector::Tip)
                .await?
                .unwrap_or_default();
            println!("{}", head_hash);
        }
        Command::LatestTipDigests { n } => {
            let head_hashes = client.latest_tip_digests(ctx, n).await?;
            for hash in head_hashes {
                println!("{hash}");
            }
        }
        Command::TipHeader => {
            let val = client
                .header(ctx, BlockSelector::Tip)
                .await?
                .expect("Tip header should be found");
            println!("{val}")
        }
        Command::Header { block_selector } => {
            let res = client.header(ctx, block_selector).await?;
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
            println!("{}", serde_json::to_string_pretty(&wallet_status)?);
        }
        Command::OwnReceivingAddress => {
            let rec_addr = client
                .next_receiving_address(ctx, KeyType::Generation)
                .await?;
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
            let receiving_address = ReceivingAddressType::from_bech32m(&address, args.network)?;

            client
                .send(
                    ctx,
                    amount,
                    receiving_address,
                    UtxoNotifyMethod::OnChain,
                    fee,
                )
                .await?;
            println!("Send completed.");
        }
        Command::SendToMany { outputs, fee } => {
            let parsed_outputs = outputs
                .into_iter()
                .map(|o| o.to_receiving_address_amount_tuple(args.network))
                .collect::<Result<Vec<_>>>()?;

            client
                .send_to_many(ctx, parsed_outputs, UtxoNotifyMethod::OnChain, fee)
                .await?;
            println!("Send completed.");
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
