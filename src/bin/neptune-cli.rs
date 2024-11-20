use std::io;
use std::io::stdout;
use std::io::Write;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Result;
use clap::CommandFactory;
use clap::Parser;
use clap::Subcommand;
use clap_complete::generate;
use clap_complete::Shell;
use neptune_core::config_models::data_directory::DataDirectory;
use neptune_core::config_models::network::Network;
use neptune_core::models::blockchain::block::block_selector::BlockSelector;
use neptune_core::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
use neptune_core::models::state::wallet::address::KeyType;
use neptune_core::models::state::wallet::address::ReceivingAddress;
use neptune_core::models::state::wallet::coin_with_possible_timelock::CoinWithPossibleTimeLock;
use neptune_core::models::state::wallet::transaction_output::PrivateNotificationData;
use neptune_core::models::state::wallet::transaction_output::UtxoNotificationMedium;
use neptune_core::models::state::wallet::wallet_status::WalletStatus;
use neptune_core::models::state::wallet::WalletSecret;
use neptune_core::rpc_server::RPCClient;
use serde::Deserialize;
use serde::Serialize;
use tarpc::client;
use tarpc::context;
use tarpc::tokio_serde::formats::Json;

const SELF: &str = "self";
const ANONYMOUS: &str = "anonymous";

// for parsing SendToMany <output> arguments.
#[derive(Debug, Clone)]
struct TransactionOutput {
    address: String,
    amount: NeptuneCoins,
}

/// represents data format of input to claim-utxo
#[derive(Debug, Clone, Subcommand)]
enum ClaimUtxoFormat {
    /// reads a utxo-transfer json file
    File {
        /// path to the file
        path: PathBuf,
    },
}

/// AddressEnum is used by send and send-to-many to distinguish between
/// key-types when writing utxo-transfer file(s) for any off-chain-serialized
/// utxos.
///
/// the issue is that it is useful to display the address in the file, or even an
/// abbreviation in the filename. This aids the sender in identifying the utxo
/// and routing it to the intended recipient.
///
/// however this should never be done for symmetric keys as it would expose the
/// private key, so we only display the receiver_identifier.
///
/// normally unowned utxo-transfer would not be using symmetric keys, however
/// there are some use cases for it such as when a person or org holds multiple
/// wallets and is transferrng between them.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum AddressEnum {
    Generation {
        address_abbrev: String,
        address: String,
        receiver_identifier: String,
    },
    Symmetric {
        receiver_identifier: String,
    },
}

impl AddressEnum {
    fn new(addr: ReceivingAddress, network: Network) -> Self {
        match addr {
            ReceivingAddress::Generation(addr) => Self::Generation {
                address_abbrev: addr
                    .to_bech32m_abbreviated(network)
                    .expect("Must be able to convert to abbreviated Bech32"),
                address: addr
                    .to_bech32m(network)
                    .expect("Bech32m encoding must succeed"),
                receiver_identifier: addr.receiver_identifier.to_string(),
            },
            ReceivingAddress::Symmetric(_) => Self::Symmetric {
                receiver_identifier: addr.receiver_identifier().to_string(),
            },
        }
    }
}

impl AddressEnum {
    fn short_id(&self) -> &str {
        match *self {
            Self::Generation {
                ref address_abbrev, ..
            } => address_abbrev,
            Self::Symmetric {
                ref receiver_identifier,
                ..
            } => receiver_identifier,
        }
    }
}

/// represents a UtxoTransfer entry in a utxo-transfer file.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct UtxoTransferEntry {
    pub data_format: String,
    pub recipient: String,
    pub ciphertext: String,
    pub address_info: AddressEnum,
}

impl UtxoTransferEntry {
    fn data_format() -> String {
        "neptune-utxo-transfer-v1.0".to_string()
    }
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
    ) -> Result<(ReceivingAddress, NeptuneCoins)> {
        Ok((
            ReceivingAddress::from_bech32m(&self.address, network)?,
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
    AllPunishedPeers,
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
    SyncedBalanceUnconfirmed,
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
    /// claim an off-chain utxo-transfer.
    ClaimUtxo {
        #[clap(subcommand)]
        format: ClaimUtxoFormat,

        /// Indicates how many blocks to look back in case the UTXO was already
        /// mined.
        max_search_depth: Option<u64>,
    },
    Send {
        address: String,
        amount: NeptuneCoins,
        fee: NeptuneCoins,

        /// local tag for identifying a receiver
        receiver_tag: String,
        notify_self: UtxoNotificationMedium,
        notify_other: UtxoNotificationMedium,
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
        Command::AllPunishedPeers => {
            let peer_sanctions = client.all_punished_peers(ctx).await?;
            for (ip, sanction) in peer_sanctions {
                let standing = sanction.standing;
                let latest_sanction_str = match sanction.latest_punishment {
                    Some((sanction, _timestamp)) => sanction.to_string(),
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
        Command::SyncedBalanceUnconfirmed => {
            let val = client.synced_balance_unconfirmed(ctx).await?;
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
        Command::ClaimUtxo {
            format,
            max_search_depth,
        } => {
            let ciphertext = match format {
                ClaimUtxoFormat::File { path } => {
                    let buf = std::fs::read_to_string(path)?;
                    let utxo_transfer_entry: UtxoTransferEntry = serde_json::from_str(&buf)?;
                    utxo_transfer_entry.ciphertext
                }
            };

            client
                .claim_utxo(ctx, ciphertext, max_search_depth)
                .await?
                .map_err(|s| anyhow!(s))?;

            println!("Success.  1 Utxo Transfer was imported.");
        }
        Command::Send {
            address,
            amount,
            fee,
            receiver_tag,
            notify_self,
            notify_other,
        } => {
            // Parse on client
            let receiving_address = ReceivingAddress::from_bech32m(&address, args.network)?;
            let network = client.network(ctx).await?;
            let root_dir = DataDirectory::get(None, network)?;

            let resp = client
                .send(
                    ctx,
                    amount,
                    receiving_address,
                    notify_self,
                    notify_other,
                    fee,
                )
                .await?;
            let Some((txid, private_notifications)) = resp else {
                eprintln!("Failed to create transaction. Please check the log.");
                bail!("Failed to create transaction. Please check the log.");
            };

            println!("Successfully created transaction: {txid}");

            process_utxo_notifications(
                &root_dir,
                network,
                private_notifications,
                Some(receiver_tag),
            )?
        }
        Command::SendToMany { outputs, fee } => {
            let parsed_outputs = outputs
                .into_iter()
                .map(|o| o.to_receiving_address_amount_tuple(args.network))
                .collect::<Result<Vec<_>>>()?;

            let res = client
                .send_to_many(
                    ctx,
                    parsed_outputs,
                    UtxoNotificationMedium::OnChain,
                    UtxoNotificationMedium::OnChain,
                    fee,
                )
                .await?;
            match res {
                Some((txid, _offchain_notifications)) => {
                    println!("Successfully created transaction: {txid}")
                }
                None => println!("Failed to create transaction. Please check the log."),
            }
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

// processes utxo-notifications in TxParams outputs, if any.
//
// 1. find off-chain-serialized outputs and add metadata
//    (address, label, owner-type)
// 2. create utxo-transfer dir if not existing
// 3. write out one UtxoTransferEntry in a json file, per output
// 4. provide instructions for sender and receiver. (if needed)
fn process_utxo_notifications(
    root_data_dir: &DataDirectory,
    network: Network,
    private_notifications: Vec<PrivateNotificationData>,
    receiver_tag: Option<String>,
) -> anyhow::Result<()> {
    let data_dir = root_data_dir.utxo_transfer_directory_path();

    if !private_notifications.is_empty() {
        // create utxo-transfer dir if not existing
        std::fs::create_dir_all(&data_dir)?;

        println!("\n*** Utxo Transfer Files ***\n");
    }

    // TODO: It would be better if this timestamp was read from the created
    // transaction.
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();

    // write out one UtxoTransferEntry in a json file, per output
    let mut wrote_file_cnt = 0usize;
    for entry in private_notifications {
        let receiver_tag = if entry.owned {
            SELF.to_owned()
        } else {
            receiver_tag.clone().unwrap_or(ANONYMOUS.to_owned())
        };
        let file_dir = data_dir.join(&receiver_tag);
        std::fs::create_dir_all(&file_dir)?;

        let entry = UtxoTransferEntry {
            data_format: UtxoTransferEntry::data_format(),
            recipient: entry
                .recipient_address
                .to_bech32m(network)
                .expect("String encoding of address must succeed"),
            ciphertext: entry.ciphertext,
            address_info: AddressEnum::new(entry.recipient_address, network),
        };

        let file_name = format!("{}-{}.json", entry.address_info.short_id(), timestamp);
        let file_path = file_dir.join(&file_name);
        println!("creating file: {}", file_path.to_string_lossy());
        let file = std::fs::File::create_new(&file_path)?;
        let mut writer = std::io::BufWriter::new(file);
        serde_json::to_writer_pretty(&mut writer, &entry)?;
        writer.flush()?;

        wrote_file_cnt += 1;

        println!("wrote {}", file_path.display());
    }

    // provide instructions for sender and receiver. (if needed)
    if wrote_file_cnt > 0 {
        println!("\n*** Important - Read or risk losing funds ***\n");
        println!(
            "
{wrote_file_cnt} transaction outputs were each written to individual files for off-chain transfer.
-- Sender Instructions --
You must transfer each file to the corresponding recipient for claiming or they will never be able to claim the funds.
You should also provide them the following recipient instructions.
-- Recipient Instructions --
run `neptune-cli claim-utxo file <file>` or use equivalent claim functionality of your chosen wallet software.
"
        );
    }

    Ok(())
}
