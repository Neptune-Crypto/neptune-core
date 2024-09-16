use std::io;
use std::io::stdout;
use std::io::Read;
use std::io::Write;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Result;
use clap::CommandFactory;
use clap::Parser;
use clap::Subcommand;
use clap_complete::generate;
use clap_complete::Shell;
use itertools::EitherOrBoth;
use itertools::Itertools;
use neptune_core::config_models::data_directory::DataDirectory;
use neptune_core::config_models::network::Network;
use neptune_core::models::blockchain::block::block_selector::BlockSelector;
use neptune_core::models::blockchain::transaction::OwnedUtxoNotifyMethod;
use neptune_core::models::blockchain::transaction::TxParams;
use neptune_core::models::blockchain::transaction::UnownedUtxoNotifyMethod;
use neptune_core::models::blockchain::transaction::UtxoNotification;
use neptune_core::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
use neptune_core::models::state::wallet::address::KeyType;
use neptune_core::models::state::wallet::address::ReceivingAddress;
use neptune_core::models::state::wallet::coin_with_possible_timelock::CoinWithPossibleTimeLock;
use neptune_core::models::state::wallet::wallet_status::WalletStatus;
use neptune_core::models::state::wallet::WalletSecret;
use neptune_core::models::state::TxOutputMeta;
use neptune_core::rpc_server::RPCClient;
use serde::Deserialize;
use serde::Serialize;
use tarpc::client;
use tarpc::context;
use tarpc::tokio_serde::formats::Json;

const SELF: &str = "self";
const ANONYMOUS: &str = "anonymous";

/// for parsing SendToMany `<output>` arguments.
#[derive(Debug, Clone)]
struct TransactionOutput {
    address: String,
    amount: NeptuneCoins,
    recipient: String,
}

/// We impl FromStr deserialization so that clap can parse the --outputs arg of
/// send-to-many command.
///
/// We do not bother with serialization via `impl Display` because that is
/// not presently needed and would just be unused code.
impl FromStr for TransactionOutput {
    type Err = anyhow::Error;

    /// parses address:amount:recipient or address:amount into TransactionOutput{address, amount, recipient}
    ///
    /// This is used by the outputs arg of send-to-many command.  Usage looks
    /// like:
    ///
    ///     <OUTPUTS>...  format: address:amount address:amount:recipient ...
    ///
    /// So each output is space delimited and the 2 (or 3) fields are colon
    /// delimited.
    ///
    /// if `recipient` is omitted for any output, then it defaults to
    /// "anonymous".
    ///
    /// This format was chosen because it should be simple for humans to
    /// generate on the command-line.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts = s.split(':').collect::<Vec<_>>();

        if parts.len() != 2 && parts.len() != 3 {
            anyhow::bail!("Invalid transaction output.  missing :")
        }

        Ok(Self {
            address: parts[0].to_string(),
            amount: NeptuneCoins::from_str(parts[1])?,
            recipient: match parts.len() {
                3 if !parts[2].trim().is_empty() => parts[2].trim(),
                _ => ANONYMOUS,
            }
            .to_string(),
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
pub enum AddressEnum {
    Generation {
        address_abbrev: String,
        address: String,
        receiver_identifier: String,
    },
    Symmetric {
        receiver_identifier: String,
    },
}
impl TryFrom<(&ReceivingAddress, Network)> for AddressEnum {
    type Error = anyhow::Error;

    fn try_from(v: (&ReceivingAddress, Network)) -> Result<Self> {
        let (addr, network) = v;
        Ok(match *addr {
            ReceivingAddress::Generation(_) => Self::Generation {
                address_abbrev: addr.to_bech32m_abbreviated(network)?,
                address: addr.to_bech32m(network)?,
                receiver_identifier: addr.receiver_identifier().to_string(),
            },
            ReceivingAddress::Symmetric(_) => Self::Symmetric {
                receiver_identifier: addr.receiver_identifier().to_string(),
            },
        })
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
pub struct UtxoTransferEntry {
    pub data_format: String,
    pub recipient: String,
    pub amount: String,
    pub utxo_transfer_encrypted: String,
    pub address_info: AddressEnum,
}

impl UtxoTransferEntry {
    fn data_format() -> String {
        "neptune-utxo-transfer-v1.0".to_string()
    }
}

/// represents data format of input to claim-utxo
#[derive(Debug, Clone, Subcommand)]
pub enum ClaimUtxoFormat {
    /// reads utxo-transfer-encrypted field of the utxo-transfer json file.
    Raw {
        /// will be read from stdin if not present
        raw: Option<String>,
    },
    /// reads contents of a utxo-transfer json file
    Json {
        /// will be read from stdin if not present
        json: Option<String>,
    },
    /// reads a utxo-transfer json file
    File {
        /// path to the file
        path: PathBuf,
    },
}

/// represents cli command
#[derive(Debug, Clone, Parser)]
enum Command {
    /// Dump shell completions.
    Completions,

    /******** READ STATE ********/
    /// retrieve network that neptune-core is running on
    Network,

    /// retrieve address for peers to contact this neptune-core node
    OwnListenAddressForPeers,

    /// retrieve instance-id of this neptune-core node
    OwnInstanceId,

    /// retrieve current block height
    BlockHeight,

    /// retrieve information about a block
    BlockInfo {
        /// one of: `genesis, tip, height/<n>, digest/<hex>`
        block_selector: BlockSelector,
    },

    /// retrieve confirmations
    Confirmations,

    /// retrieve info about peers
    PeerInfo,

    /// retrieve list of sanctioned peers
    AllSanctionedPeers,

    /// retrieve digest/hash of newest block
    TipDigest,

    /// retrieve digests of newest n blocks
    LatestTipDigests { n: usize },

    /// retrieve block-header of any block
    Header {
        /// one of: `genesis, tip, height/<n>, digest/<hex>`
        block_selector: BlockSelector,
    },

    /// retrieve confirmed balance
    SyncedBalance,

    /// retrieve wallet status information
    WalletStatus,

    /// retrieve next unused receiving address
    NextReceivingAddress {
        #[clap(value_enum, default_value_t = KeyType::Generation)]
        key_type: KeyType,
    },

    /// list known coins
    ListCoins,

    /// retrieve count of transactions in the mempool
    MempoolTxCount,

    /// retrieve size of mempool in bytes (in RAM)
    MempoolSize,

    /******** CHANGE STATE ********/
    /// shutdown neptune-core
    Shutdown,

    /// clear all peer standings
    ClearAllStandings,

    /// clear peer standing for a given IP address
    ClearStandingByIp { ip: IpAddr },

    /// send to a single recipient
    Send {
        /// recipient's address
        address: String,

        /// amount to send
        amount: NeptuneCoins,

        /// transaction fee
        fee: NeptuneCoins,

        /// recipient name or label, for local usage only
        #[clap(value_parser = clap::builder::NonEmptyStringValueParser::new(), default_value = ANONYMOUS)]
        recipient: String,

        /// how to notify our wallet of utxos.
        #[clap(long, value_enum, default_value_t)]
        owned_utxo_notify_method: OwnedUtxoNotifyMethod,

        /// how to notify recipient's wallet of utxos.
        #[clap(long, value_enum, default_value_t)]
        unowned_utxo_notify_method: UnownedUtxoNotifyMethod,
    },

    /// send to multiple recipients
    SendToMany {
        /// transaction outputs. format: address:amount:recipient address:amount ...
        ///
        /// recipient is a local-only label and will be "anonymous" if omitted.
        #[clap(value_parser, num_args = 1.., required=true, value_delimiter = ' ')]
        outputs: Vec<TransactionOutput>,

        /// transaction fee
        fee: NeptuneCoins,

        /// how to notify our wallet of utxos.
        #[clap(long, value_enum, default_value_t)]
        owned_utxo_notify_method: OwnedUtxoNotifyMethod,

        /// how to notify recipient's wallet(s) of utxos.
        #[clap(long, value_enum, default_value_t)]
        unowned_utxo_notify_method: UnownedUtxoNotifyMethod,
    },
    /// claim an off-chain utxo-transfer.
    ClaimUtxo {
        #[clap(subcommand)]
        format: ClaimUtxoFormat,
    },

    /// pause mining
    PauseMiner,

    /// resume mining
    RestartMiner,

    /// prune monitored utxos from abandoned chains
    PruneAbandonedMonitoredUtxos,

    /******** WALLET ********/
    /// generate a new wallet
    GenerateWallet {
        #[clap(long, default_value_t)]
        network: Network,

        /// neptune-core data directory containing wallet and blockchain state
        #[clap(long)]
        data_dir: Option<PathBuf>,
    },
    /// displays path to wallet secrets file
    WhichWallet {
        #[clap(long, default_value_t)]
        network: Network,

        /// neptune-core data directory containing wallet and blockchain state
        #[clap(long)]
        data_dir: Option<PathBuf>,
    },
    /// export mnemonic seed phrase
    ExportSeedPhrase {
        #[clap(long, default_value_t)]
        network: Network,

        /// neptune-core data directory containing wallet and blockchain state
        #[clap(long)]
        data_dir: Option<PathBuf>,
    },
    /// import mnemonic seed phrase
    ImportSeedPhrase {
        #[clap(long, default_value_t)]
        network: Network,

        /// neptune-core data directory containing wallet and blockchain state
        #[clap(long)]
        data_dir: Option<PathBuf>,
    },
}

/// represents top-level cli args
#[derive(Debug, Clone, Parser)]
#[clap(name = "neptune-cli", about = "An RPC client")]
struct Config {
    /// Sets the server address to connect to.
    #[clap(long, default_value = "127.0.0.1:9799")]
    server_addr: SocketAddr,

    #[clap(subcommand)]
    command: Command,
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
        Command::WhichWallet { network, data_dir } => {
            let wallet_dir = DataDirectory::get(data_dir, network)?.wallet_directory_path();

            // Get wallet object, create various wallet secret files
            let wallet_file = WalletSecret::wallet_secret_path(&wallet_dir);
            if !wallet_file.exists() {
                bail!("No wallet file found at {}.", wallet_file.display());
            } else {
                println!("{}", wallet_file.display());
            }
            return Ok(());
        }
        Command::GenerateWallet { network, data_dir } => {
            let wallet_dir = DataDirectory::get(data_dir, network)?.wallet_directory_path();

            // Get wallet object, create various wallet secret files
            DataDirectory::create_dir_if_not_exists(&wallet_dir).await?;

            let (_, secret_file_paths) = WalletSecret::read_from_file_or_create(&wallet_dir)?;

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
        Command::ImportSeedPhrase { network, data_dir } => {
            let wallet_dir = DataDirectory::get(data_dir, network)?.wallet_directory_path();
            let wallet_file = WalletSecret::wallet_secret_path(&wallet_dir);

            // if the wallet file already exists,
            if wallet_file.exists() {
                bail!(
                    "Cannot import seed phrase; wallet file {} already exists. Move it to another location (or remove it) to import a seed phrase.",
                    wallet_file.display()
                );
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
                    bail!("Invalid seed phrase.");
                }
                Ok(ws) => ws,
            };

            // wallet file does not exist yet, so create it and save
            println!("Saving wallet to disk at {} ...", wallet_file.display());
            DataDirectory::create_dir_if_not_exists(&wallet_dir).await?;
            match wallet_secret.save_to_disk(&wallet_file) {
                Err(e) => {
                    bail!("Could not save imported wallet to disk. {e}");
                }
                Ok(_) => {
                    println!("Success.");
                }
            }

            return Ok(());
        }
        Command::ExportSeedPhrase { network, data_dir } => {
            // The root path is where both the wallet and all databases are stored
            let wallet_dir = DataDirectory::get(data_dir, network)?.wallet_directory_path();

            // Get wallet object, create various wallet secret files
            let wallet_file = WalletSecret::wallet_secret_path(&wallet_dir);
            if !wallet_file.exists() {
                bail!(
                    concat!("Cannot export seed phrase because there is no wallet.dat file to export from.\n",
                    "Generate one using `neptune-cli generate-wallet` or `neptune-wallet-gen`, or import a seed phrase using `neptune-cli import-seed-phrase`.")
                );
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

    match args.clone().command {
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
        Command::Header { block_selector } => match client.header(ctx, block_selector).await? {
            Some(header) => println!("{}", header),
            None => println!("Block did not exist in database."),
        },
        Command::SyncedBalance => {
            let val = client.synced_balance(ctx).await?;
            println!("{val}");
        }
        Command::WalletStatus => {
            let wallet_status: WalletStatus = client.wallet_status(ctx).await?;
            println!("{}", serde_json::to_string_pretty(&wallet_status)?);
        }
        Command::NextReceivingAddress { key_type } => {
            let rec_addr = client.next_receiving_address(ctx, key_type).await?;
            println!("{}", rec_addr.to_bech32m(client.network(ctx).await?)?)
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
            address,
            amount,
            fee,
            recipient,
            owned_utxo_notify_method,
            unowned_utxo_notify_method,
        } => {
            // Parse on client
            let data_dir = client.data_directory(ctx).await?;
            let network = client.network(ctx).await?;
            let receiving_address = ReceivingAddress::from_bech32m(&address, network)?;
            let parsed_outputs = vec![(receiving_address, amount)];
            let recipients = vec![recipient];

            let (tx_params, tx_output_meta) = client
                .generate_tx_params(
                    ctx,
                    parsed_outputs.clone(),
                    fee,
                    owned_utxo_notify_method,
                    unowned_utxo_notify_method,
                )
                .await?
                .map_err(|s| anyhow!(s))?;

            let tx_digest = client
                .send(ctx, tx_params.clone())
                .await?
                .map_err(|s| anyhow!(s))?;

            process_utxo_notifications(&data_dir, network, tx_params, tx_output_meta, recipients)?;
            println!("Send completed. Tx Digest: {}", tx_digest.to_hex());
        }
        Command::SendToMany {
            outputs,
            fee,
            owned_utxo_notify_method,
            unowned_utxo_notify_method,
        } => {
            let data_dir = client.data_directory(ctx).await?;
            let network = client.network(ctx).await?;
            let parsed_outputs = outputs
                .iter()
                .map(|o| o.to_receiving_address_amount_tuple(network))
                .collect::<Result<Vec<_>>>()?;

            let (tx_params, tx_output_meta) = client
                .generate_tx_params(
                    ctx,
                    parsed_outputs.clone(),
                    fee,
                    owned_utxo_notify_method,
                    unowned_utxo_notify_method,
                )
                .await?
                .map_err(|s| anyhow!(s))?;

            let tx_digest = client
                .send(ctx, tx_params.clone())
                .await?
                .map_err(|s| anyhow!(s))?;

            let recipients = outputs.into_iter().map(|o| o.recipient).collect_vec();
            process_utxo_notifications(&data_dir, network, tx_params, tx_output_meta, recipients)?;
            println!("Send completed. Tx Digest: {}", tx_digest.to_hex());
        }
        Command::ClaimUtxo { format } => {
            let utxo_transfer_encrypted = match format {
                ClaimUtxoFormat::Raw { raw } => val_or_stdin_line(raw)?,
                ClaimUtxoFormat::File { path } => {
                    let buf = std::fs::read_to_string(path)?;
                    let utxo_transfer_entry: UtxoTransferEntry = serde_json::from_str(&buf)?;
                    utxo_transfer_entry.utxo_transfer_encrypted
                }
                ClaimUtxoFormat::Json { json } => {
                    let buf = val_or_stdin(json)?;
                    let utxo_transfer_entry: UtxoTransferEntry = serde_json::from_str(&buf)?;
                    utxo_transfer_entry.utxo_transfer_encrypted
                }
            };
            client
                .claim_utxo(ctx, utxo_transfer_encrypted)
                .await?
                .map_err(|s| anyhow!(s))?;

            println!("Success.  1 Utxo Transfer was imported.");
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
    tx_params: TxParams,
    tx_output_meta: Vec<TxOutputMeta>,
    recipients: Vec<String>,
) -> anyhow::Result<()> {
    assert_eq!(tx_params.tx_output_list().len(), tx_output_meta.len());
    assert!(tx_output_meta.len() >= recipients.len());

    let data_dir = root_data_dir.utxo_transfer_directory_path();

    // find off-chain-serialized outputs and add metadata
    // (address, label, owner-type)
    let mut entries = tx_params
        .tx_output_list()
        .iter()
        .zip(tx_output_meta)
        .zip_longest(recipients)
        .map(|pair| match pair {
            EitherOrBoth::Both((o, m), r) => (o, m, r),
            EitherOrBoth::Left((o, m)) => (o, m, SELF.to_string()),
            EitherOrBoth::Right(_) => unreachable!(),
        })
        .filter_map(|(o, m, recipient)| match &o.utxo_notification {
            UtxoNotification::OffChainSerialized(x) => Some((
                m.receiving_address,
                o.utxo.get_native_currency_amount(),
                x,
                match m.self_owned {
                    true => SELF.to_string(),
                    false => recipient,
                },
            )),
            _ => None,
        })
        .peekable();

    if entries.peek().is_some() {
        // create utxo-transfer dir if not existing
        std::fs::create_dir_all(&data_dir)?;

        println!("\n*** Utxo Transfer Files ***\n");
    }

    // write out one UtxoTransferEntry in a json file, per output
    let mut wrote_file_cnt = 0usize;
    for (address, amount, utxo_transfer_encrypted, recipient) in entries {
        let file_dir = data_dir.join(&recipient);
        std::fs::create_dir_all(&file_dir)?;

        let entry = UtxoTransferEntry {
            data_format: UtxoTransferEntry::data_format(),
            recipient: recipient.clone(),
            amount: amount.to_string(),
            utxo_transfer_encrypted: utxo_transfer_encrypted.to_bech32m(network)?,
            address_info: (&address, network).try_into()?,
        };

        let mut file_name = format!("{}-{}.json", entry.address_info.short_id(), entry.amount);
        let file_path = (1..)
            .filter_map(|i| {
                let path = file_dir.join(&file_name);
                file_name = format!("{}-{}.{}.json", recipient, entry.amount, i);
                match path.exists() {
                    false => Some(path),
                    true => None,
                }
            })
            .next()
            .ok_or_else(|| anyhow!("could not determine file path"))?;

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

// retrieves value from Option or else from first line of stdin (trimmed).
fn val_or_stdin_line<T: std::fmt::Display>(val: Option<T>) -> Result<String> {
    match val {
        Some(v) => Ok(v.to_string()),
        None => {
            let mut buffer = String::new();
            std::io::stdin().read_line(&mut buffer)?;
            Ok(buffer.trim().to_string())
        }
    }
}

// retrieves value from Option or else from stdin (trimmed).
fn val_or_stdin<T: std::fmt::Display>(val: Option<T>) -> Result<String> {
    match val {
        Some(v) => Ok(v.to_string()),
        None => {
            let mut buffer = String::new();
            std::io::stdin().read_to_string(&mut buffer)?;
            Ok(buffer.trim().to_string())
        }
    }
}
