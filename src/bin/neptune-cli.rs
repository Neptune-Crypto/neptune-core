use std::io;
use std::io::stdout;
use std::io::Write;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use anyhow::bail;
use anyhow::Result;
use clap::CommandFactory;
use clap::Parser;
use clap::Subcommand;
use clap_complete::generate;
use clap_complete::Shell;
use itertools::Itertools;
use neptune_cash::config_models::data_directory::DataDirectory;
use neptune_cash::config_models::network::Network;
use neptune_cash::models::blockchain::block::block_selector::BlockSelector;
use neptune_cash::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
use neptune_cash::models::state::wallet::address::KeyType;
use neptune_cash::models::state::wallet::address::ReceivingAddress;
use neptune_cash::models::state::wallet::coin_with_possible_timelock::CoinWithPossibleTimeLock;
use neptune_cash::models::state::wallet::utxo_notification::PrivateNotificationData;
use neptune_cash::models::state::wallet::utxo_notification::UtxoNotificationMedium;
use neptune_cash::models::state::wallet::wallet_status::WalletStatus;
use neptune_cash::models::state::wallet::WalletSecret;
use neptune_cash::rpc_auth;
use neptune_cash::rpc_server::error::RpcError;
use neptune_cash::rpc_server::RPCClient;
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
    Raw {
        /// The encrypted UTXO notification payload.
        ciphertext: String,
    },
}

/// represents a UtxoTransfer entry in a utxo-transfer file.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct UtxoTransferEntry {
    pub data_format: String,
    pub recipient_abbrev: String,
    pub recipient: String,
    pub ciphertext: String,
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

    /// retrieve block digests for a given block height
    BlockDigestsByHeight {
        height: u64,
    },

    /// retrieve confirmations
    Confirmations,

    /// retrieve info about peers
    PeerInfo,

    /// retrieve list of punished peers
    AllPunishedPeers,

    /// retrieve digest/hash of newest block
    TipDigest,
    LatestTipDigests {
        n: usize,
    },

    /// retrieve digests of newest n blocks
    TipHeader,

    /// retrieve block-header of any block
    Header {
        /// one of: `genesis, tip, height/<n>, digest/<hex>`
        block_selector: BlockSelector,
    },

    /// retrieve confirmed balance
    SyncedBalance,

    /// retrieve unconfirmed balance (includes unconfirmed transactions)
    SyncedBalanceUnconfirmed,

    /// retrieve wallet status information
    WalletStatus,

    /// retrieves number of utxos the wallet expects to receive.
    NumExpectedUtxos,

    /// Get next unused generation receiving address
    NextReceivingAddress,

    /// Get the nth generation receiving address.
    ///
    /// Ignoring the ones that have been generated in the past; re-generate them
    /// if necessary. Do not increment any counters or modify state in any way.
    NthReceivingAddress {
        index: usize,

        #[clap(long, default_value_t)]
        network: Network,
    },

    /// Get a static generation receiving address, for premine recipients.
    ///
    /// This command is an alias for `nth-receiving-address 0`. It will be
    /// disabled after mainnet launch.
    PremineReceivingAddress {
        #[clap(long, default_value_t)]
        network: Network,
    },

    /// list known coins
    ListCoins,

    /// retrieve count of transactions in the mempool
    MempoolTxCount,

    /// retrieve size of mempool in bytes (in RAM)
    MempoolSize,

    /******** BLOCKCHAIN STATISTICS ********/
    /// Show block intervals in milliseconds, in reverse chronological order.
    BlockIntervals {
        last_block: BlockSelector,
        max_num_blocks: Option<usize>,
    },

    /// Show mean block interval in milliseconds within the specified range.
    MeanBlockInterval {
        last_block: BlockSelector,
        max_num_blocks: Option<usize>,
    },

    /// Show biggest block interval in the specified range.
    MaxBlockInterval {
        last_block: BlockSelector,
        max_num_blocks: Option<usize>,
    },

    /// Show smallest block interval in the specified range.
    MinBlockInterval {
        last_block: BlockSelector,
        max_num_blocks: Option<usize>,
    },

    /// Show difficulties for a list of blocks.
    BlockDifficulties {
        last_block: BlockSelector,
        max_num_blocks: Option<usize>,
    },

    /// Show largest difficulty in the specified range.
    MaxBlockDifficulty {
        last_block: BlockSelector,
        max_num_blocks: Option<usize>,
    },

    /******** CHANGE STATE ********/
    /// shutdown neptune-core
    Shutdown,

    /// clear all peer standings
    ClearAllStandings,

    /// clear standings for peer with a given IP
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

    /// send a payment to a single recipient
    Send {
        /// recipient's address
        address: String,

        /// amount to send
        amount: NeptuneCoins,

        /// transaction fee
        fee: NeptuneCoins,

        /// local tag for identifying a receiver
        receiver_tag: String,
        notify_self: UtxoNotificationMedium,
        notify_other: UtxoNotificationMedium,
    },

    /// send a payment to one or more recipients
    SendToMany {
        /// format: address:amount address:amount ...
        #[clap(value_parser, num_args = 1.., required=true, value_delimiter = ' ')]
        outputs: Vec<TransactionOutput>,
        fee: NeptuneCoins,
    },

    /// pause mining
    PauseMiner,

    /// resume mining
    RestartMiner,

    /// prune monitored utxos from abandoned chains
    PruneAbandonedMonitoredUtxos,

    /******** WALLET -- offline actions ********/
    /// generate a new wallet
    GenerateWallet {
        #[clap(long, default_value_t)]
        network: Network,
    },

    /// displays path to wallet secrets file
    WhichWallet {
        #[clap(long, default_value_t)]
        network: Network,
    },

    /// export mnemonic seed phrase
    ExportSeedPhrase {
        #[clap(long, default_value_t)]
        network: Network,
    },

    /// import mnemonic seed phrase
    ImportSeedPhrase {
        #[clap(long, default_value_t)]
        network: Network,
    },
}

/// represents top-level cli args
#[derive(Debug, Clone, Parser)]
#[clap(name = "neptune-cli", about = "An RPC client")]
struct Config {
    /// Sets the server address to connect to.
    #[clap(long, default_value = "127.0.0.1:9799")]
    server_addr: SocketAddr,

    /// neptune-core data directory containing wallet and blockchain state
    #[clap(long)]
    data_dir: Option<PathBuf>,

    #[clap(subcommand)]
    command: Command,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Config = Config::parse();

    // Handle commands that don't require a server
    match &args.command {
        Command::Completions => {
            if let Some(shell) = Shell::from_env() {
                generate(shell, &mut Config::command(), "neptune-cli", &mut stdout());
                return Ok(());
            } else {
                bail!("Unknown shell.  Shell completions not available.")
            }
        }
        Command::WhichWallet { network } => {
            let wallet_dir =
                DataDirectory::get(args.data_dir.clone(), *network)?.wallet_directory_path();

            // Get wallet object, create various wallet secret files
            let wallet_file = WalletSecret::wallet_secret_path(&wallet_dir);
            if !wallet_file.exists() {
                bail!("No wallet file found at {}.", wallet_file.display());
            } else {
                println!("{}", wallet_file.display());
            }
            return Ok(());
        }
        Command::GenerateWallet { network } => {
            let wallet_dir =
                DataDirectory::get(args.data_dir.clone(), *network)?.wallet_directory_path();

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
        Command::ImportSeedPhrase { network } => {
            let wallet_dir =
                DataDirectory::get(args.data_dir.clone(), *network)?.wallet_directory_path();
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
        Command::ExportSeedPhrase { network } => {
            // The root path is where both the wallet and all databases are stored
            let wallet_dir =
                DataDirectory::get(args.data_dir.clone(), *network)?.wallet_directory_path();

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
            println!("Seed phrase for {}.", network);
            println!("Read from file `{}`.", wallet_file.display());
            for (i, word) in wallet_secret.to_phrase().into_iter().enumerate() {
                println!("{}. {word}", i + 1);
            }
            return Ok(());
        }
        Command::NthReceivingAddress { network, index } => {
            return get_nth_receiving_address(*network, args.data_dir.clone(), *index);
        }
        Command::PremineReceivingAddress { network } => {
            return get_nth_receiving_address(*network, args.data_dir.clone(), 0);
        }
        _ => {}
    }

    // all other operations need a connection to the server
    let Ok(transport) = tarpc::serde_transport::tcp::connect(args.server_addr, Json::default).await
    else {
        eprintln!("This command requires a connection to `neptune-core`, but that connection could not be established. Is `neptune-core` running?");
        return Ok(());
    };
    let client = RPCClient::new(client::Config::default(), transport).spawn();
    let ctx = context::current();

    let rpc_auth::CookieHint {
        data_directory,
        network,
    } = match get_cookie_hint(&client, &args).await {
        Ok(h) => h,
        Err(e) => {
            eprintln!("{e}");
            eprintln!(
                "Could not ping neptune-core. Do configurations match? Or is it still starting up?"
            );
            std::process::exit(1);
        }
    };

    let token: rpc_auth::Token = match rpc_auth::Cookie::try_load(&data_directory).await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Unable to load RPC auth cookie. error = {}", e);
            std::process::exit(2)
        }
    }
    .into();

    match args.command {
        Command::Completions
        | Command::GenerateWallet { .. }
        | Command::WhichWallet { .. }
        | Command::ExportSeedPhrase { .. }
        | Command::ImportSeedPhrase { .. }
        | Command::NthReceivingAddress { .. }
        | Command::PremineReceivingAddress { .. } => {
            unreachable!("Case should be handled earlier.")
        }

        /******** READ STATE ********/
        Command::ListCoins => {
            let list = client.list_own_coins(ctx, token).await??;
            println!("{}", CoinWithPossibleTimeLock::report(&list));
        }
        Command::Network => {
            // we already queries the network above.
            println!("{network}")
        }
        Command::OwnListenAddressForPeers => {
            let own_listen_addres = client.own_listen_address_for_peers(ctx, token).await??;
            match own_listen_addres {
                Some(addr) => println!("{addr}"),
                None => println!("No listen address configured"),
            }
        }
        Command::OwnInstanceId => {
            let val = client.own_instance_id(ctx, token).await??;
            println!("{val}")
        }
        Command::BlockHeight => {
            let block_height = client.block_height(ctx, token).await??;
            println!("Block height: {}", block_height)
        }
        Command::BlockInfo { block_selector } => {
            let data = client.block_info(ctx, token, block_selector).await??;
            match data {
                Some(block_info) => println!("{}", block_info),
                None => println!("Not found"),
            }
        }
        Command::BlockDigestsByHeight { height } => {
            let digests = client
                .block_digests_by_height(ctx, token, height.into())
                .await??;
            println!("{}", digests.iter().join("\n"));
        }
        Command::Confirmations => {
            let val = client.confirmations(ctx, token).await??;
            match val {
                Some(confs) => println!("{confs}"),
                None => println!("Wallet has not received any ingoing transactions yet"),
            }
        }
        Command::PeerInfo => {
            let peers = client.peer_info(ctx, token).await??;
            println!("{} connected peers", peers.len());
            println!("{}", serde_json::to_string(&peers)?);
        }
        Command::AllPunishedPeers => {
            let peer_sanctions = client.all_punished_peers(ctx, token).await??;
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
                .block_digest(ctx, token, BlockSelector::Tip)
                .await??
                .unwrap_or_default();
            println!("{}", head_hash);
        }
        Command::LatestTipDigests { n } => {
            let head_hashes = client.latest_tip_digests(ctx, token, n).await??;
            for hash in head_hashes {
                println!("{hash}");
            }
        }
        Command::TipHeader => {
            let val = client
                .header(ctx, token, BlockSelector::Tip)
                .await??
                .expect("Tip header should be found");
            println!("{val}")
        }
        Command::Header { block_selector } => {
            let res = client.header(ctx, token, block_selector).await??;
            if res.is_none() {
                println!("Block did not exist in database.");
            } else {
                println!("{}", res.unwrap());
            }
        }
        Command::SyncedBalance => {
            let val = client.synced_balance(ctx, token).await??;
            println!("{val}");
        }
        Command::SyncedBalanceUnconfirmed => {
            let val = client.synced_balance_unconfirmed(ctx, token).await??;
            println!("{val}");
        }
        Command::WalletStatus => {
            let wallet_status: WalletStatus = client.wallet_status(ctx, token).await??;
            println!("{}", serde_json::to_string_pretty(&wallet_status)?);
        }
        Command::NumExpectedUtxos => {
            let num = client.num_expected_utxos(ctx, token).await??;
            println!("Found a total of {num} expected UTXOs in the database");
        }
        Command::NextReceivingAddress => {
            let rec_addr = client
                .next_receiving_address(ctx, token, KeyType::Generation)
                .await??;
            println!("{}", rec_addr.to_display_bech32m(network).unwrap())
        }
        Command::MempoolTxCount => {
            let count: usize = client.mempool_tx_count(ctx, token).await??;
            println!("{}", count);
        }
        Command::MempoolSize => {
            let size_in_bytes: usize = client.mempool_size(ctx, token).await??;
            println!("{} bytes", size_in_bytes);
        }

        /******** BLOCKCHAIN STATISTICS ********/
        Command::BlockIntervals {
            last_block,
            max_num_blocks,
        } => {
            let data = client
                .block_intervals(ctx, token, last_block, max_num_blocks)
                .await??;
            match data {
                Some(intervals) => {
                    println!(
                        "{}",
                        intervals
                            .iter()
                            .map(|(height, interval)| format!("{height}: {interval}"))
                            .join("\n")
                    )
                }
                None => println!("Not found"),
            }
        }

        Command::MeanBlockInterval {
            last_block,
            max_num_blocks,
        } => {
            let intervals = client
                .block_intervals(ctx, token, last_block, max_num_blocks)
                .await??;
            if intervals.as_ref().is_none_or(|x| x.is_empty()) {
                println!("Not found");
                return Ok(());
            }
            let intervals = intervals.unwrap();

            let num_samples: u64 = intervals.len().try_into().unwrap();
            let mut acc = 0;
            let mut acc_squared = 0;
            for (_height, interval) in intervals {
                acc += interval;
                acc_squared += interval * interval;
            }

            let fst_moment = acc / num_samples;
            let snd_moment = acc_squared / num_samples;
            let std_dev = (snd_moment as f64).sqrt();

            println!(
                "Average block interval of specified range: {fst_moment}, std. dev: {std_dev}."
            )
        }

        Command::MaxBlockInterval {
            last_block,
            max_num_blocks,
        } => {
            let intervals = client
                .block_intervals(ctx, token, last_block, max_num_blocks)
                .await??;
            if intervals.as_ref().is_none_or(|x| x.is_empty()) {
                println!("Not found");
                return Ok(());
            }
            let intervals = intervals.unwrap();

            let (height, interval) = intervals
                .iter()
                .max_by_key(|(_height, interval)| interval)
                .unwrap();

            println!("Biggest block interval in specified range:\n{interval}ms at block height {height}.")
        }

        Command::MinBlockInterval {
            last_block,
            max_num_blocks,
        } => {
            let intervals = client
                .block_intervals(ctx, token, last_block, max_num_blocks)
                .await??;
            if intervals.as_ref().is_none_or(|x| x.is_empty()) {
                println!("Not found");
                return Ok(());
            }
            let intervals = intervals.unwrap();

            let (height, interval) = intervals
                .iter()
                .min_by_key(|(_height, interval)| interval)
                .unwrap();

            println!("Smallest block interval in specified range:\n{interval}ms at block height {height}.")
        }

        Command::BlockDifficulties {
            last_block,
            max_num_blocks,
        } => {
            let difficulties = client
                .block_difficulties(ctx, token, last_block, max_num_blocks)
                .await??;

            println!(
                "{}",
                difficulties
                    .iter()
                    .map(|(height, difficulty)| format!("{height}: {difficulty}"))
                    .join("\n")
            )
        }

        Command::MaxBlockDifficulty {
            last_block,
            max_num_blocks,
        } => {
            let difficulties = client
                .block_difficulties(ctx, token, last_block, max_num_blocks)
                .await??;
            if difficulties.is_empty() {
                println!("Not found");
                return Ok(());
            }

            let (height, difficulty) = difficulties
                .iter()
                .max_by_key(|(_height, difficulty)| difficulty)
                .unwrap();

            println!(
                "Greatest difficulty in specified range:\n{difficulty} at block height {height}."
            )
        }

        /******** CHANGE STATE ********/
        Command::Shutdown => {
            println!("Sending shutdown-command.");
            client.shutdown(ctx, token).await??;
            println!("Shutdown-command completed successfully.");
        }
        Command::ClearAllStandings => {
            client.clear_all_standings(ctx, token).await??;
            println!("Cleared all standings.");
        }
        Command::ClearStandingByIp { ip } => {
            client.clear_standing_by_ip(ctx, token, ip).await??;
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
                ClaimUtxoFormat::Raw { ciphertext } => ciphertext,
            };

            let claim_was_new = client
                .claim_utxo(ctx, token, ciphertext, max_search_depth)
                .await??;

            if claim_was_new {
                println!("Success.  1 Utxo Transfer was imported.");
            } else {
                println!("This claim has already been registered.");
            }
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
            let receiving_address = ReceivingAddress::from_bech32m(&address, network)?;

            let resp = client
                .send(
                    ctx,
                    token,
                    amount,
                    receiving_address,
                    notify_self,
                    notify_other,
                    fee,
                )
                .await?;
            let (txid, private_notifications) = match resp {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("{}", e);
                    bail!("Failed to create transaction.");
                }
            };

            println!("Successfully created transaction: {txid}");

            process_utxo_notifications(
                &data_directory,
                network,
                private_notifications,
                Some(receiver_tag),
            )?
        }
        Command::SendToMany { outputs, fee } => {
            let parsed_outputs = outputs
                .into_iter()
                .map(|o| o.to_receiving_address_amount_tuple(network))
                .collect::<Result<Vec<_>>>()?;

            let res = client
                .send_to_many(
                    ctx,
                    token,
                    parsed_outputs,
                    UtxoNotificationMedium::OnChain,
                    UtxoNotificationMedium::OnChain,
                    fee,
                )
                .await?;
            match res {
                Ok((txid, _offchain_notifications)) => {
                    println!("Successfully created transaction: {txid}")
                }
                Err(e) => eprintln!("{}", e),
            }
        }
        Command::PauseMiner => {
            println!("Sending command to pause miner.");
            client.pause_miner(ctx, token).await??;
            println!("Command completed successfully");
        }
        Command::RestartMiner => {
            println!("Sending command to restart miner.");
            client.restart_miner(ctx, token).await??;
            println!("Command completed successfully");
        }

        Command::PruneAbandonedMonitoredUtxos => {
            let prunt_res_count = client.prune_abandoned_monitored_utxos(ctx, token).await??;
            println!("{prunt_res_count} monitored UTXOs marked as abandoned");
        }
    }

    Ok(())
}

// returns result with a CookieHint{ data_directory, network }.
//
// We use the data-dir provided by user if present.
//
// Otherwise we call cookie_hint() RPC to obtain data-dir.
// But the API might be disabled, which we detect and fallback to the default data-dir.
async fn get_cookie_hint(
    client: &RPCClient,
    args: &Config,
) -> anyhow::Result<rpc_auth::CookieHint> {
    async fn fallback(client: &RPCClient, args: &Config) -> anyhow::Result<rpc_auth::CookieHint> {
        let network = client.network(context::current()).await??;
        let data_directory = DataDirectory::get(args.data_dir.clone(), network)?;
        Ok(rpc_auth::CookieHint {
            data_directory,
            network,
        })
    }

    if args.data_dir.is_some() {
        return fallback(client, args).await;
    }

    let result = client.cookie_hint(context::current()).await?;

    match result {
        Ok(hint) => Ok(hint),
        Err(RpcError::CookieHintDisabled) => fallback(client, args).await,
        Err(e) => Err(e.into()),
    }
}

/// Get the nth receiving address directly from the wallet.
///
/// Read the wallet file directly; avoid going through the RPC interface of
/// `neptune-core`.
fn get_nth_receiving_address(
    network: Network,
    data_dir: Option<PathBuf>,
    index: usize,
) -> Result<()> {
    let wallet_dir = DataDirectory::get(data_dir.clone(), network)?.wallet_directory_path();

    // Get wallet object, create various wallet secret files
    let wallet_file = WalletSecret::wallet_secret_path(&wallet_dir);
    if !wallet_file.exists() {
        bail!("No wallet file found at {}.", wallet_file.display());
    } else {
        println!("{}", wallet_file.display());
    }

    let wallet_secret = match WalletSecret::read_from_file(&wallet_file) {
        Ok(ws) => ws,
        Err(e) => {
            eprintln!(
                "Could not open wallet file at {}. Got error: {e}",
                wallet_file.to_string_lossy()
            );
            return Ok(());
        }
    };

    let nth_spending_key = wallet_secret.nth_generation_spending_key(index as u64);
    let nth_receiving_address = nth_spending_key.to_address();
    let nth_address_as_string = match nth_receiving_address.to_bech32m(network) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "Could not export address as bech32m; got error:{e}\nRaw address:\n{:?}",
                nth_receiving_address
            );
            return Ok(());
        }
    };

    println!("{nth_address_as_string}");
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
            recipient_abbrev: entry
                .recipient_address
                .to_display_bech32m_abbreviated(network)
                .expect("String encoding of address must succeed"),
            recipient: entry
                .recipient_address
                .to_display_bech32m(network)
                .expect("String encoding of address must succeed"),
            ciphertext: entry.ciphertext,
        };

        let file_name = format!("{}-{}.json", entry.recipient_abbrev, timestamp);
        let file_path = file_dir.join(&file_name);
        println!("creating file: {}", file_path.display());
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
run `neptune-cli claim-utxo file <file>`, or
run `neptune-cli claim-utxo raw <ciphertext>`,
or use equivalent claim functionality of your chosen wallet software.
"
        );
    }

    Ok(())
}
