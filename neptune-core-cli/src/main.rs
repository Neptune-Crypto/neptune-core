pub(crate) mod command;
pub(crate) mod models;
mod parser;

use std::io;
use std::io::stdout;
use std::io::Write;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use anyhow::bail;
use anyhow::ensure;
use anyhow::Result;
use clap::CommandFactory;
use clap::Parser;
use clap_complete::generate;
use clap_complete::Shell;
use itertools::Itertools;
use neptune_cash::api::tx_initiation::builder::tx_output_list_builder::OutputFormat;
use neptune_cash::application::config::data_directory::DataDirectory;
use neptune_cash::application::config::network::Network;
use neptune_cash::application::rpc::auth;
use neptune_cash::application::rpc::server::coinbase_output_readable::CoinbaseOutputReadable;
use neptune_cash::application::rpc::server::error::RpcError;
use neptune_cash::application::rpc::server::RPCClient;
use neptune_cash::protocol::consensus::block::block_selector::BlockSelector;
use neptune_cash::protocol::consensus::block::block_selector::BlockSelectorLiteral;
use neptune_cash::state::wallet::address::KeyType;
use neptune_cash::state::wallet::address::ReceivingAddress;
use neptune_cash::state::wallet::change_policy::ChangePolicy;
use neptune_cash::state::wallet::coin_with_possible_timelock::CoinWithPossibleTimeLock;
use neptune_cash::state::wallet::secret_key_material::SecretKeyMaterial;
use neptune_cash::state::wallet::utxo_notification::PrivateNotificationData;
use neptune_cash::state::wallet::utxo_notification::UtxoNotificationMedium;
use neptune_cash::state::wallet::wallet_file::WalletFile;
use neptune_cash::state::wallet::wallet_file::WalletFileContext;
use neptune_cash::state::wallet::wallet_status::WalletStatus;
use neptune_cash::state::wallet::wallet_status::WalletStatusExportFormat;
use rand::Rng;
use regex::Regex;
use tarpc::client;
use tarpc::context;
use tarpc::tokio_serde::formats::Json;

use crate::command::blockchain::BlockchainCommand;
use crate::command::mempool::MempoolCommand;
use crate::command::mining::MiningCommand;
use crate::command::network::NetworkCommand;
use crate::command::node::NodeCommand;
use crate::command::payment::PaymentCommand;
use crate::command::statistics::StatisticsCommand;
use crate::command::wallet::WalletCommand;
use crate::command::Command;
use crate::models::claim_utxo::ClaimUtxoFormat;
use crate::models::utxo_transfer_entry::UtxoTransferEntry;
use crate::parser::beneficiary::Beneficiary;

const SELF: &str = "self";
const ANONYMOUS: &str = "anonymous";

/// Top-level CLI args
#[derive(Debug, Clone, Parser)]
#[clap(name = "neptune-cli", about = "An RPC client")]
struct Config {
    /// Sets the neptune-core rpc server localhost port to connect to.
    #[clap(short, long, default_value = "9799", value_name = "port")]
    port: u16,

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
            }
            bail!("Unknown shell. Shell completions not available.")
        }
        Command::Wallet(WalletCommand::WhichWallet { network }) => {
            let wallet_dir =
                DataDirectory::get(args.data_dir.clone(), *network)?.wallet_directory_path();

            // Get wallet object, create various wallet secret files
            let wallet_file = WalletFileContext::wallet_secret_path(&wallet_dir);
            if !wallet_file.exists() {
                eprintln!("No wallet file found at {}.", wallet_file.display());
                return Ok(());
            }
            println!("{}", wallet_file.display());
            return Ok(());
        }
        Command::Wallet(WalletCommand::GenerateWallet { network }) => {
            let wallet_dir =
                DataDirectory::get(args.data_dir.clone(), *network)?.wallet_directory_path();

            // Get wallet object, create various wallet secret files
            DataDirectory::create_dir_if_not_exists(&wallet_dir).await?;

            let wallet_file_context = WalletFileContext::read_from_file_or_create(&wallet_dir)?;

            if wallet_file_context.wallet_is_new {
                println!("New wallet generated.");
            } else {
                println!("Not generating a new wallet because an existing one is present already.");
            }

            println!(
                "Wallet stored in: {}\nMake sure you also see this path if you run the neptune-core client",
                wallet_file_context.wallet_secret_path.display()
            );

            println!(
                "To display the seed phrase, run `{} export-seed-phrase`.",
                std::env::args().next().unwrap()
            );

            return Ok(());
        }
        Command::Wallet(WalletCommand::ImportSeedPhrase { network }) => {
            let data_directory = DataDirectory::get(args.data_dir.clone(), *network)?;
            let wallet_dir = data_directory.wallet_directory_path();
            let wallet_db_dir = data_directory.wallet_database_dir_path();
            let wallet_secret_path = WalletFileContext::wallet_secret_path(&wallet_dir);

            ensure!(
                !wallet_dir.exists(),
                "Cannot import seed phrase; wallet directory {} already exists. \
                Move it to another location to import a seed phrase.",
                wallet_dir.display(),
            );

            ensure!(
                !wallet_db_dir.exists(),
                "Cannot import seed phrase; wallet database directory {} already exists. \
                Move it to another location to import a seed phrase.",
                wallet_db_dir.display(),
            );

            // read seed phrase from user input
            println!("Importing seed phrase. Please enter words:");
            let secret_key = match enter_seed_phrase_dialog() {
                Ok(k) => k,
                Err(e) => {
                    println!("Failed to import seed phrase.");
                    eprintln!("Error: {e}");
                    return Ok(());
                }
            };
            let wallet_secret = WalletFile::new(secret_key);

            // wallet file does not exist yet, so create it and save
            println!(
                "Saving wallet to disk at {} ...",
                wallet_secret_path.display()
            );
            DataDirectory::create_dir_if_not_exists(&wallet_dir).await?;
            match wallet_secret.save_to_disk(&wallet_secret_path) {
                Err(e) => {
                    bail!("Could not save imported wallet to disk. {e}");
                }
                Ok(_) => {
                    println!("Success.");
                }
            }

            return Ok(());
        }
        Command::Wallet(WalletCommand::ExportSeedPhrase { network }) => {
            // The root path is where both the wallet and all databases are stored
            let wallet_dir =
                DataDirectory::get(args.data_dir.clone(), *network)?.wallet_directory_path();

            // Get wallet object, create various wallet secret files
            let wallet_file = WalletFileContext::wallet_secret_path(&wallet_dir);
            ensure!(
                wallet_file.exists(),
                "Cannot export seed phrase because there is no wallet.dat file to export from.\n\
                Generate one using `neptune-cli generate-wallet`, or import a seed phrase using \
                `neptune-cli import-seed-phrase`."
            );
            let wallet_secret = match WalletFile::read_from_file(&wallet_file) {
                Err(e) => {
                    println!("Could not export seed phrase.");
                    println!("Error:");
                    println!("{e}");
                    return Ok(());
                }
                Ok(result) => result,
            };
            println!("Seed phrase for {network}.");
            println!("Read from file `{}`.", wallet_file.display());
            print_seed_phrase_dialog(wallet_secret.secret_key());
            return Ok(());
        }
        Command::Wallet(WalletCommand::NthReceivingAddress { network, index }) => {
            return get_nth_receiving_address(*network, args.data_dir.clone(), *index);
        }
        Command::Wallet(WalletCommand::PremineReceivingAddress { network }) => {
            return get_nth_receiving_address(*network, args.data_dir.clone(), 0);
        }
        Command::Wallet(WalletCommand::ShamirCombine { t, network }) => {
            let wallet_dir =
                DataDirectory::get(args.data_dir.clone(), *network)?.wallet_directory_path();
            let wallet_file = WalletFileContext::wallet_secret_path(&wallet_dir);

            // if the wallet file already exists, bail
            if wallet_file.exists() {
                println!(
                    "Cannot import wallet from Shamir secret shares; wallet file {} already exists. Move it to another location (or remove it) to perform this operation.",
                    wallet_file.display()
                );
                return Ok(());
            }

            // prompt user for all shares
            let mut shares = vec![];
            let capture_integers = Regex::new(r"^(\d+)\/(\d+)$").unwrap();
            while shares.len() != *t {
                println!("Enter share index (\"i/n\"): ");

                let mut buffer = "".to_string();
                std::io::stdin()
                    .read_line(&mut buffer)
                    .expect("Cannot accept user input.");
                let buffer = buffer.trim();

                let (before_slash, after_slash) =
                    if let Some(captures) = capture_integers.captures(buffer) {
                        let before_slash = captures.get(1).unwrap().as_str();
                        let after_slash = captures.get(2).unwrap().as_str();

                        (before_slash, after_slash)
                    } else {
                        println!("Could not parse index. Please try again.");
                        continue;
                    };

                let i = match usize::from_str(before_slash) {
                    Ok(i) => i,
                    Err(_e) => {
                        println!("Failed to parse `{before_slash}`. Please try again.");
                        continue;
                    }
                };

                let n = match usize::from_str(after_slash) {
                    Ok(i) => i,
                    Err(_e) => {
                        println!("Failed to parse `{after_slash}`. Please try again.");
                        continue;
                    }
                };

                if i == 0 {
                    println!("Index i == 0 is invalid. Please try again.");
                    continue;
                }

                if i > n {
                    println!("Index i = {i} > n = {n} is disallowed. Please try again.");
                    continue;
                }

                if shares.iter().any(|(j, _)| *j == i) {
                    println!("Index i = {i} is a duplicate; cannot have duplicates.");
                    println!(
                        "Already have shares with indices {{{}}}/{n}",
                        shares.iter().map(|(j, _)| *j).sorted().join(",")
                    );
                    println!("Please try again.");
                    continue;
                }

                loop {
                    println!("Enter seed phrase for key share {i}/{n}:");
                    let key = match enter_seed_phrase_dialog() {
                        Ok(key) => key,
                        Err(e) => {
                            println!("Failed to process seed phrase.");
                            eprintln!("Error: {e}");
                            println!("Please try again.");
                            continue;
                        }
                    };
                    shares.push((i, key));
                    break;
                }
                println!();
                println!(
                    "Have shares {{{}}}/{n}.\n",
                    shares.iter().map(|(j, _)| *j).sorted().join(",")
                );
            }

            let original_secret = match SecretKeyMaterial::combine_shamir(*t, shares) {
                Ok(key) => {
                    println!("Shamir recombination successful.");
                    key
                }
                Err(e) => {
                    println!("Could not recombine Shamir secret shares.");
                    eprintln!("Error: {e}");
                    return Ok(());
                }
            };

            // create wallet and save to disk
            let wallet_secret = WalletFile::new(original_secret);

            // wallet file does not exist yet (we verified that upstairs) so
            // create it and save
            println!("Saving wallet to disk at {} ...", wallet_file.display());
            DataDirectory::create_dir_if_not_exists(&wallet_dir).await?;
            match wallet_secret.save_to_disk(&wallet_file) {
                Err(e) => {
                    bail!("Could not save wallet to disk. {e}");
                }
                Ok(_) => {
                    println!("Success.");
                }
            }

            return Ok(());
        }
        Command::Wallet(WalletCommand::ShamirShare { t, n, network }) => {
            if *n < 1 {
                println!("Share count n must be larger than 1.");
                return Ok(());
            }
            if *t > *n {
                println!("Cannot split secret into fewer shares than would be required to reproduce the original secret. Try setting t <= n.");
                return Ok(());
            }
            if *t <= 1 {
                println!(
                    "Quorum t must be larger than 1, otherwise Shamir secret sharing is moot."
                );
                return Ok(());
            }

            // The root path is where both the wallet and all databases are stored
            let wallet_dir =
                DataDirectory::get(args.data_dir.clone(), *network)?.wallet_directory_path();

            // Get wallet object, create various wallet secret files
            let wallet_file_name = WalletFileContext::wallet_secret_path(&wallet_dir);
            if !wallet_file_name.exists() {
                println!(
                    "Cannot Shamir-secret-share wallet secret because there is no wallet.dat file to read from.\n \
                    Generate one using `neptune-cli generate-wallet`, or import a seed phrase using `neptune-cli import-seed-phrase`."
                );
                return Ok(());
            }
            let wallet_file = match WalletFile::read_from_file(&wallet_file_name) {
                Err(e) => {
                    println!("Could not read from wallet file.");
                    eprintln!("Error: {e}");
                    return Ok(());
                }
                Ok(result) => result,
            };
            let wallet_secret = wallet_file.secret_key();
            println!("Wallet for {network}.");
            println!("Read from file `{}`.\n", wallet_file_name.display());

            let mut rng = rand::rng();
            let shamir_shares = match wallet_secret.share_shamir(*t, *n, rng.random()) {
                Ok(shares) => shares,
                Err(e) => {
                    println!("Could not Shamir secret share wallet secret.");
                    eprintln!("Error: {e}");
                    return Ok(());
                }
            };

            let n = shamir_shares.len();
            for (i, secret_key) in shamir_shares {
                println!("Key share {i}/{n}:");
                let wallet_secret = WalletFile::new(secret_key);
                print_seed_phrase_dialog(wallet_secret.secret_key());
                println!();
            }

            return Ok(());
        }
        _ => {}
    }

    // all other operations need a connection to the server
    let server_socket = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), args.port);
    let Ok(transport) = tarpc::serde_transport::tcp::connect(server_socket, Json::default).await
    else {
        eprintln!("This command requires a connection to `neptune-core`, but that connection could not be established. Is `neptune-core` running?");
        return Ok(());
    };
    let client = RPCClient::new(client::Config::default(), transport).spawn();
    let ctx = context::current();

    let auth::CookieHint {
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

    let token: auth::Token = match auth::Cookie::try_load(&data_directory).await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Unable to load RPC auth cookie. error = {e}");
            std::process::exit(2)
        }
    }
    .into();

    match args.command {
        Command::Completions
        | Command::Wallet(
            WalletCommand::GenerateWallet { .. }
            | WalletCommand::WhichWallet { .. }
            | WalletCommand::ExportSeedPhrase { .. }
            | WalletCommand::ImportSeedPhrase { .. }
            | WalletCommand::ShamirCombine { .. }
            | WalletCommand::ShamirShare { .. }
            | WalletCommand::NthReceivingAddress { .. }
            | WalletCommand::PremineReceivingAddress { .. },
        ) => {
            unreachable!("Case should be handled earlier.")
        }

        /******** READ STATE ********/
        Command::Wallet(WalletCommand::ListCoins) => {
            let list = client.list_own_coins(ctx, token).await??;
            println!("{}", CoinWithPossibleTimeLock::report(&list));
        }
        Command::Blockchain(BlockchainCommand::Network) => {
            // we already queried the network above.
            println!("{network}")
        }
        Command::Network(NetworkCommand::OwnListenAddressForPeers) => {
            let own_listen_address = client.own_listen_address_for_peers(ctx, token).await??;
            match own_listen_address {
                Some(addr) => println!("{addr}"),
                None => println!("No listen address configured"),
            }
        }
        Command::Network(NetworkCommand::OwnInstanceId) => {
            let val = client.own_instance_id(ctx, token).await??;
            println!("{val}")
        }
        Command::Blockchain(BlockchainCommand::BlockHeight) => {
            let block_height = client.block_height(ctx, token).await??;
            println!("Block height: {block_height}")
        }
        Command::Blockchain(BlockchainCommand::BlockInfo { block_selector }) => {
            let data = client.block_info(ctx, token, block_selector).await??;
            match data {
                Some(block_info) => println!("{block_info}"),
                None => println!("Not found"),
            }
        }
        Command::Blockchain(BlockchainCommand::BlockDigestsByHeight { height }) => {
            let digests = client
                .block_digests_by_height(ctx, token, height.into())
                .await??;
            for digest in digests {
                println!("{digest:x}");
            }
        }
        Command::Mining(MiningCommand::BestBlockProposal) => {
            let best_proposal = client.best_proposal(ctx, token).await??;
            match best_proposal {
                Some(block_info) => println!("{block_info}"),
                None => println!("Not found"),
            }
        }
        Command::Wallet(WalletCommand::Confirmations) => {
            let val = client.confirmations(ctx, token).await??;
            match val {
                Some(confs) => println!("{confs}"),
                None => println!("Wallet has not received any ingoing transactions yet"),
            }
        }
        Command::Network(NetworkCommand::PeerInfo) => {
            let peers = client.peer_info(ctx, token).await??;
            println!("{} connected peers", peers.len());
            println!("{}", serde_json::to_string(&peers)?);
        }
        Command::Network(NetworkCommand::AllPunishedPeers) => {
            let peer_sanctions = client.all_punished_peers(ctx, token).await??;
            for (ip, sanction) in peer_sanctions {
                let standing = sanction.standing;
                let latest_sanction_str = match sanction.latest_punishment {
                    Some((sanction, _timestamp)) => sanction.to_string(),
                    None => String::default(),
                };
                println!("{ip}\nstanding: {standing}\nlatest sanction: {latest_sanction_str} \n\n");
            }
        }
        Command::Blockchain(BlockchainCommand::TipDigest) => {
            let head_hash = client
                .block_digest(
                    ctx,
                    token,
                    BlockSelector::Special(BlockSelectorLiteral::Tip),
                )
                .await??
                .unwrap_or_default();
            println!("{head_hash:x}");
        }
        Command::Blockchain(BlockchainCommand::LatestTipDigests { n }) => {
            let head_hashes = client.latest_tip_digests(ctx, token, n).await??;
            for hash in head_hashes {
                println!("{hash:x}");
            }
        }
        Command::Blockchain(BlockchainCommand::TipHeader) => {
            let val = client
                .header(
                    ctx,
                    token,
                    BlockSelector::Special(BlockSelectorLiteral::Tip),
                )
                .await??
                .expect("Tip header should be found");
            println!("{val}")
        }
        Command::Blockchain(BlockchainCommand::Header { block_selector }) => {
            let res = client.header(ctx, token, block_selector).await??;
            if let Some(res) = res {
                println!("{res}");
            } else {
                println!("Block did not exist in database.");
            }
        }
        Command::Wallet(WalletCommand::ConfirmedAvailableBalance) => {
            let val = client.confirmed_available_balance(ctx, token).await??;
            println!("{val}");
        }
        Command::Wallet(WalletCommand::UnconfirmedAvailableBalance) => {
            let val = client.unconfirmed_available_balance(ctx, token).await??;
            println!("{val}");
        }
        Command::Wallet(WalletCommand::WalletStatus { json, table }) => {
            let wallet_status: WalletStatus = client.wallet_status(ctx, token).await??;
            let exported_string = if json {
                WalletStatusExportFormat::Json.export(&wallet_status)
            } else if table {
                WalletStatusExportFormat::Table.export(&wallet_status)
            } else {
                WalletStatusExportFormat::Json.export(&wallet_status)
            };
            println!("{exported_string}");
        }
        Command::Wallet(WalletCommand::NumExpectedUtxos) => {
            let num = client.num_expected_utxos(ctx, token).await??;
            println!("Found a total of {num} expected UTXOs in the database");
        }
        Command::Wallet(WalletCommand::NextReceivingAddress) => {
            let receiving_address = client
                .next_receiving_address(ctx, token, KeyType::Generation)
                .await??;
            println!("{}", receiving_address.to_display_bech32m(network).unwrap())
        }
        Command::Mempool(MempoolCommand::MempoolTxCount) => {
            let count: usize = client.mempool_tx_count(ctx, token).await??;
            println!("{count}");
        }
        Command::Mempool(MempoolCommand::MempoolSize) => {
            let size_in_bytes: usize = client.mempool_size(ctx, token).await??;
            println!("{size_in_bytes} bytes");
        }
        Command::Mempool(MempoolCommand::ListMempoolTransactionIds) => {
            let txids = client.mempool_tx_ids(ctx, token).await??;
            println!("{}", txids.iter().join("\n"));
        }

        /******** BLOCKCHAIN STATISTICS ********/
        Command::Statistics(StatisticsCommand::BlockIntervals {
            last_block,
            max_num_blocks,
        }) => {
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

        Command::Statistics(StatisticsCommand::MeanBlockInterval {
            last_block,
            max_num_blocks,
        }) => {
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

        Command::Statistics(StatisticsCommand::MaxBlockInterval {
            last_block,
            max_num_blocks,
        }) => {
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

        Command::Statistics(StatisticsCommand::MinBlockInterval {
            last_block,
            max_num_blocks,
        }) => {
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

        Command::Statistics(StatisticsCommand::BlockDifficulties {
            last_block,
            max_num_blocks,
        }) => {
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

        Command::Statistics(StatisticsCommand::MaxBlockDifficulty {
            last_block,
            max_num_blocks,
        }) => {
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

        Command::Statistics(StatisticsCommand::CirculatingSupply) => {
            let circulating_supply = client.circulating_supply(ctx, token).await??;
            println!("{}", circulating_supply.display_lossless());
        }

        Command::Statistics(StatisticsCommand::MaxSupply) => {
            let max_supply = client.max_supply(ctx, token).await??;
            println!("{}", max_supply.display_lossless());
        }

        Command::Statistics(StatisticsCommand::BurnedSupply) => {
            let burned_supply = client.burned_supply(ctx, token).await??;
            println!("{}", burned_supply.display_lossless());
        }

        /******** PEER INTERACTIONS ********/
        Command::Mempool(MempoolCommand::BroadcastMempoolTransactions) => {
            println!("Broadcasting transaction-notifications for all transactions in mempool.");
            client.broadcast_all_mempool_txs(ctx, token).await??;
        }

        Command::Mining(MiningCommand::BroadcastBlockProposal) => {
            println!("Broadcasting block proposal notifications if any is known.");
            client.broadcast_block_proposal(ctx, token).await??;
        }

        /******** CHANGE STATE ********/
        Command::Node(NodeCommand::Shutdown) => {
            println!("Sending shutdown-command.");
            client.shutdown(ctx, token).await??;
            println!("Shutdown-command completed successfully.");
        }
        Command::Network(NetworkCommand::ClearAllStandings) => {
            client.clear_all_standings(ctx, token).await??;
            println!("Cleared all standings.");
        }
        Command::Network(NetworkCommand::ClearStandingByIp { ip }) => {
            client.clear_standing_by_ip(ctx, token, ip).await??;
            println!("Cleared standing of {ip}");
        }
        Command::Network(NetworkCommand::Ban { addresses }) => {
            for address in addresses {
                client.ban(ctx, token, address.clone()).await??;
                println!("Banned {address}.");
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
        Command::Network(NetworkCommand::Unban { addresses, all }) => {
            if all {
                client.unban_all(ctx, token).await??;
                println!("Unbanned all.");
            } else {
                for address in addresses {
                    client.unban(ctx, token, address.clone()).await??;
                    println!("Unbanned {address}.");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
        Command::Network(NetworkCommand::Dial { address }) => {
            client.dial(ctx, token, address).await??;
            println!("beeep brp");
        }
        Command::Network(NetworkCommand::ProbeNat) => {
            client.probe_nat(ctx, token).await??;
        }
        Command::Network(NetworkCommand::ResetRelayReservations) => {
            client.reset_relay_reservations(ctx, token).await??;
        }
        Command::Network(NetworkCommand::NetworkOverview) => {
            let overview = client.get_network_overview(ctx, token).await??;
            println!("{overview}");
        }
        Command::Wallet(WalletCommand::ClaimUtxo {
            format,
            max_search_depth,
        }) => {
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
        Command::Wallet(WalletCommand::RescanAnnounced { first, last }) => {
            client
                .rescan_announced(ctx, token, first.into(), last.into())
                .await??;
            println!("Rescan started. Please check application log for progress.");
        }
        Command::Wallet(WalletCommand::RescanExpected { first, last }) => {
            client
                .rescan_expected(ctx, token, first.into(), last.into())
                .await??;
            println!("Rescan started. Please check application log for progress.");
        }
        Command::Wallet(WalletCommand::RescanOutgoing { first, last }) => {
            client
                .rescan_outgoing(ctx, token, first.into(), last.into())
                .await??;
            println!("Rescan started. Please check application log for progress.");
        }
        Command::Wallet(WalletCommand::RescanGuesserRewards { first, last }) => {
            client
                .rescan_guesser_rewards(ctx, token, first.into(), last.into())
                .await??;
            println!("Rescan started. Please check application log for progress.");
        }
        Command::Payment(PaymentCommand::Send {
            address,
            amount,
            fee,
            receiver_tag,
            notify_self,
            notify_other,
        }) => {
            // Parse on client
            let receiving_address = ReceivingAddress::from_bech32m(&address, network)?;

            // abort early on negative fee
            if fee.is_negative() {
                eprintln!("Fee must be non-negative.");
                bail!("Failed to create transaction.");
            }

            let resp = client
                .send(
                    ctx,
                    token,
                    vec![OutputFormat::AddressAndAmountAndMedium(
                        receiving_address,
                        amount,
                        notify_other,
                    )],
                    ChangePolicy::recover_to_next_unused_key(KeyType::Symmetric, notify_self),
                    fee,
                )
                .await?;
            let tx_artifacts = match resp {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("{e}");
                    bail!("Failed to create transaction.");
                }
            };

            println!(
                "Successfully created transaction: {}",
                tx_artifacts.transaction().txid()
            );

            process_utxo_notifications(
                &data_directory,
                network,
                tx_artifacts.all_offchain_notifications(),
                Some(receiver_tag),
            )?
        }
        Command::Payment(PaymentCommand::SendToMany { file, outputs, fee }) => {
            let parsed_outputs = if let Some(filename) = file {
                if !outputs.is_empty() {
                    bail!("specify raw outputs or a file to read them from but not both");
                }
                let s = std::fs::read_to_string(filename)?;
                println!("read file: {s}");
                let mut beneficiaries = vec![];
                for chunk in s.split_whitespace() {
                    let beneficiary = Beneficiary::from_str(chunk)?;
                    beneficiaries.push(beneficiary);
                }
                beneficiaries
                    .into_iter()
                    .map(|beneficiary| beneficiary.to_output_format(network))
                    .collect::<Result<Vec<_>>>()?
            } else {
                if outputs.is_empty() {
                    bail!("must specify at least one beneficiary");
                }
                outputs
                    .into_iter()
                    .map(|o| o.to_output_format(network))
                    .collect::<Result<Vec<_>>>()?
            };

            let res = client
                .send(
                    ctx,
                    token,
                    parsed_outputs,
                    ChangePolicy::recover_to_next_unused_key(
                        KeyType::Symmetric,
                        UtxoNotificationMedium::OnChain,
                    ),
                    fee,
                )
                .await?;
            match res {
                Ok(tx_artifacts) => {
                    println!(
                        "Successfully created transaction: {}",
                        tx_artifacts.transaction().txid()
                    );

                    process_utxo_notifications(
                        &data_directory,
                        network,
                        tx_artifacts.all_offchain_notifications(),
                        None, // todo:  parse receiver tags from cmd-line.
                    )?
                }
                Err(e) => eprintln!("{e}"),
            }
        }
        Command::Payment(PaymentCommand::SendTransparent { file, outputs, fee }) => {
            let parsed_outputs = if let Some(filename) = file {
                if !outputs.is_empty() {
                    bail!("specify raw outputs or a file to read them from but not both");
                }
                let s = std::fs::read_to_string(filename)?;
                let mut beneficiaries = vec![];
                for chunk in s.split_whitespace() {
                    let beneficiary = Beneficiary::from_str(chunk)?;
                    beneficiaries.push(beneficiary);
                }
                beneficiaries
                    .into_iter()
                    .map(|beneficiary| beneficiary.to_output_format(network))
                    .collect::<Result<Vec<_>>>()?
            } else {
                if outputs.is_empty() {
                    bail!("must specify at least one beneficiary");
                }
                outputs
                    .into_iter()
                    .map(|o| o.to_output_format(network))
                    .collect::<Result<Vec<_>>>()?
            };

            let res = client
                .send_transparent(
                    ctx,
                    token,
                    parsed_outputs,
                    ChangePolicy::recover_to_next_unused_key(
                        KeyType::Symmetric,
                        UtxoNotificationMedium::OnChain,
                    ),
                    fee,
                )
                .await?;
            match res {
                Ok(tx_artifacts) => {
                    println!(
                        "Successfully created transparent transaction: {}",
                        tx_artifacts.transaction().txid()
                    );

                    // no need to process UTXO notifications:
                    // all outputs (change included) generate *on-chain*
                    // notifications
                }
                Err(e) => eprintln!("{e}"),
            }
        }
        Command::Payment(PaymentCommand::Consolidate { batch, address }) => {
            let network = client.network(ctx).await??;
            let address = match address {
                None => None,
                Some(string) => Some(ReceivingAddress::from_bech32m(&string, network)?),
            };
            let num_utxos_consolidated = client
                .consolidate(ctx, token, Some(batch), address)
                .await??;

            println!("Initiating transaction to consolidate {num_utxos_consolidated} UTXOs.");
        }
        Command::Mining(MiningCommand::Upgrade { tx_kernel_id }) => {
            println!("Attempting to upgrade transaction {tx_kernel_id}");
            let response = client.upgrade(ctx, token, tx_kernel_id).await??;
            if response {
                println!("Initiated upgrade of transaction {tx_kernel_id}");
            } else {
                println!("Found no transaction in need of upgrading");
            }
        }
        Command::Mempool(MempoolCommand::ClearMempool) => {
            println!("Sending command to delete all commands from the mempool.");
            client.clear_mempool(ctx, token).await??;
        }
        Command::Node(NodeCommand::Freeze) => {
            println!("Sending command to pause state updates.");
            client.freeze(ctx, token).await??;
        }
        Command::Node(NodeCommand::Unfreeze) => {
            println!("Sending command to resume state updates.");
            client.unfreeze(ctx, token).await??;
        }
        Command::Mining(MiningCommand::PauseMiner) => {
            println!("Sending command to pause miner.");
            client.pause_miner(ctx, token).await??;
            println!("Command completed successfully");
        }
        Command::Mining(MiningCommand::RestartMiner) => {
            println!("Sending command to restart miner.");
            client.restart_miner(ctx, token).await??;
            println!("Command completed successfully");
        }
        Command::Mining(MiningCommand::SetCoinbaseDistribution { file }) => {
            let file = std::fs::read_to_string(file)?;
            let coinbase_distribution: Vec<CoinbaseOutputReadable> = serde_json::from_str(&file)?;

            client
                .set_coinbase_distribution(ctx, token, coinbase_distribution)
                .await??;
            println!("Coinbase distribution sent to node");
        }
        Command::Mining(MiningCommand::UnsetCoinbaseDistribution) => {
            client.unset_coinbase_distribution(ctx, token).await??;
            println!("Coinbase distribution reset to own wallet");
        }

        Command::Node(NodeCommand::SetTip { digest }) => {
            println!("Setting tip ...");
            match client.set_tip(ctx, token, digest.0).await? {
                Ok(_) => {
                    println!("message delivered; setting tip now.");
                }
                Err(server_error) => {
                    println!("failed to set tip: {server_error}");
                }
            };
        }

        Command::Wallet(WalletCommand::PruneAbandonedMonitoredUtxos) => {
            let prunt_res_count = client.prune_abandoned_monitored_utxos(ctx, token).await??;
            println!("{prunt_res_count} monitored UTXOs marked as abandoned");
        }

        /******** RegTest Mode *********/
        Command::Mining(MiningCommand::MineBlocksToWallet { num_blocks }) => {
            println!("Sending command to mine block(s).");
            client
                .mine_blocks_to_wallet(ctx, token, num_blocks)
                .await??;
            println!("Command completed successfully");
        }
    }

    Ok(())
}

// returns result with a CookieHint{ data_directory, network }.
//
// We use the data-dir provided by user if present.
//
// Otherwise, we call cookie_hint() RPC to obtain data-dir.
// But the API might be disabled, which we detect and fallback to the default data-dir.
async fn get_cookie_hint(client: &RPCClient, args: &Config) -> anyhow::Result<auth::CookieHint> {
    async fn fallback(client: &RPCClient, args: &Config) -> anyhow::Result<auth::CookieHint> {
        let network = client.network(context::current()).await??;
        let data_directory = DataDirectory::get(args.data_dir.clone(), network)?;
        Ok(auth::CookieHint {
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
    let wallet_file_name = WalletFileContext::wallet_secret_path(&wallet_dir);
    ensure!(
        wallet_file_name.exists(),
        "No wallet file found at {}.",
        wallet_file_name.display(),
    );

    println!("{}", wallet_file_name.display());

    let wallet_file = match WalletFile::read_from_file(&wallet_file_name) {
        Ok(ws) => ws,
        Err(e) => {
            eprintln!(
                "Could not open wallet file at {}. Got error: {e}",
                wallet_file_name.to_string_lossy()
            );
            return Ok(());
        }
    };
    let wallet_entropy = wallet_file.entropy();

    let nth_spending_key = wallet_entropy.nth_generation_spending_key(index as u64);
    let nth_receiving_address = nth_spending_key.to_address();
    let nth_address_as_string = match nth_receiving_address.to_bech32m(network) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "Could not export address as bech32m; got error:{e}\nRaw address:\n{nth_receiving_address:?}"
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

fn enter_seed_phrase_dialog() -> Result<SecretKeyMaterial> {
    let mut phrase = vec![];
    let mut i = 1;
    loop {
        print!("{i}. ");
        io::stdout().flush()?;
        let mut buffer = "".to_string();
        std::io::stdin()
            .read_line(&mut buffer)
            .expect("Cannot accept user input.");
        let word = buffer.trim();
        if bip39::Language::English
            .wordlist()
            .get_words_by_prefix("")
            .contains(&word)
        {
            phrase.push(word.to_string());
            i += 1;
            if i > 18 {
                break;
            }
        } else {
            println!("Did not recognize word \"{word}\"; please try again.");
        }
    }
    match SecretKeyMaterial::from_phrase(&phrase) {
        Ok(key) => Ok(key),
        Err(_) => bail!("invalid seed phrase"),
    }
}

fn print_seed_phrase_dialog(wallet_secret: SecretKeyMaterial) {
    for (i, word) in wallet_secret.to_phrase().into_iter().enumerate() {
        println!("{}. {word}", i + 1);
    }
}
