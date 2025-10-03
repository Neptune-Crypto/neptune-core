//! Request handlers for RPC server
//!
//! Handles JSON-RPC requests and routes them to appropriate handlers.

use anyhow::Result;
use neptune_cash::application::config::data_directory::DataDirectory;
use neptune_cash::application::config::network::Network;
use neptune_cash::application::rpc::auth;
use neptune_cash::application::rpc::server::error::RpcError;
use neptune_cash::application::rpc::server::RPCClient;
use neptune_cash::state::wallet::wallet_file::WalletFile;
use neptune_cash::state::wallet::wallet_file::WalletFileContext;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use tarpc::client;
use tarpc::context;
use tarpc::tokio_serde::formats::Json;
use tracing::{debug, info};

/// JSON-RPC request structure
#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    #[serde(rename = "jsonrpc")]
    pub _jsonrpc: String,
    pub method: String,
    pub params: Option<serde_json::Value>,
    pub id: serde_json::Value,
}

/// JSON-RPC response structure
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JsonRpcResponse {
    Success(JsonRpcSuccess),
    Error(JsonRpcError),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcSuccess {
    pub jsonrpc: String,
    pub result: serde_json::Value,
    pub id: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub jsonrpc: String,
    pub error: JsonRpcErrorObject,
    pub id: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcErrorObject {
    pub code: i32,
    pub message: String,
    pub data: Option<serde_json::Value>,
}

impl JsonRpcResponse {
    pub fn success(id: serde_json::Value, result: serde_json::Value) -> Self {
        JsonRpcResponse::Success(JsonRpcSuccess {
            jsonrpc: "2.0".to_string(),
            result,
            id,
        })
    }

    pub fn error(id: serde_json::Value, code: i32, message: String) -> Self {
        JsonRpcResponse::Error(JsonRpcError {
            jsonrpc: "2.0".to_string(),
            error: JsonRpcErrorObject {
                code,
                message,
                data: None,
            },
            id,
        })
    }
}

/// Connect to neptune-core using existing connection logic from main.rs
async fn connect_to_neptune_core(
    port: u16,
    data_dir: Option<PathBuf>,
) -> Result<(RPCClient, auth::Token)> {
    debug!("Connecting to neptune-core on port {}", port);

    // Exact same connection pattern as main.rs lines 755-785
    let server_socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let transport = tarpc::serde_transport::tcp::connect(server_socket, Json::default)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to connect to neptune-core: {}", e))?;

    let client = RPCClient::new(client::Config::default(), transport).spawn();
    debug!("Connected to neptune-core successfully");

    // Copy get_cookie_hint logic from main.rs
    let auth::CookieHint {
        data_directory,
        network: _network,
    } = get_cookie_hint(&client, data_dir).await?;

    // Use neptune-core's existing cookie system (same as main.rs)
    let token: auth::Token = auth::Cookie::try_load(&data_directory).await?.into();
    debug!("Loaded authentication token from {:?}", data_directory);

    Ok((client, token))
}

/// Get cookie hint from neptune-core (copied from main.rs lines 1357-1378)
async fn get_cookie_hint(
    client: &RPCClient,
    data_dir: Option<PathBuf>,
) -> Result<auth::CookieHint> {
    // If data_dir is provided, use it directly
    if let Some(data_dir) = data_dir {
        let network = client.network(context::current()).await??;
        let data_directory = DataDirectory::get(Some(data_dir), network)?;
        return Ok(auth::CookieHint {
            data_directory,
            network,
        });
    }

    // Otherwise, try to get hint from neptune-core
    let result = client.cookie_hint(context::current()).await?;
    match result {
        Ok(hint) => Ok(hint),
        Err(RpcError::CookieHintDisabled) => {
            // Fallback to default data directory
            let network = client.network(context::current()).await??;
            let data_directory = DataDirectory::get(None, network)?;
            Ok(auth::CookieHint {
                data_directory,
                network,
            })
        }
        Err(e) => Err(e.into()),
    }
}

/// Handle JSON-RPC request
pub async fn handle_request(request: JsonRpcRequest) -> Result<JsonRpcResponse> {
    match request.method.as_str() {
        // Standalone Commands (No Server Required)
        "completions" => {
            let shell = extract_string_param(&request.params, "shell")
                .unwrap_or_else(|| "bash".to_string());
            let completions = generate_completions(&shell)?;
            let result = serde_json::Value::String(completions);
            Ok(JsonRpcResponse::success(request.id, result))
        }

        "help" => {
            let command = extract_string_param(&request.params, "command");
            let help_text = generate_help(command.as_deref())?;
            let result = serde_json::Value::String(help_text);
            Ok(JsonRpcResponse::success(request.id, result))
        }

        "which_wallet" => {
            let network = extract_string_param(&request.params, "network")
                .unwrap_or_else(|| "main".to_string());
            let wallet_path = get_wallet_path(&network)?;
            let result = serde_json::Value::String(wallet_path);
            Ok(JsonRpcResponse::success(request.id, result))
        }

        "generate_wallet" => {
            let network = extract_string_param(&request.params, "network")
                .unwrap_or_else(|| "main".to_string());
            let wallet_info = generate_wallet(&network)?;
            let result = serde_json::Value::String(wallet_info);
            Ok(JsonRpcResponse::success(request.id, result))
        }

        "export_seed_phrase" => {
            let network = extract_string_param(&request.params, "network")
                .unwrap_or_else(|| "main".to_string());
            let seed_phrase = export_seed_phrase(&network)?;
            let result = serde_json::Value::String(seed_phrase);
            Ok(JsonRpcResponse::success(request.id, result))
        }

        "nth_receiving_address" => {
            let n = extract_u32_param(&request.params, "n")?;
            let network = extract_string_param(&request.params, "network")
                .unwrap_or_else(|| "main".to_string());
            let address = get_nth_receiving_address(n, &network)?;
            let result = serde_json::Value::String(address);
            Ok(JsonRpcResponse::success(request.id, result))
        }

        "premine_receiving_address" => {
            let network = extract_string_param(&request.params, "network")
                .unwrap_or_else(|| "main".to_string());
            let address = get_premine_receiving_address(&network)?;
            let result = serde_json::Value::String(address);
            Ok(JsonRpcResponse::success(request.id, result))
        }

        "import_seed_phrase" => {
            let seed_phrase = extract_string_param(&request.params, "seed_phrase")
                .ok_or_else(|| anyhow::anyhow!("Missing seed_phrase parameter"))?;
            let network = extract_string_param(&request.params, "network")
                .unwrap_or_else(|| "main".to_string());
            let result_text = import_seed_phrase(&seed_phrase, &network).await?;
            let result = serde_json::Value::String(result_text);
            Ok(JsonRpcResponse::success(request.id, result))
        }

        "shamir_share" => {
            let t = extract_u32_param(&request.params, "t")?;
            let n = extract_u32_param(&request.params, "n")?;
            let network = extract_string_param(&request.params, "network")
                .unwrap_or_else(|| "main".to_string());
            let shares = shamir_share(t, n, &network)?;
            let result = serde_json::Value::String(shares);
            Ok(JsonRpcResponse::success(request.id, result))
        }

        "shamir_combine" => {
            let shares = extract_string_param(&request.params, "shares")
                .ok_or_else(|| anyhow::anyhow!("Missing shares parameter"))?;
            let network = extract_string_param(&request.params, "network")
                .unwrap_or_else(|| "main".to_string());
            let result_text = shamir_combine(&shares, &network).await?;
            let result = serde_json::Value::String(result_text);
            Ok(JsonRpcResponse::success(request.id, result))
        }

        // Server-Dependent Methods (Require neptune-core connection)
        "block_height" => {
            let (client, token) = connect_to_neptune_core(9799, None).await?;
            let ctx = context::current();
            let height = client.block_height(ctx, token).await??;
            let result = serde_json::Value::String(height.to_string());
            Ok(JsonRpcResponse::success(request.id, result))
        }

        "network" => {
            let (client, _token) = connect_to_neptune_core(9799, None).await?;
            let ctx = context::current();
            let network = client.network(ctx).await??;
            let result = serde_json::Value::String(network.to_string());
            Ok(JsonRpcResponse::success(request.id, result))
        }

        "confirmed_available_balance" => {
            let (client, token) = connect_to_neptune_core(9799, None).await?;
            let ctx = context::current();
            let balance = client.confirmed_available_balance(ctx, token).await??;
            let result = serde_json::Value::String(balance.to_string());
            Ok(JsonRpcResponse::success(request.id, result))
        }

        "dashboard_overview_data" => {
            let (client, token) = connect_to_neptune_core(9799, None).await?;
            let ctx = context::current();
            match client.dashboard_overview_data(ctx, token).await {
                Ok(Ok(dashboard_data)) => {
                    // Create a simplified version that converts problematic fields to strings
                    let simplified_data = serde_json::json!({
                        "tip_digest": dashboard_data.tip_digest.to_hex(),
                        "tip_header": {
                            "height": dashboard_data.tip_header.height,
                            "timestamp": dashboard_data.tip_header.timestamp,
                        },
                        "syncing": dashboard_data.syncing,
                        "confirmed_available_balance": dashboard_data.confirmed_available_balance.to_string(),
                        "confirmed_total_balance": dashboard_data.confirmed_total_balance.to_string(),
                        "unconfirmed_available_balance": dashboard_data.unconfirmed_available_balance.to_string(),
                        "unconfirmed_total_balance": dashboard_data.unconfirmed_total_balance.to_string(),
                        "mempool_size": dashboard_data.mempool_size,
                        "mempool_total_tx_count": dashboard_data.mempool_total_tx_count,
                        "mempool_own_tx_count": dashboard_data.mempool_own_tx_count,
                        "peer_count": dashboard_data.peer_count,
                        "max_num_peers": dashboard_data.max_num_peers,
                        "mining_status": dashboard_data.mining_status.map(|s| s.to_string()),
                        "proving_capability": dashboard_data.proving_capability.to_string(),
                        "confirmations": dashboard_data.confirmations.map(|c| c.to_string()),
                        "cpu_temp": dashboard_data.cpu_temp,
                    });
                    Ok(JsonRpcResponse::success(request.id, simplified_data))
                }
                Ok(Err(e)) => {
                    eprintln!("RPC error: {:?}", e);
                    Ok(JsonRpcResponse::error(
                        request.id,
                        -32603,
                        format!("RPC error: {:?}", e),
                    ))
                }
                Err(e) => {
                    eprintln!("Connection error: {}", e);
                    Ok(JsonRpcResponse::error(
                        request.id,
                        -32603,
                        format!("Connection error: {}", e),
                    ))
                }
            }
        }

        // Phase 1: Core Wallet Functionality
        "next_receiving_address" => {
            let (client, token) = connect_to_neptune_core(9799, None).await?;
            let ctx = context::current();
            let key_type = extract_string_param(&request.params, "key_type")
                .unwrap_or_else(|| "Generation".to_string());
            let key_type_enum = match key_type.as_str() {
                "Generation" => neptune_cash::api::export::KeyType::Generation,
                "Symmetric" => neptune_cash::api::export::KeyType::Symmetric,
                _ => neptune_cash::api::export::KeyType::Generation,
            };
            debug!(
                "Generating next receiving address with key_type: {}",
                key_type
            );
            let address = client
                .next_receiving_address(ctx, token, key_type_enum)
                .await??;
            let result = serde_json::Value::String(
                address.to_bech32m(neptune_cash::api::export::Network::Main)?,
            );
            info!("Generated receiving address successfully");
            Ok(JsonRpcResponse::success(request.id, result))
        }

        "wallet_status" => {
            let (client, token) = connect_to_neptune_core(9799, None).await?;
            let ctx = context::current();
            let wallet_status = client.wallet_status(ctx, token).await??;
            let result = serde_json::to_value(wallet_status)?;
            Ok(JsonRpcResponse::success(request.id, result))
        }

        "confirmations" => {
            let (client, token) = connect_to_neptune_core(9799, None).await?;
            let ctx = context::current();
            let confirmations = client.confirmations(ctx, token).await??;
            let result = match confirmations {
                Some(c) => serde_json::Value::String(c.to_string()),
                None => serde_json::Value::Null,
            };
            Ok(JsonRpcResponse::success(request.id, result))
        }

        "send" => {
            let (client, token) = connect_to_neptune_core(9799, None).await?;
            let ctx = context::current();
            let outputs = extract_string_param(&request.params, "outputs")
                .ok_or_else(|| anyhow::anyhow!("Missing outputs parameter"))?;
            let change_policy = extract_string_param(&request.params, "change_policy")
                .ok_or_else(|| anyhow::anyhow!("Missing change_policy parameter"))?;
            let fee = extract_string_param(&request.params, "fee")
                .ok_or_else(|| anyhow::anyhow!("Missing fee parameter"))?;

            // Parse outputs from JSON string
            let outputs_parsed: Vec<neptune_cash::api::export::OutputFormat> =
                serde_json::from_str(&outputs)?;
            let change_policy_parsed: neptune_cash::api::export::ChangePolicy =
                serde_json::from_str(&change_policy)?;
            let fee_parsed: neptune_cash::api::export::NativeCurrencyAmount =
                serde_json::from_str(&fee)?;

            let tx_artifacts = client
                .send(ctx, token, outputs_parsed, change_policy_parsed, fee_parsed)
                .await??;
            let result = serde_json::to_value(tx_artifacts)?;
            Ok(JsonRpcResponse::success(request.id, result))
        }

        "claim_utxo" => {
            let (client, token) = connect_to_neptune_core(9799, None).await?;
            let ctx = context::current();
            let utxo_transfer_encrypted =
                extract_string_param(&request.params, "utxo_transfer_encrypted")
                    .ok_or_else(|| anyhow::anyhow!("Missing utxo_transfer_encrypted parameter"))?;
            let max_search_depth = extract_u32_param(&request.params, "max_search_depth")
                .map(|d| Some(d as u64))
                .unwrap_or(None);

            let claimed = client
                .claim_utxo(ctx, token, utxo_transfer_encrypted, max_search_depth)
                .await??;
            let result = serde_json::Value::Bool(claimed);
            Ok(JsonRpcResponse::success(request.id, result))
        }

        // Phase 2: Enhanced Features
        "list_own_coins" => {
            let (client, token) = connect_to_neptune_core(9799, None).await?;
            let ctx = context::current();
            let coins = client.list_own_coins(ctx, token).await??;
            let result = serde_json::to_value(coins)?;
            Ok(JsonRpcResponse::success(request.id, result))
        }

        "history" => {
            let (client, token) = connect_to_neptune_core(9799, None).await?;
            let ctx = context::current();
            let history = client.history(ctx, token).await??;
            let result = serde_json::to_value(history)?;
            Ok(JsonRpcResponse::success(request.id, result))
        }

        "validate_address" => {
            let (client, token) = connect_to_neptune_core(9799, None).await?;
            let ctx = context::current();
            let address = extract_string_param(&request.params, "address")
                .ok_or_else(|| anyhow::anyhow!("Missing address parameter"))?;
            let network = extract_string_param(&request.params, "network")
                .unwrap_or_else(|| "main".to_string());
            let network_enum = match network.as_str() {
                "main" => neptune_cash::api::export::Network::Main,
                "testnet" => neptune_cash::api::export::Network::Testnet(0),
                "regtest" => neptune_cash::api::export::Network::RegTest,
                _ => neptune_cash::api::export::Network::Main,
            };
            let is_valid = client
                .validate_address(ctx, token, address, network_enum)
                .await??;
            let result = serde_json::Value::Bool(is_valid.is_some());
            Ok(JsonRpcResponse::success(request.id, result))
        }

        "validate_amount" => {
            let (client, token) = connect_to_neptune_core(9799, None).await?;
            let ctx = context::current();
            let amount = extract_string_param(&request.params, "amount")
                .ok_or_else(|| anyhow::anyhow!("Missing amount parameter"))?;
            let is_valid = client.validate_amount(ctx, token, amount).await??;
            let result = serde_json::Value::Bool(is_valid.is_some());
            Ok(JsonRpcResponse::success(request.id, result))
        }

        "peer_info" => {
            let (client, token) = connect_to_neptune_core(9799, None).await?;
            let ctx = context::current();
            let peers = client.peer_info(ctx, token).await??;
            let result = serde_json::to_value(peers)?;
            Ok(JsonRpcResponse::success(request.id, result))
        }

        "mempool_tx_count" => {
            let (client, token) = connect_to_neptune_core(9799, None).await?;
            let ctx = context::current();
            let count = client.mempool_tx_count(ctx, token).await??;
            let result = serde_json::Value::Number(serde_json::Number::from(count));
            Ok(JsonRpcResponse::success(request.id, result))
        }

        "unconfirmed_available_balance" => {
            let (client, token) = connect_to_neptune_core(9799, None).await?;
            let ctx = context::current();
            let balance = client.unconfirmed_available_balance(ctx, token).await??;
            let result = serde_json::Value::String(balance.to_string());
            Ok(JsonRpcResponse::success(request.id, result))
        }

        // Phase 3: Advanced Features
        "send_transparent" => {
            let (client, token) = connect_to_neptune_core(9799, None).await?;
            let ctx = context::current();
            let outputs = extract_string_param(&request.params, "outputs")
                .ok_or_else(|| anyhow::anyhow!("Missing outputs parameter"))?;
            let change_policy = extract_string_param(&request.params, "change_policy")
                .ok_or_else(|| anyhow::anyhow!("Missing change_policy parameter"))?;
            let fee = extract_string_param(&request.params, "fee")
                .ok_or_else(|| anyhow::anyhow!("Missing fee parameter"))?;

            let outputs_parsed: Vec<neptune_cash::api::export::OutputFormat> =
                serde_json::from_str(&outputs)?;
            let change_policy_parsed: neptune_cash::api::export::ChangePolicy =
                serde_json::from_str(&change_policy)?;
            let fee_parsed: neptune_cash::api::export::NativeCurrencyAmount =
                serde_json::from_str(&fee)?;

            let tx_artifacts = client
                .send_transparent(ctx, token, outputs_parsed, change_policy_parsed, fee_parsed)
                .await??;
            let result = serde_json::to_value(tx_artifacts)?;
            Ok(JsonRpcResponse::success(request.id, result))
        }

        "upgrade" => {
            let (client, token) = connect_to_neptune_core(9799, None).await?;
            let ctx = context::current();
            let tx_kernel_id = extract_string_param(&request.params, "tx_kernel_id")
                .ok_or_else(|| anyhow::anyhow!("Missing tx_kernel_id parameter"))?;
            let tx_kernel_id_parsed: neptune_cash::api::export::TransactionKernelId =
                serde_json::from_str(&tx_kernel_id)?;

            let upgraded = client.upgrade(ctx, token, tx_kernel_id_parsed).await??;
            let result = serde_json::Value::Bool(upgraded);
            Ok(JsonRpcResponse::success(request.id, result))
        }

        "pause_miner" => {
            let (client, token) = connect_to_neptune_core(9799, None).await?;
            let ctx = context::current();
            client.pause_miner(ctx, token).await??;
            let result = serde_json::Value::Null;
            Ok(JsonRpcResponse::success(request.id, result))
        }

        "restart_miner" => {
            let (client, token) = connect_to_neptune_core(9799, None).await?;
            let ctx = context::current();
            client.restart_miner(ctx, token).await??;
            let result = serde_json::Value::Null;
            Ok(JsonRpcResponse::success(request.id, result))
        }

        "shutdown" => {
            let (client, token) = connect_to_neptune_core(9799, None).await?;
            let ctx = context::current();
            let shutdown_result = client.shutdown(ctx, token).await??;
            let result = serde_json::Value::Bool(shutdown_result);
            Ok(JsonRpcResponse::success(request.id, result))
        }

        _ => Ok(JsonRpcResponse::error(
            request.id,
            -32601,
            format!("Method '{}' not found", request.method),
        )),
    }
}

// Helper functions for parameter extraction

fn extract_string_param(params: &Option<serde_json::Value>, key: &str) -> Option<String> {
    params
        .as_ref()?
        .as_object()?
        .get(key)?
        .as_str()
        .map(|s| s.to_string())
}

fn extract_u32_param(params: &Option<serde_json::Value>, key: &str) -> Result<u32> {
    let value = params
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Missing parameters"))?
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("Invalid parameters"))?
        .get(key)
        .ok_or_else(|| anyhow::anyhow!("Missing '{}' parameter", key))?
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("Invalid '{}' parameter", key))?;

    Ok(value as u32)
}

// Helper functions for standalone commands

/// Generate shell completions
fn generate_completions(shell: &str) -> Result<String> {
    use clap::Command;
    use clap_complete::{generate, Shell};

    let cmd = Command::new("neptune-cli");
    let cmd = cmd.about("An RPC client");

    let shell_type = match shell {
        "bash" => Shell::Bash,
        "zsh" => Shell::Zsh,
        "fish" => Shell::Fish,
        "powershell" => Shell::PowerShell,
        "elvish" => Shell::Elvish,
        _ => Shell::Bash,
    };

    let mut buf = Vec::new();
    generate(shell_type, &mut cmd.clone(), "neptune-cli", &mut buf);
    Ok(String::from_utf8(buf)?)
}

/// Generate help text
fn generate_help(command: Option<&str>) -> Result<String> {
    use clap::Command;

    let cmd = Command::new("neptune-cli");
    let mut cmd = cmd.about("An RPC client");

    if let Some(cmd_name) = command {
        // Generate help for specific command
        Ok(format!("Help for command: {}", cmd_name))
    } else {
        // Generate general help
        Ok(cmd.render_help().to_string())
    }
}

/// Get wallet file path
fn get_wallet_path(network: &str) -> Result<String> {
    let network_type = match network {
        "main" => Network::Main,
        "regtest" => Network::RegTest,
        _ => Network::Main,
    };

    let data_dir = DataDirectory::get(None, network_type)?;
    let wallet_dir = data_dir.wallet_directory_path();
    let wallet_path = WalletFileContext::wallet_secret_path(&wallet_dir);
    Ok(wallet_path.to_string_lossy().to_string())
}

/// Generate new wallet
fn generate_wallet(network: &str) -> Result<String> {
    let network_type = match network {
        "main" => Network::Main,
        "regtest" => Network::RegTest,
        _ => Network::Main,
    };

    let data_dir = DataDirectory::get(None, network_type)?;
    let wallet_dir = data_dir.wallet_directory_path();
    let wallet_path = WalletFileContext::wallet_secret_path(&wallet_dir);

    // Check if wallet already exists
    if wallet_path.exists() {
        return Ok(format!(
            "Wallet already exists at: {}",
            wallet_path.to_string_lossy()
        ));
    }

    // Create wallet directory if it doesn't exist
    if let Some(parent_dir) = wallet_path.parent() {
        std::fs::create_dir_all(parent_dir)?;
    }

    // Generate new wallet
    let wallet_file_context = WalletFileContext::read_from_file_or_create(&wallet_dir)?;

    if wallet_file_context.wallet_is_new {
        Ok(format!(
            "New wallet generated.\nWallet stored in: {}\nTo display the seed phrase, run export_seed_phrase.",
            wallet_file_context.wallet_secret_path.display()
        ))
    } else {
        Ok(format!(
            "Not generating a new wallet because an existing one is present already.\nWallet stored in: {}",
            wallet_file_context.wallet_secret_path.display()
        ))
    }
}

/// Export seed phrase
fn export_seed_phrase(network: &str) -> Result<String> {
    let network_type = match network {
        "main" => Network::Main,
        "regtest" => Network::RegTest,
        _ => Network::Main,
    };

    let data_dir = DataDirectory::get(None, network_type)?;
    let wallet_dir = data_dir.wallet_directory_path();
    let wallet_path = WalletFileContext::wallet_secret_path(&wallet_dir);

    if !wallet_path.exists() {
        return Err(anyhow::anyhow!(
            "Wallet not found at: {}",
            wallet_path.to_string_lossy()
        ));
    }

    // Read wallet file and export seed phrase
    let wallet_file = WalletFile::read_from_file(&wallet_path)?;
    let wallet_secret = wallet_file.secret_key();

    // Export seed phrase
    let phrase = wallet_secret.to_phrase();
    let seed_phrase = phrase.join(" ");

    Ok(seed_phrase)
}

/// Get nth receiving address
fn get_nth_receiving_address(n: u32, network: &str) -> Result<String> {
    let network_type = match network {
        "main" => Network::Main,
        "regtest" => Network::RegTest,
        _ => Network::Main,
    };

    let data_dir = DataDirectory::get(None, network_type)?;
    let wallet_dir = data_dir.wallet_directory_path();
    let wallet_path = WalletFileContext::wallet_secret_path(&wallet_dir);

    if !wallet_path.exists() {
        return Err(anyhow::anyhow!(
            "Wallet not found at: {}",
            wallet_path.to_string_lossy()
        ));
    }

    // Read wallet file and generate address
    let wallet_file = WalletFile::read_from_file(&wallet_path)?;
    let wallet_entropy = wallet_file.entropy();

    // Generate nth receiving address
    let nth_spending_key = wallet_entropy.nth_generation_spending_key(n as u64);
    let nth_receiving_address = nth_spending_key.to_address();
    let address_string = nth_receiving_address.to_bech32m(network_type)?;

    Ok(address_string)
}

/// Get premine receiving address
fn get_premine_receiving_address(network: &str) -> Result<String> {
    let network_type = match network {
        "main" => Network::Main,
        "regtest" => Network::RegTest,
        _ => Network::Main,
    };

    let data_dir = DataDirectory::get(None, network_type)?;
    let wallet_dir = data_dir.wallet_directory_path();
    let wallet_path = WalletFileContext::wallet_secret_path(&wallet_dir);

    if !wallet_path.exists() {
        return Err(anyhow::anyhow!(
            "Wallet not found at: {}",
            wallet_path.to_string_lossy()
        ));
    }

    // Read wallet file and generate premine address
    let wallet_file = WalletFile::read_from_file(&wallet_path)?;
    let wallet_entropy = wallet_file.entropy();

    // Generate premine receiving address (index 0)
    let nth_spending_key = wallet_entropy.nth_generation_spending_key(0);
    let nth_receiving_address = nth_spending_key.to_address();
    let address_string = nth_receiving_address.to_bech32m(network_type)?;

    Ok(address_string)
}

/// Import seed phrase and create wallet
async fn import_seed_phrase(seed_phrase: &str, network: &str) -> Result<String> {
    use neptune_cash::state::wallet::secret_key_material::SecretKeyMaterial;

    let network_type = match network {
        "main" => Network::Main,
        "regtest" => Network::RegTest,
        _ => Network::Main,
    };

    let data_dir = DataDirectory::get(None, network_type)?;
    let wallet_dir = data_dir.wallet_directory_path();
    let wallet_db_dir = data_dir.wallet_database_dir_path();
    let wallet_path = WalletFileContext::wallet_secret_path(&wallet_dir);

    // Check if wallet already exists
    if wallet_dir.exists() {
        return Err(anyhow::anyhow!(
            "Cannot import seed phrase; wallet directory {} already exists. Move it to another location to import a seed phrase.",
            wallet_dir.display()
        ));
    }

    if wallet_db_dir.exists() {
        return Err(anyhow::anyhow!(
            "Cannot import seed phrase; wallet database directory {} already exists. Move it to another location to import a seed phrase.",
            wallet_db_dir.display()
        ));
    }

    // Parse seed phrase
    let words: Vec<String> = seed_phrase
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();
    if words.len() != 24 {
        return Err(anyhow::anyhow!(
            "Invalid seed phrase length. Expected 24 words, got {}",
            words.len()
        ));
    }

    // Convert seed phrase to secret key material
    let secret_key = SecretKeyMaterial::from_phrase(&words)?;
    let wallet_secret = WalletFile::new(secret_key);

    // Create wallet directory and save wallet
    DataDirectory::create_dir_if_not_exists(&wallet_dir).await?;
    wallet_secret.save_to_disk(&wallet_path)?;

    Ok(format!(
        "Successfully imported seed phrase and created wallet at: {}",
        wallet_path.display()
    ))
}

/// Create Shamir secret shares
fn shamir_share(t: u32, n: u32, network: &str) -> Result<String> {
    use rand::Rng;

    let network_type = match network {
        "main" => Network::Main,
        "regtest" => Network::RegTest,
        _ => Network::Main,
    };

    let data_dir = DataDirectory::get(None, network_type)?;
    let wallet_dir = data_dir.wallet_directory_path();
    let wallet_path = WalletFileContext::wallet_secret_path(&wallet_dir);

    if !wallet_path.exists() {
        return Err(anyhow::anyhow!(
            "Wallet not found at: {}",
            wallet_path.to_string_lossy()
        ));
    }

    // Validate parameters
    if t < 2 || t > n || n > 255 {
        return Err(anyhow::anyhow!(
            "Invalid parameters: t={}, n={}. Must have 2 <= t <= n <= 255",
            t,
            n
        ));
    }

    // Read wallet file and get secret key
    let wallet_file = WalletFile::read_from_file(&wallet_path)?;
    let wallet_secret = wallet_file.secret_key();

    // Generate Shamir shares
    let mut rng = rand::rng();
    let shamir_shares = wallet_secret
        .share_shamir(t as usize, n as usize, rng.random())
        .map_err(|e| anyhow::anyhow!("Shamir sharing failed: {:?}", e))?;

    // Convert shares to seed phrases for output
    let share_phrases: Vec<String> = shamir_shares
        .into_iter()
        .map(|(index, secret)| {
            let phrase = secret.to_phrase();
            format!("{}: {}", index, phrase.join(" "))
        })
        .collect();

    Ok(format!(
        "Generated {} Shamir secret shares (t={}, n={}):\n{}",
        share_phrases.len(),
        t,
        n,
        share_phrases.join("\n")
    ))
}

/// Combine Shamir secret shares
async fn shamir_combine(shares: &str, network: &str) -> Result<String> {
    use neptune_cash::state::wallet::secret_key_material::SecretKeyMaterial;

    let network_type = match network {
        "main" => Network::Main,
        "regtest" => Network::RegTest,
        _ => Network::Main,
    };

    let data_dir = DataDirectory::get(None, network_type)?;
    let wallet_dir = data_dir.wallet_directory_path();
    let wallet_path = WalletFileContext::wallet_secret_path(&wallet_dir);

    // Check if wallet already exists
    if wallet_path.exists() {
        return Err(anyhow::anyhow!(
            "Cannot import wallet from Shamir secret shares; wallet file {} already exists. Move it to another location (or remove it) to perform this operation.",
            wallet_path.display()
        ));
    }

    // Parse shares (expecting format: [{"index": 1, "phrase": "word1 word2 ..."}, ...])
    let shares_data: Vec<serde_json::Value> = serde_json::from_str(shares)
        .map_err(|_| anyhow::anyhow!("Invalid shares format. Expected JSON array of objects with 'index' and 'phrase' fields"))?;

    if shares_data.is_empty() {
        return Err(anyhow::anyhow!("No shares provided"));
    }

    // Parse each share
    let mut parsed_shares = Vec::new();
    for share_data in shares_data {
        let index = share_data
            .get("index")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'index' field in share"))?
            as usize;

        let phrase_str = share_data
            .get("phrase")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'phrase' field in share"))?;

        let words: Vec<String> = phrase_str
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();
        if words.len() != 24 {
            return Err(anyhow::anyhow!(
                "Invalid seed phrase length in share {}. Expected 24 words, got {}",
                index,
                words.len()
            ));
        }

        let secret = SecretKeyMaterial::from_phrase(&words)?;
        parsed_shares.push((index, secret));
    }

    // Determine t from the number of shares provided
    let t = parsed_shares.len();

    // Combine shares
    let original_secret = SecretKeyMaterial::combine_shamir(t, parsed_shares)
        .map_err(|e| anyhow::anyhow!("Shamir combining failed: {:?}", e))?;
    let wallet_secret = WalletFile::new(original_secret);

    // Create wallet directory and save wallet
    DataDirectory::create_dir_if_not_exists(&wallet_dir).await?;
    wallet_secret.save_to_disk(&wallet_path)?;

    Ok(format!(
        "Successfully combined {} Shamir secret shares and created wallet at: {}",
        t,
        wallet_path.display()
    ))
}
