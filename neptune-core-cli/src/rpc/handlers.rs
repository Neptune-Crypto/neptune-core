//! Request handlers for RPC server
//!
//! Handles JSON-RPC requests and routes them to appropriate handlers.

use anyhow::Result;
use neptune_cash::api::export::{
    AdditionRecord, BlockHeight, TxCreationArtifacts,
};
use neptune_cash::application::config::data_directory::DataDirectory;
use neptune_cash::application::config::network::Network;
use neptune_cash::application::rpc::auth;
use neptune_cash::application::rpc::server::error::RpcError;
use neptune_cash::application::rpc::server::RPCClient;
use neptune_cash::protocol::consensus::block::{
    Block, block_header::BlockPow,
};
use neptune_cash::protocol::consensus::block::block_selector::BlockSelector;
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
pub async fn handle_request(request: JsonRpcRequest, neptune_core_port: u16) -> Result<JsonRpcResponse> {
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
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
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
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();
            let balance = client.confirmed_available_balance(ctx, token).await??;
            let result = serde_json::Value::String(balance.to_string());
            Ok(JsonRpcResponse::success(request.id, result))
        }

        "dashboard_overview_data" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
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
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
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
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();
            let wallet_status = client.wallet_status(ctx, token).await??;
            let result = serde_json::to_value(wallet_status)?;
            Ok(JsonRpcResponse::success(request.id, result))
        }

        "confirmations" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();
            let confirmations = client.confirmations(ctx, token).await??;
            let result = match confirmations {
                Some(c) => serde_json::Value::String(c.to_string()),
                None => serde_json::Value::Null,
            };
            Ok(JsonRpcResponse::success(request.id, result))
        }

        "send" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();

            // Get network from client (for parsing addresses)
            let network = client.network(ctx).await??;

            // Extract parameters as JSON values (not strings!)
            let outputs_json = extract_param(&request.params, "outputs")?;
            let fee_str = extract_param(&request.params, "fee")
                .ok()
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_else(|| "0".to_string());

            // Parse outputs from wallet-friendly format: [{"address": "nolgam1...", "amount": "123"}]
            // Convert to Neptune's OutputFormat enum with proper address parsing
            let outputs_array = outputs_json.as_array()
                .ok_or_else(|| anyhow::anyhow!("outputs must be an array"))?;

            let mut outputs_parsed: Vec<neptune_cash::api::export::OutputFormat> = Vec::new();
            for (idx, output) in outputs_array.iter().enumerate() {
                let address_str = output.get("address")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'address' in output {}", idx))?;
                let amount_str = output.get("amount")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'amount' in output {}", idx))?;

                // Parse bech32m address to ReceivingAddress enum
                let receiving_address = neptune_cash::api::export::ReceivingAddress::from_bech32m(address_str, network)?;

                // Parse amount from decimal string (e.g. "0.1" or "123.456")
                let amount = neptune_cash::api::export::NativeCurrencyAmount::coins_from_str(amount_str)?;

                // Create OutputFormat::AddressAndAmount variant
                outputs_parsed.push(neptune_cash::api::export::OutputFormat::AddressAndAmount(
                    receiving_address,
                    amount,
                ));
            }

            // Use default change policy: RecoverToNextUnusedKey with Generation key and OnChain medium
            let change_policy = neptune_cash::api::export::ChangePolicy::recover_to_next_unused_key(
                neptune_cash::api::export::KeyType::Generation,
                neptune_cash::state::wallet::utxo_notification::UtxoNotificationMedium::OnChain,
            );

            // Parse fee from decimal string
            let fee = neptune_cash::api::export::NativeCurrencyAmount::coins_from_str(&fee_str)?;

            // Send transaction
            let tx_artifacts = client
                .send(ctx, token, outputs_parsed, change_policy, fee)
                .await??;
            let result = serde_json::to_value(tx_artifacts)?;
            Ok(JsonRpcResponse::success(request.id, result))
        }

        "claim_utxo" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
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
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();
            let coins = client.list_own_coins(ctx, token).await??;

            // Manually construct JSON to avoid "number out of range" errors
            let coins_json: Vec<serde_json::Value> = coins.into_iter().map(|coin| {
                serde_json::json!({
                    "amount": coin.amount.to_string(),
                    "confirmed": coin.confirmed.to_string(),
                    "release_date": coin.release_date.map(|d| d.to_string())
                })
            }).collect();

            Ok(JsonRpcResponse::success(request.id, serde_json::Value::Array(coins_json)))
        }

        "history" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();
            let history = client.history(ctx, token).await??;

            // Manually construct JSON to avoid "number out of range" errors
            let history_json: Vec<serde_json::Value> = history.into_iter().map(|(digest, height, timestamp, amount)| {
                serde_json::json!({
                    "digest": digest.to_hex(),
                    "height": height.to_string(),
                    "timestamp": timestamp.to_string(),
                    "amount": amount.to_string()
                })
            }).collect();

            Ok(JsonRpcResponse::success(request.id, serde_json::Value::Array(history_json)))
        }

        "validate_address" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
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
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();
            let amount = extract_string_param(&request.params, "amount")
                .ok_or_else(|| anyhow::anyhow!("Missing amount parameter"))?;
            let is_valid = client.validate_amount(ctx, token, amount).await??;
            let result = serde_json::Value::Bool(is_valid.is_some());
            Ok(JsonRpcResponse::success(request.id, result))
        }

        // ============================================================================
        // WALLET-SPECIFIC WRAPPER ENDPOINTS
        // ============================================================================

        "get_balance" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();

            // Get both balances in parallel
            let (confirmed_result, unconfirmed_result) = tokio::try_join!(
                client.confirmed_available_balance(ctx.clone(), token.clone()),
                client.unconfirmed_available_balance(ctx, token)
            )?;

            let confirmed = confirmed_result?;
            let unconfirmed = unconfirmed_result?;

            // Transform to wallet format
            let balance_info = serde_json::json!({
                "confirmed": confirmed.to_string(),
                "unconfirmed": unconfirmed.to_string(),
                "lastUpdated": chrono::Utc::now().to_rfc3339()
            });

            Ok(JsonRpcResponse::success(request.id, balance_info))
        }

        "get_network_info" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();

            // Get network, block height, and tip digest in parallel
            let (network_result, height_result, dashboard_result) = tokio::try_join!(
                client.network(ctx.clone()),
                client.block_height(ctx.clone(), token.clone()),
                client.dashboard_overview_data(ctx, token)
            )?;

            let network = network_result?;
            let height = height_result?;
            let dashboard = dashboard_result?;

            // Transform to wallet format
            let network_info = serde_json::json!({
                "network": network.to_string(),
                "blockHeight": height.to_string(),
                "tipDigest": dashboard.tip_digest.to_hex(),
                "lastUpdated": chrono::Utc::now().to_rfc3339()
            });

            Ok(JsonRpcResponse::success(request.id, network_info))
        }

        "get_peer_info" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();
            let peer_info = client.peer_info(ctx, token).await??;

            // Transform complex peer info to simplified wallet format
            let peers_json: Vec<serde_json::Value> = peer_info.into_iter().map(|peer| {
                serde_json::json!({
                    "address": peer.connected_address().to_string(),
                    "connected": true, // If we got the peer info, it's connected
                    "lastSeen": peer.connection_established().duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs()
                })
            }).collect();

            let peer_info_wallet = serde_json::json!({
                "peers": peers_json,
                "connectedCount": peers_json.len(),
                "lastUpdated": chrono::Utc::now().to_rfc3339()
            });

            Ok(JsonRpcResponse::success(request.id, peer_info_wallet))
        }

        "get_sync_status" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();
            let dashboard = client.dashboard_overview_data(ctx, token).await??;

            // Transform dashboard data to sync status format
            let sync_status = serde_json::json!({
                "isSynced": !dashboard.syncing,
                "currentBlockHeight": dashboard.tip_header.height.to_string(),
                "latestBlockHash": dashboard.tip_digest.to_hex(),
                "connectedPeers": dashboard.peer_count.unwrap_or(0),
                "pendingTransactions": dashboard.mempool_total_tx_count,
                "lastSyncCheck": chrono::Utc::now().to_rfc3339()
            });

            Ok(JsonRpcResponse::success(request.id, sync_status))
        }

        // ============================================================================
        // BATCH 1: ESSENTIAL WALLET OPERATIONS
        // ============================================================================


        "send_transparent" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();

            // Extract parameters
            let outputs = extract_param(&request.params, "outputs")?;
            let _change_policy = extract_param(&request.params, "change_policy")
                .unwrap_or_else(|_| serde_json::Value::String("default".to_string()));
            let fee = extract_param(&request.params, "fee")?;

            // Parse parameters
            let outputs_vec: Vec<neptune_cash::api::export::OutputFormat> = serde_json::from_value(outputs)?;
            let change_policy_enum = neptune_cash::api::export::ChangePolicy::default(); // Simplified
            let fee_amount: neptune_cash::api::export::NativeCurrencyAmount = serde_json::from_value(fee)?;

            let result = client.send_transparent(ctx, token, outputs_vec, change_policy_enum, fee_amount).await??;
            let result_json = serde_json::to_value(result)?;
            Ok(JsonRpcResponse::success(request.id, result_json))
        }


        "mempool_overview" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();

            // Extract parameters with defaults
            let start_index = extract_param(&request.params, "start_index")
                .ok()
                .and_then(|v| v.as_u64())
                .map(|v| v as usize)
                .unwrap_or(0);
            let number = extract_param(&request.params, "number")
                .ok()
                .and_then(|v| v.as_u64())
                .map(|v| v as usize)
                .unwrap_or(10);

            let overview = client.mempool_overview(ctx, token, start_index, number).await??;
            let result = serde_json::to_value(overview)?;
            Ok(JsonRpcResponse::success(request.id, result))
        }

        "mempool_tx_ids" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();
            let tx_ids = client.mempool_tx_ids(ctx, token).await??;
            let result = serde_json::to_value(tx_ids)?;
            Ok(JsonRpcResponse::success(request.id, result))
        }

        "mempool_size" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();
            let size = client.mempool_size(ctx, token).await??;
            Ok(JsonRpcResponse::success(request.id, serde_json::Value::Number(serde_json::Number::from(size))))
        }

        "num_expected_utxos" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();
            let count = client.num_expected_utxos(ctx, token).await??;
            Ok(JsonRpcResponse::success(request.id, serde_json::Value::String(count.to_string())))
        }

        "list_utxos" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();
            let utxos = client.list_utxos(ctx, token).await??;

            // Manually construct JSON to avoid "number out of range" errors
            let utxos_json: Vec<serde_json::Value> = utxos.into_iter().map(|utxo| {
                let received_json = match utxo.received {
                    neptune_cash::application::rpc::server::ui_utxo::UtxoStatusEvent::Confirmed { block_height, timestamp } => {
                        serde_json::json!({
                            "type": "Confirmed",
                            "block_height": block_height.to_string(),
                            "timestamp": timestamp.to_string()
                        })
                    },
                    neptune_cash::application::rpc::server::ui_utxo::UtxoStatusEvent::Pending => {
                        serde_json::json!({"type": "Pending"})
                    },
                    neptune_cash::application::rpc::server::ui_utxo::UtxoStatusEvent::Expected => {
                        serde_json::json!({"type": "Expected"})
                    },
                    neptune_cash::application::rpc::server::ui_utxo::UtxoStatusEvent::Abandoned => {
                        serde_json::json!({"type": "Abandoned"})
                    },
                    neptune_cash::application::rpc::server::ui_utxo::UtxoStatusEvent::None => {
                        serde_json::json!({"type": "None"})
                    },
                };

                let spent_json = match utxo.spent {
                    neptune_cash::application::rpc::server::ui_utxo::UtxoStatusEvent::Confirmed { block_height, timestamp } => {
                        serde_json::json!({
                            "type": "Confirmed",
                            "block_height": block_height.to_string(),
                            "timestamp": timestamp.to_string()
                        })
                    },
                    neptune_cash::application::rpc::server::ui_utxo::UtxoStatusEvent::Pending => {
                        serde_json::json!({"type": "Pending"})
                    },
                    neptune_cash::application::rpc::server::ui_utxo::UtxoStatusEvent::Expected => {
                        serde_json::json!({"type": "Expected"})
                    },
                    neptune_cash::application::rpc::server::ui_utxo::UtxoStatusEvent::Abandoned => {
                        serde_json::json!({"type": "Abandoned"})
                    },
                    neptune_cash::application::rpc::server::ui_utxo::UtxoStatusEvent::None => {
                        serde_json::json!({"type": "None"})
                    },
                };

                serde_json::json!({
                    "received": received_json,
                    "aocl_leaf_index": utxo.aocl_leaf_index.map(|i| i.to_string()),
                    "spent": spent_json,
                    "amount": {
                        "value": utxo.amount.to_string()
                    },
                    "release_date": utxo.release_date.map(|d| d.to_string())
                })
            }).collect();

            Ok(JsonRpcResponse::success(request.id, serde_json::Value::Array(utxos_json)))
        }

        // ============================================================================
        // BATCH 2: MINING & PROOF OF WORK
        // ============================================================================

        "pow_puzzle_internal_key" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();
            let puzzle = client.pow_puzzle_internal_key(ctx, token).await??;
            let result = serde_json::to_value(puzzle)?;
            Ok(JsonRpcResponse::success(request.id, result))
        }

        "pow_puzzle_external_key" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();

            // Extract parameters
            let guesser_fee_address = extract_string_param(&request.params, "guesser_fee_address")
                .ok_or_else(|| anyhow::anyhow!("Missing guesser_fee_address parameter"))?;
            let network = neptune_cash::application::config::network::Network::Main; // Default to main network
            let address = neptune_cash::api::export::ReceivingAddress::from_bech32m(&guesser_fee_address, network)?;

            let puzzle = client.pow_puzzle_external_key(ctx, token, address).await??;
            let result = serde_json::to_value(puzzle)?;
            Ok(JsonRpcResponse::success(request.id, result))
        }

        "full_pow_puzzle_external_key" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();

            // Extract parameters
            let guesser_fee_address = extract_string_param(&request.params, "guesser_fee_address")
                .ok_or_else(|| anyhow::anyhow!("Missing guesser_fee_address parameter"))?;
            let network = neptune_cash::application::config::network::Network::Main; // Default to main network
            let address = neptune_cash::api::export::ReceivingAddress::from_bech32m(&guesser_fee_address, network)?;

            let result = client.full_pow_puzzle_external_key(ctx, token, address).await??;
            let result_json = serde_json::to_value(result)?;
            Ok(JsonRpcResponse::success(request.id, result_json))
        }

        "spendable_inputs" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();
            let inputs = client.spendable_inputs(ctx, token).await??;
            let result = serde_json::to_value(inputs)?;
            Ok(JsonRpcResponse::success(request.id, result))
        }

        "select_spendable_inputs" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();

            // Extract parameters
            let amount = extract_param(&request.params, "amount")?;
            let amount_value: neptune_cash::api::export::NativeCurrencyAmount = serde_json::from_value(amount)?;
            let policy = neptune_cash::api::export::InputSelectionPolicy::default(); // Use default policy

            let inputs = client.select_spendable_inputs(ctx, token, policy, amount_value).await??;
            let result = serde_json::to_value(inputs)?;
            Ok(JsonRpcResponse::success(request.id, result))
        }

        "pause_miner" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();
            client.pause_miner(ctx, token).await??;
            Ok(JsonRpcResponse::success(request.id, serde_json::Value::String("Miner paused".to_string())))
        }

        "restart_miner" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();
            client.restart_miner(ctx, token).await??;
            Ok(JsonRpcResponse::success(request.id, serde_json::Value::String("Miner restarted".to_string())))
        }

        "mine_blocks_to_wallet" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();

            // Extract parameters
            let n_blocks = extract_param(&request.params, "n_blocks")?
                .as_u64()
                .ok_or_else(|| anyhow::anyhow!("Missing or invalid n_blocks parameter"))? as u32;

            client.mine_blocks_to_wallet(ctx, token, n_blocks).await??;
            Ok(JsonRpcResponse::success(request.id, serde_json::Value::String(format!("Mined {} blocks to wallet", n_blocks))))
        }

        // ============================================================================
        // BATCH 3: TRANSACTION ASSEMBLY
        // ============================================================================

        "generate_tx_outputs" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();

            // Extract parameters
            let outputs = extract_param(&request.params, "outputs")?;
            let outputs_list: Vec<neptune_cash::api::export::OutputFormat> = serde_json::from_value(outputs)?;

            let result = client.generate_tx_outputs(ctx, token, outputs_list).await??;
            let result_json = serde_json::to_value(result)?;
            Ok(JsonRpcResponse::success(request.id, result_json))
        }

        "generate_tx_details" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();

            // Extract parameters
            let inputs = extract_param(&request.params, "inputs")?;
            let outputs = extract_param(&request.params, "outputs")?;
            let _change_policy = extract_param(&request.params, "change_policy")?;
            let fee = extract_param(&request.params, "fee")?;

            let inputs_list: neptune_cash::api::export::TxInputList = serde_json::from_value(inputs)?;
            let outputs_list: neptune_cash::api::export::TxOutputList = serde_json::from_value(outputs)?;
            let change_policy_value: neptune_cash::api::export::ChangePolicy = serde_json::from_value(_change_policy)?;
            let fee_value: neptune_cash::api::export::NativeCurrencyAmount = serde_json::from_value(fee)?;

            let result = client.generate_tx_details(ctx, token, inputs_list, outputs_list, change_policy_value, fee_value).await??;
            let result_json = serde_json::to_value(result)?;
            Ok(JsonRpcResponse::success(request.id, result_json))
        }

        "generate_witness_proof" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();

            // Extract parameters
            let tx_details = extract_param(&request.params, "tx_details")?;
            let tx_details_value: neptune_cash::api::export::TransactionDetails = serde_json::from_value(tx_details)?;

            let result = client.generate_witness_proof(ctx, token, tx_details_value).await??;
            let result_json = serde_json::to_value(result)?;
            Ok(JsonRpcResponse::success(request.id, result_json))
        }

        "assemble_transaction" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();

            // Extract parameters
            let tx_details = extract_param(&request.params, "tx_details")?;
            let tx_proof = extract_param(&request.params, "tx_proof")?;

            let tx_details_value: neptune_cash::api::export::TransactionDetails = serde_json::from_value(tx_details)?;
            let tx_proof_value: neptune_cash::api::export::TransactionProof = serde_json::from_value(tx_proof)?;

            let result = client.assemble_transaction(ctx, token, tx_details_value, tx_proof_value).await??;
            let result_json = serde_json::to_value(result)?;
            Ok(JsonRpcResponse::success(request.id, result_json))
        }

        "assemble_transaction_artifacts" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();

            // Extract parameters
            let tx_details = extract_param(&request.params, "tx_details")?;
            let tx_proof = extract_param(&request.params, "tx_proof")?;

            let tx_details_value: neptune_cash::api::export::TransactionDetails = serde_json::from_value(tx_details)?;
            let tx_proof_value: neptune_cash::api::export::TransactionProof = serde_json::from_value(tx_proof)?;

            let result = client.assemble_transaction_artifacts(ctx, token, tx_details_value, tx_proof_value).await??;
            let result_json = serde_json::to_value(result)?;
            Ok(JsonRpcResponse::success(request.id, result_json))
        }

        "peer_info" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();
            let peers = client.peer_info(ctx, token).await??;

            // Manually construct JSON to avoid "number out of range" errors
            let peers_json: Vec<serde_json::Value> = peers.into_iter().map(|peer| {
                serde_json::json!({
                    "address": peer.connected_address().to_string(),
                    "connected": true,
                    "lastSeen": peer.connection_established().duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs()
                })
            }).collect();

            Ok(JsonRpcResponse::success(request.id, serde_json::Value::Array(peers_json)))
        }

        "mempool_tx_count" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();
            let count = client.mempool_tx_count(ctx, token).await??;
            let result = serde_json::Value::Number(serde_json::Number::from(count));
            Ok(JsonRpcResponse::success(request.id, result))
        }

        "unconfirmed_available_balance" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();
            let balance = client.unconfirmed_available_balance(ctx, token).await??;
            let result = serde_json::Value::String(balance.to_string());
            Ok(JsonRpcResponse::success(request.id, result))
        }

        // Phase 3: Advanced Features

        "upgrade" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();
            let tx_kernel_id = extract_string_param(&request.params, "tx_kernel_id")
                .ok_or_else(|| anyhow::anyhow!("Missing tx_kernel_id parameter"))?;
            let tx_kernel_id_parsed: neptune_cash::api::export::TransactionKernelId =
                serde_json::from_str(&tx_kernel_id)?;

            let upgraded = client.upgrade(ctx, token, tx_kernel_id_parsed).await??;
            let result = serde_json::Value::Bool(upgraded);
            Ok(JsonRpcResponse::success(request.id, result))
        }


        "shutdown" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();
            let shutdown_result = client.shutdown(ctx, token).await??;
            let result = serde_json::Value::Bool(shutdown_result);
            Ok(JsonRpcResponse::success(request.id, result))
        }

        // ============================================================================
        // REMAINING ENDPOINTS FOR FULL RPC TRAIT COVERAGE
        // ============================================================================

        // Blockchain Operations
        "addition_record_indices_for_block" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();

            let block_selector = extract_param(&request.params, "block_selector")?;
            let block_selector_value: BlockSelector = serde_json::from_value(block_selector)?;

            let result = client.addition_record_indices_for_block(ctx, token, block_selector_value).await??;
            let result_json = serde_json::to_value(result)?;
            Ok(JsonRpcResponse::success(request.id, result_json))
        }

        "all_punished_peers" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();
            let result = client.all_punished_peers(ctx, token).await??;
            let result_json = serde_json::to_value(result)?;
            Ok(JsonRpcResponse::success(request.id, result_json))
        }

        "amount_leq_confirmed_available_balance" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();

            let amount = extract_param(&request.params, "amount")?;
            let amount_value: neptune_cash::api::export::NativeCurrencyAmount = serde_json::from_value(amount)?;

            let result = client.amount_leq_confirmed_available_balance(ctx, token, amount_value).await??;
            Ok(JsonRpcResponse::success(request.id, serde_json::Value::Bool(result)))
        }

        "announcements_in_block" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();

            let block_selector = extract_param(&request.params, "block_selector")?;
            let block_selector_value: BlockSelector = serde_json::from_value(block_selector)?;

            let result = client.announcements_in_block(ctx, token, block_selector_value).await??;
            let result_json = serde_json::to_value(result)?;
            Ok(JsonRpcResponse::success(request.id, result_json))
        }

        "best_proposal" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();
            let result = client.best_proposal(ctx, token).await??;
            let result_json = serde_json::to_value(result)?;
            Ok(JsonRpcResponse::success(request.id, result_json))
        }

        "block_difficulties" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();

            let block_selector = extract_param(&request.params, "block_selector")?;
            let block_selector_value: BlockSelector = serde_json::from_value(block_selector)?;
            let max_num_blocks = extract_param(&request.params, "max_num_blocks")
                .ok()
                .and_then(|v| v.as_u64())
                .map(|v| v as usize);

            let result = client.block_difficulties(ctx, token, block_selector_value, max_num_blocks).await??;
            let result_json = serde_json::to_value(result)?;
            Ok(JsonRpcResponse::success(request.id, result_json))
        }

        "block_digest" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();

            let block_selector = extract_param(&request.params, "block_selector")?;
            let block_selector_value: BlockSelector = serde_json::from_value(block_selector)?;

            let result = client.block_digest(ctx, token, block_selector_value).await??;

            // Manually construct JSON to avoid "number out of range" errors
            let result_json = match result {
                Some(digest) => serde_json::json!({
                    "digest": digest.to_string(),
                    "found": true,
                    "lastUpdated": chrono::Utc::now().to_rfc3339()
                }),
                None => serde_json::json!({
                    "digest": null,
                    "found": false,
                    "lastUpdated": chrono::Utc::now().to_rfc3339()
                })
            };
            Ok(JsonRpcResponse::success(request.id, result_json))
        }

        "block_digests_by_height" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();

            let height = extract_param(&request.params, "height")?
                .as_u64()
                .ok_or_else(|| anyhow::anyhow!("Missing or invalid height parameter"))? as u32;

            let result = client.block_digests_by_height(ctx, token, BlockHeight::from(height as u64)).await??;

            // Manually construct JSON to avoid "number out of range" errors
            let digests: Vec<String> = result.iter().map(|d| d.to_string()).collect();
            let result_json = serde_json::json!({
                "digests": digests,
                "height": height.to_string(),
                "count": result.len(),
                "lastUpdated": chrono::Utc::now().to_rfc3339()
            });
            Ok(JsonRpcResponse::success(request.id, result_json))
        }

        "block_info" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();

            let block_selector = extract_param(&request.params, "block_selector")?;
            let block_selector_value: BlockSelector = serde_json::from_value(block_selector)?;

            let result = client.block_info(ctx, token, block_selector_value).await??;
            let result_json = serde_json::to_value(result)?;
            Ok(JsonRpcResponse::success(request.id, result_json))
        }

        "block_intervals" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();

            let block_selector = extract_param(&request.params, "block_selector")?;
            let block_selector_value: BlockSelector = serde_json::from_value(block_selector)?;
            let max_num_blocks = extract_param(&request.params, "max_num_blocks")
                .ok()
                .and_then(|v| v.as_u64())
                .map(|v| v as usize);

            let result = client.block_intervals(ctx, token, block_selector_value, max_num_blocks).await??;
            let result_json = serde_json::to_value(result)?;
            Ok(JsonRpcResponse::success(request.id, result_json))
        }

        "block_kernel" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();

            let block_selector = extract_param(&request.params, "block_selector")?;
            let block_selector_value: BlockSelector = serde_json::from_value(block_selector)?;

            let result = client.block_kernel(ctx, token, block_selector_value).await??;
            let result_json = serde_json::to_value(result)?;
            Ok(JsonRpcResponse::success(request.id, result_json))
        }

        "broadcast_all_mempool_txs" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();
            client.broadcast_all_mempool_txs(ctx, token).await??;
            Ok(JsonRpcResponse::success(request.id, serde_json::Value::String("All mempool transactions broadcasted".to_string())))
        }

        // Network Management
        "broadcast_block_proposal" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();

            client.broadcast_block_proposal(ctx, token).await??;
            Ok(JsonRpcResponse::success(request.id, serde_json::Value::String("Block proposal broadcasted".to_string())))
        }

        "clear_all_standings" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();
            client.clear_all_standings(ctx, token).await??;
            Ok(JsonRpcResponse::success(request.id, serde_json::Value::String("All peer standings cleared".to_string())))
        }

        "clear_mempool" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();
            client.clear_mempool(ctx, token).await??;
            Ok(JsonRpcResponse::success(request.id, serde_json::Value::String("Mempool cleared".to_string())))
        }

        "clear_standing_by_ip" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();

            let ip_param = extract_param(&request.params, "ip")?;
            let ip = ip_param.as_str()
                .ok_or_else(|| anyhow::anyhow!("Missing or invalid ip parameter"))?;
            let ip_addr: std::net::IpAddr = ip.parse()?;

            client.clear_standing_by_ip(ctx, token, ip_addr).await??;
            Ok(JsonRpcResponse::success(request.id, serde_json::Value::String("Peer standing cleared".to_string())))
        }

        // Advanced Operations
        "cookie_hint" => {
            let (client, _token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();
            let result = client.cookie_hint(ctx).await??;
            let result_json = serde_json::to_value(result)?;
            Ok(JsonRpcResponse::success(request.id, result_json))
        }

        "cpu_temp" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();
            let result = client.cpu_temp(ctx, token).await??;
            let result_json = serde_json::to_value(result)?;
            Ok(JsonRpcResponse::success(request.id, result_json))
        }

        "freeze" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();
            client.freeze(ctx, token).await??;
            Ok(JsonRpcResponse::success(request.id, serde_json::Value::String("Node frozen".to_string())))
        }

        "unfreeze" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();
            client.unfreeze(ctx, token).await??;
            Ok(JsonRpcResponse::success(request.id, serde_json::Value::String("Node unfrozen".to_string())))
        }

        "header" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();

            let block_selector = extract_param(&request.params, "block_selector")?;
            let block_selector_value: BlockSelector = serde_json::from_value(block_selector)?;

            let result = client.header(ctx, token, block_selector_value).await??;
            let result_json = serde_json::to_value(result)?;
            Ok(JsonRpcResponse::success(request.id, result_json))
        }

        "known_keys" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();
            let result = client.known_keys(ctx, token).await??;
            let result_json = serde_json::to_value(result)?;
            Ok(JsonRpcResponse::success(request.id, result_json))
        }

        "known_keys_by_keytype" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();

            let key_type = extract_param(&request.params, "key_type")?;
            let key_type_value: neptune_cash::api::export::KeyType = serde_json::from_value(key_type)?;

            let result = client.known_keys_by_keytype(ctx, token, key_type_value).await??;
            let result_json = serde_json::to_value(result)?;
            Ok(JsonRpcResponse::success(request.id, result_json))
        }

        "latest_tip_digests" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();

            let n = extract_param(&request.params, "n")?
                .as_u64()
                .ok_or_else(|| anyhow::anyhow!("Missing or invalid n parameter"))? as usize;

            let result = client.latest_tip_digests(ctx, token, n).await??;

            // Manually construct JSON to avoid "number out of range" errors
            let digests: Vec<String> = result.iter().map(|d| d.to_string()).collect();
            let result_json = serde_json::json!({
                "digests": digests,
                "count": result.len(),
                "requested": n,
                "lastUpdated": chrono::Utc::now().to_rfc3339()
            });
            Ok(JsonRpcResponse::success(request.id, result_json))
        }

        // UTXO & Transaction Management
        "mempool_tx_kernel" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();

            let tx_kernel_id = extract_param(&request.params, "tx_kernel_id")?;
            let tx_kernel_id_value: neptune_cash::api::export::TransactionKernelId = serde_json::from_value(tx_kernel_id)?;

            let result = client.mempool_tx_kernel(ctx, token, tx_kernel_id_value).await??;
            let result_json = serde_json::to_value(result)?;
            Ok(JsonRpcResponse::success(request.id, result_json))
        }

        "own_instance_id" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();
            let result = client.own_instance_id(ctx, token).await??;

            // Manually construct JSON to avoid "number out of range" errors
            let result_json = serde_json::json!({
                "instance_id": result.to_string(),
                "lastUpdated": chrono::Utc::now().to_rfc3339()
            });
            Ok(JsonRpcResponse::success(request.id, result_json))
        }

        "own_listen_address_for_peers" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();
            let result = client.own_listen_address_for_peers(ctx, token).await??;
            let result_json = serde_json::to_value(result)?;
            Ok(JsonRpcResponse::success(request.id, result_json))
        }

        "proof_type" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();

            let txid = extract_param(&request.params, "txid")?;
            let txid_value: neptune_cash::api::export::TransactionKernelId = serde_json::from_value(txid)?;

            let result = client.proof_type(ctx, token, txid_value).await??;
            let result_json = serde_json::to_value(result)?;
            Ok(JsonRpcResponse::success(request.id, result_json))
        }

        // Advanced Blockchain
        "provide_new_tip" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();

            let pow = extract_param(&request.params, "pow")?;
            let block_proposal = extract_param(&request.params, "block_proposal")?;

            let pow_value: BlockPow = serde_json::from_value(pow)?;
            let block_proposal_value: Block = serde_json::from_value(block_proposal)?;

            let result = client.provide_new_tip(ctx, token, pow_value, block_proposal_value).await??;
            Ok(JsonRpcResponse::success(request.id, serde_json::Value::Bool(result)))
        }

        "provide_pow_solution" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();

            let pow = extract_param(&request.params, "pow")?;
            let proposal_id = extract_param(&request.params, "proposal_id")?;

            let pow_value: BlockPow = serde_json::from_value(pow)?;
            let proposal_id_value: neptune_cash::api::export::Digest = serde_json::from_value(proposal_id)?;

            let result = client.provide_pow_solution(ctx, token, pow_value, proposal_id_value).await??;
            Ok(JsonRpcResponse::success(request.id, serde_json::Value::Bool(result)))
        }

        "prune_abandoned_monitored_utxos" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();
            let result = client.prune_abandoned_monitored_utxos(ctx, token).await??;
            Ok(JsonRpcResponse::success(request.id, serde_json::Value::Number(serde_json::Number::from(result))))
        }

        "record_and_broadcast_transaction" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();

            let tx_artifacts = extract_param(&request.params, "tx_artifacts")?;
            let tx_artifacts_value: TxCreationArtifacts = serde_json::from_value(tx_artifacts)?;

            client.record_and_broadcast_transaction(ctx, token, tx_artifacts_value).await??;
            Ok(JsonRpcResponse::success(request.id, serde_json::Value::String("Transaction recorded and broadcasted".to_string())))
        }

        // Utilities
        "set_tip" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();

            let indicated_tip = extract_param(&request.params, "indicated_tip")?;
            let indicated_tip_value: neptune_cash::api::export::Digest = serde_json::from_value(indicated_tip)?;

            client.set_tip(ctx, token, indicated_tip_value).await??;
            Ok(JsonRpcResponse::success(request.id, serde_json::Value::String("Tip set".to_string())))
        }

        "utxo_digest" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();

            let leaf_index = extract_param(&request.params, "leaf_index")?
                .as_u64()
                .ok_or_else(|| anyhow::anyhow!("Missing or invalid leaf_index parameter"))?;

            let result = client.utxo_digest(ctx, token, leaf_index).await??;

            // Manually construct JSON to avoid "number out of range" errors
            let result_json = match result {
                Some(digest) => serde_json::json!({
                    "digest": digest.to_string(),
                    "leaf_index": leaf_index.to_string(),
                    "found": true,
                    "lastUpdated": chrono::Utc::now().to_rfc3339()
                }),
                None => serde_json::json!({
                    "digest": null,
                    "leaf_index": leaf_index.to_string(),
                    "found": false,
                    "lastUpdated": chrono::Utc::now().to_rfc3339()
                })
            };
            Ok(JsonRpcResponse::success(request.id, result_json))
        }

        "utxo_origin_block" => {
            let (client, token) = connect_to_neptune_core(neptune_core_port, None).await?;
            let ctx = context::current();

            let addition_record = extract_param(&request.params, "addition_record")?;
            let addition_record_value: AdditionRecord = serde_json::from_value(addition_record)?;
            let max_search_depth = extract_param(&request.params, "max_search_depth")
                .ok()
                .and_then(|v| v.as_u64())
                .map(|v| v as u64);

            let result = client.utxo_origin_block(ctx, token, addition_record_value, max_search_depth).await??;
            let result_json = serde_json::to_value(result)?;
            Ok(JsonRpcResponse::success(request.id, result_json))
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

fn extract_param(params: &Option<serde_json::Value>, key: &str) -> Result<serde_json::Value> {
    let value = params
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Missing parameters"))?
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("Invalid parameters"))?
        .get(key)
        .ok_or_else(|| anyhow::anyhow!("Missing '{}' parameter", key))?
        .clone();
    Ok(value)
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
