//! HTTP JSON-RPC server implementation
//!
//! Provides a simple HTTP server that accepts JSON-RPC requests and returns responses.

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

use crate::rpc::handlers::{handle_request, JsonRpcRequest};
use neptune_cash::application::rpc::auth::{Cookie, Token};

/// Start the RPC server
pub async fn start(config: crate::rpc::RpcConfig) -> Result<()> {
    let addr = format!("127.0.0.1:{}", config.port);
    let listener = TcpListener::bind(&addr)
        .await
        .context("Failed to bind RPC server")?;

    info!("Starting neptune-cli RPC server on {}", addr);
    info!("Data directory: {:?}", config.data_dir);

    // Use neptune-core's existing cookie system (same pattern as main.rs)
    // The data_dir in RpcConfig is already the full path from DataDirectory::get().root_dir_path()
    let data_directory = neptune_cash::application::config::data_directory::DataDirectory::get(
        None, // Use default data directory since config.data_dir is already the full path
        neptune_cash::application::config::network::Network::Main,
    )?;

    // Load cookie using exact same pattern as main.rs
    let token: neptune_cash::application::rpc::auth::Token =
        match neptune_cash::application::rpc::auth::Cookie::try_load(&data_directory).await {
            Ok(t) => t.into(),
            Err(e) => {
                error!("Unable to load RPC auth cookie: {}", e);
                anyhow::bail!("Failed to load authentication cookie: {}", e);
            }
        };

    info!("Authentication cookie ready");
    info!("neptune-cli RPC server is ready to accept connections");

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                debug!("New connection from {}", addr);
                let token = token.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, token).await {
                        error!("Error handling connection from {}: {}", addr, e);
                    }
                });
            }
            Err(e) => {
                error!("Failed to accept connection: {}", e);
            }
        }
    }
}

/// Handle individual HTTP connection
async fn handle_connection(mut stream: TcpStream, server_token: Token) -> Result<()> {
    let mut buffer = [0; 4096];

    match stream.read(&mut buffer).await {
        Ok(0) => {
            debug!("Connection closed by client");
            return Ok(());
        }
        Ok(n) => {
            let request_str = String::from_utf8_lossy(&buffer[..n]);
            debug!("Received HTTP request ({} bytes)", n);

            // Parse HTTP request
            let http_request = parse_http_request(&request_str)?;

            // Extract and validate cookie
            let cookie_valid = validate_cookie(&http_request, &server_token);
            if !cookie_valid {
                warn!("Authentication failed for request");
            } else {
                debug!("Authentication successful");
            }

            // Handle JSON-RPC request
            let response = if let Some(json_body) = http_request.body {
                match serde_json::from_str::<JsonRpcRequest>(&json_body) {
                    Ok(req) => {
                        let method = req.method.clone();
                        let id = req.id.clone();
                        info!("RPC request: method='{}', id={}", method, id);

                        // Check if method requires authentication
                        if requires_auth(&method) && !cookie_valid {
                            warn!("Authentication required for method '{}'", method);
                            let error_response = serde_json::json!({
                                "jsonrpc": "2.0",
                                "error": {
                                    "code": -32001,
                                    "message": "Authentication required"
                                },
                                "id": id
                            });
                            let response_body = serde_json::to_string(&error_response)?;
                            create_http_response(401, "Unauthorized", &response_body)
                        } else {
                            match handle_request(req).await {
                                Ok(rpc_response) => {
                                    debug!("RPC method '{}' completed successfully", method);
                                    let response_body = serde_json::to_string(&rpc_response)?;
                                    create_http_response(200, "OK", &response_body)
                                }
                                Err(e) => {
                                    error!("RPC method '{}' failed: {}", method, e);
                                    let error_response = serde_json::json!({
                                        "jsonrpc": "2.0",
                                        "error": {
                                            "code": -32603,
                                            "message": format!("Internal error: {}", e)
                                        },
                                        "id": null
                                    });
                                    let response_body = serde_json::to_string(&error_response)?;
                                    create_http_response(200, "OK", &response_body)
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to parse JSON-RPC request: {}", e);
                        let error_response = serde_json::json!({
                            "jsonrpc": "2.0",
                            "error": {
                                "code": -32700,
                                "message": format!("Parse error: {}", e)
                            },
                            "id": null
                        });
                        let response_body = serde_json::to_string(&error_response)?;
                        create_http_response(200, "OK", &response_body)
                    }
                }
            } else {
                warn!("Received request without JSON body");
                create_http_response(400, "Bad Request", "No JSON body found")
            };

            // Send HTTP response
            stream.write_all(response.as_bytes()).await?;
            stream.flush().await?;
            debug!("Response sent to client");
        }
        Err(e) => {
            error!("Error reading from stream: {}", e);
        }
    }

    Ok(())
}

/// Simple HTTP request parser
fn parse_http_request(request: &str) -> Result<HttpRequest> {
    let lines: Vec<&str> = request.lines().collect();
    if lines.is_empty() {
        anyhow::bail!("Empty request");
    }

    let request_line = lines[0];
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 3 {
        anyhow::bail!("Invalid HTTP request line");
    }

    let method = parts[0];
    let path = parts[1];
    let version = parts[2];

    // Parse headers
    let mut headers = Vec::new();
    let mut body_start = 0;
    for (i, line) in lines.iter().enumerate() {
        if line.is_empty() {
            body_start = i + 1;
            break;
        }
        if i > 0 {
            // Skip request line
            headers.push(line.to_string());
        }
    }

    // Find body (after empty line)
    let mut body = None;
    if body_start < lines.len() {
        body = Some(lines[body_start..].join("\n"));
    }

    Ok(HttpRequest {
        _method: method.to_string(),
        _path: path.to_string(),
        _version: version.to_string(),
        headers,
        body,
    })
}

/// Simple HTTP request structure
#[derive(Debug)]
struct HttpRequest {
    _method: String,
    _path: String,
    _version: String,
    headers: Vec<String>,
    body: Option<String>,
}

/// Validate cookie from HTTP request using neptune-core's Token system
fn validate_cookie(http_request: &HttpRequest, server_token: &Token) -> bool {
    // Look for Cookie header
    for line in http_request.headers.iter() {
        if line.to_lowercase().starts_with("cookie:") {
            let cookie_value = line.split(':').nth(1).unwrap_or("").trim();
            // Look for neptune-cli=value format
            if let Some(cookie_part) = cookie_value
                .split(';')
                .find(|part| part.trim().starts_with("neptune-cli="))
            {
                let hex_value = cookie_part.split('=').nth(1).unwrap_or("").trim();
                if let Ok(cookie_bytes) = hex::decode(hex_value) {
                    if cookie_bytes.len() == 32 {
                        let mut cookie_array = [0u8; 32];
                        cookie_array.copy_from_slice(&cookie_bytes);
                        let client_cookie = Cookie::from(cookie_array);
                        // Extract the cookie from the server token for comparison
                        if let Token::Cookie(server_cookie) = server_token {
                            return client_cookie.auth(server_cookie).is_ok();
                        }
                    }
                }
            }
        }
    }
    false
}

/// Check if a method requires authentication
fn requires_auth(_method: &str) -> bool {
    // All methods require authentication for security
    true
}

/// Create HTTP response
fn create_http_response(status_code: u16, status_text: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {} {}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Access-Control-Allow-Methods: POST, GET, OPTIONS\r\n\
         Access-Control-Allow-Headers: Content-Type\r\n\
         \r\n\
         {}",
        status_code,
        status_text,
        body.len(),
        body
    )
}
