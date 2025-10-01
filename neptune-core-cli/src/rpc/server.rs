//! HTTP JSON-RPC server implementation
//!
//! Provides a simple HTTP server that accepts JSON-RPC requests and returns responses.

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info};

use crate::rpc::{
    auth::Cookie,
    handlers::{handle_request, JsonRpcRequest},
};

/// Start the RPC server
pub async fn start(config: crate::rpc::RpcConfig) -> Result<()> {
    let addr = format!("127.0.0.1:{}", config.port);
    let listener = TcpListener::bind(&addr)
        .await
        .context("Failed to bind RPC server")?;

    info!("Starting neptune-cli RPC server on {}", addr);

    // Generate authentication cookie
    let cookie = Cookie::try_new(&config.data_dir)
        .await
        .context("Failed to create authentication cookie")?;

    info!("Authentication cookie generated");

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                let cookie = cookie.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, cookie).await {
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
async fn handle_connection(mut stream: TcpStream, server_cookie: Cookie) -> Result<()> {
    let mut buffer = [0; 4096];

    match stream.read(&mut buffer).await {
        Ok(0) => return Ok(()), // Connection closed
        Ok(n) => {
            let request_str = String::from_utf8_lossy(&buffer[..n]);

            // Parse HTTP request
            let http_request = parse_http_request(&request_str)?;

            // Extract and validate cookie
            let cookie_valid = validate_cookie(&http_request, &server_cookie);

            // Handle JSON-RPC request
            let response = if let Some(json_body) = http_request.body {
                match serde_json::from_str::<JsonRpcRequest>(&json_body) {
                    Ok(req) => {
                        // Check if method requires authentication
                        if requires_auth(&req.method) && !cookie_valid {
                            let error_response = serde_json::json!({
                                "jsonrpc": "2.0",
                                "error": {
                                    "code": -32001,
                                    "message": "Authentication required"
                                },
                                "id": req.id
                            });
                            let response_body = serde_json::to_string(&error_response)?;
                            create_http_response(401, "Unauthorized", &response_body)
                        } else {
                            match handle_request(req).await {
                                Ok(rpc_response) => {
                                    let response_body = serde_json::to_string(&rpc_response)?;
                                    create_http_response(200, "OK", &response_body)
                                }
                                Err(e) => {
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
                create_http_response(400, "Bad Request", "No JSON body found")
            };

            // Send HTTP response
            stream.write_all(response.as_bytes()).await?;
            stream.flush().await?;
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

/// Validate cookie from HTTP request
fn validate_cookie(http_request: &HttpRequest, server_cookie: &Cookie) -> bool {
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
                        return client_cookie == *server_cookie;
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
