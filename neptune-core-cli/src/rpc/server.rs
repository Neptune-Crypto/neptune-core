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
async fn handle_connection(mut stream: TcpStream, _cookie: Cookie) -> Result<()> {
    let mut buffer = [0; 4096];

    match stream.read(&mut buffer).await {
        Ok(0) => return Ok(()), // Connection closed
        Ok(n) => {
            let request_str = String::from_utf8_lossy(&buffer[..n]);

            // Parse HTTP request
            let http_request = parse_http_request(&request_str)?;

            // Handle JSON-RPC request
            let response = if let Some(json_body) = http_request.body {
                match serde_json::from_str::<JsonRpcRequest>(&json_body) {
                    Ok(req) => match handle_request(req).await {
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
                    },
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

    // Find body (after empty line)
    let mut body = None;
    for (i, line) in lines.iter().enumerate() {
        if line.is_empty() && i + 1 < lines.len() {
            body = Some(lines[i + 1..].join("\n"));
            break;
        }
    }

    Ok(HttpRequest {
        method: method.to_string(),
        path: path.to_string(),
        version: version.to_string(),
        body,
    })
}

/// Simple HTTP request structure
#[derive(Debug)]
struct HttpRequest {
    method: String,
    path: String,
    version: String,
    body: Option<String>,
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
