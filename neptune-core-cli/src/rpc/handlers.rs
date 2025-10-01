//! Request handlers for RPC server
//!
//! Handles JSON-RPC requests and routes them to appropriate handlers.

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// JSON-RPC request structure
#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    pub params: Option<serde_json::Value>,
    pub id: serde_json::Value,
}

/// JSON-RPC response structure
#[derive(Debug, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    pub id: serde_json::Value,
}

/// JSON-RPC error structure
#[derive(Debug, Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl JsonRpcResponse {
    /// Create success response
    pub fn success(id: serde_json::Value, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: Some(result),
            error: None,
            id,
        }
    }

    /// Create error response
    pub fn error(id: serde_json::Value, code: i32, message: String) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(JsonRpcError {
                code,
                message,
                data: None,
            }),
            id,
        }
    }
}

/// Handle JSON-RPC request
pub async fn handle_request(request: JsonRpcRequest) -> Result<JsonRpcResponse> {
    match request.method.as_str() {
        "hello" => {
            let result = serde_json::Value::String("Hello, world".to_string());
            Ok(JsonRpcResponse::success(request.id, result))
        }
        _ => Ok(JsonRpcResponse::error(
            request.id,
            -32601,
            format!("Method '{}' not found", request.method),
        )),
    }
}
