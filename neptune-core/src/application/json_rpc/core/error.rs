use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;

#[derive(Debug, Deserialize)]
pub struct RpcRequest {
    #[serde(default)]
    pub jsonrpc: Option<String>,
    pub method: String,
    pub params: Value,
    pub id: Option<Value>,
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcError {
    ParseError = -32700,
    InvalidRequest = -32600,
    MethodNotFound = -32601,
    InvalidParams = -32602,
    InternalError = -32603,
}

impl RpcError {
    pub fn message(self) -> &'static str {
        match self {
            Self::ParseError => "Parse error",
            Self::InvalidRequest => "Invalid Request",
            Self::MethodNotFound => "Method not found/unavailable",
            Self::InvalidParams => "Invalid params",
            Self::InternalError => "Internal error",
        }
    }
}

impl Serialize for RpcError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("RpcError", 2)?;
        state.serialize_field("code", &(*self as i32))?;
        state.serialize_field("message", self.message())?;
        state.end()
    }
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum RpcResponse {
    Success {
        jsonrpc: &'static str,
        id: Option<Value>,
        result: Value,
    },
    Error {
        jsonrpc: &'static str,
        id: Option<Value>,
        error: RpcError,
    },
}

impl RpcResponse {
    pub const VERSION: &'static str = "2.0";

    pub fn success(id: Option<Value>, result: Value) -> Self {
        RpcResponse::Success {
            jsonrpc: Self::VERSION,
            id,
            result,
        }
    }

    pub fn error(id: Option<Value>, error: RpcError) -> Self {
        RpcResponse::Error {
            jsonrpc: Self::VERSION,
            id,
            error,
        }
    }
}

pub type RpcResult<T> = Result<T, RpcError>;
