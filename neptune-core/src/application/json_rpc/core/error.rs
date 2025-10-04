use serde::Deserialize;
use serde::Serialize;
use serde::Serializer;
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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn rpc_error_serialization() {
        let error = RpcError::MethodNotFound;
        let serialized = serde_json::to_string(&error).unwrap();
        assert_eq!(
            serialized,
            r#"{"code":-32601,"message":"Method not found/unavailable"}"#
        );
    }

    #[test]
    fn rpc_response_success() {
        let response = RpcResponse::success(Some(json!(1)), json!({"success": true}));

        let serialized = serde_json::to_string(&response).unwrap();
        assert!(serialized.contains(r#"{"jsonrpc":"2.0","id":1,"result":{"success":true}}"#));
    }

    #[test]
    fn rpc_response_error() {
        let response = RpcResponse::error(Some(json!("1")), RpcError::InvalidParams);

        let serialized = serde_json::to_string(&response).unwrap();
        assert!(serialized.contains(
            r#"{"jsonrpc":"2.0","id":"1","error":{"code":-32602,"message":"Invalid params"}}"#
        ));
    }

    #[test]
    fn rpc_request_deserialization() {
        let json_data = r#"{
            "jsonrpc": "2.0",
            "method": "test",
            "params": ["arg1", "arg2"],
            "id": 1
        }"#;

        let request: RpcRequest = serde_json::from_str(json_data).unwrap();

        assert_eq!(request.jsonrpc, Some("2.0".to_string()));
        assert_eq!(request.method, "test");
        assert_eq!(request.params, json!(["arg1", "arg2"]));
        assert_eq!(request.id, Some(json!(1)));
    }

    #[test]
    fn rpc_response_with_null_id() {
        let success = RpcResponse::success(None, json!(true));
        let error = RpcResponse::error(None, RpcError::InternalError);

        let success_str = serde_json::to_string(&success).unwrap();
        let error_str = serde_json::to_string(&error).unwrap();

        assert!(success_str.contains(r#"{"jsonrpc":"2.0","id":null,"result":true}"#));
        assert!(error_str.contains(
            r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"Internal error"}}"#
        ));
    }
}
