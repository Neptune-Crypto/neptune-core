use serde::ser::SerializeStruct;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;
use serde_json::Value;
use thiserror::Error;

use crate::application::json_rpc::core::api::rpc::RpcError;

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRequest {
    #[serde(default)]
    pub jsonrpc: Option<String>,
    pub method: String,
    pub params: Value,
    pub id: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum JsonError {
    #[error("Parse error")]
    ParseError,
    #[error("Invalid request")]
    InvalidRequest,
    #[error("Method not found")]
    MethodNotFound,
    #[error("Invalid params")]
    InvalidParams,
    #[error("Internal error")]
    InternalError,
    #[error("Server error")]
    Custom {
        code: i32,
        message: String,
        data: Option<Value>,
    },
}

impl JsonError {
    pub fn code(&self) -> i32 {
        match self {
            Self::ParseError => -32700,
            Self::InvalidRequest => -32600,
            Self::MethodNotFound => -32601,
            Self::InvalidParams => -32602,
            Self::InternalError => -32603,
            Self::Custom { code, .. } => *code,
        }
    }

    pub fn data(&self) -> Option<&serde_json::Value> {
        match self {
            Self::Custom { data, .. } => data.as_ref(),
            _ => None,
        }
    }
}

#[allow(unreachable_patterns)] // Currently there is only one variant in enum.
impl From<RpcError> for JsonError {
    fn from(err: RpcError) -> Self {
        match err {
            RpcError::Server(error) => error,
            _ => JsonError::Custom {
                code: -32000,
                message: "RPC error".to_string(),
                data: Some(serde_json::to_value(err).unwrap()),
            },
        }
    }
}

impl From<JsonError> for RpcError {
    fn from(err: JsonError) -> Self {
        match err {
            JsonError::Custom {
                data: Some(value), ..
            } => serde_json::from_value(value).unwrap_or(RpcError::Server(JsonError::ParseError)),
            err => RpcError::Server(err),
        }
    }
}

impl Serialize for JsonError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("JsonError", 3)?;
        state.serialize_field("code", &self.code())?;
        state.serialize_field("message", &self.to_string())?;

        if let Some(data) = self.data() {
            state.serialize_field("data", data)?;
        }

        state.end()
    }
}

impl<'de> Deserialize<'de> for JsonError {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Envelope {
            code: i32,
            message: String,
            data: Option<serde_json::Value>,
        }

        let err = Envelope::deserialize(deserializer)?;

        match err.code {
            -32700 => Ok(JsonError::ParseError),
            -32600 => Ok(JsonError::InvalidRequest),
            -32601 => Ok(JsonError::MethodNotFound),
            -32602 => Ok(JsonError::InvalidParams),
            -32603 => Ok(JsonError::InternalError),
            code => Ok(JsonError::Custom {
                code,
                message: err.message,
                data: err.data,
            }),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JsonResponse {
    Success {
        #[serde(skip_deserializing)]
        jsonrpc: &'static str,
        id: Option<Value>,
        result: Value,
    },
    Error {
        #[serde(skip_deserializing)]
        jsonrpc: &'static str,
        id: Option<Value>,
        error: JsonError,
    },
}

impl JsonResponse {
    pub const VERSION: &'static str = "2.0";

    pub fn success(id: Option<Value>, result: Value) -> Self {
        JsonResponse::Success {
            jsonrpc: Self::VERSION,
            id,
            result,
        }
    }

    pub fn error(id: Option<Value>, error: JsonError) -> Self {
        JsonResponse::Error {
            jsonrpc: Self::VERSION,
            id,
            error,
        }
    }
}

pub type JsonResult<T> = Result<T, JsonError>;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn json_error_serialization() {
        let error = JsonError::MethodNotFound;
        let serialized = serde_json::to_string(&error).unwrap();
        assert_eq!(
            serialized,
            r#"{"code":-32601,"message":"Method not found"}"#
        );
    }

    #[test]
    fn json_rpc_error_roundtrip() {
        let error = JsonError::MethodNotFound;

        let rpc_error: RpcError = error.clone().into();
        assert_eq!(rpc_error, RpcError::Server(error.clone()));

        let json_error: JsonError = rpc_error.into();
        assert_eq!(json_error, error);
    }

    #[test]
    fn json_response_success() {
        let response = JsonResponse::success(Some(json!(1)), json!({"success": true}));

        let serialized = serde_json::to_string(&response).unwrap();
        assert!(serialized.contains(r#"{"jsonrpc":"2.0","id":1,"result":{"success":true}}"#));
    }

    #[test]
    fn json_response_error() {
        let response = JsonResponse::error(Some(json!("1")), JsonError::InvalidParams);

        let serialized = serde_json::to_string(&response).unwrap();
        assert!(serialized.contains(
            r#"{"jsonrpc":"2.0","id":"1","error":{"code":-32602,"message":"Invalid params"}}"#
        ));
    }

    #[test]
    fn json_request_deserialization() {
        let json_data = r#"{
            "jsonrpc": "2.0",
            "method": "test",
            "params": ["arg1", "arg2"],
            "id": 1
        }"#;

        let request: JsonRequest = serde_json::from_str(json_data).unwrap();

        assert_eq!(request.jsonrpc, Some("2.0".to_string()));
        assert_eq!(request.method, "test");
        assert_eq!(request.params, json!(["arg1", "arg2"]));
        assert_eq!(request.id, Some(json!(1)));
    }

    #[test]
    fn json_response_with_null_id() {
        let success = JsonResponse::success(None, json!(true));
        let error = JsonResponse::error(None, JsonError::InternalError);

        let success_str = serde_json::to_string(&success).unwrap();
        let error_str = serde_json::to_string(&error).unwrap();

        assert!(success_str.contains(r#"{"jsonrpc":"2.0","id":null,"result":true}"#));
        assert!(error_str.contains(
            r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"Internal error"}}"#
        ));
    }
}
