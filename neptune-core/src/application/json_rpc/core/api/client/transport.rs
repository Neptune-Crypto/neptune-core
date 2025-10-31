use async_trait::async_trait;

use crate::application::rpc::server::RpcResult;

#[async_trait]
pub trait Transport: Send + Sync {
    async fn call(&self, method: &str, params: serde_json::Value) -> RpcResult<serde_json::Value>;
}
