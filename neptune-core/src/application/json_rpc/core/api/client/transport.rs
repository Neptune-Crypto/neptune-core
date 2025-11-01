use async_trait::async_trait;
use serde_json::Value;

use crate::application::json_rpc::core::model::json::JsonResult;

#[async_trait]
pub trait Transport: Send + Sync {
    async fn call(&self, method: &str, params: Value) -> JsonResult<Value>;
}
