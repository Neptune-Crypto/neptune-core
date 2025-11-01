use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use async_trait::async_trait;
use neptune_cash::application::json_rpc::core::api::client::transport::Transport;
use neptune_cash::application::json_rpc::core::model::json::JsonError;
use neptune_cash::application::json_rpc::core::model::json::JsonRequest;
use neptune_cash::application::json_rpc::core::model::json::JsonResult;
use reqwest::Client;

#[derive(Clone, Debug)]
pub struct HttpTransport {
    url: String,
    client: Client,
    last_id: Arc<AtomicU64>,
}

impl HttpTransport {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            client: Client::new(),
            last_id: Arc::new(AtomicU64::new(0)),
        }
    }
}

#[async_trait]
impl Transport for HttpTransport {
    async fn call(&self, method: &str, params: serde_json::Value) -> JsonResult<serde_json::Value> {
        let request = JsonRequest {
            jsonrpc: Some("2.0".to_string()),
            method: method.to_string(),
            params,
            id: Some(self.last_id.fetch_add(1, Ordering::SeqCst).into()),
        };

        let response = self
            .client
            .post(&self.url)
            .json(&request)
            .send()
            .await
            .map_err(|_| JsonError::InternalError)?;
        if !response.status().is_success() {
            return Err(JsonError::InternalError);
        }

        let value: serde_json::Value = response.json().await.map_err(|_| JsonError::ParseError)?;

        if let Some(error_val) = value.get("error") {
            return Err(
                serde_json::from_value(error_val.clone()).unwrap_or(JsonError::InternalError)
            );
        }

        value.get("result").cloned().ok_or(JsonError::InvalidParams)
    }
}
