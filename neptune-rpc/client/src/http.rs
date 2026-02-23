use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use async_trait::async_trait;
use neptune_cash::application::json_rpc::core::api::client::transport::Transport;
use neptune_cash::application::json_rpc::core::model::json::JsonError;
use neptune_cash::application::json_rpc::core::model::json::JsonRequest;
use neptune_cash::application::json_rpc::core::model::json::JsonResponse;
use neptune_cash::application::json_rpc::core::model::json::JsonResult;
use reqwest::Client;

#[derive(Clone, Debug)]
pub struct HttpClient {
    url: String,
    client: Client,
    last_id: Arc<AtomicU64>,
}

impl HttpClient {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            client: Client::new(),
            last_id: Arc::new(AtomicU64::new(0)),
        }
    }
}

#[async_trait]
impl Transport for HttpClient {
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

        let response: serde_json::Value =
            response.json().await.map_err(|_| JsonError::ParseError)?;
        let response: JsonResponse =
            serde_json::from_value(response).map_err(|_| JsonError::ParseError)?;

        match response {
            JsonResponse::Success { result, .. } => Ok(result),
            JsonResponse::Error { error, .. } => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::net::SocketAddr;
    use std::path::Path;
    use std::path::PathBuf;
    use std::time::Duration;

    use neptune_cash::api::export::Args;
    use neptune_cash::application::json_rpc::core::api::rpc::RpcApi;
    use neptune_cash::application::json_rpc::core::api::rpc::RpcError;
    use neptune_cash::application::json_rpc::core::model::json::JsonError;
    use neptune_cash::protocol::consensus::block::block_selector::BlockSelector;
    use neptune_cash::protocol::consensus::block::block_selector::BlockSelectorLiteral;
    use rand::distr::Alphanumeric;
    use rand::distr::SampleString;

    use crate::http::HttpClient;

    #[tokio::test]
    async fn client_responds_in_real_world_scenario() {
        let rpc_address = "127.0.0.1:56390";

        let mut cli_args = Args::default();

        // allow run if instance is running, and don't overwrite
        // existing data dir.
        cli_args.peer_port = 56386;
        cli_args.rpc_port = 56387;
        cli_args.quic_port = 56388;
        cli_args.tcp_port = 56389;
        let tmp_root: PathBuf = env::temp_dir()
            .join("neptune-unit-tests")
            .join(Path::new(&Alphanumeric.sample_string(&mut rand::rng(), 16)));

        cli_args.data_dir = Some(tmp_root);
        cli_args.listen_rpc = Some(rpc_address.parse::<SocketAddr>().unwrap());
        let _ = neptune_cash::initialize(cli_args).await.unwrap();

        // Wait a few seconds so node will fully initialize.
        tokio::time::sleep(Duration::from_secs(3)).await;

        let client = HttpClient::new(format!("http://{}", rpc_address));

        // Chain namespace is available by default.
        let tip_response = client.tip().await;
        assert!(tip_response.is_ok());

        // Archival is disabled by default.
        let block_response = client
            .get_block(BlockSelector::Special(BlockSelectorLiteral::Genesis))
            .await;
        assert!(block_response.is_err());
        assert_eq!(
            block_response.unwrap_err(),
            RpcError::Server(JsonError::MethodNotFound)
        );
    }
}
