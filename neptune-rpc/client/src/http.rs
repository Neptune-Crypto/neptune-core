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
    use std::collections::HashSet;
    use std::env;
    use std::net::SocketAddr;
    use std::path::Path;
    use std::path::PathBuf;
    use std::time::Duration;

    use neptune_cash::api::export::Args;
    use neptune_cash::api::export::BlockHeight;
    use neptune_cash::api::export::Digest;
    use neptune_cash::api::export::KeyType;
    use neptune_cash::api::export::Network;
    use neptune_cash::application::json_rpc::core::api::ops::Namespace;
    use neptune_cash::application::json_rpc::core::api::rpc::RpcApi;
    use neptune_cash::application::json_rpc::core::api::rpc::RpcError;
    use neptune_cash::application::json_rpc::core::model::block::transaction_kernel::RpcAdditionRecord;
    use neptune_cash::application::json_rpc::core::model::json::JsonError;
    use neptune_cash::protocol::consensus::block::Block;
    use neptune_cash::protocol::consensus::block::block_selector::BlockSelector;
    use neptune_cash::protocol::consensus::block::block_selector::BlockSelectorLiteral;
    use rand::distr::Alphanumeric;
    use rand::distr::SampleString;

    use crate::http::HttpClient;

    /// Start a real neptune-core node with a specified port offset to allow
    /// tests to run in parallel.
    ///
    /// Don't use this real server to test all cornercases of inner workings of
    /// neptune-core. Think of this server as integration testing.
    async fn start_pseudo_real_server(
        activated_namespaces: HashSet<Namespace>,
        unsafe_rpc: bool,
        port_offset: u16,
    ) -> HttpClient {
        let rpc_address = format!("127.0.0.1:{port_offset}");

        let mut cli_args = Args::default();
        cli_args.utxo_index = true;

        // allow run if instance is running, and don't overwrite
        // existing data dir.
        cli_args.peer_port = port_offset + 1;
        cli_args.rpc_port = port_offset + 2;
        cli_args.quic_port = port_offset + 3;
        cli_args.tcp_port = port_offset + 4;
        cli_args.rpc_modules = activated_namespaces.into_iter().collect();
        cli_args.unsafe_rpc = unsafe_rpc;
        let tmp_root: PathBuf = env::temp_dir()
            .join("neptune-unit-tests")
            .join(Path::new(&Alphanumeric.sample_string(&mut rand::rng(), 16)));

        cli_args.data_dir = Some(tmp_root);
        cli_args.listen_rpc = Some(rpc_address.parse::<SocketAddr>().unwrap());
        let mut main_loop = neptune_cash::initialize(cli_args).await.unwrap();

        tokio::spawn(async move {
            main_loop.run().await.unwrap();
        });

        // Wait a few seconds so node will fully initialize. Initializing
        // neptune-core spawns multiple loops. They might need a bit time to
        // be ready for responses.
        tokio::time::sleep(Duration::from_secs(1)).await;

        HttpClient::new(format!("http://{}", rpc_address))
    }

    #[tokio::test]
    async fn client_responds_in_real_world_scenario() {
        let unsafe_rpc = false;
        let client =
            start_pseudo_real_server(HashSet::from([Namespace::Chain]), unsafe_rpc, 40500).await;

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

    #[tokio::test]
    async fn get_new_address_bumps_derivation_index() {
        let unsafe_rpc = false;
        let client = start_pseudo_real_server(
            HashSet::from([Namespace::Chain, Namespace::Personal]),
            unsafe_rpc,
            40510,
        )
        .await;

        for key_type in [KeyType::Generation, KeyType::Symmetric] {
            let old_index = client.derivation_index(key_type).await.unwrap();
            let _ = client.generate_address(key_type).await.unwrap();
            let new_index = client.derivation_index(key_type).await.unwrap();
            assert_eq!(new_index.derivation_index, old_index.derivation_index + 1);
        }
    }

    #[tokio::test]
    async fn was_mined_on_genesis() {
        let unsafe_rpc = false;
        let client =
            start_pseudo_real_server(HashSet::from([Namespace::Utxoindex]), unsafe_rpc, 40520)
                .await;

        let a_genesis_output = Block::genesis(Network::Main)
            .body()
            .transaction_kernel
            .outputs[0];
        assert_eq!(
            vec![BlockHeight::genesis()],
            client
                .was_mined(vec![], vec![a_genesis_output.into()])
                .await
                .unwrap()
                .block_heights
        );

        let unknown_output = RpcAdditionRecord(Digest::default());
        assert!(
            client
                .was_mined(vec![], vec![unknown_output])
                .await
                .unwrap()
                .block_heights
                .is_empty()
        );
        assert_eq!(
            RpcError::EmptyFilteringConditions,
            client.was_mined(vec![], vec![]).await.unwrap_err()
        );
    }

    #[tokio::test]
    async fn outgoing_history_empty_wallet_db() {
        let unsafe_rpc = false;
        let client =
            start_pseudo_real_server(HashSet::from([Namespace::Personal]), unsafe_rpc, 40530).await;

        assert!(
            client
                .outgoing_history(None, None, None, None, None, None, None)
                .await
                .unwrap()
                .matching_sent
                .is_empty()
        );
    }
}
