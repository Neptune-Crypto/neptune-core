use std::collections::HashSet;
use std::sync::Arc;

use axum::extract::rejection::JsonRejection;
use axum::extract::State;
use axum::routing::post;
use axum::Json;
use axum::Router;
use tokio::net::TcpListener;
use tracing::warn;

use crate::application::json_rpc::core::api::ops::Namespace;
use crate::application::json_rpc::core::api::ops::RpcMethods;
use crate::application::json_rpc::core::api::router::RpcRouter;
use crate::application::json_rpc::core::api::rpc::RpcApi;
use crate::application::json_rpc::core::error::RpcError;
use crate::application::json_rpc::core::error::RpcRequest;
use crate::application::json_rpc::core::error::RpcResponse;
use crate::state::GlobalStateLock;

#[derive(Clone, Debug)]
pub struct RpcServer {
    pub(crate) state: GlobalStateLock,
}

impl RpcServer {
    pub fn new(state: GlobalStateLock) -> Self {
        Self { state }
    }

    /// Returns the enabled set of RPC namespaces with node configuration check.
    async fn enabled_namespaces(&self) -> HashSet<Namespace> {
        let state = self.state.lock_guard().await;
        let mut namespaces: HashSet<Namespace> =
            self.state.cli().rpc_modules.iter().copied().collect();

        if namespaces.contains(&Namespace::Archival) {
            let is_archival = state.chain.is_archival_node();

            if !is_archival {
                namespaces.remove(&Namespace::Archival);
                warn!("Node is not archival, cannot enable Archival namespace.");
            }
        }

        namespaces
    }

    /// Starts the RPC server.
    ///
    /// All RPC endpoints are accessible via `POST` requests to the root path `/`.
    /// The specific method is selected using the `method` field in the JSON request body,
    /// formatted as `namespace_method`.
    pub async fn serve(&self, listener: TcpListener) {
        let api: Arc<dyn RpcApi> = Arc::new(self.clone());
        let namespaces = self.enabled_namespaces().await;
        let router = RpcMethods::new_router(api, namespaces);

        let app = Router::new()
            .route("/", post(Self::rpc_handler))
            .with_state(Arc::new(router));

        axum::serve(listener, app).await.unwrap();
    }

    /// Handles incoming RPC requests.
    ///
    /// # Request Body
    ///
    /// Expects a JSON-RPC 2.0 compliant body with the following fields:
    /// - `jsonrpc`: `"2.0"`
    /// - `method`: The RPC method to call, formatted as `namespace_method`
    /// - `params`: An array of parameters to pass to the method
    /// - `id` (optional): Request identifier for matching responses
    ///
    /// # Response
    ///
    /// Returns a JSON-RPC 2.0 response:
    /// - On success:  
    ///   `{
    ///       "jsonrpc": "2.0",
    ///       "id": <request_id>,
    ///       "result": <method_result>
    ///   }`
    ///
    /// - On error:  
    ///   `{
    ///       "jsonrpc": "2.0",
    ///       "id": <request_id>,
    ///       "error": {
    ///           "code": <error_code>,
    ///           "message": <error_message>
    ///       }
    ///   }`
    ///
    /// # Example
    ///
    /// Request:
    /// ```json
    /// POST /
    /// {
    ///     "method": "node_network",
    ///     "params": [],
    ///     "id": 1
    /// }
    /// ```
    ///
    /// Success Response:
    /// ```json
    /// {
    ///     "jsonrpc": "2.0",
    ///     "id": 1,
    ///     "result": { "network": "main" }
    /// }
    /// ```
    ///
    /// Error Response:
    /// ```json
    /// {
    ///     "jsonrpc": "2.0",
    ///     "id": 1,
    ///     "error": {
    ///         "code": -32601,
    ///         "message": "Method not found"
    ///     }
    /// }
    /// ```
    async fn rpc_handler(
        State(router): State<Arc<RpcRouter>>,
        // An optimization to avoid deserializing 2 times
        body: Result<Json<RpcRequest>, JsonRejection>,
    ) -> Json<RpcResponse> {
        let Ok(Json(request)) = body else {
            return Json(RpcResponse::error(None, RpcError::ParseError));
        };

        let res = router.dispatch(&request.method, request.params).await;
        let response = match res {
            Ok(result) => RpcResponse::success(request.id, result),
            Err(error) => RpcResponse::error(request.id, error),
        };

        Json(response)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::collections::HashSet;
    use std::sync::Arc;

    use axum::extract::State;
    use axum::Json;
    use macro_rules_attr::apply;
    use serde_json::json;

    use crate::application::json_rpc::core::api::ops::Namespace;
    use crate::application::json_rpc::core::api::ops::RpcMethods;
    use crate::application::json_rpc::core::api::router::RpcRouter;
    use crate::application::json_rpc::core::error::RpcError;
    use crate::application::json_rpc::core::error::RpcRequest;
    use crate::application::json_rpc::core::error::RpcResponse;
    use crate::application::json_rpc::server::http::RpcServer;
    use crate::application::json_rpc::server::service::tests::test_rpc_server;
    use crate::tests::shared_tokio_runtime;

    #[apply(shared_tokio_runtime)]
    async fn namespace_isolates_correctly() {
        let router_no_chain = Arc::new(RpcMethods::new_router(
            Arc::new(test_rpc_server().await),
            HashSet::from([Namespace::Node]),
        ));
        let router_with_chain = Arc::new(RpcMethods::new_router(
            Arc::new(test_rpc_server().await),
            HashSet::from([Namespace::Node, Namespace::Chain]),
        ));

        async fn make_rpc_request(router: Arc<RpcRouter>, method: &str) -> RpcResponse {
            let request = RpcRequest {
                jsonrpc: Some("2.0".to_string()),
                method: method.to_string(),
                params: json!([]),
                id: None,
            };
            RpcServer::rpc_handler(State(router), Ok(Json(request)))
                .await
                .0
        }

        let node_network_res = make_rpc_request(router_no_chain.clone(), "node_network").await;
        assert!(
            matches!(node_network_res, RpcResponse::Success { .. }),
            "Expected success for node_network, got: {:?}",
            node_network_res
        );

        let chain_height_method_name = "chain_height";
        let chain_height_res_bad =
            make_rpc_request(router_no_chain, chain_height_method_name).await;
        assert!(
            matches!(
                chain_height_res_bad,
                RpcResponse::Error {
                    error: RpcError::MethodNotFound,
                    ..
                }
            ),
            "Expected MethodNotFound error for chain_height, got: {:?}",
            chain_height_res_bad
        );
        let chain_height_res_good =
            make_rpc_request(router_with_chain.clone(), chain_height_method_name).await;
        assert!(
            matches!(chain_height_res_good, RpcResponse::Success { .. }),
            "Expected success for chain_height, got: {:?}",
            chain_height_res_good
        );
    }
}
