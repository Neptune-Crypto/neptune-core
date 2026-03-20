use std::sync::Arc;
use std::sync::LazyLock;

use axum::extract::DefaultBodyLimit;
use axum::extract::State;
use axum::routing::post;
use axum::Json;
use axum::Router;
use tokio::net::TcpListener;

use crate::application::json_rpc::core::api::ops::Namespace;
use crate::application::json_rpc::core::api::ops::RpcMethods;
use crate::application::json_rpc::core::api::rpc::RpcApi;
use crate::application::json_rpc::core::api::server::router::RpcRouter;
use crate::application::json_rpc::core::model::json::JsonError;
use crate::application::json_rpc::core::model::json::JsonRequest;
use crate::application::json_rpc::core::model::json::JsonResponse;
use crate::application::json_rpc::server::rpc::RpcServer;

/// Max request size for any HTTP requests. Enforced by server. This size must
/// be big enough to handle both the submission of blocks (~8MB) and submission
/// of proof collections (unbounded). A size of 120MB can handle proof
/// collections with over 100 inputs though.
const MAX_REQUEST_SIZE_IN_BYTES: usize = 120 * 1024 * 1024;
const MAX_REQUEST_SIZE_FOR_BLOCK_SUBMISSION_IN_BYTES: usize = 16 * 1024 * 1024;
const MAX_DEFAULT_REQUEST_SIZE_IN_BYTES: usize = 1024 * 1024;

impl RpcServer {
    /// Starts the HTTP RPC server.
    ///
    /// All RPC endpoints are accessible via `POST` requests to the root path `/`.
    /// The specific method is selected using the `method` field in the JSON request body,
    /// formatted as `namespace_method`.
    pub async fn serve_http(&self, listener: TcpListener) {
        let api: Arc<dyn RpcApi> = Arc::new(self.clone());
        let namespaces = self.enabled_namespaces().await;
        let router = RpcMethods::new_router(api, namespaces);

        let app = Router::new()
            .route("/", post(Self::rpc_handler))
            .layer(DefaultBodyLimit::max(MAX_REQUEST_SIZE_IN_BYTES))
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
        body: axum::body::Bytes,
    ) -> Json<JsonResponse> {
        static SUBMIT_TX: LazyLock<String> =
            LazyLock::new(|| format!("{}_{}", Namespace::Wallet, RpcMethods::SubmitTransaction));
        static SUBMIT_BLOCK: LazyLock<String> =
            LazyLock::new(|| format!("{}_{}", Namespace::Mining, RpcMethods::SubmitBlock));

        let request: JsonRequest = match serde_json::from_slice(&body) {
            Ok(req) => req,
            Err(_) => {
                return Json(JsonResponse::error(None, JsonError::ParseError));
            }
        };

        let max_size = if request.method == *SUBMIT_TX {
            MAX_REQUEST_SIZE_IN_BYTES
        } else if request.method == *SUBMIT_BLOCK {
            MAX_REQUEST_SIZE_FOR_BLOCK_SUBMISSION_IN_BYTES
        } else {
            MAX_DEFAULT_REQUEST_SIZE_IN_BYTES
        };

        if body.len() > max_size {
            return Json(JsonResponse::error(
                request.id,
                JsonError::RequestBodyTooBig {
                    max: max_size,
                    got: body.len(),
                },
            ));
        }

        let res = router.dispatch(&request.method, request.params).await;
        let response = match res {
            Ok(result) => JsonResponse::success(request.id, result),
            Err(error) => JsonResponse::error(request.id, error),
        };

        Json(response)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::sync::Arc;

    use axum::body::Bytes;
    use axum::extract::State;
    use axum::Json;
    use macro_rules_attr::apply;
    use serde_json::json;

    use crate::application::json_rpc::core::api::ops::Namespace;
    use crate::application::json_rpc::core::api::ops::RpcMethods;
    use crate::application::json_rpc::core::api::server::router::RpcRouter;
    use crate::application::json_rpc::core::model::json::JsonError;
    use crate::application::json_rpc::core::model::json::JsonRequest;
    use crate::application::json_rpc::core::model::json::JsonResponse;
    use crate::application::json_rpc::server::rpc::RpcServer;
    use crate::application::json_rpc::server::service::tests::test_rpc_server;
    use crate::tests::shared_tokio_runtime;

    async fn test_router() -> Arc<RpcRouter> {
        let api = Arc::new(test_rpc_server().await);

        Arc::new(RpcMethods::new_router(api, [Namespace::Node].into()))
    }

    #[apply(shared_tokio_runtime)]
    async fn handles_common_scenarios_properly() {
        const TEST_METHOD: &str = "node_network";
        const UNKNOWN_TEST_METHOD: &str = "node_crash";

        let router = test_router().await;

        // 1. Valid -> Success
        let valid_req = JsonRequest {
            jsonrpc: Some("2.0".into()),
            method: TEST_METHOD.into(),
            params: json!([]),
            id: Some(json!(1)),
        };
        let valid_req = Bytes::from(serde_json::to_vec(&valid_req).unwrap());
        let Json(valid_res) = RpcServer::rpc_handler(State(router.clone()), valid_req).await;
        assert!(
            matches!(valid_res, JsonResponse::Success { id: Some(id), result, .. }
                if id == json!(1) && result.is_object() // shouldn't be null
            )
        );

        // 2. Bad params -> InvalidParams
        let bad_req = JsonRequest {
            jsonrpc: Some("2.0".into()),
            method: TEST_METHOD.into(),
            params: json!([1, "x"]),
            id: Some(json!(2)),
        };
        let bad_req = Bytes::from(serde_json::to_vec(&bad_req).unwrap());
        let Json(bad_res) = RpcServer::rpc_handler(State(router.clone()), bad_req).await;
        assert!(
            matches!(bad_res, JsonResponse::Error { id: Some(id), error: JsonError::InvalidParams, .. }
                if id == json!(2)
            )
        );

        // 3. Unknown method -> MethodNotFound
        let unknown_req = JsonRequest {
            jsonrpc: Some("2.0".into()),
            method: UNKNOWN_TEST_METHOD.into(),
            params: json!([]),
            id: Some(json!(3)),
        };
        let unknown_req = Bytes::from(serde_json::to_vec(&unknown_req).unwrap());
        let Json(unknown_res) = RpcServer::rpc_handler(State(router.clone()), unknown_req).await;
        assert!(
            matches!(unknown_res, JsonResponse::Error { id: Some(id), error: JsonError::MethodNotFound, .. }
                if id == json!(3)
            )
        );

        // 4. Too big body -> RequestBodyTooBig
        let large_data = "a".repeat(1_100_000); // ~1.1 MB
        let large_req = JsonRequest {
            jsonrpc: Some("2.0".into()),
            method: TEST_METHOD.into(),
            params: json!([large_data]),
            id: Some(json!(4)),
        };
        let large_req = Bytes::from(serde_json::to_vec(&large_req).unwrap());
        let Json(too_big) = RpcServer::rpc_handler(State(router.clone()), large_req).await;
        assert!(
            matches!(too_big, JsonResponse::Error { id: Some(id), error: JsonError::RequestBodyTooBig {..}, .. }
                if id == json!(4)
            )
        );
    }
}
