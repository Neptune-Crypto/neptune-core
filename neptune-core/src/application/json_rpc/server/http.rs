use std::{collections::HashSet, sync::Arc};

use axum::{
    extract::{rejection::JsonRejection, State},
    routing::post,
    Json, Router,
};
use tokio::net::TcpListener;

use crate::{
    application::json_rpc::core::{
        api::{
            ops::{Namespace, RpcMethods},
            router::RpcRouter,
            rpc::RpcApi,
        },
        error::{RpcError, RpcRequest, RpcResponse},
    },
    state::GlobalStateLock,
};

#[derive(Clone, Debug)]
pub struct RpcServer {
    pub(crate) state: GlobalStateLock,
}

impl RpcServer {
    pub fn new(state: GlobalStateLock) -> Self {
        Self { state }
    }

    pub async fn serve(&self, listener: TcpListener) {
        let api: Arc<dyn RpcApi> = Arc::new(self.clone());
        let namespaces: HashSet<Namespace> = self.state.cli().rpc_modules.iter().copied().collect();
        let router = RpcMethods::new_router(api, namespaces);

        let app = Router::new()
            .route("/", post(Self::rpc_handler))
            .with_state(Arc::new(router));

        axum::serve(listener, app).await.unwrap();
    }

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
    use std::{collections::HashSet, sync::Arc};

    use crate::{
        application::json_rpc::{
            core::{
                api::{
                    ops::{Namespace, RpcMethods},
                    router::RpcRouter,
                    rpc::RpcApi,
                },
                error::{RpcError, RpcRequest, RpcResponse},
            },
            server::{http::RpcServer, service::tests::test_rpc_server},
        },
        tests::shared_tokio_runtime,
    };
    use axum::{extract::State, Json};
    use macro_rules_attr::apply;
    use serde_json::json;

    #[test]
    fn namespace_parses_case_insensitively() {
        use std::str::FromStr;

        assert_eq!(Namespace::from_str("node").unwrap(), Namespace::Node);
        assert_eq!(Namespace::from_str("Node").unwrap(), Namespace::Node);
        assert_eq!(Namespace::from_str("NODE").unwrap(), Namespace::Node);
        assert_eq!(Namespace::from_str("NoDe").unwrap(), Namespace::Node);

        assert!(
            Namespace::from_str("nodewallet").is_err(),
            "Expected parse error for invalid namespace"
        );
    }

    #[apply(shared_tokio_runtime)]
    async fn namespace_isolates_correctly() {
        let server = test_rpc_server().await;
        let api: Arc<dyn RpcApi> = Arc::new(server);
        let namespaces = HashSet::from([Namespace::Node]);
        let router = Arc::new(RpcMethods::new_router(api, namespaces));

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

        let node_network_res = make_rpc_request(router.clone(), "node_network").await;
        assert!(
            matches!(node_network_res, RpcResponse::Success { .. }),
            "Expected success for node_network, got: {:?}",
            node_network_res
        );

        let chain_height_res = make_rpc_request(router, "chain_height").await;
        assert!(
            matches!(
                chain_height_res,
                RpcResponse::Error {
                    error: RpcError::MethodNotFound,
                    ..
                }
            ),
            "Expected MethodNotFound error for chain_height, got: {:?}",
            chain_height_res
        );
    }
}
