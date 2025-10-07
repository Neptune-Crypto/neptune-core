use std::{collections::HashSet, sync::Arc};

use async_trait::async_trait;
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
        model::message::*,
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

#[async_trait]
impl RpcApi for RpcServer {
    async fn network_call(&self, _: NetworkRequest) -> NetworkResponse {
        NetworkResponse {
            network: self.state.cli().network.to_string(),
        }
    }

    async fn height_call(&self, _: HeightRequest) -> HeightResponse {
        HeightResponse {
            height: self
                .state
                .lock_guard()
                .await
                .chain
                .light_state()
                .kernel
                .header
                .height
                .into(),
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use crate::{
        api::export::Network,
        application::{
            config::cli_args,
            json_rpc::{core::api::rpc::RpcApi, server::http::RpcServer},
        },
        state::wallet::wallet_entropy::WalletEntropy,
        tests::{shared::globalstate::mock_genesis_global_state, shared_tokio_runtime},
    };
    use anyhow::Result;
    use macro_rules_attr::apply;

    async fn test_rpc_server() -> RpcServer {
        let global_state_lock = mock_genesis_global_state(
            2,
            WalletEntropy::new_random(),
            cli_args::Args::default_with_network(Network::Main),
        )
        .await;

        RpcServer::new(global_state_lock)
    }

    #[apply(shared_tokio_runtime)]
    async fn test_network_is_consistent() -> Result<()> {
        let rpc_server = test_rpc_server().await;
        assert_eq!("main", rpc_server.network().await.network);
        Ok(())
    }

    #[apply(shared_tokio_runtime)]
    async fn test_height_is_correct() -> Result<()> {
        let rpc_server = test_rpc_server().await;
        assert_eq!(0, rpc_server.height().await.height);
        Ok(())
    }
}
