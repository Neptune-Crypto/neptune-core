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
