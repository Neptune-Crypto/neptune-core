use std::{collections::HashMap, future::Future, pin::Pin, sync::Arc};

use crate::application::json_rpc::core::api::rpc::RpcApi;
use crate::application::json_rpc::core::error::{RpcError, RpcResult};

type HandlerFn = Box<
    dyn Fn(serde_json::Value) -> Pin<Box<dyn Future<Output = RpcResult<serde_json::Value>> + Send>>
        + Send
        + Sync,
>;

#[allow(missing_debug_implementations)]
pub struct RpcRouter {
    routes: HashMap<&'static str, HandlerFn>,
    api: Arc<dyn RpcApi>,
}

impl RpcRouter {
    pub fn new(api: Arc<dyn RpcApi>) -> Self {
        Self {
            routes: HashMap::new(),
            api,
        }
    }

    pub fn insert<F, Fut>(&mut self, name: &'static str, f: F)
    where
        F: Fn(Arc<dyn RpcApi>, serde_json::Value) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = RpcResult<serde_json::Value>> + Send + 'static,
    {
        let api = self.api.clone();
        self.routes.insert(
            name,
            Box::new(move |params| Box::pin(f(api.clone(), params))),
        );
    }

    pub async fn dispatch(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> RpcResult<serde_json::Value> {
        if let Some(handler) = self.routes.get(method) {
            handler(params).await
        } else {
            Err(RpcError::MethodNotFound)
        }
    }
}
