use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::application::json_rpc::core::api::rpc::RpcApi;
use crate::application::json_rpc::core::error::RpcError;
use crate::application::json_rpc::core::error::RpcResult;

type HandlerFn = Box<
    dyn Fn(serde_json::Value) -> Pin<Box<dyn Future<Output = RpcResult<serde_json::Value>> + Send>>
        + Send
        + Sync,
>;

#[allow(missing_debug_implementations)]
pub struct Router<A: ?Sized> {
    routes: HashMap<&'static str, HandlerFn>,
    api: Arc<A>,
}

impl<A> Router<A>
where
    A: Send + Sync + 'static + ?Sized,
{
    pub fn new(api: Arc<A>) -> Self {
        Self {
            routes: HashMap::new(),
            api,
        }
    }

    pub fn insert<F, Fut>(&mut self, name: &'static str, f: F)
    where
        F: Fn(Arc<A>, serde_json::Value) -> Fut + Send + Sync + 'static,
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

pub type RpcRouter = Router<dyn RpcApi>;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::sync::Arc;

    use macro_rules_attr::apply;
    use serde_json::json;

    use crate::application::json_rpc::core::api::router::Router;
    use crate::application::json_rpc::core::error::RpcError;
    use crate::tests::shared_tokio_runtime;

    struct DummyApi;

    #[apply(shared_tokio_runtime)]
    async fn dispatch_known_method() {
        let api = Arc::new(DummyApi);
        let mut router = Router::new(api.clone());

        router.insert("echo", |_api, params| async move {
            Ok(json!({ "echo": params }))
        });

        let params = json!({ "message": "hello" });
        let result = router.dispatch("echo", params.clone()).await.unwrap();

        assert_eq!(result, json!({ "echo": params }));
    }

    #[apply(shared_tokio_runtime)]
    async fn dispatch_unknown_method() {
        let api = Arc::new(DummyApi);
        let router = Router::new(api);

        let err = router.dispatch("nonexistent", json!({})).await.unwrap_err();
        assert!(matches!(err, RpcError::MethodNotFound));
    }
}
