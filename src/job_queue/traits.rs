use std::any::Any;

use serde::de::DeserializeOwned;

pub trait JobResult: Any + Send + Sync + std::fmt::Debug {
    fn as_any(&self) -> &dyn Any;
}

pub(crate) enum Synchronicity {
    Blocking,
    Async,
    Process,
}

// represents any kind of job
#[async_trait::async_trait]
pub trait Job: Send + Sync {
    type ResultType: DeserializeOwned + Send;

    fn synchronicity(&self) -> Synchronicity;

    // note: we provide unimplemented default methods for
    // run and run_async.  This is so that implementing types
    // only need to impl the appropriate method.

    fn run(&self) -> Box<dyn JobResult> {
        unimplemented!()
    }

    // fn run_async(&self) ->  std::future::Future<Output = Box<dyn JobResult>> + Send;
    async fn run_async(&self) -> Box<dyn JobResult> {
        unimplemented!()
    }

    /// Implement if synchronicity is set to `Process`
    fn process(&self) -> tokio::process::Child {
        unimplemented!()
    }

    fn deserialize_result(&self, string: &str) -> serde_json::Result<Self::ResultType> {
        serde_json::from_str(string)
    }
}
