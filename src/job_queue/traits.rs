use std::any::Any;

pub trait JobResult: Any + Send + Sync + std::fmt::Debug {
    fn as_any(&self) -> &dyn Any;
}

// represents any kind of job
#[async_trait::async_trait]
pub trait Job: Send + Sync {
    fn is_async(&self) -> bool;

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
}
