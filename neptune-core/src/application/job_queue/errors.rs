use std::sync::Mutex;

/// a job-handle error.
#[derive(Debug, thiserror::Error)]
pub enum JobHandleError {
    #[error("the job was cancelled")]
    JobCancelled,

    // see comment for PanicInfo below
    #[error("the job panicked during processing")]
    JobPanicked(PanicInfo),

    #[error("channel send error cancelling job")]
    CancelJobError(#[from] tokio::sync::watch::error::SendError<()>),

    #[error("channel recv error waiting for job results: {0}")]
    JobResultError(#[from] tokio::sync::oneshot::error::RecvError),

    #[error("downcast failed converting '{from}' to '{to}'")]
    JobResultWrapperError {
        from: &'static str,
        to: &'static str,
    },
}

impl From<Box<dyn std::any::Any + Send + 'static>> for JobHandleError {
    fn from(panic_info: Box<dyn std::any::Any + Send + 'static>) -> Self {
        Self::JobPanicked(PanicInfo(Mutex::new(panic_info)))
    }
}

impl JobHandleError {
    /// Returns true if the error was caused by the task panicking.
    ///
    /// ```
    /// use neptune_cash::application::job_queue::JobQueue;
    /// use neptune_cash::application::job_queue::traits::*;
    ///
    /// struct PanicJob;
    ///
    /// #[async_trait::async_trait]
    /// impl Job for PanicJob {
    ///     fn is_async(&self) -> bool {
    ///         true
    ///     }
    ///     async fn run_async(&self) -> Box<dyn JobResult> {
    ///        panic!("{}", "boom");
    ///     }
    /// }
    ///
    /// #[tokio::main]
    /// async fn main() -> anyhow::Result<()> {
    ///     let job_queue = JobQueue::start();
    ///     let job_handle = job_queue.add_job(PanicJob, 1)?;
    ///
    ///     let err = job_handle.await?.unwrap_err();
    ///     assert!(err.is_panic());
    ///
    ///     Ok(())
    /// }
    /// ```
    pub fn is_panic(&self) -> bool {
        matches!(self, Self::JobPanicked(_))
    }

    /// into_panic() panics if the Error does not represent the underlying task terminating with a panic. Use is_panic to check the error reason or try_into_panic for a variant that does not panic.
    ///
    /// ```should_panic(expected = "boom")
    /// use neptune_cash::application::job_queue::JobQueue;
    /// use neptune_cash::application::job_queue::traits::*;
    ///
    /// struct PanicJob;
    ///
    /// #[async_trait::async_trait]
    /// impl Job for PanicJob {
    ///     fn is_async(&self) -> bool {
    ///         true
    ///     }
    ///     async fn run_async(&self) -> Box<dyn JobResult> {
    ///        panic!("{}", "boom");
    ///     }
    /// }
    ///
    /// #[tokio::main]
    /// async fn main() -> anyhow::Result<()> {
    ///     let job_queue = JobQueue::start();
    ///     let job_handle = job_queue.add_job(PanicJob, 1)?;
    ///
    ///     let err = job_handle.await?.unwrap_err();
    ///
    ///     // Resume the panic on the main task
    ///     std::panic::resume_unwind(err.into_panic());
    ///
    ///     Ok(())
    /// }
    /// ```
    pub fn into_panic(self) -> Box<dyn std::any::Any + Send + 'static> {
        self.try_into_panic()
            .expect("should be JobPanicked variant")
    }

    /// Consumes the `JobHandleError`, returning the object with which the task panicked if the task terminated due to a panic. Otherwise, self is returned.
    ///
    /// ```should_panic(expected = "boom")
    /// use neptune_cash::application::job_queue::JobQueue;
    /// use neptune_cash::application::job_queue::traits::*;
    ///
    /// struct PanicJob;
    ///
    /// #[async_trait::async_trait]
    /// impl Job for PanicJob {
    ///     fn is_async(&self) -> bool {
    ///         true
    ///     }
    ///     async fn run_async(&self) -> Box<dyn JobResult> {
    ///        panic!("{}", "boom");
    ///     }
    /// }
    ///
    /// #[tokio::main]
    /// async fn main() -> anyhow::Result<()> {
    ///     let job_queue = JobQueue::start();
    ///     let job_handle = job_queue.add_job(PanicJob, 1)?;
    ///
    ///     let err = job_handle.await?.unwrap_err();
    ///
    ///     // Resume the panic on the main task
    ///     let panic = err.try_into_panic()?;
    ///     std::panic::resume_unwind(panic);
    ///
    ///     Ok(())
    /// }
    /// ```
    pub fn try_into_panic(self) -> Result<Box<dyn std::any::Any + Send + 'static>, Self> {
        match self {
            // Consume self here
            Self::JobPanicked(panic_mutex) => {
                // The unwrap() cannot fail. see PanicInfo comment.
                Ok(panic_mutex.0.into_inner().unwrap())
            }
            other => Err(other), // For other variants, just return them
        }
    }

    /// returns panic message, if available
    ///
    /// returns None if Error variant is not `JobPanicked` or panic info cannot
    /// be downcast to a string representation
    ///
    /// ```
    /// use neptune_cash::application::job_queue::JobQueue;
    /// use neptune_cash::application::job_queue::traits::*;
    ///
    /// struct PanicJob;
    ///
    /// #[async_trait::async_trait]
    /// impl Job for PanicJob {
    ///     fn is_async(&self) -> bool {
    ///         true
    ///     }
    ///     async fn run_async(&self) -> Box<dyn JobResult> {
    ///        panic!("{}", "boom");
    ///     }
    /// }
    ///
    /// #[tokio::main]
    /// async fn main() -> anyhow::Result<()> {
    ///     let job_queue = JobQueue::start();
    ///     let job_handle = job_queue.add_job(PanicJob, 1)?;
    ///
    ///     let err = job_handle.await?.unwrap_err();
    ///     assert_eq!( Some("boom".to_string()), err.panic_message());
    ///
    ///     Ok(())
    /// }
    /// ```
    pub fn panic_message(&self) -> Option<String> {
        match self {
            JobHandleError::JobPanicked(panic_mutex) => {
                let guard = panic_mutex.0.lock().unwrap();
                if let Some(s) = guard.downcast_ref::<&'static str>() {
                    Some((*s).to_string())
                } else {
                    guard.downcast_ref::<String>().cloned()
                }
            }
            _ => None,
        }
    }
}

/// Holds panic information
//
// 1. The Box holds panic info as returned from tokio JoinError::into_panic()
// 2. The Mutex makes the panic info `Sync`.
// 3. PanicInfo makes the mutex private to guarantee lock() can never be called
//    on it by code outside this module.
// 4. lock() is never called inside this module.
// 5. Since lock() is never called:
//    a. the mutex can never be poisoned.
//    b. Mutex::into_inner() is guaranteed to succeed.
//
// possible alternatives to Mutex:
//
// Mutex is only being used for `Sync` not for locking.
//
// other possible candidates are discussed here:
// https://github.com/Neptune-Crypto/neptune-core/pull/584#discussion_r2086163632
//
// std::sync::Exclusive seems a better fit, but is not yet in stable rust as
// of rust 1.86.0.
#[derive(Debug)]
pub struct PanicInfo(Mutex<Box<dyn std::any::Any + Send + 'static>>);

#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum AddJobError {
    #[error("channel send error adding job.  error: {0}")]
    SendError(#[from] tokio::sync::mpsc::error::SendError<()>),
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StopQueueError {
    #[error("channel send error adding job.  error: {0}")]
    SendError(#[from] tokio::sync::watch::error::SendError<()>),

    #[error("join error while waiting for job-queue to stop.  error: {0}")]
    JoinError(#[from] tokio::task::JoinError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn job_handle_error_into_panic() {
        let join_err = tokio::spawn(async { panic!("boom") }).await.unwrap_err();
        let err: JobHandleError = join_err.into_panic().into();
        // just execute, to ensure it does not panic.
        let _ = err.into_panic();
    }

    #[tokio::test]
    async fn job_handle_error_try_into_panic() {
        let join_err = tokio::spawn(async { panic!("boom") }).await.unwrap_err();
        let err: JobHandleError = join_err.into_panic().into();
        assert!(err.try_into_panic().is_ok());
    }

    #[tokio::test]
    async fn job_handle_error_panic_message() {
        let join_err = tokio::spawn(async { panic!("boom") }).await.unwrap_err();
        let err: JobHandleError = join_err.into_panic().into();
        assert_eq!(Some("boom"), err.panic_message().as_deref());
    }
}
