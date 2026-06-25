use std::any::Any;

use super::channels::JobCancelReceiver;
use super::job_completion::JobCompletion;

/// represents a job result, which can be any type.
pub trait JobResult: Any + Send + Sync {
    fn as_any(&self) -> &dyn Any;
    fn into_any(self: Box<Self>) -> Box<dyn Any>;
}

// represents any kind of job
#[async_trait::async_trait]
pub trait Job: Send + Sync {
    fn is_async(&self) -> bool;

    // note: we provide unimplemented default methods for
    // run and run_async.  This is so that implementing types
    // only need to impl the appropriate method.

    fn run(&self, _rx: JobCancelReceiver) -> JobCompletion {
        unimplemented!()
    }

    /// This method is called by JobQueue.  The default implementation handles job
    /// cancellation, so most Job implementors can simply impl run_async() and
    /// cancellation is automatic.
    async fn run_async_cancellable(&self, mut rx: JobCancelReceiver) -> JobCompletion {
        tokio::select! {
            _ = rx.changed() => {
                tracing::debug!("async job got cancel message. cancelling.");
                JobCompletion::Cancelled
            }

            job_result = self.run_async() => {
                JobCompletion::Finished(job_result)
            },
        }
    }

    /// implement this method to perform the work of the job.
    async fn run_async(&self) -> Box<dyn JobResult> {
        unimplemented!()
    }
}

// so we can do eg:
//   job_queue.add_job(job, priority);
// instead of:
//   job_queue.add_job(Box::new(job), priority);
impl<T: Job + 'static> From<T> for Box<dyn Job> {
    fn from(job: T) -> Self {
        Box::new(job) as Box<dyn Job>
    }
}
