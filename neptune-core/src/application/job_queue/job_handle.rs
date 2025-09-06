use std::future::Future;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;

use super::channels::JobCancelSender;
use super::channels::JobResultReceiver;
use super::errors::JobHandleError;
use super::job_completion::JobCompletion;
use super::job_id::JobId;

/// A job-handle enables cancelling a job and awaiting results
///
/// A JobHandle can be awaited directly.  It returns a
/// `Result<JobCompletion, JobHandleError>`
///
/// See [JobCompletion] and [JobHandleError] for details.
///
/// When the `JobHandle` is dropped a cancellation message is sent to the job
/// task.
#[derive(Debug)]
pub struct JobHandle {
    job_id: JobId,
    result_rx: JobResultReceiver,
    cancel_tx: JobCancelSender,
}
impl JobHandle {
    // private instantiation fn.  only for use by JobQueue
    pub(super) fn new(
        job_id: JobId,
        result_rx: JobResultReceiver,
        cancel_tx: JobCancelSender,
    ) -> Self {
        Self {
            job_id,
            result_rx,
            cancel_tx,
        }
    }

    // indicates if job has finished processing or not.
    //
    // returns true if job completed normally or was cancelled or panicked.
    //
    // returns false if job is still waiting in the queue or is presently
    // processing.
    pub fn is_finished(&self) -> bool {
        self.cancel_tx.is_closed()
    }

    /// sends cancel message to job and returns immediately.
    ///
    /// note: await the JobHandle after calling `cancel()` to ensure the job has
    /// ended and obtain a [JobCompletion]
    ///
    /// Basic example:
    ///
    /// ```
    /// use neptune_cash::application::job_queue::JobQueue;
    /// use neptune_cash::application::job_queue::JobCompletion;
    /// use neptune_cash::application::job_queue::traits::Job;
    /// use neptune_cash::application::job_queue::errors::JobHandleError;
    ///
    /// async fn add_and_cancel_job(job_queue: &mut JobQueue<u8>, job: Box<dyn Job>) -> Result<JobCompletion, JobHandleError> {
    ///
    ///     let job_priority: u8 = 10;
    ///     let job_handle = job_queue.add_job(job, job_priority).unwrap();
    ///
    ///     // some time later...
    ///     tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    ///
    ///     job_handle.cancel()?;
    ///
    ///     let job_completion_result = job_handle.await;
    ///     assert!(matches!(job_completion_result, Ok(JobCompletion::Cancelled)));
    ///
    ///     job_completion_result
    /// }
    /// ```
    ///
    /// Sometimes it is necessary to listen for an application message that
    /// the job needs to cancel.  This can be achieved with tokio::select!{}
    ///
    /// Example:
    ///
    /// ```
    /// use neptune_cash::application::job_queue::JobQueue;
    /// use neptune_cash::application::job_queue::JobCompletion;
    /// use neptune_cash::application::job_queue::traits::Job;
    /// use neptune_cash::application::job_queue::errors::JobHandleError;
    ///
    /// async fn do_some_work(
    ///     job_queue: &mut JobQueue<u8>,
    ///     job: Box<dyn Job>,
    ///     cancel_work_rx: tokio::sync::oneshot::Receiver<()>,
    /// ) -> Result<JobCompletion, JobHandleError> {
    ///
    ///     // add the job to queue
    ///     let job_priority: u8 = 10;
    ///     let job_handle = job_queue.add_job(job, job_priority).unwrap();
    ///
    ///     // pin job_handle, so borrow checker knows the address can't change
    ///     // and it is safe to use in both select branches
    ///     tokio::pin!(job_handle);
    ///
    ///     // execute job and simultaneously listen for cancel msg from elsewhere
    ///     let job_completion_result = tokio::select! {
    ///         // case: job completion.
    ///         completion = &mut job_handle => completion,
    ///
    ///         // case: sender cancelled, or sender dropped.
    ///         _ = cancel_work_rx => {
    ///             job_handle.cancel()?;
    ///             job_handle.await
    ///         }
    ///     };
    ///     job_completion_result
    /// }
    /// ```
    pub fn cancel(&self) -> Result<(), JobHandleError> {
        let result = self.cancel_tx.send(()).map_err(JobHandleError::from);

        match result {
            Ok(_) => tracing::debug!("Sent job-cancel msg to job: {}", self.job_id),
            Err(ref e) => tracing::error!("{}", e),
        };

        result
    }

    /// obtain the job identifier
    pub fn job_id(&self) -> JobId {
        self.job_id
    }
}

// we implement Future for JobHandle so that a JobHandle can be
// directly awaited (like a tokio JoinHandle).
impl Future for JobHandle {
    type Output = Result<JobCompletion, JobHandleError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Directly poll the underlying result_rx
        let result_rx = &mut self.get_mut().result_rx;
        Pin::new(result_rx).poll(cx).map_err(|e| e.into())
    }
}

impl Drop for JobHandle {
    fn drop(&mut self) {
        tracing::debug!("JobHandle dropping for job: {}", self.job_id);
        if !self.cancel_tx.is_closed() {
            let _ = self.cancel();
        }
    }
}
