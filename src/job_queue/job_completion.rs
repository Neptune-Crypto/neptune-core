use super::errors::JobHandleError;
use super::traits::JobResult;

/// represents completion state of a job
#[derive(Debug, strum::Display)]
pub enum JobCompletion {
    /// The job finished processing normally.
    Finished(Box<dyn JobResult>),

    /// The job was cancelled before or during processing.
    Cancelled,

    /// The job panicked during processing.
    ///
    /// the payload comes from [tokio::task::JoinError::into_panic()]
    /// and can be used as input to [std::panic::resume_unwind()]
    Panicked(Box<dyn std::any::Any + Send + 'static>),
}

impl<T: JobResult> From<T> for JobCompletion {
    fn from(result: T) -> Self {
        Self::Finished(Box::new(result))
    }
}

impl TryFrom<JobCompletion> for Box<dyn JobResult> {
    type Error = JobHandleError;

    fn try_from(jc: JobCompletion) -> Result<Self, Self::Error> {
        jc.result()
    }
}

impl JobCompletion {
    pub fn result(self) -> Result<Box<dyn JobResult>, JobHandleError> {
        match self {
            JobCompletion::Finished(r) => Ok(r),
            JobCompletion::Cancelled => Err(JobHandleError::JobCancelled),
            JobCompletion::Panicked(e) => Err(JobHandleError::JobPanicked(e)),
        }
    }
}
