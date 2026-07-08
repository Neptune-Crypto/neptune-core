use std::fmt;

use super::errors::JobHandleError;
use super::traits::JobResult;

/// represents completion state of a job
#[derive(strum::Display)]
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

impl fmt::Debug for JobCompletion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JobCompletion::Finished(result) => {
                // Attempt to downcast and debug if the underlying JobResult implements Debug
                if let Some(debuggable) = result
                    .as_any()
                    .downcast_ref::<Box<dyn fmt::Debug + Send + Sync>>()
                {
                    write!(f, "Finished({:?})", debuggable)
                } else {
                    write!(f, "Finished(Box<dyn JobResult>)")
                }
            }
            JobCompletion::Cancelled => write!(f, "Cancelled"),
            JobCompletion::Panicked(_) => write!(f, "Panicked(<payload>)"),
        }
    }
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
    /// convert into a JobResult fallibly.
    pub fn result(self) -> Result<Box<dyn JobResult>, JobHandleError> {
        match self {
            JobCompletion::Finished(r) => Ok(r),
            JobCompletion::Cancelled => Err(JobHandleError::JobCancelled),
            JobCompletion::Panicked(e) => Err(e.into()),
        }
    }

    /// obtain a JobResult reference fallibly
    pub fn result_ref(&self) -> Option<&dyn JobResult> {
        match self {
            JobCompletion::Finished(r) => Some(&**r),
            _ => None,
        }
    }

    /// convert into a JobResult.  panics if job did not finish.
    pub fn unwrap(self) -> Box<dyn JobResult> {
        self.result()
            .unwrap_or_else(|e| panic!("Job did not finish. no result available. {}", e))
    }

    /// indicates if job finished successfully or not.
    ///
    /// if true, [Self::unwrap()] is guaranteed to succeed.
    /// if false [Self::unwrap_err()] is guaranteed to succeed.
    pub fn finished(&self) -> bool {
        match self {
            JobCompletion::Finished(_) => true,
            JobCompletion::Cancelled => false,
            JobCompletion::Panicked(_) => false,
        }
    }

    // convert into JobHandleError. panics if job Finished.
    pub fn unwrap_err(self) -> JobHandleError {
        self.err()
            .unwrap_or_else(|| panic!("Job finished. no error available"))
    }

    // fallibly convert into JobHandleError
    pub fn err(self) -> Option<JobHandleError> {
        self.result().err()
    }
}
