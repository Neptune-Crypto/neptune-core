/// a job-handle error.
///
/// This error is not `Sync` due to the `JobPanicked` variant
/// which holds panic information as returned from tokio::spawn().
///
/// If a Sync type is needed, use the `into_sync()` method.
#[derive(Debug, thiserror::Error)]
pub enum JobHandleError {
    #[error("the job was cancelled")]
    JobCancelled,

    #[error("the job panicked during processing")]
    JobPanicked(Box<dyn std::any::Any + Send + 'static>),

    #[error("channel send error cancelling job")]
    CancelJobError(#[from] tokio::sync::watch::error::SendError<()>),

    #[error("channel recv error waiting for job results")]
    JobResultError(#[from] tokio::sync::oneshot::error::RecvError),
}

impl JobHandleError {
    /// convert into a type that implements `Sync`
    ///
    /// note that the JobPanicked variant becomes a `String`.
    pub fn into_sync(self) -> JobHandleErrorSync {
        self.into()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum JobHandleErrorSync {
    #[error("the job was cancelled")]
    JobCancelled,

    #[error("the job panicked: {0}")]
    JobPanicked(String),

    #[error("channel send error cancelling job")]
    CancelJobError(#[from] tokio::sync::watch::error::SendError<()>),

    #[error("channel recv error waiting for job results")]
    JobResultError(#[from] tokio::sync::oneshot::error::RecvError),
}

impl From<JobHandleError> for JobHandleErrorSync {
    fn from(e: JobHandleError) -> Self {
        match e {
            JobHandleError::JobPanicked(panic_info) => {
                // we have to convert panic payload to a string because panics can
                // contain any type, and they are Send but not Sync.
                let panic_message =
                    panic_info
                        .downcast_ref::<String>()
                        .cloned()
                        .unwrap_or_else(|| {
                            if let Some(s) = panic_info.downcast_ref::<&'static str>() {
                                (*s).to_string()
                            } else {
                                format!(
                                    "Panic occurred with an unsupported payload type: {}",
                                    std::any::type_name_of_val(&*panic_info)
                                )
                            }
                        });
                Self::JobPanicked(panic_message)
            }
            JobHandleError::JobCancelled => Self::JobCancelled,
            JobHandleError::CancelJobError(e) => Self::CancelJobError(e),
            JobHandleError::JobResultError(e) => Self::JobResultError(e),
        }
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum JobQueueError {
    #[error("channel send error adding job.  error: {0}")]
    AddJobError(String),
}
