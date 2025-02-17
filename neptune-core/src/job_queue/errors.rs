#[derive(Debug, Clone, thiserror::Error)]
pub enum JobHandleError {
    #[error("the job was cancelled")]
    JobCancelled,

    #[error("channel send error cancelling job")]
    CancelJobError(#[from] tokio::sync::watch::error::SendError<()>),

    #[error("channel recv error waiting for job results")]
    JobResultError(#[from] tokio::sync::oneshot::error::RecvError),
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum JobQueueError {
    #[error("channel send error adding job")]
    AddJobError(String),
}
