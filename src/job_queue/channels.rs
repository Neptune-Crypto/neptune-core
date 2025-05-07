use tokio::sync::oneshot;
use tokio::sync::watch;

use super::job_completion::JobCompletion;

pub type JobCancelReceiver = watch::Receiver<()>; // used in pub trait
pub(super) type JobCancelSender = watch::Sender<()>;

pub(super) type JobResultReceiver = oneshot::Receiver<JobCompletion>;
pub(super) type JobResultSender = oneshot::Sender<JobCompletion>;
