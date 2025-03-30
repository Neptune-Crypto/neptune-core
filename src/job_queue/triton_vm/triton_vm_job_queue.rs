use std::ops::Deref;
use std::ops::DerefMut;
use std::sync::Arc;

use super::super::JobQueue;

// todo: maybe we want to have more levels or just make it an integer eg u8.
// or maybe name the levels by type/usage of job/proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum TritonVmJobPriority {
    Lowest = 1,
    Low = 2,
    #[default]
    Normal = 3,
    High = 4,
    Highest = 5,
}

#[derive(Debug)]
pub struct TritonVmJobQueue(JobQueue<TritonVmJobPriority>);

impl Deref for TritonVmJobQueue {
    type Target = JobQueue<TritonVmJobPriority>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for TritonVmJobQueue {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl TritonVmJobQueue {
    /// returns the triton vm job queue (singleton).
    ///
    /// callers should execute resource intensive triton-vm tasks in this
    /// queue to avoid running simultaneous tasks that could exceed hardware
    /// capabilities.
    #[cfg(not(test))]
    pub fn get_instance() -> Arc<Self> {
        use std::sync::OnceLock;
        static INSTANCE: OnceLock<Arc<TritonVmJobQueue>> = OnceLock::new();
        INSTANCE
            .get_or_init(|| Arc::new(Self(JobQueue::<TritonVmJobPriority>::start())))
            .clone()
    }

    // note: this cfg(test) is temporary. It is needed because tests each
    // run in their own tokio runtime, so they cannot share a single job-queue instance
    // which spawns its own async tasks.  Because when the test runtime shuts down it
    // kills the job-queue tasks.
    //
    // The temporary solution is that each call returns a new JobQueue instance.
    // That prevents tests from interfering with eachother at the cost that multiple job-queue
    // exist concurrently.
    //
    // The proper solution is for tests to share a single tokio runtime.
    // This change will be coming in a followup commit/PR.
    #[cfg(test)]
    pub fn get_instance() -> Arc<Self> {
        Arc::new(Self(JobQueue::<TritonVmJobPriority>::start()))
    }

    /// Wrapper for Self::get_instance()
    /// here for two reasons:
    ///  1. backwards compat with existing tests
    ///  2. if tests call dummy() instead of start(), then it is easier
    ///     to find where start() is called for real.
    #[cfg(test)]
    pub fn dummy() -> Arc<Self> {
        Self::get_instance()
    }
}

/// returns a clonable reference to the single (per process) VM job queue.
pub fn vm_job_queue() -> Arc<TritonVmJobQueue> {
    TritonVmJobQueue::get_instance()
}
