use std::ops::Deref;
use std::ops::DerefMut;
use std::sync::Arc;

use super::job_queue::JobQueue;

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
    pub fn get_instance() -> Arc<Self> {
        use std::sync::OnceLock;
        static INSTANCE: OnceLock<Arc<TritonVmJobQueue>> = OnceLock::new();
        INSTANCE
            .get_or_init(|| Arc::new(Self(JobQueue::<TritonVmJobPriority>::start())))
            .clone()
    }
}

/// returns a clonable reference to the single (per process) VM job queue.
pub fn vm_job_queue() -> Arc<TritonVmJobQueue> {
    TritonVmJobQueue::get_instance()
}
