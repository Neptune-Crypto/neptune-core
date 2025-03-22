use std::sync::Arc;
use std::sync::OnceLock;

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

/// provides type safety and clarity in case we implement multiple job queues.
pub type TritonVmJobQueue = JobQueue<TritonVmJobPriority>;

/// returns reference-counted clone of the triton vm job queue.
///
/// callers should execute resource intensive triton-vm tasks in this
/// queue to avoid running simultaneous tasks that could exceed hardware
/// capabilities.
pub fn vm_job_queue() -> Arc<TritonVmJobQueue> {
    static JOB_QUEUE_LOCK: OnceLock<Arc<TritonVmJobQueue>> = OnceLock::new();

    JOB_QUEUE_LOCK
        .get_or_init(|| Arc::new(TritonVmJobQueue::start()))
        .clone()
}
