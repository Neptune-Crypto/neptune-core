use std::sync::OnceLock;

use crate::job_queue::JobQueue;

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

/// A job queue for Triton VM Jobs.
pub type TritonVmJobQueue = JobQueue<TritonVmJobPriority>;

/// Global singleton accessor for the Triton VM Job Queue
//
// Ideally we implement a generic function `instance` on JobQueue but it seems
// as though generic type arguments do not play ball with static pointers.
pub fn global_triton_vm_job_queue() -> &'static TritonVmJobQueue {
    static REGISTRY: OnceLock<TritonVmJobQueue> = OnceLock::new();
    REGISTRY.get_or_init(TritonVmJobQueue::start)
}
