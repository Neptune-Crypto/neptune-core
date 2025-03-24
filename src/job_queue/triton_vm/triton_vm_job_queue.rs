use crate::job_queue::JobQueue;
use crate::singleton_job_queue;

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

singleton_job_queue! {
    #[doc = "A singleton job queue for Triton VM jobs."]
    TritonVmJobQueue = JobQueue<TritonVmJobPriority>
}
