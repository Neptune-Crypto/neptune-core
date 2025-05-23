use std::ops::Deref;
use std::ops::DerefMut;
use std::sync::Arc;

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
    /// returns the single, shared triton vm job queue (singleton).
    ///
    /// callers should execute resource intensive triton-vm tasks in this
    /// queue to avoid running simultaneous tasks that could exceed hardware
    /// capabilities.
    #[cfg(not(test))]
    pub fn get_instance() -> Arc<Self> {
        Self::get_instance_internal()
    }

    /// returns a triton vm job queue.
    ///
    /// By default, the returned queue will be a shared singleton instance.
    ///
    /// When running unit tests, a shared instance has these characteristics:
    ///
    /// 1. tests must wait for each other's jobs to complete. CPU usage tends to
    ///    be low for much of the testing duration.
    /// 2. it is possible to run all tests in parallel and generate proofs when
    ///    proofs do not exist in local cache or on proof-server.
    /// 3. total time for running all tests increases substantially compared to
    ///    scenario where each test using its own job-queue instance.
    ///
    /// A non-shared instance has these characteristics:
    ///
    /// 1. tests run independently and use up all CPU cores.
    /// 2. it is not possible to run all tests in parallel and generate proofs
    ///    as it would exhaust device's resources, especially RAM.  This mode
    ///    only works well when proofs are already cached.  A workaround is to
    ///    run with --test-threads 1 to generate proofs.
    /// 3. total time for running all tests decrease substantially (assuming
    ///    proofs are cached) vs the shared-instance scenario.
    ///
    /// When running unit tests, shared mode is the default. The mode can be
    /// selected at runtime via:
    ///
    /// ```text
    /// # disable shared queue (each test gets it's own queue)
    /// VM_JOB_QUEUE_SHARED=false cargo test <args>
    ///
    /// # enable shared queue (default behavior)
    /// VM_JOB_QUEUE_SHARED=true cargo test <args>
    /// ```
    #[cfg(test)]
    pub fn get_instance() -> Arc<Self> {
        let shared = std::env::var("VM_JOB_QUEUE_SHARED").unwrap_or_else(|_| "true".to_string());

        match shared.as_str() {
            "false" => Arc::new(Self(JobQueue::<TritonVmJobPriority>::start())),
            "true" | &_ => Self::get_instance_internal(),
        }
    }

    fn get_instance_internal() -> Arc<Self> {
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
