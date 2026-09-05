use std::ops::Deref;
use std::ops::DerefMut;
use std::sync::Arc;

use neptune_job_queue::JobQueue;

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
            .get_or_init(|| {
                // Started on the queue's own runtime, not the caller's.
                //
                // `JobQueue::start` spawns its worker with `tokio::spawn`, so
                // the worker lives on whichever runtime is current at first
                // use. That is right for a queue whose lifetime is the
                // caller's, and the job-queue crate tests it deliberately
                // (`runtime_shutdown_cancels_job`). It is wrong for *this*
                // queue, which is a process-wide singleton: the first caller's
                // runtime is an arbitrary one, and when it goes so does the
                // worker, leaving every later `add_job` to fail with
                // `AddJobError(SendError)` -- a queue that exists but cannot be
                // reached.
                //
                // The case where that bites is `#[tokio::test]`: each test
                // builds its own runtime and drops it at test end, so whichever
                // test touches the queue first takes the worker down with it.
                // It surfaces only when a test actually has to prove, since a
                // proof-cache hit submits no job -- which is what made it look
                // like an unreproducible flake for three days.
                //
                // So the singleton brings a runtime of matching lifetime. It is
                // a `static`, hence never dropped, which also means
                // `Runtime::drop` -- which panics inside an async context --
                // can never run.
                let _guard = worker_runtime().enter();

                Arc::new(Self(JobQueue::<TritonVmJobPriority>::start()))
            })
            .clone()
    }
}

/// The runtime hosting the singleton queue's worker task, built on first use and
/// never torn down. See [`TritonVmJobQueue::get_instance`].
fn worker_runtime() -> &'static tokio::runtime::Runtime {
    use std::sync::OnceLock;
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("triton-vm-job-queue")
            .build()
            .expect("the Triton VM job queue's runtime must build")
    })
}

/// returns a clonable reference to the single (per process) VM job queue.
pub fn vm_job_queue() -> Arc<TritonVmJobQueue> {
    TritonVmJobQueue::get_instance()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use neptune_job_queue::channels::JobCancelReceiver;
    use neptune_job_queue::traits::Job;
    use neptune_job_queue::traits::JobResult;
    use neptune_job_queue::JobCompletion;

    use super::*;

    /// The smallest thing the queue will run. Sync, so the impl needs no
    /// `async_trait` attribute -- what is under test is whether the worker is
    /// alive, not what it runs.
    #[derive(Debug)]
    struct Noop;

    impl JobResult for Noop {
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }

        fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
            self
        }
    }

    impl Job for Noop {
        fn is_async(&self) -> bool {
            false
        }

        fn run(&self, _cancel_rx: JobCancelReceiver) -> JobCompletion {
            JobCompletion::Finished(Box::new(Noop))
        }
    }

    /// The singleton's worker outlives the runtime that first reached it.
    ///
    /// Without the private runtime, the worker is spawned onto whichever
    /// runtime called `get_instance` first; here that runtime is dropped
    /// outright, and a job submitted afterwards still has to run. This is the
    /// whole of the `AddJobError(SendError)` failure that every proof-bearing
    /// `#[tokio::test]` inherits on a cold proof cache -- each test brings its
    /// own runtime and drops it on the way out.
    ///
    /// Order-sensitive in one direction only: if another test in this binary
    /// already initialized the singleton on a runtime that is still alive, this
    /// passes without proving anything. It cannot pass *spuriously* after a
    /// regression -- it still fails whenever it gets there first -- but run it
    /// alone if you want to watch it fail.
    #[test]
    fn singleton_outlives_the_runtime_that_created_it() {
        let creator = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let queue = creator.block_on(async { vm_job_queue() });
        drop(creator);

        let later = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        later.block_on(async {
            let handle = queue
                .add_job(Noop, TritonVmJobPriority::Normal)
                .expect("the queue must still accept jobs once its creator's runtime is gone");

            assert!(
                matches!(handle.await, Ok(JobCompletion::Finished(_))),
                "and must still run them to completion"
            );
        });
    }
}
