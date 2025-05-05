//! This module implements a prioritized, heterogenous job queue that sends
//! completed job results to the initiator/caller.
//!
//! This is intended for running heavy multi-threaded jobs that should be run
//! one at a time to avoid resource contention.  By using this queue, multiple
//! (async) tasks can initiate these tasks and wait for results without need
//! of any other synchronization.
//!
//! note: Other rust job queues I found either did not support waiting for job
//! results or else were overly complicated, requiring backend database, etc.
//!
//! Both blocking and non-blocking (async) jobs are supported.  Non-blocking jobs
//! are called inside spawn_blocking() in order to execute on tokio's blocking
//! thread-pool.  Async jobs are simply awaited.
//!
//! There is no upper limit on the number of jobs. (except RAM).
//!
//! Jobs may be of mixed (heterogenous) types in a single [JobQueue] instance.
//! Any type that implements the [Job](traits::Job) trait may be a job.
//!
//! Each Job has an associated [JobHandle] that is used to await or cancel the
//! job.  If the `JobHandle` is dropped, the job will be cancelled.

// please note that the job_queue module has zero neptune-core specific
// code in it.  It is intended/planned to move job_queue into its own
// crate in the (near) future.

pub mod errors;
mod queue;
pub mod traits;
pub mod triton_vm;

pub use queue::JobQueue;
