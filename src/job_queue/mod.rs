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
//! An async_priority_channel::unbounded is used for queueing the jobs.
//! This is much like tokio::sync::mpsc::unbounded except:
//!  1. it supports prioritizing channel events (jobs)
//!  2. order of events with same priority is undefined.
//!     see: <https://github.com/rmcgibbo/async-priority-channel/issues/75>
//!
//! Using an unbounded channel means that there is no backpressure and no
//! upper limit on the number of jobs. (except RAM).
//!
//! A nice feature is that jobs may be of mixed (heterogenous) types
//! in a single JobQueue instance.  Any type that implements the Job trait
//! may be a job.

pub mod errors;
mod queue;
pub mod traits;
pub mod triton_vm;

pub use queue::JobQueue;
