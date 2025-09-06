//! This module implements a prioritized, heterogenous job queue that sends
//! completed job results of arbitrary type to the initiator/caller.
//!
//! This is intended for running heavy multi-threaded jobs that should be run
//! one at a time to avoid resource contention.  By using this queue, multiple
//! (async) tasks can initiate these tasks and wait for results without need
//! of any other synchronization.
//!
//! note: Other rust job queues investigated cerca 2024 either did not support
//! waiting for job results or else were overly complicated, requiring backend
//! database, etc.
//!
//! Both blocking and non-blocking (async) jobs are supported.  Non-blocking jobs
//! are called inside spawn_blocking() in order to execute on tokio's blocking
//! thread-pool.  Async jobs are simply awaited.
//!
//! It supports prioritizing Jobs. The order of job execution is not a simple
//! FIFO or LIFO but rather depends on the assigned priority of each job.
//! Job priority level can be specified via any type that implements [Ord]
//! such as a custom enum.
//!
//! There is no upper limit on the number of jobs. (except RAM).
//!
//! Jobs may be of mixed (heterogenous) types in a single [JobQueue] instance.
//! Any type that implements the [Job](traits::Job) trait may be a job.
//!
//! Jobs may be async or blocking.  Both types can be run in the same JobQueue
//! instance concurrently.
//!
//! Job results also may be of any type.  Typically each type of Job will return
//! a single concrete result type.  A [JobResultWrapper] is provided to
//! facilitate this usage pattern.
//!
//! Each Job has an associated [JobHandle] that is used to await or cancel the
//! job.  If the `JobHandle` is dropped, the job will be cancelled.
//!
//! ## hello job-queue world.
//!
//! Here we demonstrate the most basic usage by creating a `HelloJobAsync` job
//! and running it once in the JobQueue.
//!
//! We choose an async job for this example because it's a little bit simpler.
//! We don't have to check for job-cancellation in the job itself.
//!
//! ```
//! use neptune_cash::application::job_queue::JobResultWrapper;
//! use neptune_cash::application::job_queue::JobQueue;
//! use neptune_cash::application::job_queue::traits::*;
//!
//! // define our custom job type that just returns "hello <name>"
//! pub struct HelloJobAsync(String);
//!
//! // implement Job trait.
//! #[async_trait::async_trait]
//! impl Job for HelloJobAsync {
//!     // indicate that we are an async Job
//!     fn is_async(&self) -> bool {
//!         true
//!     }
//!
//!     // as an async job we must impl run_async() or run_async_cancellable()
//!     async fn run_async(&self) -> Box<dyn JobResult> {
//!         let job_result = format!("hello {}", self.0);
//!         JobResultWrapper::<String>::new(job_result).into()
//!     }
//! }
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // we choose a simple u8 for prioritizing jobs in this queue.
//!     type QueuePriority = u8;
//!
//!     // start the JobQueue running.
//!     let mut job_queue = JobQueue::<QueuePriority>::start();
//!
//!     let job = HelloJobAsync("world".to_string());
//!     let job_handle = job_queue.add_job_mut(job, 1)?;
//!
//!     // await job to complete and obtain the (wrapped) job result
//!     let completion = job_handle.await?;
//!     let output = JobResultWrapper::<String>::try_from(completion)?.into_inner();
//!
//!     assert_eq!("hello world", output);
//!
//!     Ok(())
//! }
//! ```
//!
//! ## async vs blocking Job.
//!
//! To demonstrate the difference, we will implement an example job first as an
//! async job and then as a blocking job.
//!
//! The example job finds all the prime numbers in a provided range.
//!
//! We create 100 jobs, each searching a range of 100 numbers. So the first
//! 10000 integers are searched by all jobs.
//!
//! We use a `JobQueue<QueueJobPriority>` where `QueueJobPriority` is an enum we
//! define that simply has `Low` and `High` variants.
//!
//! The jobs are added to the queue in ascending order but each is assigned a
//! random job priority (either High or Low).  High priority jobs will process
//! first, thus queue-processing order will not match the order of adding jobs.
//!
//! In this example, job results are obtained by awaiting each JobHandle in the
//! order it was added.  Thus results are obtained in FIFO order despite the
//! out-of-order processing.
//!
//! Alternatively a JoinSet or join_all() could be used to await all job-handles
//! simultaneously and obtain results in queue-processing order as they complete.
//!
//! Likewise in an application with many concurrent tasks, each task might be
//! submitting a job and immediately awaiting the JobHandle.  In that scenario
//! whichever task has submitted the highest priority job will obtain results
//! first.
//!
//! ### Async Job considerations
//!
//! 1. the Job::is_async() impl returns true.
//! 2. Job::run_async() or Job::run_async_cancellable() must be implemented.
//!
//! It is important the job yield regularly to the async runtime.  Our
//! processing is inherently blocking, so we accomplish this simply by making
//! the is_prime() fn async, which is called in every loop iteration.
//!
//! ### Blocking job considerations
//!
//! 1. the Job::is_async() impl returns false.
//! 2. Job::run() must be implemented.
//! 3. it is necessary to regularly poll for a job-cancellation message in the
//!    job's main processing loop.
//!
//! ### Example
//!
//! ```
//! use neptune_cash::application::job_queue::JobCompletion;
//! use neptune_cash::application::job_queue::JobResultWrapper;
//! use neptune_cash::application::job_queue::JobQueue;
//! use neptune_cash::application::job_queue::channels::JobCancelReceiver;
//! use neptune_cash::application::job_queue::traits::*;
//! use rand::Rng;
//!
//! // ### First lets define some common types ###
//! // -------------------------------------------
//!
//! // define job priority levels for this job-queue.
//! #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
//! enum QueueJobPriority {
//!     Low = 1,
//!     High = 2,
//! }
//! impl QueueJobPriority {
//!     pub fn random() -> Self {
//!         let variants = [QueueJobPriority::Low, QueueJobPriority::High];
//!         variants[rand::rng().random_range(0..variants.len())]
//!     }
//! }
//!
//! // define type alias for a wrapper around the data returned by our
//! // job type. The wrapper is not required, but simplifies
//! // conversions.
//! type FindPrimesJobResult = JobResultWrapper<Vec<u64>>;
//!
//!
//! // ### Now we define an async Job ###
//! // ----------------------------------
//!
//! // define our custom job type that finds prime numbers within a range
//! #[derive(Debug)]
//! pub struct FindPrimesJobAsync {
//!     start: u64,
//!     len: u64,
//! }
//!
//! // The prime-number finding algorithm can be described as:
//! // Trial Division with Square Root Limit and 6k ± 1 Optimization
//! //
//! // we make the functions async because our "impl Job"
//! // defines this as an async job and thus the runtime needs
//! // some await points for cancellation and cooperating with
//! // other async tasks.
//! impl FindPrimesJobAsync {
//!     async fn is_prime(num: u64) -> bool {
//!         if num <= 1 {
//!             return false;
//!         }
//!         if num <= 3 {
//!             return true;
//!         }
//!         if num % 2 == 0 || num % 3 == 0 {
//!             return false;
//!         }
//!         let mut i = 5;
//!         while i * i <= num {
//!             if num % i == 0 || num % (i + 2) == 0 {
//!                 return false;
//!             }
//!             i += 6;
//!         }
//!         true
//!     }
//!
//!     async fn find_primes(&self) -> Vec<u64> {
//!         let mut primes = Vec::new();
//!         for num in self.start..=self.start + self.len {
//!             if Self::is_prime(num).await {
//!                 primes.push(num);
//!             }
//!         }
//!
//!         primes
//!     }
//! }
//!
//! // implement Job trait.
//! #[async_trait::async_trait]
//! impl Job for FindPrimesJobAsync {
//!     // we are an async Job, so we must impl the run_async method
//!     fn is_async(&self) -> bool {
//!         true
//!     }
//!
//!     async fn run_async(&self) -> Box<dyn JobResult> {
//!         let found_primes = self.find_primes().await;
//!         FindPrimesJobResult::new(found_primes).into()
//!     }
//! }
//!
//! // ### Define an equivalent blocking job ###
//! // -----------------------------------------
//!
//! // define our custom job type that finds prime numbers within a range
//! #[derive(Debug)]
//! pub struct FindPrimesJob {
//!     start: u64,
//!     len: u64,
//! }
//!
//! // The prime-number finding algorithm can be described as:
//! // Trial Division with Square Root Limit and 6k ± 1 Optimization
//! //
//! // None of the functions are async because our "impl Job"
//! // defines this as blocking job.  It will be run in tokio's blocking
//! // threadpool via a spawn_blocking() call in the job-queue.
//! impl FindPrimesJob {
//!     fn is_prime(num: u64) -> bool {
//!         if num <= 1 {
//!             return false;
//!         }
//!         if num <= 3 {
//!             return true;
//!         }
//!         if num % 2 == 0 || num % 3 == 0 {
//!             return false;
//!         }
//!         let mut i = 5;
//!         while i * i <= num {
//!             if num % i == 0 || num % (i + 2) == 0 {
//!                 return false;
//!             }
//!             i += 6;
//!         }
//!         true
//!     }
//! }
//!
//! // implement Job trait.
//! #[async_trait::async_trait]
//! impl Job for FindPrimesJob {
//!     // we are *not* an async Job.
//!     fn is_async(&self) -> bool {
//!         false
//!     }
//!
//!     // as a blocking job we must impl the run() method
//!     fn run(&self, cancel_rx: JobCancelReceiver) -> JobCompletion {
//!         let mut primes = Vec::new();
//!
//!         // this is the main processing loop of our job, so it should poll for
//!         // a cancellation message.  It could be more efficient and poll
//!         // every 100 iterations or n milliseconds, etc.
//!         for num in self.start..=self.start + self.len {
//!
//!             match cancel_rx.has_changed() {
//!                 Ok(changed) if changed => return JobCompletion::Cancelled,
//!                 Err(_) => return JobCompletion::Cancelled,
//!                 _ => {}
//!             }
//!
//!             if Self::is_prime(num) {
//!                 primes.push(num);
//!             }
//!         }
//!
//!         JobCompletion::Finished(FindPrimesJobResult::new(primes).into())
//!     }
//! }
//!
//! // Now let's run these jobs.
//! // -------------------------
//!
//! // Note that we will be mixing jobs of two different types.
//! // Result processing is simplified because they both return the same
//! // result type but that's not necessary.
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // setup
//!     const NUM_PRIMES_PER_JOB: u64 = 100;
//!     let mut job_handles = vec![];
//!
//!     // start the JobQueue running.
//!     let mut job_queue = JobQueue::<QueueJobPriority>::start();
//!
//!     // start 100 jobs, each searching 100 numbers for primes, with random job priorities
//!     // note that jobs begin processing right away while this loop is running.
//!     for n in 0..100 {
//!         let job_handle = if n % 2 == 0 {
//!             let job = FindPrimesJob {
//!                 start: n * NUM_PRIMES_PER_JOB,
//!                 len: NUM_PRIMES_PER_JOB,
//!             };
//!             job_queue.add_job_mut(job, QueueJobPriority::random())?
//!         } else {
//!             let job = FindPrimesJobAsync {
//!                 start: n * NUM_PRIMES_PER_JOB,
//!                 len: NUM_PRIMES_PER_JOB,
//!             };
//!             job_queue.add_job_mut(job, QueueJobPriority::random())?
//!         };
//!
//!         job_handles.push(job_handle);
//!     }
//!
//!     // await all the jobs to complete.  note that:
//!     // 1. jobs will be processed in a different order than they were added due to the random priorities
//!     // 2. we are awaiting the job_handles in the order of adding, thus results are printed
//!     //    sequentially from lowest primes to highest.
//!     // 3. if we moved the println!() inside FindPrimesJob::run_async() we would see the
//!     //    order of processing, with prime ranges out-of-order.
//!     let mut max: u64 = 0;
//!     for job_handle in job_handles {
//!         let job_id = job_handle.job_id();
//!
//!         // await job to complete and obtain the (wrapped) job result
//!         let completion = job_handle.await?;
//!         let found_primes = FindPrimesJobResult::try_from(completion)?.into_inner();
//!
//!         // check for last (highest) prime in the result set
//!         if let Some(last_found) = found_primes.last() {
//!             // verify that max of each set is larger than previous set.
//!             // which indicates that job results are in same order as jobs were added.
//!             assert!(*last_found > max);
//!
//!             max = std::cmp::max(max, *last_found);
//!         }
//!
//!         println!(
//!             "job {} found {} primes: {:?}",
//!             job_id,
//!             found_primes.len(),
//!             found_primes
//!         );
//!     }
//!
//!     // verify
//!     assert_eq!(9973, max); // 9973 is the largest prime number below 10000
//!
//!     Ok(())
//! }
//! ```

// please note that the job_queue module has zero neptune-core specific
// code in it.  It is intended/planned to move job_queue into its own
// crate in the (near) future.

pub mod channels;
pub mod errors;
mod job_completion;
mod job_handle;
mod job_id;
mod job_result_wrapper;
mod queue;
pub mod traits;

pub use job_completion::JobCompletion;
pub use job_handle::JobHandle;
pub use job_id::JobId;
pub use job_result_wrapper::JobResultWrapper;
pub use queue::JobQueue;
