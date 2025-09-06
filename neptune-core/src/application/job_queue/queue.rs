use std::collections::VecDeque;
use std::fmt;
use std::sync::Arc;
use std::sync::Mutex;

use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use super::channels::JobCancelReceiver;
use super::channels::JobCancelSender;
use super::channels::JobResultSender;
use super::errors::AddJobError;
use super::errors::StopQueueError;
use super::job_completion::JobCompletion;
use super::job_handle::JobHandle;
use super::job_id::JobId;
use super::traits::Job;

/// implements a job queue that sends result of each job to a listener.
#[derive(Debug)]
pub struct JobQueue<P: Ord + Send + Sync + 'static> {
    /// holds job-queue which is shared between tokio tasks
    shared_queue: Arc<Mutex<SharedQueue<P>>>,

    /// channel to inform process_jobs task that a job has been added
    tx_job_added: mpsc::UnboundedSender<()>,

    /// channel to inform process_jobs task to stop processing.
    tx_stop: tokio::sync::watch::Sender<()>,

    /// JoinHandle of process_jobs task
    process_jobs_task_handle: Option<JoinHandle<()>>,
}

// we implement Drop so we can send stop message to process_jobs task
impl<P: Ord + Send + Sync + 'static> Drop for JobQueue<P> {
    fn drop(&mut self) {
        tracing::debug!("in JobQueue::drop()");

        if !self.tx_stop.is_closed() {
            if let Err(e) = self.tx_stop.send(()) {
                tracing::error!("{}", e);
            }
        }
    }
}

impl<P: Ord + Send + Sync + 'static> JobQueue<P> {
    /// creates job queue and starts it processing.
    ///
    /// returns immediately.
    pub fn start() -> Self {
        // create a SharedQueue that is shared between tokio tasks.
        let shared_queue = SharedQueue {
            jobs: VecDeque::new(),
            current_job: None,
        };
        let shared_queue: Arc<Mutex<SharedQueue<P>>> = Arc::new(Mutex::new(shared_queue));

        // create 'job_added' and 'stop' channels for signalling to process_jobs task
        let (tx_job_added, rx_job_added) = mpsc::unbounded_channel();
        let (tx_stop, rx_stop) = watch::channel(());

        // spawn the process_jobs task
        let process_jobs_task_handle =
            tokio::spawn(process_jobs(shared_queue.clone(), rx_stop, rx_job_added));

        tracing::debug!("JobQueue: started new queue.");

        // construct and return JobQueue
        Self {
            tx_job_added,
            tx_stop,
            shared_queue,
            process_jobs_task_handle: Some(process_jobs_task_handle),
        }
    }

    /// stop the job-queue, and drop it.
    ///
    /// this method sends a message to the spawned job-queue task
    /// to stop and then waits for it to complete.
    ///
    /// Comparison with drop():
    ///
    /// if JobQueue is dropped:
    ///  1. the stop message will be sent, but any error is ignored.
    ///  2. the spawned task is not awaited.
    pub async fn stop(mut self) -> Result<(), StopQueueError> {
        tracing::info!("JobQueue: stopping.");

        // send stop message to process_jobs task
        self.tx_stop.send(())?;

        // wait for process_jobs task to finish
        if let Some(jh) = self.process_jobs_task_handle.take() {
            jh.await?;
        }

        Ok(())
    }

    /// adds job to job-queue (with interior mutability)
    ///
    /// returns a [`JobHandle`] that can be used to await or cancel the job.
    ///
    /// note that this method utilizes interior mutability. Consider calling
    /// [`Self::add_job_mut()`] instead to make the mutation explicit.
    pub fn add_job(
        &self,
        job: impl Into<Box<dyn Job>>,
        priority: P,
    ) -> Result<JobHandle, AddJobError> {
        let (result_tx, result_rx) = oneshot::channel();
        let (cancel_tx, cancel_rx) = watch::channel::<()>(());

        // each job gets a random JobId
        let job_id = JobId::random();

        // represent a job in the queue
        let m = QueuedJob {
            job: job.into(),
            job_id,
            result_tx,
            cancel_tx: cancel_tx.clone(),
            cancel_rx,
            priority,
        };

        // add job to queue and obtain number of jobs in queue and current-job (if any)
        let (num_jobs, job_running) = {
            // acquire mutex lock
            let mut guard = self.shared_queue.lock().unwrap();

            // add job to job-queue
            guard.jobs.push_back(m);

            let job_running = match &guard.current_job {
                Some(j) => format!("#{} - {}", j.job_num, j.job_id),
                None => "none".to_string(),
            };
            (guard.jobs.len(), job_running)
        }; // mutex lock released on drop

        // notify process_jobs task that a job was added.
        self.tx_job_added.send(())?;

        // log that job is added to the queue
        tracing::debug!(
            "JobQueue: job added - {}  {} queued job(s).  job running: {}",
            job_id,
            num_jobs,
            job_running
        );

        // create and return JobHandle
        Ok(JobHandle::new(job_id, result_rx, cancel_tx))
    }

    /// Adds a job to the queue (with explicit mutability).
    ///
    /// returns a [`JobHandle`] that can be used to await or cancel the job.
    ///
    /// job-results can be obtained by via JobHandle::results().await
    /// The job can be cancelled by JobHandle::cancel()
    ///
    /// Unlike [`Self::add_job()`], this method takes `&mut self`, explicitly
    /// signaling to the compiler that the `JobQueue` internal state is being
    /// modified.
    ///
    /// This explicit mutability encourages callers to use correct function
    /// signatures and avoids hidden interior mutability, which can be a source
    /// of confusion and potentially subtle borrow checker issues when reasoning
    /// about a given codebase/architecture.
    ///
    /// Explicit mutability generally leads to improved compiler optimizations
    /// and stronger borrow checker guarantees by enforcing exclusive access.
    pub fn add_job_mut(
        &mut self,
        job: impl Into<Box<dyn Job>>,
        priority: P,
    ) -> Result<JobHandle, AddJobError> {
        self.add_job(job, priority)
    }

    /// returns total number of jobs, queued plus running.
    pub fn num_jobs(&self) -> usize {
        let guard = self.shared_queue.lock().unwrap();
        guard.jobs.len() + guard.current_job.as_ref().map(|_| 1).unwrap_or(0)
    }

    /// returns number of queued jobs
    pub fn num_queued_jobs(&self) -> usize {
        self.shared_queue.lock().unwrap().jobs.len()
    }
}

/// implements the process_jobs task, spawned by JobQueue::start().
///
/// this fn calls tokio::select!{} in a loop.  The select has two branches:
/// 1. receive 'job_added' message over mpsc channel (unbounded)
/// 2. receive 'stop' message over watch channel
///
/// job_added:
///
/// When a 'job_added' msg is received, the highest priority queued job is picked
/// to run next.  We await the job, and then send results to the JobHandle.
///
/// Note that jobs can take a long time to run and thus msgs can pile up in the
/// job_added channel, which is unbounded. These messages are of type "()" so
/// are as small as possible.
///
/// stop:
///
/// When a 'stop' msg is received we send a cancel msg to the current job (if any) and
/// wait for it to complete. Then we exit the loop and return.
async fn process_jobs<P: Ord + Send + Sync + 'static>(
    shared_queue: Arc<Mutex<SharedQueue<P>>>,
    mut rx_stop: watch::Receiver<()>,
    mut rx_job_added: mpsc::UnboundedReceiver<()>,
) {
    // job number starts at 1 and increments with each job that is processed.
    // note that processing order may be different than order in which jobs
    // are added due to job priorities.
    let mut job_num: usize = 1;

    // loop until 'stop' msg is received or job_added channel is closed.
    //
    // note:  this unbounded channel will grow in size as new job(s) are
    // added while an existing job is running.  ie, we read from the
    // channel after each job completes.
    while rx_job_added.recv().await.is_some() {
        // Find the next job to run, and the number of jobs left in queue
        tracing::debug!("task process_jobs received JobAdded message.");
        let (next_job, num_pending) = {
            // acquire mutex lock
            let mut guard = shared_queue.lock().unwrap();

            // pick the highest priority job
            guard
                .jobs
                .make_contiguous()
                .sort_by(|a, b| b.priority.cmp(&a.priority));
            let job = guard.jobs.pop_front().unwrap();

            // set highest priority job as the current job
            guard.current_job = Some(CurrentJob {
                job_num,
                job_id: job.job_id,
                cancel_tx: job.cancel_tx.clone(),
            });

            (job, guard.jobs.len())
        }; // mutex lock is released when guard drops.

        // log that we are starting a job
        tracing::debug!(
            "  *** JobQueue: begin job #{} - {} - {} queued job(s) ***",
            job_num,
            next_job.job_id,
            num_pending
        );

        // record time that job starts
        let timer = tokio::time::Instant::now();

        // spawn task that performs the job, either async or blocking.
        let job_task_handle = if next_job.job.is_async() {
            tokio::spawn(
                async move { next_job.job.run_async_cancellable(next_job.cancel_rx).await },
            )
        } else {
            tokio::task::spawn_blocking(move || next_job.job.run(next_job.cancel_rx))
        };

        // execute job task and simultaneously listen for a 'stop' message.
        let job_task_result = tokio::select! {
            // execute the job task
            job_task_result = job_task_handle => job_task_result,

            // handle msg over 'stop' channel which indicates we must exit the loop.
            _ = rx_stop.changed() => {

                handle_stop_signal(&shared_queue).await;

                // exit loop, processing ends.
                break;
            },
        };

        // create JobCompletion from task results
        let job_completion = match job_task_result {
            Ok(jc) => jc,
            Err(e) => {
                if e.is_panic() {
                    JobCompletion::Panicked(e.into_panic())
                } else if e.is_cancelled() {
                    JobCompletion::Cancelled
                } else {
                    unreachable!()
                }
            }
        };

        // log that job has ended.
        tracing::debug!(
            "  *** JobQueue: ended job #{} - {} - Completion: {} - {} secs ***",
            job_num,
            next_job.job_id,
            job_completion,
            timer.elapsed().as_secs_f32()
        );
        job_num += 1;

        // obtain mutex lock and set current-job to None
        shared_queue.lock().unwrap().current_job = None;

        // send job results to the JobHandle receiver
        if let Err(e) = next_job.result_tx.send(job_completion) {
            tracing::warn!("job-handle dropped? {}", e);
        }
    }
    tracing::debug!("task process_jobs exiting");
}

/// handles the 'stop' branch of tokio::select!{} in process_job() task
async fn handle_stop_signal<P: Ord + Send + Sync + 'static>(
    shared_queue: &Arc<Mutex<SharedQueue<P>>>,
) {
    tracing::debug!("task process_jobs received Stop message.");

    // acquire mutex lock and obtain current_job info, if any.
    let maybe_info = shared_queue
        .lock()
        .unwrap()
        .current_job
        .as_ref()
        .map(|cj| (cj.job_id, cj.cancel_tx.clone()));

    // if there is a presently executing job we need to cancel it
    // and wait for it to complete.
    if let Some((job_id, cancel_tx)) = maybe_info {
        match cancel_tx.send(()) {
            Ok(()) => {
                // wait for channel to close, indicating job has cancelled (or otherwise completed)
                tracing::debug!(
                    "JobQueue: notified current job {} to cancel.  waiting...",
                    job_id
                );
                cancel_tx.closed().await;
                tracing::debug!("JobQueue: current job {} has cancelled.", job_id);
            }
            Err(e) => {
                tracing::warn!(
                    "could not send cancellation msg to current job {}. {}",
                    job_id,
                    e
                )
            }
        }
    }
}

/// represents a job in the queue.
pub(super) struct QueuedJob<P> {
    job: Box<dyn Job>,
    job_id: JobId,
    result_tx: JobResultSender,
    cancel_tx: JobCancelSender,
    cancel_rx: JobCancelReceiver,
    priority: P,
}

impl<P: fmt::Debug> fmt::Debug for QueuedJob<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QueuedJob")
            .field("job", &"Box<dyn Job>")
            .field("job_id", &self.job_id)
            .field("result_tx", &"JobResultSender")
            .field("cancel_tx", &"JobCancelSender")
            .field("cancel_rx", &"JobCancelReceiver")
            .field("priority", &self.priority)
            .finish()
    }
}

/// represents the currently executing job
#[derive(Debug)]
pub(super) struct CurrentJob {
    job_num: usize,
    job_id: JobId,
    cancel_tx: JobCancelSender,
}

/// represents data shared between tasks/threads
#[derive(Debug)]
pub(super) struct SharedQueue<P: Ord> {
    jobs: VecDeque<QueuedJob<P>>,
    current_job: Option<CurrentJob>,
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::time::Instant;

    use tracing_test::traced_test;

    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    #[traced_test]
    async fn run_sync_jobs_by_priority() -> anyhow::Result<()> {
        workers::run_jobs_by_priority(false).await
    }

    #[tokio::test(flavor = "multi_thread")]
    #[traced_test]
    async fn run_async_jobs_by_priority() -> anyhow::Result<()> {
        workers::run_jobs_by_priority(true).await
    }

    #[tokio::test(flavor = "multi_thread")]
    #[traced_test]
    async fn get_sync_job_result() -> anyhow::Result<()> {
        workers::get_job_result(false).await
    }

    #[tokio::test(flavor = "multi_thread")]
    #[traced_test]
    async fn get_async_job_result() -> anyhow::Result<()> {
        workers::get_job_result(true).await
    }

    #[tokio::test(flavor = "multi_thread")]
    #[traced_test]
    async fn cancel_sync_job() -> anyhow::Result<()> {
        workers::cancel_job(false).await
    }

    #[tokio::test(flavor = "multi_thread")]
    #[traced_test]
    async fn cancel_async_job() -> anyhow::Result<()> {
        workers::cancel_job(true).await
    }

    #[tokio::test(flavor = "multi_thread")]
    #[traced_test]
    async fn cancel_sync_job_in_select() -> anyhow::Result<()> {
        workers::cancel_job_in_select(false).await
    }

    #[tokio::test(flavor = "multi_thread")]
    #[traced_test]
    async fn cancel_async_job_in_select() -> anyhow::Result<()> {
        workers::cancel_job_in_select(true).await
    }

    #[test]
    #[traced_test]
    fn runtime_shutdown_timeout_force_cancels_sync_job() -> anyhow::Result<()> {
        workers::runtime_shutdown_timeout_force_cancels_job(false)
    }

    #[test]
    #[traced_test]
    fn runtime_shutdown_timeout_force_cancels_async_job() -> anyhow::Result<()> {
        workers::runtime_shutdown_timeout_force_cancels_job(true)
    }

    #[test]
    #[traced_test]
    fn runtime_shutdown_cancels_sync_job() {
        let _ = workers::runtime_shutdown_cancels_job(false);
    }

    #[test]
    #[traced_test]
    fn runtime_shutdown_cancels_async_job() -> anyhow::Result<()> {
        workers::runtime_shutdown_cancels_job(true)
    }

    #[test]
    #[traced_test]
    fn spawned_tasks_live_as_long_as_jobqueue() -> anyhow::Result<()> {
        workers::spawned_tasks_live_as_long_as_jobqueue(true)
    }

    #[tokio::test(flavor = "multi_thread")]
    #[traced_test]
    async fn panic_in_async_job_ends_job_cleanly() -> anyhow::Result<()> {
        workers::panics::panic_in_job_ends_job_cleanly(true).await
    }

    #[tokio::test(flavor = "multi_thread")]
    #[traced_test]
    async fn panic_in_blocking_job_ends_job_cleanly() -> anyhow::Result<()> {
        workers::panics::panic_in_job_ends_job_cleanly(false).await
    }

    #[tokio::test(flavor = "multi_thread")]
    #[traced_test]
    async fn stop_queue() -> anyhow::Result<()> {
        workers::stop_queue().await
    }

    #[tokio::test(flavor = "multi_thread")]
    #[traced_test]
    async fn job_result_wrapper() -> anyhow::Result<()> {
        workers::job_result_wrapper().await
    }

    mod workers {
        use super::*;
        use crate::application::job_queue::errors::JobHandleError;
        use crate::application::job_queue::traits::JobResult;
        use crate::application::job_queue::JobResultWrapper;

        #[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
        pub enum DoubleJobPriority {
            Low = 1,
            Medium = 2,
            High = 3,
        }

        type DoubleJobResult = JobResultWrapper<(u64, u64, Instant)>;

        // represents a prover job.  implements Job.
        #[derive(Debug)]
        struct DoubleJob {
            data: u64,
            duration: std::time::Duration,
            is_async: bool,
        }

        #[async_trait::async_trait]
        impl Job for DoubleJob {
            fn is_async(&self) -> bool {
                self.is_async
            }

            fn run(&self, cancel_rx: JobCancelReceiver) -> JobCompletion {
                let start = Instant::now();
                let sleep_time =
                    std::cmp::min(std::time::Duration::from_micros(100), self.duration);

                let r = loop {
                    if start.elapsed() < self.duration {
                        match cancel_rx.has_changed() {
                            Ok(changed) if changed => break JobCompletion::Cancelled,
                            Err(_) => break JobCompletion::Cancelled,
                            _ => {}
                        }

                        std::thread::sleep(sleep_time);
                    } else {
                        break JobCompletion::Finished(
                            DoubleJobResult::new((self.data, self.data * 2, Instant::now())).into(),
                        );
                    }
                };

                tracing::info!("results: {:?}", r);
                r
            }

            async fn run_async(&self) -> Box<dyn JobResult> {
                tokio::time::sleep(self.duration).await;
                let r = DoubleJobResult::new((self.data, self.data * 2, Instant::now()));
                tracing::info!("results: {:?}", r);
                r.into()
            }
        }

        // this test demonstrates/verifies that:
        //  1. jobs are run in priority order, highest priority first.
        //  2. when multiple jobs have the same priority, they run in FIFO order.
        pub(super) async fn run_jobs_by_priority(is_async: bool) -> anyhow::Result<()> {
            let start_of_test = Instant::now();

            // create a job queue
            let mut job_queue = JobQueue::start();

            let mut handles = vec![];
            let duration = std::time::Duration::from_millis(20);

            // create 30 jobs, 10 at each priority level.
            for i in (1..10).rev() {
                let job1 = DoubleJob {
                    data: i,
                    duration,
                    is_async,
                };
                let job2 = DoubleJob {
                    data: i * 100,
                    duration,
                    is_async,
                };
                let job3 = DoubleJob {
                    data: i * 1000,
                    duration,
                    is_async,
                };

                // process job and print results.
                handles.push(job_queue.add_job_mut(job1, DoubleJobPriority::Low)?);
                handles.push(job_queue.add_job_mut(job2, DoubleJobPriority::Medium)?);
                handles.push(job_queue.add_job_mut(job3, DoubleJobPriority::High)?);
            }

            // we can't know exact number of jobs in queue because it is already processing.
            assert!(job_queue.num_jobs() > 0);
            assert!(job_queue.num_queued_jobs() > 0);

            // wait for all jobs to complete.
            let mut results = futures::future::join_all(handles).await;

            assert_eq!(0, job_queue.num_jobs());
            assert_eq!(0, job_queue.num_queued_jobs());

            // the results are in the same order as handles passed to join_all.
            // we sort them by the timestamp in job result, ascending.
            results.sort_by(|a_completion, b_completion| {
                let a = <&DoubleJobResult>::try_from(a_completion.as_ref().unwrap())
                    .unwrap()
                    .2;
                let b = <&DoubleJobResult>::try_from(b_completion.as_ref().unwrap())
                    .unwrap()
                    .2;

                a.cmp(&b)
            });

            // iterate job results and verify that:
            //   timestamp of each is greater than prev.
            //   input value of each is greater than prev, except every 9th item which should be < prev
            //     because there are nine jobs per level.
            let mut prev = DoubleJobResult::new((9999, 0, start_of_test));
            for (i, c) in results.into_iter().enumerate() {
                let job_result = DoubleJobResult::try_from(c?)?;

                assert!(job_result.2 > prev.2);

                // we don't do the assertion for the 2nd job because the job-queue starts
                // processing immediately and so a race condition is setup where it is possible
                // for either the Low priority or High job to start processing first.
                if i != 1 {
                    assert!(job_result.0 < prev.0);
                }

                prev = job_result;
            }

            Ok(())
        }

        // this test demonstrates/verifies that a job can return a result back to
        // the job initiator.
        pub(super) async fn get_job_result(is_async: bool) -> anyhow::Result<()> {
            // create a job queue
            let mut job_queue = JobQueue::start();
            let duration = std::time::Duration::from_millis(20);

            // create 10 jobs
            for i in 0..10 {
                let job = DoubleJob {
                    data: i,
                    duration,
                    is_async,
                };

                let completion = job_queue.add_job_mut(job, DoubleJobPriority::Low)?.await?;

                let job_result = DoubleJobResult::try_from(completion)?;

                assert_eq!(i, job_result.0);
                assert_eq!(i * 2, job_result.1);
            }

            Ok(())
        }

        // tests that stopping job_queue also cancels presently running job
        // and queued job(s)
        pub(super) async fn stop_queue() -> anyhow::Result<()> {
            // create a job queue
            let mut job_queue = JobQueue::start();
            // start a 1 hour job.
            let duration = std::time::Duration::from_secs(3600); // 1 hour job.

            let job = DoubleJob {
                data: 10,
                duration,
                is_async: true,
            };
            let job2 = DoubleJob {
                data: 10,
                duration,
                is_async: true,
            };
            let job_handle = job_queue.add_job_mut(job, DoubleJobPriority::Low)?;
            let job2_handle = job_queue.add_job_mut(job2, DoubleJobPriority::Low)?;

            // so we have some test coverage for debug impls.
            println!("job-queue: {:?}", job_queue);

            tokio::time::sleep(std::time::Duration::from_millis(20)).await;

            job_queue.stop().await?;

            assert!(job_handle.is_finished());
            assert!(job2_handle.is_finished());

            assert!(matches!(
                job_handle.await,
                Err(JobHandleError::JobResultError(_))
            ));
            assert!(matches!(
                job2_handle.await,
                Err(JobHandleError::JobResultError(_))
            ));

            Ok(())
        }

        // tests/demonstrates that a long running job can be cancelled early.
        pub(super) async fn cancel_job(is_async: bool) -> anyhow::Result<()> {
            // create a job queue
            let mut job_queue = JobQueue::start();
            // start a 1 hour job.
            let duration = std::time::Duration::from_secs(3600); // 1 hour job.

            let job = DoubleJob {
                data: 10,
                duration,
                is_async,
            };
            let job_handle = job_queue.add_job_mut(job, DoubleJobPriority::Low)?;

            tokio::time::sleep(std::time::Duration::from_millis(20)).await;

            job_handle.cancel().unwrap();
            let completion = job_handle.await.unwrap();
            assert!(matches!(completion, JobCompletion::Cancelled));

            Ok(())
        }

        // this test demonstrates how to listen for a cancellation message
        // and cancel a job when it is received.
        //
        // The key concepts demonstrated are:
        //  1. using tokio::select!{} to execute the job and listen for a
        //     cancellation message simultaneously.
        //  2. using tokio::pin!() to avoid borrow-checker complaints in the select.
        //  3. obtaining the job result.
        pub async fn cancel_job_in_select(is_async: bool) -> anyhow::Result<()> {
            async fn do_some_work(
                is_async: bool,
                cancel_work_rx: tokio::sync::oneshot::Receiver<()>,
            ) -> Result<DoubleJobResult, JobHandleError> {
                // create a job queue.  (this could be done elsewhere)
                let mut job_queue = JobQueue::start();

                // start a 1 hour job.
                let duration = std::time::Duration::from_secs(3600); // 1 hour job.

                let job = DoubleJob {
                    data: 10,
                    duration,
                    is_async,
                };

                // add the job to queue
                let job_handle = job_queue.add_job_mut(job, DoubleJobPriority::Low).unwrap();

                // pin job_handle, so borrow checker knows the address can't change
                // and it is safe to use in both select branches
                tokio::pin!(job_handle);

                // execute job and simultaneously listen for cancel msg from elsewhere
                let completion = tokio::select! {
                    // case: job completion.
                    completion = &mut job_handle => completion,

                    // case: sender cancelled, or sender dropped.
                    _ = cancel_work_rx => {
                        job_handle.cancel()?;
                        job_handle.await
                    }
                };

                println!("job_completion: {:#?}", completion);

                // obtain job result (via downcast)
                let result = DoubleJobResult::try_from(completion?)?;

                println!("job_result: {:#?}", result);

                Ok(result)
            }

            // create cancellation channel for the worker task
            let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();

            // create the worker task, that will create and run the job
            let worker_task = async move { do_some_work(is_async, cancel_rx).await };

            // spawn the worker task
            let jh = tokio::task::spawn(worker_task);

            // send cancel message to the worker task
            cancel_tx.send(()).unwrap();

            // wait for worker task to finish (with an error)
            let job_handle_error = jh.await?.unwrap_err();

            // ensure the error indicates JobCancelled
            assert!(matches!(job_handle_error, JobHandleError::JobCancelled));

            Ok(())
        }

        // note: creates own tokio runtime.  caller must not use [tokio::test]
        //
        // this test starts a job that runs for 1 hour and then attempts to
        // shutdown tokio runtime via shutdown_timeout() with a 1 sec timeout.
        //
        // any async tasks should be aborted quickly.
        // any sync tasks will continue to run to completion.
        //
        // shutdown_timeout() will wait for tasks to abort for 1 sec and then
        // returns.  Any un-aborted tasks/threads become ignored/detached.
        // The OS can cleanup such threads when the process exits.
        //
        // the test checks that the shutdown completes in under 2 secs.
        //
        // the test demonstrates that shutdown_timeout() can be used to shutdown
        // tokio runtime even if sync (spawn_blocking) tasks/threads are still running
        // in the blocking threadpool.
        //
        // when called with is_async=true, it demonstrates that shutdown_timeout() also
        // aborts async jobs, as one would expect.
        pub(super) fn runtime_shutdown_timeout_force_cancels_job(
            is_async: bool,
        ) -> anyhow::Result<()> {
            let rt = tokio::runtime::Runtime::new()?;
            let result = rt.block_on(async {
                // create a job queue
                let mut job_queue = JobQueue::start();
                // start a 1 hour job.
                let duration = std::time::Duration::from_secs(3600); // 1 hour job.

                let job = DoubleJob {
                    data: 10,
                    duration,
                    is_async,
                };
                let _rx = job_queue.add_job_mut(job, DoubleJobPriority::Low)?;

                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                println!("finished scope");

                Ok(())
            });

            let start = std::time::Instant::now();

            println!("waiting 1 second for job before shutdown runtime");
            rt.shutdown_timeout(tokio::time::Duration::from_secs(1));

            assert!(start.elapsed() < std::time::Duration::from_secs(2));

            result
        }

        // note: creates own tokio runtime.  caller must not use [tokio::test]
        //
        // this test starts a job that runs for 5 secs and then attempts to
        // shutdown tokio runtime normally by dropping it.
        //
        // any async tasks should be aborted quickly.
        // any sync tasks will continue to run to completion.
        //
        // the tokio runtime does not complete the drop() until all tasks
        // have completed/aborted.
        //
        // the test checks that the job finishes in less than the 5 secs
        // required for full completion.  In other words, that it aborts.
        //
        // the test is expected to succeed for async jobs but fail for sync jobs.
        pub(super) fn runtime_shutdown_cancels_job(is_async: bool) -> anyhow::Result<()> {
            let rt = tokio::runtime::Runtime::new()?;
            let start = tokio::time::Instant::now();

            let result = rt.block_on(async {
                // create a job queue
                let mut job_queue = JobQueue::start();

                // this job takes at least 5 secs to complete.
                let duration = std::time::Duration::from_secs(5);

                let job = DoubleJob {
                    data: 10,
                    duration,
                    is_async,
                };

                let rx_handle = job_queue.add_job_mut(job, DoubleJobPriority::Low)?;
                drop(rx_handle);

                // sleep 50 ms to let job get started.
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;

                Ok(())
            });

            // drop the tokio runtime. It will attempt to abort tasks.
            //   - async tasks can normally be aborted
            //   - spawn_blocking (sync) tasks cannot normally be aborted.
            drop(rt);

            // if test is successful, elapsed time should be less than the 5 secs
            // it takes for the job to complete.  (should be around 0.5 ms)

            // however it is expected/normal that sync tasks will not be aborted
            // and will run for full 5 secs.  thus this assert will fail for them.

            assert!(start.elapsed() < std::time::Duration::from_secs(5));

            result
        }

        // this test attempts to verify that the task spawned by the JobQueue
        // continues running until the JobQueue is dropped after the tokio
        // runtime is dropped.
        //
        // If the tasks are cencelled before JobQueue is dropped then a subsequent
        // api call that sends a msg will result in a "channel closed" error, which
        // is what the test checks for.
        //
        // note that the test has to do some tricky stuff to setup conditions
        // where the "channel closed" error can occur. It's a subtle issue.
        //
        // see description at:
        // https://github.com/tokio-rs/tokio/discussions/6961
        pub(super) fn spawned_tasks_live_as_long_as_jobqueue(is_async: bool) -> anyhow::Result<()> {
            let rt = tokio::runtime::Runtime::new()?;

            let result_ok: Arc<Mutex<bool>> = Arc::new(Mutex::new(true));

            let result_ok_clone = result_ok.clone();
            rt.block_on(async {
                // create a job queue (not mutable)
                let job_queue = Arc::new(JobQueue::start());

                // spawns background task that adds job
                let job_queue_cloned = job_queue.clone();
                let jh = tokio::spawn(async move {
                    // sleep 200 ms to let runtime finish.
                    // ie ensure drop(rt) will be reached and wait for us.
                    // note that we use std sleep.  if tokio sleep is used
                    // the test will always succeed due to the await point.
                    std::thread::sleep(std::time::Duration::from_millis(200));

                    let job = DoubleJob {
                        data: 10,
                        duration: std::time::Duration::from_secs(1),
                        is_async,
                    };

                    // add job (with JobQueue interior mutability).
                    let result = job_queue_cloned.add_job(job, DoubleJobPriority::Low);

                    // an assert on result.is_ok() would panic, but that panic would be
                    // printed and swallowed by tokio runtime, so the test would succeed
                    // despite the panic. instead we pass the result in a mutex so it
                    // can be asserted where it will be caught by the test runner.
                    *result_ok_clone.lock().unwrap() = result.is_ok();
                });

                // sleep 50 ms to let job get started.
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;

                // note; awaiting the joinhandle makes the test succeed.

                jh.abort();
                let _ = jh.await;
            });

            // drop the tokio runtime. It will abort tasks.
            drop(rt);

            assert!(*result_ok.lock().unwrap());

            Ok(())
        }

        pub mod panics {
            use super::*;

            const PANIC_STR: &str = "job panics unexpectedly";

            struct PanicJob {
                is_async: bool,
            }

            #[async_trait::async_trait]
            impl Job for PanicJob {
                fn is_async(&self) -> bool {
                    self.is_async
                }

                fn run(&self, _cancel_rx: JobCancelReceiver) -> JobCompletion {
                    panic!("{}", PANIC_STR);
                }

                async fn run_async_cancellable(
                    &self,
                    _cancel_rx: JobCancelReceiver,
                ) -> JobCompletion {
                    panic!("{}", PANIC_STR);
                }
            }

            /// verifies that a job that panics will be ended properly.
            ///
            /// Properly means that:
            /// 1. an error is returned from JobCompletion::result() indicating job panicked.
            /// 2. caller is able to obtain panic info, which matches job's panic msg.
            /// 3. the job-queue continues accepting new jobs.
            /// 4. the job-queue continues processing jobs.
            ///
            /// async_job == true --> test an async job
            /// async_job == false --> test a blocking job
            pub async fn panic_in_job_ends_job_cleanly(async_job: bool) -> anyhow::Result<()> {
                // create a job queue
                let mut job_queue = JobQueue::start();

                let job = PanicJob {
                    is_async: async_job,
                };
                let job_handle = job_queue.add_job_mut(job, DoubleJobPriority::Low)?;

                let job_result = job_handle.await?.result();

                // verify that job_queue channels are still open
                assert!(!job_queue.tx_job_added.is_closed());
                assert!(!job_queue.tx_stop.is_closed());

                // verify that we get an error with the job's panic msg.
                assert!(matches!(
                    job_result,
                    Err(e) if e.panic_message() == Some((*PANIC_STR).to_string())
                ));

                // ensure we can still run another job afterwards.
                let newjob = DoubleJob {
                    data: 10,
                    duration: std::time::Duration::from_millis(50),
                    is_async: false,
                };

                // ensure we can add another job.
                let new_job_handle = job_queue.add_job_mut(newjob, DoubleJobPriority::Low)?;

                // ensure job processes and returns a result without error.
                assert!(new_job_handle.await?.result().is_ok());

                Ok(())
            }
        }

        // demonstrates/tests usage of JobResultWrapper
        pub(super) async fn job_result_wrapper() -> anyhow::Result<()> {
            type MyJobResult = JobResultWrapper<(u64, u64, Instant)>;

            // represents a custom job.  implements Job.
            #[derive(Debug)]
            struct MyJob {
                data: u64,
                duration: std::time::Duration,
            }

            #[async_trait::async_trait]
            impl Job for MyJob {
                fn is_async(&self) -> bool {
                    true
                }

                async fn run_async(&self) -> Box<dyn JobResult> {
                    tokio::time::sleep(self.duration).await;
                    MyJobResult::new((self.data, self.data * 2, Instant::now())).into()
                }
            }

            let mut job_queue = JobQueue::start();
            let job = MyJob {
                data: 15,
                duration: std::time::Duration::from_secs(5),
            };
            let job_handle = job_queue.add_job_mut(job, 10usize)?;
            let completion = job_handle.await?;
            let job_result = MyJobResult::try_from(completion)?;
            let answer = job_result.into_inner();

            assert_eq!(answer.0 * 2, answer.1);

            Ok(())
        }
    }
}
