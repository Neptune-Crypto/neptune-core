use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::Mutex;

use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use super::traits::Job;
use super::traits::JobResult;

type JobResultOneShotChannel = oneshot::Sender<Box<dyn JobResult>>;
type JobAndResultChannel = (Box<dyn Job>, JobResultOneShotChannel);

// implements a job queue that sends result of each job to a listener.
pub struct JobQueue<P: Ord> {
    tx: mpsc::UnboundedSender<(JobAndResultChannel, P)>,
}

impl<P: Ord> std::fmt::Debug for JobQueue<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JobQueue")
            .field("tx", &"mpsc::Sender")
            .finish()
    }
}

impl<P: Ord> Clone for JobQueue<P> {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
        }
    }
}

impl<P: Ord + Send + Sync + 'static> JobQueue<P> {
    // creates job queue and starts it processing.  returns immediately.
    pub fn start() -> (Self, JoinHandle<()>, JoinHandle<()>) {
        let (tx, mut rx) = mpsc::unbounded_channel::<(JobAndResultChannel, P)>();

        let jobs: Arc<Mutex<VecDeque<(JobAndResultChannel, P)>>> =
            Arc::new(Mutex::new(VecDeque::new()));

        let (tx_deque, mut rx_deque) = tokio::sync::mpsc::unbounded_channel();

        // spawns background task that adds incoming jobs to job-queue
        let jobs_rc1 = jobs.clone();
        let sequencer = tokio::spawn(async move {
            while let Some(((job, otx), priority)) = rx.recv().await {
                jobs_rc1.lock().unwrap().push_back(((job, otx), priority));
                let _ = tx_deque.send(());
            }
        });

        // spawns background task that processes job queue and runs jobs.
        let jobs_rc2 = jobs.clone();
        let job_executor = tokio::spawn(async move {
            while rx_deque.recv().await.is_some() {
                let ((job, otx), _priority) = {
                    let mut j = jobs_rc2.lock().unwrap();
                    j.make_contiguous().sort_by(|(_, a), (_, b)| b.cmp(a));
                    j.pop_front().unwrap()
                };

                let job_result = match job.is_async() {
                    true => job.run_async().await,
                    false => tokio::task::spawn_blocking(move || job.run())
                        .await
                        .unwrap(),
                };

                let _ = otx.send(job_result);
            }
        });

        (Self { tx }, sequencer, job_executor)
    }

    // alias of Self::start().
    // here for two reasons:
    //  1. backwards compat with existing tests
    //  2. if tests call dummy() instead of start(), then it is easier
    //     to find where start() is called for real.
    #[cfg(test)]
    pub fn dummy() -> Self {
        Self::start().0
    }

    // adds job to job-queue and returns immediately.
    pub async fn add_job(
        &self,
        job: Box<dyn Job>,
        priority: P,
    ) -> anyhow::Result<oneshot::Receiver<Box<dyn JobResult>>> {
        let (otx, orx) = oneshot::channel();
        self.tx.send(((job, otx), priority))?;
        Ok(orx)
    }

    // adds job to job-queue, waits for job completion, and returns job result.
    pub async fn add_and_await_job(
        &self,
        job: Box<dyn Job>,
        priority: P,
    ) -> anyhow::Result<Box<dyn JobResult>> {
        let (otx, orx) = oneshot::channel();
        self.tx.send(((job, otx), priority))?;
        Ok(orx.await?)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn run_sync_jobs_by_priority() -> anyhow::Result<()> {
        workers::run_jobs_by_priority(false).await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn run_async_jobs_by_priority() -> anyhow::Result<()> {
        workers::run_jobs_by_priority(true).await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn get_sync_job_result() -> anyhow::Result<()> {
        workers::get_job_result(false).await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn get_async_job_result() -> anyhow::Result<()> {
        workers::get_job_result(true).await
    }

    #[test]
    fn runtime_shutdown_timeout_force_cancels_sync_job() -> anyhow::Result<()> {
        workers::runtime_shutdown_timeout_force_cancels_job(false)
    }

    #[test]
    fn runtime_shutdown_timeout_force_cancels_async_job() -> anyhow::Result<()> {
        workers::runtime_shutdown_timeout_force_cancels_job(true)
    }

    #[test]
    #[should_panic]
    fn runtime_shutdown_cancels_sync_job() {
        let _ = workers::runtime_shutdown_cancels_job(false);
    }

    #[test]
    fn runtime_shutdown_cancels_async_job() -> anyhow::Result<()> {
        workers::runtime_shutdown_cancels_job(true)
    }

    mod workers {
        use std::any::Any;

        use super::*;

        #[derive(PartialEq, Eq, PartialOrd, Ord)]
        pub enum DoubleJobPriority {
            Low = 1,
            Medium = 2,
            High = 3,
        }

        #[derive(PartialEq, Debug, Clone)]
        struct DoubleJobResult(u64, u64, Instant);
        impl JobResult for DoubleJobResult {
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        // represents a prover job.  implements Job.
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

            fn run(&self) -> Box<dyn JobResult> {
                std::thread::sleep(self.duration);

                let r = DoubleJobResult(self.data, self.data * 2, Instant::now());
                println!("{} * 2 = {}", r.0, r.1);

                Box::new(r)
            }

            async fn run_async(&self) -> Box<dyn JobResult> {
                tokio::time::sleep(self.duration).await;

                let r = DoubleJobResult(self.data, self.data * 2, Instant::now());
                println!("{} * 2 = {}", r.0, r.1);

                Box::new(r)
            }
        }

        // this test demonstrates/verifies that:
        //  1. jobs are run in priority order, highest priority first.
        //  2. when multiple jobs have the same priority, they run in FIFO order.
        pub(super) async fn run_jobs_by_priority(is_async: bool) -> anyhow::Result<()> {
            // create a job queue
            let (job_queue, _, _) = JobQueue::start();

            let mut handles = vec![];
            let duration = std::time::Duration::from_millis(20);

            // create 30 jobs, 10 at each priority level.
            for i in 1..10 {
                let job1 = Box::new(DoubleJob {
                    data: i,
                    duration,
                    is_async,
                });
                let job2 = Box::new(DoubleJob {
                    data: i * 100,
                    duration,
                    is_async,
                });
                let job3 = Box::new(DoubleJob {
                    data: i * 1000,
                    duration,
                    is_async,
                });

                // process job and print results.
                handles.push(job_queue.add_job(job1, DoubleJobPriority::Low).await?);
                handles.push(job_queue.add_job(job2, DoubleJobPriority::Medium).await?);
                handles.push(job_queue.add_job(job3, DoubleJobPriority::High).await?);
            }

            // wait for all jobs to complete.
            let mut results = futures::future::join_all(handles).await;

            // the results are in the same order as handles passed to join_all.
            // we sort them by the timestamp in job result, ascending.
            results.sort_by(|a, b| {
                let a = a
                    .as_ref()
                    .unwrap()
                    .as_any()
                    .downcast_ref::<DoubleJobResult>()
                    .unwrap()
                    .2;
                let b = b
                    .as_ref()
                    .unwrap()
                    .as_any()
                    .downcast_ref::<DoubleJobResult>()
                    .unwrap()
                    .2;

                a.cmp(&b)
            });

            // iterate job results and verify that:
            //   timestamp of each is greater than prev.
            //   input value of each is greater than prev, except every 9th item which should be < prev
            //     because there are nine jobs per level.
            let mut prev =
                DoubleJobResult(0, 0, Instant::now() - std::time::Duration::from_secs(86400));
            for (i, r) in results.into_iter().enumerate() {
                let job_result = r
                    .unwrap()
                    .as_any()
                    .downcast_ref::<DoubleJobResult>()
                    .unwrap()
                    .clone();

                //
                assert!(job_result.2 > prev.2);

                match i > 0 && (i) % 9 == 0 {
                    true => {
                        assert!(job_result.0 < prev.0)
                    }
                    false => {
                        assert!(job_result.0 > prev.0)
                    }
                };

                prev = job_result;
            }

            Ok(())
        }

        // this test demonstrates/verifies that a job can return a result back to
        // the job initiator.
        pub(super) async fn get_job_result(is_async: bool) -> anyhow::Result<()> {
            // create a job queue
            let (job_queue, _, _) = JobQueue::start();
            let duration = std::time::Duration::from_millis(20);

            // create 10 jobs
            for i in 0..10 {
                let job = Box::new(DoubleJob {
                    data: i,
                    duration,
                    is_async,
                });

                let result = job_queue
                    .add_and_await_job(job, DoubleJobPriority::Low)
                    .await?;

                let job_result = result.as_any().downcast_ref::<DoubleJobResult>().unwrap();

                assert_eq!(i, job_result.0);
                assert_eq!(i * 2, job_result.1);
            }

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
                let (job_queue, _, _) = JobQueue::start();
                // start a 1 hour job.
                let duration = std::time::Duration::from_secs(3600); // 1 hour job.

                let job = Box::new(DoubleJob {
                    data: 10,
                    duration,
                    is_async,
                });
                let _rx = job_queue.add_job(job, DoubleJobPriority::Low).await?;

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
                let (job_queue, _, _) = JobQueue::start();

                // this job takes at least 5 secs to complete.
                let duration = std::time::Duration::from_secs(5);

                let job = Box::new(DoubleJob {
                    data: 10,
                    duration,
                    is_async,
                });

                let rx_handle = job_queue.add_job(job, DoubleJobPriority::Low).await?;
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
    }
}
