use std::collections::VecDeque;

use anyhow::bail;
use async_priority_channel as mpsc;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use tokio::io::AsyncBufReadExt;
use tokio::io::AsyncReadExt;
use tokio::io::BufReader;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use tracing::info;

use super::traits::Job;
use super::traits::JobResult;
use super::traits::Synchronicity;

// todo: fix it so that jobs with same priority execute FIFO.
/// implements a prioritized job queue that sends result of each job to a listener.
/// At present order of jobs with the same priority is undefined.
type JobResultOneShotChannel = oneshot::Sender<Box<dyn JobResult>>;

pub struct JobQueue<P: Ord, T: DeserializeOwned + Send> {
    tx: mpsc::Sender<(Box<dyn Job<ResultType = T>>, JobResultOneShotChannel), P>,
}

impl<P: Ord, T: DeserializeOwned + Send> std::fmt::Debug for JobQueue<P, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JobQueue")
            .field("tx", &"mpsc::Sender")
            .finish()
    }
}

impl<P: Ord, T: DeserializeOwned + Send> Clone for JobQueue<P, T> {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
        }
    }
}

impl<P: Ord + Send + Sync + 'static, T: DeserializeOwned + Send> JobQueue<P, T> {
    // creates job queue and starts it processing.  returns immediately.
    pub fn start() -> Self {
        let (tx, rx) =
            mpsc::unbounded::<(Box<dyn Job<ResultType = T>>, JobResultOneShotChannel), P>();

        let mut thread_handles = VecDeque::new();
        // spawns background task that processes job-queue and runs jobs.
        let task_handle = tokio::spawn(async move {
            while let Ok(r) = rx.recv().await {
                let (job, otx) = r.0;

                let result = match job.synchronicity() {
                    Synchronicity::Blocking => job.run_async().await,
                    Synchronicity::Async => tokio::task::spawn_blocking(move || job.run())
                        .await
                        .unwrap(),

                    Synchronicity::Process => {
                        let token = CancellationToken::new();
                        let cloned_token = token.clone();
                        let process_handle = job.process();
                        let jobresult = tokio::spawn(async move {
                            let mut buffer = Vec::new();
                            let mut stdout = process_handle.stdout.take().unwrap();
                            loop {
                                tokio::select! {
                                    _ = token.cancelled() => {
                                        process_handle.kill().await.expect("Could not kill proof queue task");
                                        break;
                                    }
                                    result = process_handle.wait() => {
                                        match result { // make into exit code
                                            Ok(status) => info!("Child process exited with status: {}", status),
                                            Err(e) => eprintln!("Error waiting for child process: {}", e),
                                        }
                                    }
                                    result = stdout.read_to_end(&mut buffer) => {
                                        match result {
                                            Ok(n) => {
                                                if n == 0 {
                                                    // End of output
                                                    break;
                                                }
                                                // Process the output
                                                let jobresult : T = match bincode::deserialize(&buffer) {
                                                    Ok(tee) => tee,
                                                    Err(e) => {
                                                        bail!("Proof queue job failed: {e:?}");
                                                    }
                                                };
                                                buffer.clear(); // Clear the buffer for the next read
                                                return Some(jobresult);
                                            }
                                            Err(e) => {
                                                eprintln!("Error reading process output: {}", e);
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                            return None;
                        });
                        // thread_handles.push_back(thread_handle);
                        let rest = jobresult.await.unwrap();
                        // let worker_handle = tokio::task::spawn(move || job.run());
                        // worker_handle.await
                    } // false => tokio::task::spawn_blocking(move || job.run())
                      //     .await
                      //     .unwrap(),
                };
                let _ = otx.send(result);
            }
        });

        Self { tx }
    }

    // alias of Self::start().
    // here for two reasons:
    //  1. backwards compat with existing tests
    //  2. if tests call dummy() instead of start(), then it is easier
    //     to find where start() is called for real.
    #[cfg(test)]
    pub fn dummy() -> Self {
        Self::start()
    }

    // adds job to job-queue and returns immediately.
    pub async fn add_job(
        &self,
        job: Box<dyn Job>,
        priority: P,
    ) -> anyhow::Result<oneshot::Receiver<Box<dyn JobResult>>> {
        let (otx, orx) = oneshot::channel();
        self.tx.send((job, otx), priority).await?;
        Ok(orx)
    }

    // adds job to job-queue, waits for job completion, and returns job result.
    pub async fn add_and_await_job(
        &self,
        job: Box<dyn Job>,
        priority: P,
    ) -> anyhow::Result<Box<dyn JobResult>> {
        let (otx, orx) = oneshot::channel();
        self.tx.send((job, otx), priority).await?;
        Ok(orx.await?)
    }

    #[cfg(test)]
    pub async fn wait_until_queue_empty(&self) {
        loop {
            if self.tx.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::any::Any;

    use super::*;

    #[derive(PartialEq, Debug)]
    struct DoubleJobResult(u64, u64);
    impl JobResult for DoubleJobResult {
        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    // a job that doubles the input value.  implements Job.
    struct DoubleJob {
        data: u64,
    }

    impl Job for DoubleJob {
        fn synchronicity(&self) -> bool {
            false
        }

        fn run(&self) -> Box<dyn JobResult> {
            let r = DoubleJobResult(self.data, self.data * 2);

            println!("{} * 2 = {}", r.0, r.1);
            Box::new(r)
        }

        type ResultType = DoubleJobResult;
    }

    // todo: make test(s) for async jobs.

    /// todo: this should verify the priority order of jobs.
    ///       presently each job just prints result and
    ///       human can manually verify output.
    #[tokio::test]
    async fn run_jobs_by_priority() -> anyhow::Result<()> {
        // create a job queue
        let job_queue = JobQueue::<u8>::start();

        // create 10 jobs
        for i in 0..10 {
            let job1 = Box::new(DoubleJob { data: i });
            let job2 = Box::new(DoubleJob { data: i * 100 });
            let job3 = Box::new(DoubleJob { data: i * 1000 });

            // process job and print results.
            job_queue.add_job(job1, 1).await?;
            job_queue.add_job(job2, 2).await?;
            job_queue.add_job(job3, 3).await?;
        }

        job_queue.wait_until_queue_empty().await;

        Ok(())
    }

    #[tokio::test]
    async fn get_result() -> anyhow::Result<()> {
        // create a job queue
        let job_queue = JobQueue::<u8>::start();

        // create 10 jobs
        for i in 0..10 {
            let job = Box::new(DoubleJob { data: i });

            let result = job_queue.add_and_await_job(job, 1).await?;
            assert_eq!(
                Some(&DoubleJobResult(i, i * 2)),
                result.as_any().downcast_ref::<DoubleJobResult>()
            );
        }

        Ok(())
    }
}
