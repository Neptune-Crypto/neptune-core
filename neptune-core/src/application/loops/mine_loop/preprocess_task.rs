use rayon::ThreadPoolBuilder;
use tasm_lib::prelude::Digest;
use tracing::error;

use crate::application::loops::channel::Cancelable;
use crate::protocol::consensus::block::pow::GuesserBuffer;
use crate::protocol::consensus::block::pow::Pow;

/// Spawn the preprocess task.
///
/// This asynchronously function wraps [`preprocess_alpha`], which is blocking,
/// such that that blocking task can be aborted when this tokio task is.
///
/// The produced [`GuesserBuffer`] is returned through the passed channel.
pub(crate) async fn preprocess_task<const MERKLE_TREE_HEIGHT: usize>(
    predecessor_digest: Digest,
    num_threads: Option<usize>,
    return_channel: tokio::sync::oneshot::Sender<Option<GuesserBuffer<{ MERKLE_TREE_HEIGHT }>>>,
) {
    let (cancel_channel, receiver) = futures::channel::oneshot::channel::<()>();
    let preprocess_result = tokio::task::spawn_blocking(move || {
        preprocess_alpha::<{ MERKLE_TREE_HEIGHT }>(
            predecessor_digest,
            num_threads,
            Some(&cancel_channel),
        )
    })
    .await;

    drop(receiver);

    match preprocess_result {
        Ok(maybe_guesser_buffer) => {
            if let Err(_guesser_buffer) = return_channel.send(maybe_guesser_buffer) {
                error!("warn: could not send guesser buffer to mine loop");
            }
        }
        Err(e) => {
            error!("error in preprocessing task: {e}");
        }
    };
}

/// Preprocessing phase for guessing, during which the [`GuesserBuffer`] is
/// filled.
///
/// This function is tailored to consensus rule set HardForkAlpha and after.
/// For earlier consensus rule sets, use
/// [crate::protocol::consensus::block::Block::guess_preprocess_reboot].
pub(crate) fn preprocess_alpha<const MERKLE_TREE_HEIGHT: usize>(
    predecessor_digest: Digest,
    num_threads: Option<usize>,
    cancel_channel: Option<&dyn Cancelable>,
) -> Option<GuesserBuffer<MERKLE_TREE_HEIGHT>> {
    // build a rayon thread pool that respects the limitation on the number
    // of threads
    let num_threads = num_threads.unwrap_or_else(rayon::current_num_threads);
    let thread_pool = ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build()
        .unwrap();

    let guesser_buffer = thread_pool.install(|| {
        Pow::<MERKLE_TREE_HEIGHT>::preprocess_alpha(cancel_channel, predecessor_digest)
    });

    if cancel_channel.is_some_and(|cc| cc.is_canceled()) {
        None
    } else {
        Some(guesser_buffer)
    }
}

#[cfg(test)]
mod tests {
    use crate::tests::shared_tokio_runtime;
    use macro_rules_attr::apply;
    use rand::rng;
    use rand::Rng;

    use super::*;

    #[apply(shared_tokio_runtime)]
    async fn can_cancel_preprocess_task() {
        const MERKLE_TREE_HEIGHT: usize = 20;

        let mut rng = rng();

        // produce tokio channel pair
        let (sender, receiver) =
            tokio::sync::oneshot::channel::<Option<GuesserBuffer<MERKLE_TREE_HEIGHT>>>();

        // spawn preprocess task
        let join_handle = tokio::task::spawn(preprocess_task::<MERKLE_TREE_HEIGHT>(
            rng.random(),
            Some(1),
            sender,
        ));

        // abort channel
        join_handle.abort();

        assert!(join_handle.await.unwrap_err().is_cancelled());
        assert!(receiver.is_empty());
    }

    #[apply(shared_tokio_runtime)]
    async fn can_preprocess() {
        const MERKLE_TREE_HEIGHT: usize = 20;

        let mut rng = rng();

        // produce tokio channel pair
        let (sender, mut receiver) =
            tokio::sync::oneshot::channel::<Option<GuesserBuffer<MERKLE_TREE_HEIGHT>>>();

        // spawn preprocess task
        let join_handle = tokio::task::spawn(preprocess_task::<MERKLE_TREE_HEIGHT>(
            rng.random(),
            Some(1),
            sender,
        ));

        // wait for task to complete
        join_handle.await.unwrap();

        // read from channel
        let gb = receiver.try_recv().unwrap();

        assert!(gb.is_some());
    }
}
