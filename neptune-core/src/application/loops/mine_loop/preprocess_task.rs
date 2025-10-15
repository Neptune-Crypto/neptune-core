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
pub(crate) async fn preprocess_task<const MERKLE_TREE_HEIGHT: usize>(
    predecessor_digest: Digest,
    num_threads: Option<usize>,
) -> Option<GuesserBuffer<{ MERKLE_TREE_HEIGHT }>> {
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
        Ok(maybe_guesser_buffer) => maybe_guesser_buffer,
        Err(e) => {
            error!("error in preprocessing task: {e}");
            None
        }
    }
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

        // spawn preprocess task
        let join_handle =
            tokio::task::spawn(preprocess_task::<MERKLE_TREE_HEIGHT>(rng.random(), Some(1)));

        // abort channel
        join_handle.abort();

        assert!(join_handle.await.unwrap_err().is_cancelled());
    }

    #[apply(shared_tokio_runtime)]
    async fn can_preprocess() {
        const MERKLE_TREE_HEIGHT: usize = 20;

        let mut rng = rng();

        // spawn preprocess task
        let join_handle =
            tokio::task::spawn(preprocess_task::<MERKLE_TREE_HEIGHT>(rng.random(), Some(1)));

        let gb = join_handle.await.unwrap();
        assert!(gb.is_some());
    }
}
