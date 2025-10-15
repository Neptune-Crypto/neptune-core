use rayon::ThreadPoolBuilder;
use tasm_lib::prelude::Digest;

use crate::application::loops::channel::Cancelable;
use crate::protocol::consensus::block::pow::GuesserBuffer;
use crate::protocol::consensus::block::pow::Pow;

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
