use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use neptune_primitives::timestamp::Timestamp;
use neptune_wallet::address::ReceivingAddress;
use tasm_lib::triton_vm::prelude::BFieldElement;

/// Information related to guessing.
#[derive(Debug, Clone)]
pub(crate) struct GuessingConfiguration {
    pub(crate) num_guesser_threads: Option<usize>,
    pub(crate) address: ReceivingAddress,
    pub(crate) override_rng_seed: Option<u64>,
    pub(crate) override_timestamp: Option<Timestamp>,

    /// The version to set in the block's header before guessing, if any.
    pub(crate) override_version: Option<BFieldElement>,

    /// Number of guesses per seconds reported by guesser.
    pub(crate) guess_rate: Arc<AtomicU64>,
}
