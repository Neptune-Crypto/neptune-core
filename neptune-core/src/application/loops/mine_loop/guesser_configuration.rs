use neptune_primitives::timestamp::Timestamp;
use neptune_wallet::address::ReceivingAddress;
use tasm_lib::prelude::Digest;

/// Information related to guessing.
#[derive(Debug, Clone)]
pub(crate) struct GuessingConfiguration {
    pub(crate) num_guesser_threads: Option<usize>,
    pub(crate) address: ReceivingAddress,
    pub(crate) override_rng_seed: Option<u64>,
    pub(crate) override_timestamp: Option<Timestamp>,

    /// The guesser's reveal of the inactive SWBF after the proposal's parent,
    /// where required by the consensus rules.
    pub(crate) swbfi_reveal: Option<(Digest, Vec<Digest>)>,
}
