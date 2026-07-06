use neptune_primitives::timestamp::Timestamp;
use neptune_wallet::address::ReceivingAddress;
use rand::rngs::StdRng;

/// Information related to guessing.
#[derive(Debug, Clone)]
pub(crate) struct GuessingConfiguration {
    pub(crate) num_guesser_threads: Option<usize>,
    pub(crate) address: ReceivingAddress,
    pub(crate) override_rng: Option<StdRng>,
    pub(crate) override_timestamp: Option<Timestamp>,
}
