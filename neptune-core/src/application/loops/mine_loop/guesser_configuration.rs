use rand::rngs::StdRng;

use crate::api::export::ReceivingAddress;
use crate::api::export::Timestamp;

/// Information related to guessing.
#[derive(Debug, Clone)]
pub(crate) struct GuessingConfiguration {
    pub(crate) num_guesser_threads: Option<usize>,
    pub(crate) address: ReceivingAddress,
    pub(crate) override_rng: Option<StdRng>,
    pub(crate) override_timestamp: Option<Timestamp>,
}
