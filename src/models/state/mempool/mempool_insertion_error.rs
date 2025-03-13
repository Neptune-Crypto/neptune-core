/// The reasons why inserting a transaction into the mempool may fail.
#[derive(Debug, Clone, Copy, thiserror::Error)]
pub(crate) enum MempoolInsertionError {
    #[error("Too many inputs: got {got}, but only {allowed} are allowed.")]
    TooManyInputs { got: usize, allowed: usize },
}
