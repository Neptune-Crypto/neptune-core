#[derive(Debug, Clone, Copy, thiserror::Error, PartialEq, Eq)]
pub enum MutatorSetUpdateError {
    ///   0 <= transaction fee (also checked in block program).
    #[error("fee must be non-negative")]
    NegativeFee,
}
