use strum::Display;

/// Enumerates the various reasons why a connection should be bounced.
#[derive(Debug, Clone, Copy, Display, PartialEq, Eq)]
pub(crate) enum BounceReason {
    #[strum(to_string = "Maximum number of peers is reached.")]
    MaxReached,

    #[strum(to_string = "Peer was banned.")]
    Banned,

    #[strum(to_string = "Address format not supported.")]
    UnsupportedAddressFormat,
}
