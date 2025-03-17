use std::fmt::Display;
use std::time::SystemTime;

use serde_derive::Deserialize;
use serde_derive::Serialize;

/// A node's [BootstrapStatus] and some metadata.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub(crate) struct BootstrapInfo {
    pub status: BootstrapStatus,

    /// The time when the status was last set.
    pub last_set: SystemTime,
}

/// Does the node help bootstrapping the network?
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub(crate) enum BootstrapStatus {
    /// The node is not a bootstrap node.
    ///
    /// If no further information is known about a peer, it is assumed that it is an
    /// ordinary node.
    #[default]
    Ordinary,

    /// The node _is_ a bootstrap node.
    Bootstrap,
}

impl Display for BootstrapStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let display = match self {
            Self::Ordinary => "ordinary node",
            Self::Bootstrap => "bootstrap node",
        };

        write!(f, "{display}")
    }
}

impl BootstrapInfo {
    /// Create new [BootstrapInfo] right [now](SystemTime::now).
    pub fn new(status: BootstrapStatus) -> Self {
        Self {
            status,
            last_set: SystemTime::now(),
        }
    }
}
