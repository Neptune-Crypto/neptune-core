use crate::api::export::Network;
use crate::api::export::Timestamp;
use crate::protocol::consensus::block::Block;

/// An abstract function to decide if one block is valid given its predecessor.
///
/// This function is used by the sync loop when supplying tip-successor blocks
/// to the main loop: those tip-successors must be validated first.
///
/// The key word in the first sentence is abstract: using this formalism instead
/// of [`Block::is_valid`] allows the code to make abstraction of the concrete
/// validity function and, consequently, allows the caller to inject the correct
/// one. In production, there is only one variant, `Production`, which points to
/// [`Block::is_valid`]. However, for testing you might want to bypass that
/// step.
///
/// In practice, this data structure is used on the level of module `sync_loop`
/// and is not exposed through any outward-facing APIs or function signatures.
/// Indeed, the outward-facing API is given by `SyncLoopHandle` and to create it
/// the caller needs to pass a `Network` object instead. The correct
/// `BlockValidator` is inferred from this object.
#[derive(Debug, Clone, Copy)]
pub(super) enum BlockValidator {
    Production {
        network: Network,
    },
    #[cfg(test)]
    Test,
}

impl BlockValidator {
    pub(super) fn from_network(network: Network) -> Self {
        #[cfg(test)]
        match network {
            Network::Main => Self::Production { network },
            _ => Self::Test,
        }

        #[cfg(not(test))]
        Self::Production { network }
    }

    pub(crate) async fn verify(&self, successor: &Block, predecessor: &Block) -> bool {
        match self {
            BlockValidator::Production { network } => {
                let timestamp = Timestamp::now();
                successor.is_valid(predecessor, timestamp, *network).await
            }

            #[cfg(test)]
            BlockValidator::Test => true,
        }
    }
}
