use crate::api::export::Network;
use crate::api::export::Timestamp;
use crate::protocol::consensus::block::Block;

/// An abstract function to decide if one block is valid given its predecessor.
///
/// The key word is abstract: using this formalism instead of
/// [`Block::is_valid`] allows the code to make abstraction of the concrete
/// validity function and, consequently, allows the caller to inject the correct
/// one. In production, there is only one variant, `Production`, which points to
/// [`Block::is_valid`]. However, for testing you might want to bypass that
/// step.
#[derive(Debug, Clone, Copy)]
pub(crate) enum BlockValidator {
    Production {
        network: Network,
    },
    #[cfg(test)]
    Test,
}

impl BlockValidator {
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
