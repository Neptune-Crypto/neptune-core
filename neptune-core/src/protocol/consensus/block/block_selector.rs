//! BlockSelector is a helper for querying blocks.
//!
//! The idea is to instantiate a BlockSelector using any of the following as
//! identifier:
//!  * A Digest
//!  * A BlockHeight
//!  * Genesis
//!  * Tip
//!
//! Then call BlockSelector::to_digest() to obtain the block's Digest, if it
//! exists.
//!
//! Public API's such as RPCs should accept a BlockSelector rather than a Digest
//! or Height.

use std::str::FromStr;

use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;

use super::block_height::BlockHeight;
use crate::state::GlobalState;
use crate::twenty_first::prelude::Digest;
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum BlockSelector {
    Special(BlockSelectorLiteral),
    Digest(Digest),
    Height(BlockHeight),
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BlockSelectorLiteral {
    Genesis,
    Tip,
}

/// BlockSelector can be written out as any of:
/// ```text
///  genesis
///  tip
///  <N>
///  <hex>
/// ```
///
/// This is intended to be easy for humans to read and also input, ie suitable
/// for use as CLI argument.
impl std::fmt::Display for BlockSelector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Digest(d) => write!(f, "{}", d),
            Self::Height(h) => write!(f, "{}", h),
            Self::Special(BlockSelectorLiteral::Genesis) => write!(f, "genesis"),
            Self::Special(BlockSelectorLiteral::Tip) => write!(f, "tip"),
        }
    }
}

#[derive(Debug, Clone, Error)]
pub enum BlockSelectorParseError {
    #[error("Invalid selector {0}. Try genesis or tip")]
    InvalidSelector(String),
}

impl FromStr for BlockSelector {
    type Err = BlockSelectorParseError;

    // note: this parses the output of impl Display for BlockSelector
    // note: this is used by clap parser in neptune-cli for block-info command
    //       and probably future commands as well.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "genesis" => Ok(Self::Special(BlockSelectorLiteral::Genesis)),
            "tip" => Ok(Self::Special(BlockSelectorLiteral::Tip)),
            _ => {
                if let Ok(d) = Digest::try_from_hex(s) {
                    Ok(Self::Digest(d))
                } else if let Ok(h) = s.parse::<u64>() {
                    Ok(Self::Height(h.into()))
                } else {
                    Err(BlockSelectorParseError::InvalidSelector(s.to_string()))
                }
            }
        }
    }
}

impl BlockSelector {
    /// returns canonical chain block Digest for this selector, if it exists.
    ///
    /// note: if multiple blocks with same height are found only the digest
    /// of the block belonging to canonical chain is returned.
    pub async fn as_digest(&self, state: &GlobalState) -> Option<Digest> {
        match self {
            BlockSelector::Special(BlockSelectorLiteral::Tip) => {
                Some(state.chain.light_state().hash())
            }
            BlockSelector::Special(BlockSelectorLiteral::Genesis) => {
                Some(state.chain.archival_state().genesis_block().hash())
            }
            BlockSelector::Digest(d) => Some(*d),
            BlockSelector::Height(h) => {
                state
                    .chain
                    .archival_state()
                    .archival_block_mmr
                    .ammr()
                    .try_get_leaf((*h).into())
                    .await
            }
        }
    }
}
