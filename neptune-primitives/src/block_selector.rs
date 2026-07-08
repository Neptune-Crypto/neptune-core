//! BlockSelector is a helper for querying blocks.
//!
//! The idea is to instantiate a BlockSelector using any of the following as
//! identifier:
//!  * A Digest
//!  * A BlockHeight
//!  * Genesis
//!  * Tip
//!
//! Public API's such as RPCs should accept a BlockSelector rather than a Digest
//! or Height. Resolving a selector to a concrete block digest requires node
//! state, so that lives with the node (see `BlockSelectorExt` in neptune-core);
//! the selector type itself lives here so lightweight clients can construct and
//! serialize it without depending on the node.

use std::str::FromStr;

use serde::Deserialize;
use serde::Serialize;
use tasm_lib::twenty_first::prelude::Digest;
use thiserror::Error;

use crate::block_height::BlockHeight;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BlockSelectorLiteral {
    Genesis,
    Tip,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum BlockSelector {
    Special(BlockSelectorLiteral),
    Digest(Digest),
    Height(BlockHeight),
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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn block_selector_serde_json() {
        let test_cases = vec![
            (
                r#""genesis""#,
                BlockSelector::Special(BlockSelectorLiteral::Genesis),
            ),
            (
                r#""tip""#,
                BlockSelector::Special(BlockSelectorLiteral::Tip),
            ),
            (r#"0"#, BlockSelector::Height(BlockHeight::from(0))),
            (r#"42"#, BlockSelector::Height(BlockHeight::from(42))),
        ];

        for (json_str, expected) in test_cases {
            let deserialized: BlockSelector = serde_json::from_str(json_str)
                .unwrap_or_else(|e| panic!("Failed to deserialize {}: {}", json_str, e));

            assert_eq!(
                deserialized, expected,
                "JSON compatibility failed for: {}",
                json_str
            );
        }

        let known_digest = Digest::default();
        let digest_json = format!("\"{}\"", known_digest.to_hex());
        let deserialized: BlockSelector =
            serde_json::from_str(&digest_json).expect("Digest to be deserialized");

        assert_eq!(deserialized, BlockSelector::Digest(known_digest));
    }
}
