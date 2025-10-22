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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub mod tests {
    use super::*;
    use crate::api::export::Network;
    use crate::application::config::cli_args;
    use crate::protocol::consensus::transaction::Transaction;
    use crate::protocol::consensus::transaction::TransactionProof;
    use crate::state::wallet::wallet_entropy::WalletEntropy;
    use crate::tests::shared::blocks::invalid_block_with_transaction;
    use crate::tests::shared::globalstate::mock_genesis_global_state;
    use crate::tests::shared::strategies::txkernel;
    use crate::Block;

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

    #[test_strategy::proptest(async = "tokio", cases = 5)]
    async fn block_selector_consistency_with_new_block(
        #[strategy(txkernel::with_lengths(0, 2, 2, true))]
    tx_kernel: crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel,
    ) {
        let mut global_state_lock = mock_genesis_global_state(
            2,
            WalletEntropy::new_random(),
            cli_args::Args::default_with_network(Network::Main),
        )
        .await;
        let mut state = global_state_lock.lock_guard_mut().await;

        let genesis_digest = state.chain.light_state().hash();

        // Test genesis consistency
        assert_eq!(
            BlockSelector::Special(BlockSelectorLiteral::Genesis)
                .as_digest(&state)
                .await
                .unwrap(),
            genesis_digest
        );
        assert_eq!(
            BlockSelector::Special(BlockSelectorLiteral::Tip)
                .as_digest(&state)
                .await
                .unwrap(),
            genesis_digest
        );
        assert_eq!(
            BlockSelector::Height(0u64.into())
                .as_digest(&state)
                .await
                .unwrap(),
            genesis_digest
        );

        // Add a block (height 1)
        let genesis = Block::genesis(Network::Main);
        let tx_block1 = Transaction {
            kernel: tx_kernel,
            proof: TransactionProof::invalid(),
        };
        let block1 = invalid_block_with_transaction(&genesis, tx_block1);
        let block1_digest = block1.hash();
        let block1_height: BlockHeight = 1.into();

        state.set_new_tip(block1.clone()).await.unwrap();

        // Test consistency after adding new block
        let tip_digest = BlockSelector::Special(BlockSelectorLiteral::Tip)
            .as_digest(&state)
            .await
            .unwrap();
        let height1_digest = BlockSelector::Height(block1_height)
            .as_digest(&state)
            .await
            .unwrap();
        let direct_digest = BlockSelector::Digest(block1_digest)
            .as_digest(&state)
            .await
            .unwrap();

        // All selectors for block1 should return the same digest
        assert_eq!(tip_digest, block1_digest);
        assert_eq!(height1_digest, block1_digest);
        assert_eq!(direct_digest, block1_digest);

        // Non-existent height should return None
        assert!(BlockSelector::Height(2u64.into())
            .as_digest(&state)
            .await
            .is_none());
    }
}
