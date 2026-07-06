//! Resolving a [`BlockSelector`] to a concrete block digest requires node
//! state, so that logic lives here as an extension trait. The selector type
//! itself lives in `neptune-primitives` so lightweight clients can use it.

use neptune_primitives::block_selector::BlockSelector;
use neptune_primitives::block_selector::BlockSelectorLiteral;
use tasm_lib::twenty_first::prelude::Digest;

use crate::state::GlobalState;

#[async_trait::async_trait]
pub trait BlockSelectorExt {
    /// returns canonical chain block Digest for this selector, if it exists.
    ///
    /// note: if multiple blocks with same height are found only the digest
    /// of the block belonging to canonical chain is returned.
    async fn as_digest(&self, state: &GlobalState) -> Option<Digest>;
}

#[async_trait::async_trait]
impl BlockSelectorExt for BlockSelector {
    async fn as_digest(&self, state: &GlobalState) -> Option<Digest> {
        match self {
            BlockSelector::Special(BlockSelectorLiteral::Tip) => Some(state.chain.tip().hash()),
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
    use neptune_consensus::block::test_helpers::invalid_block_with_transaction;
    use neptune_consensus::transaction::test_helpers::txkernel;
    use neptune_consensus::transaction::Transaction;
    use neptune_consensus::transaction::TransactionProof;
    use neptune_primitives::block_height::BlockHeight;

    use super::*;
    use crate::api::export::Network;
    use crate::application::config::cli_args;
    use crate::state::wallet::wallet_entropy::WalletEntropy;
    use crate::tests::shared::globalstate::mock_genesis_global_state;
    use crate::Block;

    #[test_strategy::proptest(async = "tokio", cases = 5)]
    async fn block_selector_consistency_with_new_block(
        #[strategy(txkernel::with_lengths(0, 2, 2, true))]
        tx_kernel: neptune_consensus::transaction::transaction_kernel::TransactionKernel,
    ) {
        let mut global_state_lock = mock_genesis_global_state(
            2,
            WalletEntropy::new_random(),
            cli_args::Args::default_with_network(Network::Main),
        )
        .await;
        let mut state = global_state_lock.lock_guard_mut().await;

        let genesis_digest = state.chain.tip().hash();

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
