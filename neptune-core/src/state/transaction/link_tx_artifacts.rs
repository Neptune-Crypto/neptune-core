//! The results of creating a chained transaction that stays on the link
//! pipeline: the [`LinkTx`]-valued sibling of
//! [`ChainedTxArtifacts`](super::chained_tx_artifacts::ChainedTxArtifacts).

use std::sync::Arc;

use neptune_consensus::chaintx::link_tx::LinkTx;
use neptune_wallet::chained_transaction_details::ChainedTransactionDetails;

/// The results of creating a chained transaction that stays a [`LinkTx`].
#[derive(Debug, Clone)]
pub struct LinkTxArtifacts {
    pub(crate) link_tx: Arc<LinkTx>,
    pub(crate) details: Arc<ChainedTransactionDetails>,
}

impl LinkTxArtifacts {
    pub fn link_tx(&self) -> &LinkTx {
        &self.link_tx
    }

    pub fn details(&self) -> &ChainedTransactionDetails {
        &self.details
    }
}
