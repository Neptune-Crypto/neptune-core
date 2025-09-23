use std::os::unix::net::SocketAddr;

use tasm_lib::twenty_first::prelude::MmrMembershipProof;

use crate::protocol::consensus::block::Block;
use crate::protocol::peer::NegativePeerSanction;
use crate::protocol::peer::PositivePeerSanction;

pub(crate) struct MinisketchContribution;

/// Messages sent from the sync loop to the main loop.
pub(crate) enum SyncToMain {
    PunishPeer(SocketAddr, NegativePeerSanction),
    RewardPeer(SocketAddr, PositivePeerSanction),
    RequestBatchOfRandomBlocks(SocketAddr, MinisketchContribution),
    UpdatePeers,
}

/// Messages sent from the main loop to the sync loop.
pub(crate) enum MainToSync {
    PeerList(Vec<SocketAddr>),
    RandomBlocks(SocketAddr, Vec<(Block, MmrMembershipProof)>),

    /// Successor => no problem
    /// Reorg => clear cache
    UpdateTip(Block),
}
