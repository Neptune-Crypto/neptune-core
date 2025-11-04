use tasm_lib::twenty_first::prelude::MmrMembershipProof;

use crate::api::export::BlockHeight;
use crate::protocol::consensus::block::Block;
use crate::protocol::peer::NegativePeerSanction;
use crate::protocol::peer::PositivePeerSanction;

use super::PeerHandle;

/// Messages sent from the sync loop to the main loop.
#[derive(Debug, Clone)]
pub(crate) enum SyncToMain {
    PunishPeer(PeerHandle, NegativePeerSanction),
    RewardPeer(PeerHandle, PositivePeerSanction),
    Finished,
    TipSuccessor(Box<Block>),
    RequestBlock {
        peer_handle: PeerHandle,
        height: BlockHeight,
    },
    Error,
}

/// Messages sent from the main loop to the sync loop.
#[derive(Debug, Clone)]
pub(crate) enum MainToSync {
    AddPeer(PeerHandle),
    RemovePeer(PeerHandle),
    ReceiveBlock {
        peer_handle: PeerHandle,
        block: Box<Block>,
    },
}
