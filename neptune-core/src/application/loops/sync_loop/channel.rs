use crate::api::export::BlockHeight;
use crate::protocol::consensus::block::Block;

use super::PeerHandle;

#[derive(Debug, Clone)]
pub(crate) struct BlockRequest {
    pub(crate) peer_handle: PeerHandle,
    pub(crate) height: BlockHeight,
}

/// Messages sent from the sync loop to the main loop.
#[derive(Debug, Clone)]
pub(crate) enum SyncToMain {
    Finished,
    TipSuccessor(Box<Block>),
    RequestBlocks(Vec<BlockRequest>),
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
