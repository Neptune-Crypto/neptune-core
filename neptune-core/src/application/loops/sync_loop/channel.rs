use crate::api::export::BlockHeight;
use crate::application::loops::sync_loop::sync_progress::SyncProgress;
use crate::application::loops::sync_loop::SynchronizationBitMask;
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
    Finished(BlockHeight),
    TipSuccessor(Box<Block>),
    RequestBlocks(Vec<BlockRequest>),
    Status(SyncProgress),
    Punish(Vec<PeerHandle>),
    Coverage {
        coverage: SynchronizationBitMask,
        peer_handle: PeerHandle,
    },
    Error,
    SyncBlock {
        block: Box<Block>,
        peer_handle: PeerHandle,
    },
}

/// Messages sent from the main loop to the sync loop.
#[derive(Debug, Clone)]
pub(crate) enum MainToSync {
    Abort,
    AddPeer(PeerHandle),
    RemovePeer(PeerHandle),
    ReceiveBlock {
        peer_handle: PeerHandle,
        block: Box<Block>,
    },
    ExtendChain(Box<Block>),
    SyncCoverage {
        peer_handle: PeerHandle,
        coverage: SynchronizationBitMask,
    },
    Status,
    TryFetchBlock {
        peer_handle: PeerHandle,
        height: BlockHeight,
    },
    FastForward {
        new_tip: Box<Block>,
    },
}

pub(crate) enum SuccessorsToSync {
    Finished { new_tip: Block },
    Continue { new_tip: Block },
    RapidBlockDownloadError,
    SendError,
    BlockValidationError,
}
