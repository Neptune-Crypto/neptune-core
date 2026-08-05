use neptune_consensus::block::Block;
use neptune_primitives::block_height::BlockHeight;
use tasm_lib::twenty_first::prelude::MmrMembershipProof;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;

use super::PeerHandle;
use crate::application::loops::sync_loop::sync_progress::SyncProgress;
use crate::application::loops::sync_loop::SynchronizationBitMask;

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
    /// A peer requested a block with an anchor to authenticate against, but
    /// no authentication path relative to that anchor could be produced. The
    /// requester is informed so it can ask elsewhere.
    UnableToServeValidatedBlock {
        peer_handle: PeerHandle,
    },
    SyncBlock {
        block: Box<Block>,
        peer_handle: PeerHandle,
        /// An authentication path proving the block's membership in the chain
        /// anchored by the requester's anchor, if one could be produced.
        auth_path: Option<MmrMembershipProof>,
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
        /// An authentication path proving the block's membership in the chain
        /// being synced towards, if the block arrived with one. Must have
        /// been verified against the provided sync anchor.
        auth_path: Option<MmrMembershipProof>,
    },
    ExtendChain(Box<Block>),
    SyncCoverage {
        peer_handle: PeerHandle,
        coverage: SynchronizationBitMask,
    },
    TryFetchBlock {
        peer_handle: PeerHandle,
        height: BlockHeight,
        /// The sync anchor of the requesting peer, against which a served
        /// block should be authenticated, if the request carried one.
        requester_anchor: Option<MmrAccumulator>,
    },
    FastForward {
        new_tip: Box<Block>,
    },
}

pub(crate) enum SuccessorsToSync {
    Finished {
        new_tip: Block,
    },
    Continue {
        new_tip: Block,
    },
    RapidBlockDownloadError,
    SendError,
    /// The block at `height` is not a valid successor of `new_tip`. Carries the
    /// tip reached before the failure, since the subtask may have processed
    /// blocks before hitting the bad one.
    BlockValidationError {
        new_tip: Block,
        height: BlockHeight,
    },
    BlockPowError {
        new_tip: Block,
        height: BlockHeight,
    },
}
