use std::net::SocketAddr;
use std::time::SystemTime;

use tasm_lib::prelude::Digest;

use crate::api::export::BlockHeight;
use crate::application::loops::sync_loop::rapid_block_download::RapidBlockDownload;

pub(crate) mod bit_mask;
pub(crate) mod channel;
pub(crate) mod rapid_block_download;

#[derive(Debug, Clone, Default)]
pub(crate) struct PeerSyncState {
    num_block_contributed: usize,
    last_request: Option<SystemTime>,
}

#[derive(Debug, Clone)]
pub(crate) struct SyncLoop {
    download_state: RapidBlockDownload,
    current_tip_digest: Digest,
    peers: Vec<SocketAddr>,
}

impl SyncLoop {
    fn new(
        current_tip_digest: Digest,
        current_height: BlockHeight,
        target_height: BlockHeight,
    ) -> Self {
        Self {
            download_state: todo!(),
            current_tip_digest,
            peers: todo!(),
        }
    }
}
