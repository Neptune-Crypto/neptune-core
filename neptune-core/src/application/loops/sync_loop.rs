use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use std::time::SystemTime;

use rand::rng;
use rand::Rng;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Receiver;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinHandle;
use tokio::time::interval;

use crate::api::export::BlockHeight;
use crate::application::loops::sync_loop::channel::MainToSync;
use crate::application::loops::sync_loop::channel::SyncToMain;
use crate::application::loops::sync_loop::rapid_block_download::RapidBlockDownload;
use crate::application::loops::sync_loop::rapid_block_download::RapidBlockDownloadError;
use crate::protocol::consensus::block::Block;

pub(crate) mod bit_mask;
pub(crate) mod channel;
pub(crate) mod rapid_block_download;

/// After this long without any response from anyone, the sync loop will
/// terminate.
const ANY_RESPONSE_TIMEOUT: Duration = Duration::from_secs(15);
/// After this long without a response from a given peer, that peer will be sent
/// another block request.
const PEER_RESPONSE_TIMEOUT: Duration = Duration::from_secs(2);

type PeerHandle = SocketAddr;

#[derive(Debug, Clone, Default)]
pub(crate) struct PeerSyncState {
    num_blocks_contributed: usize,
    last_request: Option<SystemTime>,
}

/// Holds state for the synchronization event loop.
#[derive(Debug)]
pub(crate) struct SyncLoop {
    tip_height: BlockHeight,
    download_state: RapidBlockDownload,
    peers: HashMap<PeerHandle, PeerSyncState>,
    target: Block,
    main_channel_sender: Sender<SyncToMain>,
    main_channel_receiver: Receiver<MainToSync>,
}

impl SyncLoop {
    pub(crate) async fn new(
        tip_height: BlockHeight,
        target: &Block,
    ) -> Result<(Self, Sender<MainToSync>, Receiver<SyncToMain>), RapidBlockDownloadError> {
        const CHANNEL_CAPACITY: usize = 100;
        let download_state = RapidBlockDownload::new(tip_height, target).await?;
        let (main_to_sync_sender, main_to_sync_receiver) =
            mpsc::channel::<MainToSync>(CHANNEL_CAPACITY);
        let (sync_to_main_sender, sync_to_main_receiver) =
            mpsc::channel::<SyncToMain>(CHANNEL_CAPACITY);
        Ok((
            Self {
                tip_height,
                download_state,
                peers: HashMap::new(),
                target: target.clone(),
                main_channel_sender: sync_to_main_sender,
                main_channel_receiver: main_to_sync_receiver,
            },
            main_to_sync_sender,
            sync_to_main_receiver,
        ))
    }

    /// Start the sync loop asynchronously. Return a handle that can be aborted.
    pub(crate) fn start(self) -> JoinHandle<()> {
        tokio::spawn(async move {
            self.run().await;
        })
    }

    /// Run the event loop.
    async fn run(mut self) {
        let mut finished = false;

        // Create an interval timer with 100 millisecond period.
        let mut ticker = interval(Duration::from_millis(100));

        // Track the timestamp of the most recent block to be received.
        let mut most_recent_receipt = None;

        // Process messages as they come in. Also poll timer.
        loop {
            tokio::select! {
                Some(message_from_main) = self.main_channel_receiver.recv() => {
                    match message_from_main {
                        MainToSync::AddPeer(peer_handle) => {
                            self.peers.insert(peer_handle, PeerSyncState::default());

                            self.request_random_block(peer_handle).await;
                        }
                        MainToSync::RemovePeer(peer_handle) => {self.peers.remove(&peer_handle);}
                        MainToSync::ReceiveBlock { peer_handle, block } => {
                            // Store block and update download state.
                            if let Err(e) = self.download_state.receive_block(&block).await
                            {
                                tracing::warn!(
                                    "Could not process received block {:x} of height {}: {}",
                                    block.hash(), block.header().height, e
                                );
                                continue;
                            }
                            self.peers.entry(peer_handle).and_modify(|e|{e.num_blocks_contributed += 1;});
                            most_recent_receipt = Some(SystemTime::now());

                            // Update tip to available successors.
                            match self.process_successors_of_tip().await {
                                Ok(SyncLoopReturnCode::Finished) => {
                                    finished = true;
                                    break;
                                }
                                Ok(SyncLoopReturnCode::Continue) => {}
                                Err(_) => {break;}
                            }

                            // Send out new request.
                            self.request_random_block(peer_handle).await;
                        }
                    }
                }

                _ = ticker.tick() => {
                    // Are we still connected to peers? If not, terminate.
                    if self.peers.is_empty() {
                        break;
                    }

                    // If the last response was ages ago, then the sync loop is
                    // not doing anything any more and it should be terminated.
                    let now = SystemTime::now();
                    if now
                        .duration_since(most_recent_receipt.unwrap())
                        .ok()
                        .is_none_or(|timestamp| timestamp > ANY_RESPONSE_TIMEOUT) {
                        finished = self.download_state.is_complete();
                        break;
                    }

                    // Check all peers for timeouts.
                    let mut timeouts = vec![];
                    for (peer_handle, peer_state) in &self.peers {
                        if peer_state
                        .last_request
                        .and_then(|timestamp| now.duration_since(timestamp).ok())
                        .is_none_or(|duration| duration > PEER_RESPONSE_TIMEOUT) {
                            timeouts.push(*peer_handle);
                        }
                    }

                    // If timeout, re-request random block.
                    for peer_handle in timeouts {
                        self.request_random_block(peer_handle).await;
                    }

                }
            }
        }

        if finished {
            // Clean up the temp directory.
            self.download_state.clean_up().await;
        }
    }

    /// Request a random (but missing) block from the given peer.
    async fn request_random_block(&mut self, peer_handle: PeerHandle) {
        // Sample a random missing block height.
        let Some(height) = self
            .download_state
            .sample_missing_block_height(rng().random())
        else {
            tracing::error!(
                "Cannot request random block from peer because all blocks are in already."
            );
            return;
        };

        // Send a request to the peer for that block.
        if let Err(e) = self
            .main_channel_sender
            .send(SyncToMain::RequestBlock {
                peer_handle,
                height,
            })
            .await
        {
            tracing::warn!("Could not send message from sync loop to main loop; error: {e}");
            tracing::warn!("Relying on timeout mechanism to retry in a short while.");
        }

        // Record timestamp of last request.
        self.peers
            .entry(peer_handle)
            .and_modify(|e| e.last_request = Some(SystemTime::now()));
    }

    /// If we are sitting on blocks that immediately succeed the tip with no
    /// gaps, then send them all over to the main loop for processing. Do that
    /// until there are no more such blocks left.
    async fn process_successors_of_tip(&mut self) -> Result<SyncLoopReturnCode, SyncLoopError> {
        while self.download_state.have_received(self.tip_height.next()) {
            // get successor block
            let successor = self
                .download_state
                .get_and_free(self.tip_height.next())
                .await.map_err(|e| {
                    tracing::error!("Could not get block from temp directory even though the block was received: {e} Terminating sync mode.");
                    SyncLoopError::RapidBlockDownloadError(e)
                })?;

            // send to main
            self.main_channel_sender
                .send(SyncToMain::TipSuccessor(Box::new(successor))).await.map_err(|e|{
                    tracing::warn!("Could not send block from sync loop to main loop: {e}. Terminating sync mode.");
                    SyncLoopError::SendError(e)
                })?;

            // update tip height
            self.tip_height = self.tip_height.next();
        }

        // We processed everything we can. Are we finished?
        if self.download_state.is_complete() {
            Ok(SyncLoopReturnCode::Finished)
        } else {
            Ok(SyncLoopReturnCode::Continue)
        }
    }
}

#[derive(Debug, Clone)]
enum SyncLoopReturnCode {
    Finished,
    Continue,
}

#[derive(Debug, Clone, thiserror::Error)]
pub(crate) enum SyncLoopError {
    #[error("RapidBlockDownloadError: {0}")]
    RapidBlockDownloadError(RapidBlockDownloadError),
    #[error("SendError: {0}")]
    SendError(tokio::sync::mpsc::error::SendError<SyncToMain>),
}
