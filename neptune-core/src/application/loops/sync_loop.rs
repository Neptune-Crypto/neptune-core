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
    target_height: BlockHeight,
    main_channel_sender: Sender<SyncToMain>,
    main_channel_receiver: Receiver<MainToSync>,
}

impl SyncLoop {
    pub(crate) async fn new(
        tip_height: BlockHeight,
        target_height: BlockHeight,
    ) -> Result<(Self, Sender<MainToSync>, Receiver<SyncToMain>), RapidBlockDownloadError> {
        const CHANNEL_CAPACITY: usize = 100;
        let download_state = RapidBlockDownload::new(tip_height, target_height).await?;
        let (main_to_sync_sender, main_to_sync_receiver) =
            mpsc::channel::<MainToSync>(CHANNEL_CAPACITY);
        let (sync_to_main_sender, sync_to_main_receiver) =
            mpsc::channel::<SyncToMain>(CHANNEL_CAPACITY);
        Ok((
            Self {
                tip_height,
                download_state,
                peers: HashMap::new(),
                target_height,
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
                        .duration_since(most_recent_receipt.unwrap_or(now))
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
            // Tell main loop we are done.
            if let Err(e) = self.main_channel_sender.send(SyncToMain::Finished).await {
                tracing::error!(
                    "Failed to send message from sync loop to main loop that job is done."
                );
            }

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
        tracing::info!("requesting block {height} from peer {peer_handle}");

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

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use macro_rules_attr::apply;
    use rand::RngCore;

    use crate::{protocol::consensus::block::Block, tests::shared_tokio_runtime};

    use super::*;

    struct MockMainLoop {
        peers: HashMap<PeerHandle, MockPeer>,
        main_to_sync_sender: Sender<MainToSync>,
        sync_to_main_receiver: Receiver<SyncToMain>,
        current_tip_height: BlockHeight,
        sync_target_height: BlockHeight,
        finished: bool,
    }

    impl MockMainLoop {
        fn new(
            main_to_sync_sender: Sender<MainToSync>,
            sync_to_main_receiver: Receiver<SyncToMain>,
            current_tip_height: BlockHeight,
            sync_target_height: BlockHeight,
        ) -> Self {
            Self {
                peers: HashMap::default(),
                main_to_sync_sender,
                sync_to_main_receiver,
                current_tip_height,
                sync_target_height,
                finished: false,
            }
        }

        async fn connect(&mut self, peer: MockPeer) {
            let _ = self
                .main_to_sync_sender
                .send(MainToSync::AddPeer(peer.handle()))
                .await
                .unwrap();
            self.peers.insert(peer.handle(), peer);
        }

        async fn disconnect(&mut self, peer_handle: PeerHandle) {
            let _ = self
                .main_to_sync_sender
                .send(MainToSync::RemovePeer(peer_handle))
                .await
                .unwrap();
            self.peers.remove(&peer_handle);
        }

        fn sync_is_finished(&self) -> bool {
            self.finished
        }

        async fn run(&mut self) {
            while let Some(message) = self.sync_to_main_receiver.recv().await {
                match message {
                    SyncToMain::PunishPeer(socket_addr, negative_peer_sanction) => {}
                    SyncToMain::RewardPeer(socket_addr, positive_peer_sanction) => {}
                    SyncToMain::Finished => {
                        if self.current_tip_height == self.sync_target_height {
                            self.finished = true;
                        }
                    }
                    SyncToMain::TipSuccessor(block) => {
                        if block.header().height == self.current_tip_height.next() {
                            self.current_tip_height = block.header().height;
                        }
                    }
                    SyncToMain::RequestBlock {
                        peer_handle,
                        height,
                    } => {
                        if let Some(peer) = self.peers.get_mut(&peer_handle) {
                            if let Some(block) = peer.request(height).await {
                                tracing::info!("received response block with height {} from peer, passing on to sync loop", block.header().height);
                                self.main_to_sync_sender
                                    .send(MainToSync::ReceiveBlock {
                                        peer_handle,
                                        block: Box::new(block),
                                    })
                                    .await
                                    .unwrap();
                            }
                        }
                    }
                    SyncToMain::Error => todo!(),
                }
            }
        }
    }

    #[derive(Debug, Clone)]
    enum MockPeer {
        GoodPeer(GoodPeer),
    }

    impl MockPeer {
        async fn request(&mut self, block_height: BlockHeight) -> Option<Block> {
            tracing::info!(
                "peer {} received request for block {block_height}",
                self.handle()
            );
            match self {
                MockPeer::GoodPeer(good_peer) => good_peer.request(block_height).await,
            }
        }

        fn handle(&self) -> PeerHandle {
            match self {
                MockPeer::GoodPeer(good_peer) => good_peer.handle(),
            }
        }
    }

    #[derive(Debug, Clone)]
    struct GoodPeer {
        peer_handle: PeerHandle,
    }

    impl GoodPeer {
        fn new() -> Self {
            Self {
                peer_handle: random_peer_handle(),
            }
        }
        async fn request(&mut self, block_height: BlockHeight) -> Option<Block> {
            let mut block = rng().random::<Block>();
            tokio::time::sleep(Duration::from_millis(1)).await;
            block.set_header_height(block_height);
            Some(block)
        }

        fn handle(&self) -> PeerHandle {
            self.peer_handle
        }
    }

    fn random_peer_handle() -> PeerHandle {
        PeerHandle::new(
            std::net::IpAddr::V6(Ipv6Addr::from_bits(rng().random())),
            rng().random(),
        )
    }

    #[tracing_test::traced_test]
    #[apply(shared_tokio_runtime)]
    async fn can_sync_from_one_good_peer() {
        let mut rng = rng();
        tracing::info!("starting test ...");
        let current_tip_height = BlockHeight::from(u64::from(rng.next_u32()));
        let sync_target_height =
            BlockHeight::from(current_tip_height.value() + rng.random_range(0..500));
        let (sync_loop, main_to_sync_sender, sync_to_main_receiver) =
            SyncLoop::new(current_tip_height, sync_target_height)
                .await
                .unwrap();
        let mut main_loop = MockMainLoop::new(
            main_to_sync_sender,
            sync_to_main_receiver,
            current_tip_height,
            sync_target_height,
        );

        main_loop.connect(MockPeer::GoodPeer(GoodPeer::new())).await;
        let _sync_loop_handle = sync_loop.start();
        main_loop.run().await;
        assert!(
            main_loop.sync_is_finished(),
            "current tip height {} versus sync target height {}",
            main_loop.current_tip_height,
            main_loop.sync_target_height
        );
    }

    #[tracing_test::traced_test]
    #[apply(shared_tokio_runtime)]
    async fn can_sync_from_many_good_peers() {
        let mut rng = rng();
        tracing::info!("starting test ...");
        let current_tip_height = BlockHeight::from(u64::from(rng.next_u32()));
        let sync_target_height =
            BlockHeight::from(current_tip_height.value() + rng.random_range(0..500));
        let (sync_loop, main_to_sync_sender, sync_to_main_receiver) =
            SyncLoop::new(current_tip_height, sync_target_height)
                .await
                .unwrap();
        let mut main_loop = MockMainLoop::new(
            main_to_sync_sender,
            sync_to_main_receiver,
            current_tip_height,
            sync_target_height,
        );

        main_loop.connect(MockPeer::GoodPeer(GoodPeer::new())).await;
        main_loop.connect(MockPeer::GoodPeer(GoodPeer::new())).await;
        main_loop.connect(MockPeer::GoodPeer(GoodPeer::new())).await;
        main_loop.connect(MockPeer::GoodPeer(GoodPeer::new())).await;
        main_loop.connect(MockPeer::GoodPeer(GoodPeer::new())).await;
        let _sync_loop_handle = sync_loop.start();
        main_loop.run().await;
        assert!(
            main_loop.sync_is_finished(),
            "current tip height {} versus sync target height {}",
            main_loop.current_tip_height,
            main_loop.sync_target_height
        );
    }
}
