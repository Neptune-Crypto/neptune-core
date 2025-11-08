use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use std::time::SystemTime;

use itertools::Itertools;
use rand::rng;
use rand::Rng;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Receiver;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinHandle;
use tokio::time::interval;

use crate::api::export::BlockHeight;
use crate::application::loops::sync_loop::channel::BlockRequest;
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
#[cfg(not(test))]
const PEER_RESPONSE_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(test)]
const PEER_RESPONSE_TIMEOUT: Duration = Duration::from_millis(1);

/// Time between successive ticks of the event loop's internal clock.
const TICK_PERIOD: Duration = Duration::from_micros(100);

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
    main_channel_sender: Sender<SyncToMain>,
    main_channel_receiver: Receiver<MainToSync>,
}

impl SyncLoop {
    pub(crate) async fn new(
        tip_height: BlockHeight,
        target_height: BlockHeight,
        resume_if_possible: bool,
    ) -> Result<(Self, Sender<MainToSync>, Receiver<SyncToMain>), RapidBlockDownloadError> {
        const CHANNEL_CAPACITY: usize = 10;
        let download_state =
            RapidBlockDownload::new(tip_height, target_height, resume_if_possible).await?;
        let (main_to_sync_sender, main_to_sync_receiver) =
            mpsc::channel::<MainToSync>(CHANNEL_CAPACITY);
        let (sync_to_main_sender, sync_to_main_receiver) =
            mpsc::channel::<SyncToMain>(CHANNEL_CAPACITY);
        Ok((
            Self {
                tip_height,
                download_state,
                peers: HashMap::new(),
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

        // Create an interval timer, triggering a tick event regularly.
        let mut ticker = interval(TICK_PERIOD);

        // Join handle for an asynchronous task that sends tip-successors to the
        // main loop one-by-one. This task must be asynchronous because it can
        // take a while and we do not want it to halt iteration of the event
        // loop.
        let mut maybe_successors_subtask: Option<
            JoinHandle<Result<SyncLoopReturnCode, SyncLoopError>>,
        > = None;

        // Track the timestamp of the most recent block to be received.
        let mut most_recent_receipt = None;

        // Track the time of disconnect of the last peer.
        let mut last_peer_disconnect_time = None;

        // Collect the block requests that are going to be sent out in good
        // order; *i.e.*, without time-outs.
        let mut pending_block_requests = vec![];

        // Process events as they come in.
        loop {
            tokio::select! {

                // event: successors subtask finished
                successor_task_result = async {
                    if let Some(handle) = &mut maybe_successors_subtask {
                        Some(handle.await)
                    } else {
                        None
                    }
                }, if maybe_successors_subtask.is_some() => {
                    match successor_task_result.unwrap() {
                        Ok(Ok(SyncLoopReturnCode::Finished)) => {
                            finished = true;
                            break;
                        }
                        Ok(Ok(SyncLoopReturnCode::Continue{tip_height})) => {
                            self.tip_height = tip_height;
                        }
                        Ok(Err(SyncLoopError::RapidBlockDownloadError(e))) => {
                            tracing::error!("Rapid block download error while sending tip-successors to main loop: {e}");
                        }
                        Ok(Err(SyncLoopError::SendError(e))) => {
                            tracing::error!("Could not send tip-successor block to main loop: {e}");
                        }
                        Err(e) => {
                            tracing::error!("Tokio error while sending tip-successors to main loop: {e}");
                        }
                    }
                    maybe_successors_subtask = None;
                }

                // event: message from sync loop
                Some(message_from_main) = self.main_channel_receiver.recv() => {
                    match message_from_main {
                        MainToSync::AddPeer(peer_handle) => {
                            self.peers.insert(peer_handle, PeerSyncState::default());

                            // Add new block request to queue.
                            pending_block_requests.push(peer_handle);
                        }
                        MainToSync::RemovePeer(peer_handle) => {
                            self.peers.remove(&peer_handle);
                            last_peer_disconnect_time = Some(SystemTime::now());
                        }
                        MainToSync::ReceiveBlock { peer_handle, block } => {
                            tracing::info!("receiving block {} ...", block.header().height);
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
                            if maybe_successors_subtask.is_none() {
                                let moved_tip_height = self.tip_height;
                                let moved_download_state = self.download_state.clone();
                                let moved_sender = self.main_channel_sender.clone();
                                maybe_successors_subtask = Some(tokio::spawn(async move {
                                    Self::process_successors_of_tip(moved_tip_height, moved_download_state, moved_sender).await
                                }));
                            }

                            // Add new block request to queue.
                            pending_block_requests.push(peer_handle);
                        }
                    }
                }

                // event: timer ticks
                _ = ticker.tick() => {

                    // If we have not been connected to peers long enough,
                    // terminate.
                    let now = SystemTime::now();
                    if self.peers.is_empty() && last_peer_disconnect_time.and_then(|t| now.duration_since(t).ok()).is_some_and(|d| d > Duration::from_secs(10)) {
                        break;
                    }

                    // If the last response was ages ago, then the sync loop is
                    // not doing anything any more and it should be terminated.
                    // However, if there are messages on the channel that have
                    // not been read yet, read those first -- maybe they contain
                    // the blocks we are waiting for.
                    if now
                        .duration_since(most_recent_receipt.unwrap_or(now))
                        .ok()
                        .is_none_or(|timestamp| timestamp > ANY_RESPONSE_TIMEOUT)
                    && self.main_channel_receiver.is_empty() {
                        tracing::warn!("Most recent block was received a while ago; terminating sync loop.");
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

                    // If timeout, add those peers to queue of block requests.
                    pending_block_requests.sort();
                    for peer in timeouts {
                        tracing::warn!("{peer} peer timed out; sending new random block request.");
                        if !pending_block_requests.contains(&peer) {
                            pending_block_requests.push(peer);
                        }
                    }

                    // Flush queue of pending block requests.
                    self.request_random_blocks(&pending_block_requests).await;
                    pending_block_requests = vec![];

                    // There is a race condition in which the block-download
                    // finishes while an old successors subtask is running. In
                    // this case, that successors subtask will finish according
                    // to its outdated view of the available blocks. But since
                    // no new blocks come in, they will not trigger a new
                    // successors subtask. So we must trigger it through this
                    // backstop.
                    if maybe_successors_subtask.is_none() && self.download_state.is_complete() {
                        let moved_tip_height = self.tip_height;
                        let moved_download_state = self.download_state.clone();
                        let moved_sender = self.main_channel_sender.clone();
                        maybe_successors_subtask = Some(tokio::spawn(async move {
                            Self::process_successors_of_tip(moved_tip_height, moved_download_state, moved_sender).await
                        }));
                    }

                }
            }
        }

        // Tell main loop we are done, but with a success or error code.
        let return_code = if finished {
            SyncToMain::Finished
        } else {
            SyncToMain::Error
        };
        if let Err(e) = self.main_channel_sender.send(return_code).await {
            tracing::error!(
                "Failed to send message from sync loop to main loop that job is done: {e}."
            );
        }

        // Clean up the temp directory.
        self.download_state.clean_up().await;
    }

    /// Request random (but missing) blocks from the given peer.
    async fn request_random_blocks(&mut self, peer_handles: &[PeerHandle]) {
        if peer_handles.is_empty() {
            return;
        }

        tracing::debug!("sampling missing block heights ...");
        let mut block_requests = vec![];
        for peer_handle in peer_handles {
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

            block_requests.push(BlockRequest {
                peer_handle: *peer_handle,
                height,
            });

            // Yield in between height samplers.
            tokio::task::yield_now().await;
        }
        tracing::info!(
            "requesting blocks [{}] from peers",
            block_requests.iter().map(|br| br.height.value()).join(", ")
        );

        // Send a request to the peer for that block.
        // Use `try_send` here so that if the capacity is full, the message is
        // dropped and we can continue operations within this thread.
        if let Err(e) = self
            .main_channel_sender
            .try_send(SyncToMain::RequestBlocks(block_requests))
        {
            tracing::warn!("Could not send message from sync loop to main loop; error: {e}");
            tracing::warn!("Relying on timeout mechanism to retry in a short while.");
        }

        tracing::info!("sent blocks request");

        // Record timestamp of last request.
        let now = SystemTime::now();
        tracing::info!("modifying last request time to now");
        for peer_handle in peer_handles {
            self.peers
                .entry(*peer_handle)
                .and_modify(|e| e.last_request = Some(now));
        }
    }

    /// The tip-successors subtask.
    ///
    /// If we are sitting on blocks that immediately succeed the tip with no
    /// gaps, then send them all over to the main loop for processing. Do that
    /// until there are no more such blocks left.
    async fn process_successors_of_tip(
        current_tip_height: BlockHeight,
        download_state: RapidBlockDownload,
        channel_to_main: Sender<SyncToMain>,
    ) -> Result<SyncLoopReturnCode, SyncLoopError> {
        let mut tip_height = current_tip_height;
        while download_state.have_received(tip_height.next()) {
            // get successor block
            let successor = download_state
                .get_received_block(tip_height.next())
                .await.map_err(|e| {
                    tracing::error!("Could not get block from temp directory even though the block was received: {e}. Terminating sync mode.");
                    SyncLoopError::RapidBlockDownloadError(e)
                })?;

            // send to main
            channel_to_main
                .send(SyncToMain::TipSuccessor(Box::new(successor))).await.map_err(|e|{
                    tracing::warn!("Could not send block from sync loop to main loop: {e}. Terminating sync mode.");
                    SyncLoopError::SendError(e)
                })?;

            // delete the block after the main loop successfully received it
            if let Err(e) = download_state.delete_block(tip_height.next()).await {
                tracing::warn!("Could not delete block from temp directory even though the block was received: {e}. Not critical.");
            }

            // update tip height
            tip_height = tip_height.next();
        }

        // We processed everything we can. Are we finished?
        if download_state.is_complete() {
            Ok(SyncLoopReturnCode::Finished)
        } else {
            Ok(SyncLoopReturnCode::Continue { tip_height })
        }
    }
}

#[derive(Debug, Clone)]
enum SyncLoopReturnCode {
    Finished,
    Continue { tip_height: BlockHeight },
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
    use std::{net::Ipv6Addr, sync::Arc};

    use macro_rules_attr::apply;
    use rand::{rngs::StdRng, RngCore, SeedableRng};
    use tokio::sync::Mutex;

    use crate::{protocol::consensus::block::Block, tests::shared_tokio_runtime};

    use super::*;

    #[derive(Debug, Clone)]
    enum PeerControl {
        AddPeer(MockPeer),
        RemovePeer(PeerHandle),
    }

    struct MockMainLoop {
        peers: HashMap<PeerHandle, MockPeer>,
        main_to_sync_sender: Sender<MainToSync>,
        sync_to_main_receiver: Receiver<SyncToMain>,
        current_tip_height: BlockHeight,
        sync_target_height: BlockHeight,
        peer_control_receiver: Receiver<PeerControl>,
        peer_control_sender: Sender<PeerControl>,
        finished: bool,
        tip_tracker: Option<Arc<Mutex<BlockHeight>>>,
    }

    impl MockMainLoop {
        fn new(
            main_to_sync_sender: Sender<MainToSync>,
            sync_to_main_receiver: Receiver<SyncToMain>,
            current_tip_height: BlockHeight,
            sync_target_height: BlockHeight,
        ) -> Self {
            let (peer_control_sender, peer_control_receiver) = mpsc::channel::<PeerControl>(10);
            Self {
                peers: HashMap::default(),
                main_to_sync_sender,
                sync_to_main_receiver,
                current_tip_height,
                sync_target_height,
                finished: false,
                tip_tracker: None,
                peer_control_receiver,
                peer_control_sender,
            }
        }

        fn peer_control_sender(&self) -> Sender<PeerControl> {
            self.peer_control_sender.clone()
        }

        fn set_tip_tracker(&mut self, tip_tracker: Arc<Mutex<BlockHeight>>) {
            self.tip_tracker = Some(tip_tracker);
        }

        async fn connect(&mut self, peer: MockPeer) {
            tracing::debug!("adding peer");
            tracing::debug!(
                "note: channel capacity is at {}/{}",
                self.main_to_sync_sender.capacity(),
                self.main_to_sync_sender.max_capacity()
            );

            if let Err(e) = self
                .main_to_sync_sender
                .send(MainToSync::AddPeer(peer.handle()))
                .await
            {
                tracing::error!("Error sending AddPeer message to sync loop: {e} -- did the sync loop terminate?");
            }
            self.peers.insert(peer.handle(), peer);
        }

        async fn disconnect(&mut self, peer_handle: PeerHandle) {
            tracing::debug!("removing peer");
            tracing::debug!(
                "note: channel capacity is at {}/{}",
                self.main_to_sync_sender.capacity(),
                self.main_to_sync_sender.max_capacity()
            );

            if let Err(e) = self
                .main_to_sync_sender
                .send(MainToSync::RemovePeer(peer_handle))
                .await
            {
                tracing::error!("Error sending RemovePeer message to sync loop: {e} -- did the sync loop terminate");
            }
            self.peers.remove(&peer_handle);
        }

        fn sync_is_finished(&self) -> bool {
            self.finished
        }

        async fn run(&mut self) {
            loop {
                tokio::select! {
                    Some(message) = self.sync_to_main_receiver.recv() => {
                        tracing::debug!("mock main loop: got message from sync loop!");
                        match message {
                            SyncToMain::Finished => {
                                if self.current_tip_height == self.sync_target_height {
                                    self.finished = true;
                                }
                                else {
                                    tracing::warn!("Got Finished message from sync loop but we are not finished yet.");
                                }
                                break;
                            }
                            SyncToMain::TipSuccessor(block) => {
                                if block.header().height == self.current_tip_height.next() {
                                    self.current_tip_height = block.header().height;
                                    if let Some(tip_tracker) = &self.tip_tracker {
                                        *tip_tracker.lock().await = block.header().height;
                                    }
                                }
                            }
                            SyncToMain::RequestBlocks(block_requests) => {
                                tracing::debug!("mock main loop received request blocks message ...");
                                for block_request in block_requests {
                                    if let Some(peer) = self.peers.get_mut(&block_request.peer_handle.clone()) {
                                        if let Some(block) = peer.request(block_request.height).await {
                                            tracing::debug!("got block from peer; relaying to sync loop");
                                            tracing::debug!("note: channel capacity is at {}/{}", self.main_to_sync_sender.capacity(), self.main_to_sync_sender.max_capacity());
                                            if let Err(e) = self
                                                .main_to_sync_sender
                                                .try_send(MainToSync::ReceiveBlock {
                                                    peer_handle: block_request.peer_handle,
                                                    block: Box::new(block),
                                                })
                                            {
                                                tracing::warn!("error relaying block to sync loop: {e}");
                                            }
                                            tracing::debug!("done relaying");
                                        } else {
                                            tracing::debug!("no response from peer");
                                        }
                                    } else {
                                        tracing::warn!("no such peer -- was peer removed?");
                                    }
                                    tokio::task::yield_now().await;
                                }
                            }
                            SyncToMain::Error => {
                                tracing::error!("Error code from sync loop.");
                                break;
                            }
                        }
                        tracing::debug!("done processing message from sync loop");
                    }

                    Some(message) = self.peer_control_receiver.recv() => {
                        match message {
                            PeerControl::AddPeer(peer) => {
                                tracing::info!("adding peer {}", peer.handle());
                                self.connect(peer).await;
                            }
                            PeerControl::RemovePeer(handle) => {
                                tracing::info!("removing peer {}", handle);
                                self.disconnect(handle).await;
                            }
                        }
                    }
                }
            }
        }
    }

    #[derive(Debug, Clone)]
    enum MockPeer {
        Good(GoodPeer),
        Flaky(FlakyPeer),
    }

    impl MockPeer {
        async fn request(&mut self, block_height: BlockHeight) -> Option<Block> {
            match self {
                MockPeer::Good(good_peer) => good_peer.request(block_height).await,
                MockPeer::Flaky(flaky_peer) => flaky_peer.request(block_height).await,
            }
        }

        fn handle(&self) -> PeerHandle {
            match self {
                MockPeer::Good(good_peer) => good_peer.handle(),
                MockPeer::Flaky(flaky_peer) => flaky_peer.handle(),
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

    #[derive(Debug, Clone)]
    struct FlakyPeer {
        peer_handle: PeerHandle,
    }

    impl FlakyPeer {
        fn new() -> Self {
            Self {
                peer_handle: random_peer_handle(),
            }
        }
        async fn request(&mut self, block_height: BlockHeight) -> Option<Block> {
            if rng().random_bool(0.5_f64) {
                return None;
            }
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
            BlockHeight::from(current_tip_height.value() + rng.random_range(0..200));
        let (sync_loop, main_to_sync_sender, sync_to_main_receiver) =
            SyncLoop::new(current_tip_height, sync_target_height, false)
                .await
                .unwrap();
        let mut main_loop = MockMainLoop::new(
            main_to_sync_sender,
            sync_to_main_receiver,
            current_tip_height,
            sync_target_height,
        );

        main_loop.connect(MockPeer::Good(GoodPeer::new())).await;
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
            BlockHeight::from(current_tip_height.value() + rng.random_range(0..200));
        let (sync_loop, main_to_sync_sender, sync_to_main_receiver) =
            SyncLoop::new(current_tip_height, sync_target_height, false)
                .await
                .unwrap();
        let mut main_loop = MockMainLoop::new(
            main_to_sync_sender,
            sync_to_main_receiver,
            current_tip_height,
            sync_target_height,
        );

        main_loop.connect(MockPeer::Good(GoodPeer::new())).await;
        main_loop.connect(MockPeer::Good(GoodPeer::new())).await;
        main_loop.connect(MockPeer::Good(GoodPeer::new())).await;
        main_loop.connect(MockPeer::Good(GoodPeer::new())).await;
        main_loop.connect(MockPeer::Good(GoodPeer::new())).await;
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
    async fn can_sync_from_one_flaky_peer() {
        let mut rng = rng();
        tracing::info!("starting test ...");
        let current_tip_height = BlockHeight::from(u64::from(rng.next_u32()));
        let sync_target_height =
            BlockHeight::from(current_tip_height.value() + rng.random_range(0..200));
        let (sync_loop, main_to_sync_sender, sync_to_main_receiver) =
            SyncLoop::new(current_tip_height, sync_target_height, false)
                .await
                .unwrap();
        let mut main_loop = MockMainLoop::new(
            main_to_sync_sender,
            sync_to_main_receiver,
            current_tip_height,
            sync_target_height,
        );

        main_loop.connect(MockPeer::Flaky(FlakyPeer::new())).await;
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
    async fn can_sync_from_many_flaky_peers() {
        let mut rng = rng();
        tracing::info!("starting test ...");

        let current_tip_height = BlockHeight::from(u64::from(rng.next_u32()));
        let sync_target_height =
            BlockHeight::from(current_tip_height.value() + rng.random_range(0..100));
        let (sync_loop, main_to_sync_sender, sync_to_main_receiver) =
            SyncLoop::new(current_tip_height, sync_target_height, false)
                .await
                .unwrap();
        let mut main_loop = MockMainLoop::new(
            main_to_sync_sender,
            sync_to_main_receiver,
            current_tip_height,
            sync_target_height,
        );

        main_loop.connect(MockPeer::Flaky(FlakyPeer::new())).await;
        main_loop.connect(MockPeer::Flaky(FlakyPeer::new())).await;
        main_loop.connect(MockPeer::Flaky(FlakyPeer::new())).await;
        main_loop.connect(MockPeer::Flaky(FlakyPeer::new())).await;
        main_loop.connect(MockPeer::Flaky(FlakyPeer::new())).await;
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
    async fn can_resume_sync_from_saved_state() {
        let mut rng = rng();
        tracing::info!("starting test ...");

        let mut current_tip_height = BlockHeight::from(u64::from(rng.next_u32()));
        let sync_target_height =
            BlockHeight::from(current_tip_height.value() + rng.random_range(0..200));

        // set up first attempt
        let (sync_loop_a, main_to_sync_sender_a, sync_to_main_receiver_a) =
            SyncLoop::new(current_tip_height, sync_target_height, false)
                .await
                .unwrap();
        let mut main_loop = MockMainLoop::new(
            main_to_sync_sender_a,
            sync_to_main_receiver_a,
            current_tip_height,
            sync_target_height,
        );

        // keep track of tip height
        let tip_tracker = Arc::new(Mutex::new(current_tip_height));
        main_loop.set_tip_tracker(tip_tracker.clone());

        // run
        main_loop.connect(MockPeer::Flaky(FlakyPeer::new())).await;
        main_loop.connect(MockPeer::Flaky(FlakyPeer::new())).await;
        let sync_loop_handle = sync_loop_a.start();
        let main_loop_handle = tokio::spawn(async move {
            main_loop.run().await;
        });

        // after one second, interrupt
        tokio::time::sleep(Duration::from_secs(1)).await;
        sync_loop_handle.abort();
        main_loop_handle.abort();

        // start second attempt
        // Reuse tip height from previous attempt, with one block margin due to
        // race conditions.
        current_tip_height = *tip_tracker.lock().await;
        let (sync_loop_b, main_to_sync_sender_b, sync_to_main_receiver_b) =
            SyncLoop::new(current_tip_height, sync_target_height, true)
                .await
                .unwrap();
        let mut main_loop_b = MockMainLoop::new(
            main_to_sync_sender_b,
            sync_to_main_receiver_b,
            current_tip_height,
            sync_target_height,
        );

        assert!(
            !main_loop_b.sync_is_finished(),
            "current tip height {} versus sync target height {}",
            main_loop_b.current_tip_height,
            main_loop_b.sync_target_height
        );

        // run
        main_loop_b.connect(MockPeer::Flaky(FlakyPeer::new())).await;
        main_loop_b.connect(MockPeer::Flaky(FlakyPeer::new())).await;
        let _sync_loop_handle = sync_loop_b.start();
        main_loop_b.run().await;

        assert!(
            main_loop_b.sync_is_finished(),
            "current tip height {} versus sync target height {}",
            main_loop_b.current_tip_height,
            main_loop_b.sync_target_height
        );
    }

    #[tracing_test::traced_test]
    #[apply(shared_tokio_runtime)]
    async fn can_sync_from_dynamic_peer_set() {
        async fn change_peer_set(
            peer_set: &mut Vec<PeerHandle>,
            peer_control_sender: Sender<PeerControl>,
            rng: &mut StdRng,
        ) {
            if peer_set.is_empty() || rng.random_bool(0.5_f64) {
                let new_peer = FlakyPeer::new();
                let handle = new_peer.handle();
                peer_set.push(handle);
                peer_control_sender
                    .send(PeerControl::AddPeer(MockPeer::Flaky(new_peer)))
                    .await
                    .unwrap();
            } else {
                let index = rng.random_range(0..peer_set.len());
                let handle = peer_set.swap_remove(index);
                peer_control_sender
                    .send(PeerControl::RemovePeer(handle))
                    .await
                    .unwrap();
            }
        }

        let mut rng = StdRng::seed_from_u64(rng().next_u64());
        tracing::info!("starting test ...");

        let current_tip_height = BlockHeight::from(u64::from(rng.next_u32()));
        let sync_target_height =
            BlockHeight::from(current_tip_height.value() + rng.random_range(0..100));
        let (sync_loop, main_to_sync_sender, sync_to_main_receiver) =
            SyncLoop::new(current_tip_height, sync_target_height, false)
                .await
                .unwrap();
        let mut main_loop = MockMainLoop::new(
            main_to_sync_sender,
            sync_to_main_receiver,
            current_tip_height,
            sync_target_height,
        );

        let mut peer_set = vec![];
        for _ in 0..5 {
            let peer = FlakyPeer::new();
            peer_set.push(peer.handle());
            main_loop.connect(MockPeer::Flaky(peer)).await;
        }

        let _sync_loop_handle = sync_loop.start();
        let moved_peer_control_sender = main_loop.peer_control_sender();
        let peer_set_changer_handle = tokio::spawn(async move {
            for _ in 0..100 {
                tokio::time::sleep(Duration::from_millis(500)).await;
                change_peer_set(&mut peer_set, moved_peer_control_sender.clone(), &mut rng).await;
            }
        });
        main_loop.run().await;
        peer_set_changer_handle.abort();
        assert!(
            main_loop.sync_is_finished(),
            "current tip height {} versus sync target height {}",
            main_loop.current_tip_height,
            main_loop.sync_target_height
        );
    }

    #[tracing_test::traced_test]
    #[apply(shared_tokio_runtime)]
    async fn can_sync_with_moving_target() {}

    #[tracing_test::traced_test]
    #[apply(shared_tokio_runtime)]
    async fn can_sync_from_syncing_peers() {}
}
