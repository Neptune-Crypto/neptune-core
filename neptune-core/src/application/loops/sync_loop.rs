use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;

use itertools::Itertools;
use rand::rng;
use rand::Rng;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Receiver;
use tokio::sync::mpsc::Sender;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::interval;

use crate::api::export::BlockHeight;
use crate::application::loops::sync_loop::block_validator::BlockValidator;
use crate::application::loops::sync_loop::channel::BlockRequest;
use crate::application::loops::sync_loop::channel::MainToSync;
use crate::application::loops::sync_loop::channel::SuccessorsToSync;
use crate::application::loops::sync_loop::channel::SyncToMain;
use crate::application::loops::sync_loop::rapid_block_download::RapidBlockDownload;
use crate::application::loops::sync_loop::rapid_block_download::RapidBlockDownloadError;
use crate::application::loops::sync_loop::sync_progress::SyncProgress;
use crate::application::loops::sync_loop::synchronization_bit_mask::SynchronizationBitMask;
use crate::protocol::consensus::block::Block;

mod block_validator;
pub(crate) mod channel;
pub(crate) mod handle;
pub(crate) mod rapid_block_download;
pub mod sync_progress;
pub(crate) mod synchronization_bit_mask;

pub(crate) const SYNC_LOOP_CHANNEL_CAPACITY: usize = 10;

/// After this long without a response from a given peer, that peer will be sent
/// another block request.
#[cfg(not(test))]
const PEER_RESPONSE_REMINDER_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(test)]
const PEER_RESPONSE_REMINDER_TIMEOUT: Duration = Duration::from_millis(1);

/// After this long without a response from a peer, that peer will be punished.
const PEER_RESPONSE_PUNISHMENT_TIMEOUT: Duration = Duration::from_secs(10);

/// Time between successive ticks of the event loop's internal clock.
const TICK_PERIOD: Duration = Duration::from_micros(100);

type PeerHandle = SocketAddr;

#[derive(Debug, Clone, Default)]
pub(crate) struct PeerSyncState {
    num_blocks_contributed: usize,

    /// None if peer is synced. Some(bitmask) if peer is syncing.
    coverage: Option<SynchronizationBitMask>,

    /// Timestamp of the last block request sent by this sync loop to them.
    last_request: Option<SystemTime>,

    /// Timestamp of last punishment.
    last_punishment: Option<SystemTime>,

    /// Timestamp of the last message seen from them.
    last_response: Option<SystemTime>,
}

/// Holds state for the synchronization event loop.
#[derive(Debug)]
pub(crate) struct SyncLoop {
    tip: Block,
    download_state: RapidBlockDownload,
    peers: Arc<Mutex<HashMap<PeerHandle, PeerSyncState>>>,
    main_channel_sender: Sender<SyncToMain>,
    main_channel_receiver: Receiver<MainToSync>,

    block_validator: BlockValidator,
}

impl SyncLoop {
    async fn new(
        genesis_block: Block,
        target_height: BlockHeight,
        resume_if_possible: bool,
        block_validator: BlockValidator,
    ) -> Result<(Self, Sender<MainToSync>, Receiver<SyncToMain>), RapidBlockDownloadError> {
        let mut download_state = RapidBlockDownload::new(target_height, resume_if_possible).await?;
        download_state.fast_forward(genesis_block.header().height);
        let (main_to_sync_sender, main_to_sync_receiver) =
            mpsc::channel::<MainToSync>(SYNC_LOOP_CHANNEL_CAPACITY);
        let (sync_to_main_sender, sync_to_main_receiver) =
            mpsc::channel::<SyncToMain>(SYNC_LOOP_CHANNEL_CAPACITY);
        Ok((
            Self {
                tip: genesis_block,
                download_state,
                peers: Arc::new(Mutex::new(HashMap::new())),
                main_channel_sender: sync_to_main_sender,
                main_channel_receiver: main_to_sync_receiver,
                block_validator,
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
        let mut finished_downloading = false;
        let mut finished_processing = false;

        // Create an interval timer, triggering a tick event regularly.
        let mut ticker = interval(TICK_PERIOD);

        // The tip-successors subtask sends tip-successors to the main loop one
        // by one. Its return value comes to the sync loop over this channel.
        let mut maybe_successors_subtask: Option<JoinHandle<()>> = None;
        let (successors_sender, mut successors_receiver) = mpsc::channel(1);

        // Track the time of disconnect of the last peer.
        let mut last_peer_disconnect_time = None;

        // Collect the block requests that are going to be sent out in good
        // order; *i.e.*, without time-outs.
        let mut pending_block_requests = vec![];

        // Process events as they come in.
        loop {
            tokio::select! {

                // event: successors subtask finished
                Some(successor_task_result) = successors_receiver.recv() => {
                    match successor_task_result {
                        SuccessorsToSync::Finished{ new_tip } => {
                            tracing::debug!("Sync loop got return value from successors task: finished! New tip height: {}", new_tip.header().height);

                            self.tip = new_tip;

                            // The successors subtask claims it is finished, but
                            // it can only support this claim with an outdated
                            // view of the download state. In the mean time,
                            // a new block may have come in, possibly still in
                            // still in the channel but not read yet. So double-
                            // check the download state and channel, and start a
                            // new run of the subtask if necessary.
                            if self.main_channel_receiver.is_empty() && self.download_state.is_complete() && self.download_state.target() == self.tip.header().height {
                                finished_processing = true;
                                break;
                            }
                        }
                        SuccessorsToSync::Continue{ new_tip } => {
                            tracing::debug!("Sync loop got return value from successors task: continue ... New tip height: {}", new_tip.header().height);

                            self.tip = new_tip;
                        }
                        SuccessorsToSync::RapidBlockDownloadError => {
                            tracing::error!("Rapid block download error while sending tip-successors to main loop. Terminating sync loop.");
                            break;
                        }
                        SuccessorsToSync::SendError => {
                            tracing::error!("Could not send tip-successor block to main loop. Terminating sync loop.");
                            break;
                        }
                        SuccessorsToSync::BlockValidationError => {
                            tracing::error!("Block validation error occurred during syncing. Possible cause: a reorg happened while syncing. Terminating sync loop.");
                        }
                    }

                    // Start a new successors subtask, but only if it makes
                    // sense. Specifically, if we have the next tip successor,
                    // start the task. Otherwise, we wait until that block comes
                    // in and start it there.
                    if self.download_state.coverage().contains(self.tip.header().height.next().value()) {
                        tracing::debug!("Starting new successors subtask task again ...");
                        let moved_tip = self.tip.clone();
                        let moved_download_state = self.download_state.clone();
                        let moved_main_channel_sender = self.main_channel_sender.clone();
                        let moved_return_sender = successors_sender.clone();
                        maybe_successors_subtask = Some(tokio::spawn(async move {
                            Self::process_successors_of_tip(moved_tip, moved_download_state, moved_main_channel_sender, moved_return_sender, self.block_validator).await
                        }));
                    } else {
                        maybe_successors_subtask = None;
                    }
                }

                // event: message from sync loop
                Some(message_from_main) = self.main_channel_receiver.recv() => {
                    match message_from_main {
                        MainToSync::Abort => {
                            tracing::info!("Shutting down sync loop now.");
                            if let Some(running_task) = maybe_successors_subtask {
                                running_task.abort();
                            }
                            return;
                        }
                        MainToSync::AddPeer(peer_handle) => {
                            tracing::debug!("Sync loop got message from main: add peer");

                            self.peers.lock().await.insert(peer_handle, PeerSyncState::default());

                            // Add new block request to queue, if we are still
                            // downloading.
                            if !finished_downloading {
                                pending_block_requests.push(peer_handle);
                            }
                        }
                        MainToSync::RemovePeer(peer_handle) => {
                            tracing::debug!("Sync loop got message from main: remove peer");

                            self.peers.lock().await.remove(&peer_handle);
                            last_peer_disconnect_time = Some(SystemTime::now());
                        }
                        MainToSync::ReceiveBlock { peer_handle, block } => {
                            tracing::info!(
                                "Sync loop: receiving block {} out of [{}:{}) ...",
                                block.header().height,
                                self.download_state.coverage().lower_bound,
                                self.download_state.coverage().upper_bound,
                            );

                            // Store block and update download state.
                            tracing::debug!("storing block ...");
                            if let Err(e) = self.download_state.receive_block(&block).await
                            {
                                tracing::warn!(
                                    "Could not process received block {:x} of height {}: {}",
                                    block.hash(), block.header().height, e
                                );
                                continue;
                            }

                            // Track last seen state.
                            tracing::debug!("tracking state ...");
                            let now = SystemTime::now();
                            self.peers.lock().await.entry(peer_handle).and_modify(|e|{
                                e.last_response = Some(now);
                                e.num_blocks_contributed += 1;
                            });

                            // Update tip to available successors.
                            if maybe_successors_subtask.is_none() && block.header().height == self.tip.header().height.next() {
                                tracing::debug!("Starting new successors subtask in response to received block ...");
                                let moved_tip = self.tip.clone();
                                let moved_download_state = self.download_state.clone();
                                let moved_main_channel_sender = self.main_channel_sender.clone();
                                let moved_return_channel_sender = successors_sender.clone();
                                maybe_successors_subtask = Some(tokio::spawn(async move {
                                    Self::process_successors_of_tip(
                                        moved_tip,
                                        moved_download_state,
                                        moved_main_channel_sender,
                                        moved_return_channel_sender,
                                        self.block_validator
                                    ).await
                                }));
                            }

                            // If we are done downloading, transition to
                            // finished-downloading state. Otherwise, add a
                            // block request to the queue.
                            if self.download_state.is_complete() {
                                finished_downloading = true;
                            } else {
                                pending_block_requests.push(peer_handle);
                            }
                        }
                        MainToSync::ExtendChain(block) => {
                            tracing::debug!("Sync loop: extending chain to new target height {}", block.header().height);
                            if let Err(e) = self.download_state.extend_chain(&block).await {
                                tracing::error!(
                                    "Sync loop: could not extend chain of download state with new block of height {} and digest {:x}; got error: {e}",
                                    block.header().height, block.hash()
                                );
                                continue;
                            }
                            assert_eq!(self.download_state.target(), block.header().height);

                            // In the special case that the incoming target
                            // block is one ahead of the tip (the block height
                            // we already synchronized to), process it directly,
                            // without going through the tip-successors subtask.
                            // Save valuable setup-time.
                            if self.tip.header().height.next() == block.header().height {
                                tracing::debug!("chain extension is one ahead of current tip; sending directly to main loop.");
                                if !Self::ensure_send_tip_successor(&self.main_channel_sender, *block.to_owned()).await {
                                    tracing::error!("Could not send tip-successor to main loop. Terminating sync loop.");
                                    break;
                                }

                                self.tip = *block;

                                if self.main_channel_receiver.is_empty() {
                                    finished_processing = true;
                                    break;
                                }
                            }
                        }
                        MainToSync::SyncCoverage{peer_handle, coverage } => {
                            tracing::debug!("sync loop: got sync coverage message from peer via main");
                            // Record peer's status.
                            {
                                let mut peers_lock_mut = self.peers.lock().await;
                                let Some(peer) = peers_lock_mut.get_mut(&peer_handle) else {
                                    tracing::error!("Inconsistent peer dictionary in sync loop: peer {peer_handle} not present.");
                                    continue;
                                };

                                peer.last_response = Some(SystemTime::now());
                                peer.coverage = Some(coverage);
                            }

                            // If there are still blocks outstanding, add a
                            // block request to the queue.
                            if !self.download_state.is_complete() {
                                pending_block_requests.push(peer_handle);
                            }
                        }
                        MainToSync::Status => {
                            tracing::debug!("sync loop received status request, computing ...");
                            let total_span = self.download_state.target().next().value();
                            let num_blocks_processed = self.tip.header().height.value();

                            // Calculating the proportion of blocks covered is
                            // fast but not fast enough. So clone all the
                            // necessary information and hand control off to
                            // a new task that handles the computation and the
                            // return message. This way, control returns to the
                            // loop.
                            let moved_coverage = self.download_state.coverage();
                            let moved_main_channel_sender = self.main_channel_sender.clone();
                            let _jh = tokio::task::spawn(async move {
                                    let num_blocks_downloaded_but_not_processed = moved_coverage.pop_count();
                                    let total_num_blocks_downloaded = num_blocks_processed + num_blocks_downloaded_but_not_processed;
                                    tracing::debug!(
                                        "Assembling new SyncProgress object with total span {total_span}, \
                                        {num_blocks_downloaded_but_not_processed} blocks downloaded (but not \
                                        processed)."
                                    );
                                    let status = SyncProgress::new(total_span).with_num_blocks_downloaded(total_num_blocks_downloaded);
                                    let max_num_tries = 20;
                                    let mut counter = 1;
                                    loop {
                                        if let Err(e) = moved_main_channel_sender.try_send(SyncToMain::Status(status)) {
                                            tracing::warn!("Sync loop: failed to send Status({}) message to main loop: {e}.", status);
                                            tracing::debug!("Channel capacity is at {}/{}", moved_main_channel_sender.capacity(), moved_main_channel_sender.max_capacity());
                                            tokio::time::sleep(Duration::from_millis(counter * 50)).await;
                                            counter += 1;
                                        } else {
                                            break;
                                        }

                                        if counter == max_num_tries {
                                            break;
                                        }
                                    }
                                });
                        }
                        MainToSync::TryFetchBlock{ peer_handle, height } => {
                            tracing::debug!("sync loop received try-fetch-block message from peer {peer_handle} for block {height}");

                            // Test if the requested block height lives in the
                            // synchronization bit mask.
                            let have_block = self.download_state.coverage().contains(height.value());

                            // If it is absent, then the peer probably does not
                            // know our current synchronization bit mask. So
                            // send it to them.
                            if !have_block {
                                if let Err(e) = self.main_channel_sender.try_send(
                                    SyncToMain::Coverage {
                                        coverage: self.download_state.coverage(),
                                        peer_handle
                                    }) {
                                    tracing::error!("Failed to send coverage to main loop: {e}.");
                                }
                            }
                            else {
                                // Go fetch the block and send it to the peer.
                                // But do this asynchronously so we can return
                                // control to the loop ASAP.
                                let moved_download_state = self.download_state.clone();
                                let moved_main_channel_sender = self.main_channel_sender.clone();
                                let _ = tokio::task::spawn(
                                    Self::fetch_and_send_block(moved_main_channel_sender, moved_download_state, peer_handle, height)
                                ).await;
                            }
                        }
                        MainToSync::FastForward{ new_tip } => {
                            tracing::debug!("sync loop received fast-forward message; fast-forwarding to block {}", new_tip.header().height);

                            if new_tip.header().height > self.tip.header().height {
                                self.download_state.fast_forward(new_tip.header().height);
                                self.tip = *new_tip;
                            }
                        }
                    }
                }

                // event: timer ticks
                _ = ticker.tick() => {

                    // If we are finished and there are no messages waiting to
                    // be read, then we can exit.
                    if finished_processing && self.main_channel_receiver.is_empty() {
                        tracing::info!("Sync loop is finished, exiting loop.");
                        break;
                    } else if finished_processing {
                        tracing::info!(
                            "Sync loop finished downloading and processing, \
                            but there are {} unread messages on the channel; \
                            flushing queue first.",
                            self.main_channel_receiver.len()
                        );
                        continue;
                    }

                    // If we have not been connected to peers long enough,
                    // terminate.
                    let now = SystemTime::now();
                    let connected_to_peers = !self.peers.lock().await.is_empty();
                    let last_heard_too_long_ago = last_peer_disconnect_time
                        .and_then(|t| now.duration_since(t).ok())
                        .is_some_and(|d| d > Duration::from_secs(10));
                    if !connected_to_peers
                    && last_heard_too_long_ago
                    && self.main_channel_receiver.is_empty()
                    && maybe_successors_subtask.is_none()
                    && !finished_downloading {
                        tracing::warn!("Sync loop not connected to peers for too long; terminating.");
                        break;
                    }

                    // If we have finished downloading but not finished
                    // processing, then ensure that a tip-successors subtask is
                    // running.
                    if finished_downloading && !finished_processing && maybe_successors_subtask.is_none() {
                        tracing::debug!("Starting new successors subtask task again ...");
                        let moved_tip = self.tip.clone();
                        let moved_download_state = self.download_state.clone();
                        let moved_main_channel_sender = self.main_channel_sender.clone();
                        let moved_return_sender = successors_sender.clone();
                        maybe_successors_subtask = Some(tokio::spawn(async move {
                            Self::process_successors_of_tip(moved_tip, moved_download_state, moved_main_channel_sender, moved_return_sender, self.block_validator).await
                        }));
                    }

                    let peers_clone = self.peers.lock().await.clone();
                    if !finished_downloading {
                        // Check all peers for timeouts.
                        let mut reminders = vec![];
                        let mut punishments = vec![];
                        for (peer_handle, peer_state) in peers_clone {
                            if peer_state
                                .last_request
                                .and_then(|timestamp| now.duration_since(timestamp).ok())
                                .is_none_or(|duration| duration > PEER_RESPONSE_REMINDER_TIMEOUT) {
                                reminders.push(peer_handle);
                            }

                            if peer_state.last_response
                                .and_then(|timestamp| now.duration_since(timestamp).ok())
                                .is_none_or(|duration| duration > PEER_RESPONSE_PUNISHMENT_TIMEOUT)
                                && peer_state.last_punishment.and_then(|timestamp| now.duration_since(timestamp).ok())
                                .is_none_or(|duration| duration > PEER_RESPONSE_PUNISHMENT_TIMEOUT) {
                                punishments.push(peer_handle);
                            }
                        }

                        // If there are timeouts warranting reminders, add those
                        // peers to queue of block requests.
                        pending_block_requests.sort();
                        for peer in reminders {
                            tracing::warn!("Sync loop: peer {peer} timed out; sending new random block request.");
                            if !pending_block_requests.contains(&peer) {
                                pending_block_requests.push(peer);
                            }
                        }

                        // Flush queue of pending block requests. But do this in
                        // another task so control passes back to the loop.
                        if !pending_block_requests.is_empty() {
                            tracing::debug!("sync loop is starting a new random blocks request");
                            let moved_pending_block_requests = pending_block_requests.clone();
                            let moved_coverage = self.download_state.coverage();
                            let moved_peers = self.peers.clone();
                            let moved_channel_to_main = self.main_channel_sender.clone();
                            if let Err(e) = tokio::task::spawn(
                                Self::request_random_blocks(moved_coverage, moved_peers, moved_channel_to_main, moved_pending_block_requests)
                            ).await {
                                tracing::error!("Failed to request random blocks from peers: {e}.");
                            }

                            pending_block_requests = vec![];
                        }

                        // If there are timeouts warranting punishments, tell
                        // the main loop to punish the perpetrators.
                        if !punishments.is_empty() {
                            tracing::debug!("sync loop is punishing ...");
                            if let Err(e) = self.main_channel_sender.try_send(SyncToMain::Punish(punishments.clone())) {
                                tracing::warn!("Failed to send punish message to main loop: {e}.");
                            }

                            // If the main loop is busy and the channel full,
                            // don't overload it. So wait the regular timeout
                            // period before trying again.
                            let mut peers_mut = self.peers.lock().await;
                            for transgressor in punishments {
                                peers_mut.entry(transgressor).and_modify(|peer| {peer.last_punishment = Some(now);});
                            }
                        }
                    }

                }
            }
        }

        // Determine which return code is appropriate.
        let return_code = if finished_processing {
            tracing::info!("Sync loop is finished downloading and finished processing.");
            SyncToMain::Finished(self.download_state.target())
        } else {
            if !finished_downloading {
                tracing::warn!("Sync loop did not finish downloading.");
            }
            tracing::warn!("Sync loop did not finish processing.");
            SyncToMain::Error
        };

        // Tell main loop we are done. Ensure delivery.
        let mut send_success = false;
        let mut send_attempt_counter = 0;
        let max_send_attempts = 1000;
        loop {
            let send_result = self.main_channel_sender.try_send(return_code.clone());
            if send_result.is_ok() {
                send_success = true;
                break;
            }
            send_attempt_counter += 1;
            if send_attempt_counter >= max_send_attempts {
                break;
            }
            tracing::warn!("Sync loop: could not send return code to main loop. Is it busy?");
            tokio::time::sleep(Duration::from_millis(10 * send_attempt_counter)).await;
        }
        if !send_success {
            tracing::error!("Sync loop: failed to send message to main loop that job is done.");
        }

        // Clean up the temp directory.
        if let Err(error_directories) = self.download_state.clean_up().await {
            for error_directory in error_directories {
                tracing::error!(
                    "Failed to delete temporary directory '{}'. You must delete this directory manually in order for \
                    future syncs to avoid starting from a corrupt state.",
                    error_directory.display()
                );
            }
        }
    }

    async fn fetch_and_send_block(
        main_channel_sender: Sender<SyncToMain>,
        download_state: RapidBlockDownload,
        peer_handle: PeerHandle,
        height: BlockHeight,
    ) {
        let block = match download_state.get_received_block(height).await {
            Ok(b) => b,
            Err(e) => {
                tracing::error!("Failed to read block from temp directory: {e}.");
                return;
            }
        };

        if let Err(e) = main_channel_sender
            .send(SyncToMain::SyncBlock {
                block: Box::new(block),
                peer_handle,
            })
            .await
        {
            tracing::error!("Could not send sync block to main loop: {e}.");
        }
    }

    /// Sample one appropriate missing block height for each peer.
    fn sample_heights(
        peers: HashMap<PeerHandle, PeerSyncState>,
        own_coverage: SynchronizationBitMask,
        peer_handles: Vec<PeerHandle>,
    ) -> Vec<BlockRequest> {
        let mut block_requests = vec![];
        for peer_handle in peer_handles {
            let Some(peer) = peers.get(&peer_handle) else {
                // Peer disconnected in between being added to the queue and
                // this function being executed. No cause for concern. And also:
                // nothing we can do.
                tracing::warn!("Sync loop: cannot use peer {peer_handle} for syncing; ignoring.");
                continue;
            };

            // Otherwise, compute the distribution of blocks to sample from.
            let mut distribution = own_coverage.clone();
            if let Some(peer_coverage) = &peer.coverage {
                distribution = distribution.reconcile(peer_coverage);
            }

            // Sample and collect block request, if possible.
            let now = SystemTime::now();
            let distribution_is_complete = distribution.is_complete();
            let poking_time = peer
                .last_response
                .and_then(|timestamp| now.duration_since(timestamp).ok())
                .is_none_or(|silence_time| silence_time > Duration::from_secs(5));
            let height = match (distribution_is_complete, poking_time) {
                (false, _) => {
                    // Peer has blocks we do not have.
                    distribution.sample(rng().random())
                }
                (true, true) => {
                    // Peer does not have blocks we do not have, but then it is
                    // a long time since we heard from them so let us poke them
                    // again.
                    tracing::debug!("Peer had no blocks we want, but asking anyway.");
                    own_coverage.sample(rng().random())
                }
                (true, false) => {
                    tracing::debug!("Peer has no blocks we want.");
                    continue;
                }
            };

            block_requests.push(BlockRequest {
                peer_handle,
                height: BlockHeight::from(height),
            });
        }
        block_requests
    }

    /// Request random (but missing) blocks from the given peer.
    async fn request_random_blocks(
        coverage: SynchronizationBitMask,
        peers: Arc<Mutex<HashMap<PeerHandle, PeerSyncState>>>,
        channel_to_sender: Sender<SyncToMain>,
        peer_handles: Vec<PeerHandle>,
    ) {
        if peer_handles.is_empty() {
            return;
        }

        // If we are finished already, abort.
        if coverage.is_complete() {
            tracing::error!(
                "Cannot request random block from peer because all blocks are in already."
            );
            return;
        }

        tracing::debug!("Sync loop: sampling missing block heights ...");
        let moved_peers = peers.lock().await.clone();
        let moved_peer_handles = peer_handles.to_vec();
        let Ok(block_requests) = tokio::task::spawn_blocking(move || {
            Self::sample_heights(moved_peers, coverage, moved_peer_handles)
        })
        .await
        else {
            tracing::error!("Could not sample block heights due tokio/concurrency error.");
            return;
        };

        if block_requests.is_empty() {
            tracing::warn!("Sync loop: no viable blocks to request from peers.");
            return;
        }

        tracing::info!(
            "Sync loop: requesting blocks [{}] from peers",
            block_requests.iter().map(|br| br.height.value()).join(", ")
        );

        // Send a request to the peer for that block.
        let max_num_send_attempts = 100;
        let mut send_attempt_counter = 0;
        loop {
            if channel_to_sender
                .try_send(SyncToMain::RequestBlocks(block_requests.clone()))
                .is_err()
            {
                tokio::time::sleep(Duration::from_millis(send_attempt_counter)).await;
                send_attempt_counter += 1;
            } else {
                break;
            }

            if send_attempt_counter == max_num_send_attempts {
                break;
            }
        }
        let send_succeeded = send_attempt_counter != max_num_send_attempts;
        if !send_succeeded {
            tracing::warn!(
                "Sync loop: could not send message to main loop even after {max_num_send_attempts} attempts."
            );
            tracing::warn!("Relying on timeout mechanism to retry in a short while.");
            return;
        }

        // Else, send succeeded.
        // Record timestamp of last request.
        let now = SystemTime::now();
        let mut peers_lock_mut = peers.lock().await;
        for peer_handle in peer_handles {
            peers_lock_mut
                .entry(peer_handle)
                .and_modify(|e| e.last_request = Some(now));
        }
    }

    /// Send a tip-successor block to the main channel, and ensure it is
    /// received. If the channel is out-of-capacity, report and keep retrying.
    /// Return false if 100 tries fail; true otherwise.
    async fn ensure_send_tip_successor(
        channel_to_main: &Sender<SyncToMain>,
        successor: Block,
    ) -> bool {
        // send to main
        // important payload, so report on delays
        let max = 1000;
        for i in 1..=max {
            match channel_to_main.try_send(SyncToMain::TipSuccessor(Box::new(successor.clone()))) {
                Ok(_) => {
                    if i > 1 {
                        tracing::debug!("succeeded sending tip-successorblock to main");
                    }
                    return true;
                }
                Err(_) => {
                    tracing::warn!(
                        "Sync loop: could not send tip-successor block to main \
                        loop; main loop appears busy ..."
                    );
                    tokio::time::sleep(Duration::from_millis(50 * i)).await;
                }
            }
        }

        false
    }

    /// The tip-successors subtask.
    ///
    /// If we are sitting on blocks that immediately succeed the tip with no
    /// gaps, then send them all over to the main loop for processing. Do that
    /// until there are no more such blocks left.
    ///
    /// This task must be asynchronous because it can take a while and we do not
    /// want it to halt iteration of the event loop.
    async fn process_successors_of_tip(
        current_tip: Block,
        download_state: RapidBlockDownload,
        channel_to_main: Sender<SyncToMain>,
        return_channel: Sender<SuccessorsToSync>,
        block_validator: BlockValidator,
    ) {
        let mut tip = current_tip;
        while download_state.have_received(tip.header().height.next()) {
            // get successor block
            let Ok(successor) = download_state
                .get_received_block(tip.header().height.next())
                .await
            else {
                tracing::error!(
                    "Sync loop: could not get block from temp directory even \
                    though the block was received. Terminating sync mode."
                );
                let _ = return_channel
                    .send(SuccessorsToSync::RapidBlockDownloadError)
                    .await;
                return;
            };

            // validate
            if !block_validator.verify(&successor, &tip).await {
                let _ = return_channel
                    .send(SuccessorsToSync::BlockValidationError)
                    .await;
                return;
            }

            // send to main
            if !Self::ensure_send_tip_successor(&channel_to_main, successor.clone()).await {
                tracing::error!(
                    "Sync loop: failed to send tip-successor block to main \
                    loop. Aborting sync loop."
                );
                let _ = return_channel.send(SuccessorsToSync::SendError).await;
                return;
            }

            // delete the block after the main loop successfully received it
            if let Err(e) = download_state
                .delete_block(tip.header().height.next())
                .await
            {
                tracing::warn!(
                    "Sync loop: could not delete block from temp directory \
                    even though the block was received: {e}. Not critical."
                );
            }

            // update tip
            tip = successor;
        }

        // We processed everything we can. Are we finished?
        if download_state.is_complete() {
            let _ = return_channel
                .send(SuccessorsToSync::Finished { new_tip: tip })
                .await;
        } else {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let _ = return_channel
                .send(SuccessorsToSync::Continue { new_tip: tip })
                .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;
    use std::sync::Arc;

    use macro_rules_attr::apply;
    use rand::rngs::StdRng;
    use rand::RngCore;
    use rand::SeedableRng;
    use tokio::sync::Mutex;

    use crate::api::export::Network;
    use crate::application::loops::sync_loop::handle::SyncLoopHandle;
    use crate::protocol::consensus::block::Block;
    use crate::tests::shared_tokio_runtime;

    use super::*;

    /// A channel for informing the [MockMainLoop] about peer (dis)connections.
    #[derive(Debug, Clone)]
    enum PeerControl {
        AddPeer(MockPeer),
        RemovePeer(PeerHandle),
    }

    /// A channel for informing the [MockMainLoop] about new blocks on the
    /// network.
    #[derive(Debug, Clone)]
    enum BlockchainTipControl {
        NewBlock(Block),
    }

    struct MockMainLoop {
        peers: HashMap<PeerHandle, MockPeer>,
        pub(crate) sync_loop_handle: SyncLoopHandle,
        current_tip_height: BlockHeight,
        sync_target_height: BlockHeight,
        peer_control_receiver: Receiver<PeerControl>,
        peer_control_sender: Sender<PeerControl>,
        finished: bool,
        tip_tracker: Option<Arc<Mutex<BlockHeight>>>,
        blockchain_tip_control_receiver: Receiver<BlockchainTipControl>,
        blockchain_tip_control_sender: Sender<BlockchainTipControl>,
    }

    impl MockMainLoop {
        async fn new(current_tip: Block, sync_target_height: BlockHeight) -> Self {
            let current_tip_height = current_tip.header().height;
            tracing::debug!(
                "Creating new sync loop handle with current tip height {} and sync target height {}",
                current_tip.header().height,
                sync_target_height
            );
            let sync_loop_handle =
                SyncLoopHandle::new(current_tip, sync_target_height, Network::Testnet(0), false)
                    .await;
            let (peer_control_sender, peer_control_receiver) = mpsc::channel::<PeerControl>(10);
            let (blockchain_tip_control_sender, blockchain_tip_control_receiver) =
                mpsc::channel::<BlockchainTipControl>(10);
            Self {
                peers: HashMap::default(),
                sync_loop_handle,
                current_tip_height,
                sync_target_height,
                finished: false,
                tip_tracker: None,
                peer_control_receiver,
                peer_control_sender,
                blockchain_tip_control_receiver,
                blockchain_tip_control_sender,
            }
        }

        fn peer_control_sender(&self) -> Sender<PeerControl> {
            self.peer_control_sender.clone()
        }

        fn blockchain_tip_control_sender(&self) -> Sender<BlockchainTipControl> {
            self.blockchain_tip_control_sender.clone()
        }

        fn set_tip_tracker(&mut self, tip_tracker: Arc<Mutex<BlockHeight>>) {
            self.tip_tracker = Some(tip_tracker);
        }

        async fn connect(&mut self, peer: MockPeer) {
            self.sync_loop_handle.send_add_peer(peer.handle()).await;
            self.peers.insert(peer.handle(), peer);
        }

        async fn disconnect(&mut self, peer_handle: PeerHandle) {
            self.sync_loop_handle.send_remove_peer(peer_handle).await;
            self.peers.remove(&peer_handle);
        }

        fn sync_is_finished(&self) -> bool {
            self.finished
        }

        pub(crate) fn start_sync_loop(&mut self) {
            self.sync_loop_handle.start();
        }

        pub(crate) fn take_sync_loop_join_handle(&mut self) -> Option<JoinHandle<()>> {
            self.sync_loop_handle.take_join_handle()
        }

        async fn run(&mut self) {
            // Create an interval timer, triggering a tick event regularly.
            let mut ticker = interval(Duration::from_millis(100));

            loop {
                tokio::select! {
                    Some(message) = self.sync_loop_handle.recv() => {
                        match message {
                            SyncToMain::Finished(target) => {
                                tracing::info!("mock main loop: sync loop is finished");
                                if self.current_tip_height == target {
                                    self.finished = true;

                                    // There may be a race condition whereby new
                                    // "blocks" are "disseminated" while the
                                    // sync loop is finishing up. Ignore these.
                                    self.sync_target_height = target;
                                }
                                else {
                                    tracing::warn!("mock main loop: Got Finished({}) message from sync loop but we are not finished yet ({}).", target, self.current_tip_height);
                                }
                                break;
                            }
                            SyncToMain::TipSuccessor(block) => {
                                tracing::debug!("mock main loop: processing block {}", block.header().height);
                                if block.header().height == self.current_tip_height.next() {
                                    self.current_tip_height = block.header().height;
                                    if let Some(tip_tracker) = &self.tip_tracker {
                                        *tip_tracker.lock().await = block.header().height;
                                        tracing::info!("mock main loop: updated tip to new block ({})", block.header().height);
                                    }
                                }
                                else {
                                    panic!("mock main loop: tip-success is not actual successor");
                                }
                            }
                            SyncToMain::RequestBlocks(block_requests) => {
                                tracing::debug!("mock main loop: received request blocks message ...");
                                for block_request in block_requests {
                                    if let Some(peer) = self.peers.get_mut(&block_request.peer_handle.clone()) {
                                        if let Some(block) = peer.request(block_request.height).await {
                                            tracing::debug!("mock main loop: got block from peer; relaying to sync loop");
                                            self.sync_loop_handle.send_block(Box::new(block), block_request.peer_handle);
                                            tracing::debug!("mock main loop: done relaying");
                                        } else {
                                            if let MockPeer::Syncing(syncing_peer) = peer {
                                                if rng().random_bool(0.5_f64) {
                                                    self.sync_loop_handle.send_sync_coverage(block_request.peer_handle, syncing_peer.coverage());
                                                }
                                            }
                                            tracing::debug!("mock main loop: no response from peer");
                                        }
                                    } else {
                                        tracing::warn!("mock main loop: no such peer -- was peer removed?");
                                    }
                                    tokio::task::yield_now().await;
                                }
                            }
                            SyncToMain::Status(status) => {
                                tracing::info!("mock main loop: Syncing is {status} complete.");
                            }
                            SyncToMain::Error => {
                                tracing::error!("mock main loop: Error code from sync loop.");
                                break;
                            }
                            SyncToMain::Punish(peers) => {
                                tracing::info!("mock main loop: Punishing {} peers for sync timeout.", peers.len());
                            }
                            SyncToMain::Coverage{
                                coverage: _,
                                peer_handle
                            } => {
                                tracing::info!("mock main loop: Sending coverage to peer {peer_handle}");
                            }
                            SyncToMain::SyncBlock{
                                block,
                                peer_handle,
                            } => {
                                tracing::info!("mock main loop: Sending block {} over to {peer_handle}", block.header().height);
                            }
                        }
                    }

                    Some(message) = self.peer_control_receiver.recv() => {
                        match message {
                            PeerControl::AddPeer(peer) => {
                                tracing::info!("mock main loop: adding peer {}", peer.handle());
                                self.connect(peer).await;
                            }
                            PeerControl::RemovePeer(handle) => {
                                tracing::info!("mock main loop: removing peer {}", handle);
                                self.disconnect(handle).await;
                            }
                        }
                    }

                    Some(message) = self.blockchain_tip_control_receiver.recv() => {
                        tracing::debug!("mock main loop: got new block! while there is {} messages in the peer control channel", self.peer_control_receiver.len());
                        match message {
                            BlockchainTipControl::NewBlock(block) => {
                                tracing::info!("mock main loop: new block was mined; expanding sync target accordingly ******");
                                self.sync_target_height = self.sync_target_height.next();
                                self.sync_loop_handle.send_new_target(Box::new(block)).await;
                            }
                        }
                        tracing::debug!("mock main loop: done relaying new block.");
                    }

                    _ = ticker.tick() => {
                        tracing::debug!("mock main loop: sending status request");
                        self.sync_loop_handle.send_status_request();
                    }
                }
            }
        }
    }

    #[derive(Debug, Clone)]
    enum MockPeer {
        Good(GoodPeer),
        Flaky(FlakyPeer),
        Syncing(SyncingPeer),
    }

    impl MockPeer {
        async fn request(&mut self, block_height: BlockHeight) -> Option<Block> {
            match self {
                MockPeer::Good(good_peer) => good_peer.request(block_height).await,
                MockPeer::Flaky(flaky_peer) => flaky_peer.request(block_height).await,
                MockPeer::Syncing(syncing_peer) => syncing_peer.request(block_height).await,
            }
        }

        fn handle(&self) -> PeerHandle {
            match self {
                MockPeer::Good(good_peer) => good_peer.handle(),
                MockPeer::Flaky(flaky_peer) => flaky_peer.handle(),
                MockPeer::Syncing(syncing_peer) => syncing_peer.handle(),
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

    #[derive(Debug, Clone)]
    struct SyncingPeer {
        peer_handle: PeerHandle,
        coverage: SynchronizationBitMask,
    }

    impl SyncingPeer {
        fn new(coverage: SynchronizationBitMask) -> Self {
            Self {
                peer_handle: random_peer_handle(),
                coverage,
            }
        }
        async fn request(&mut self, block_height: BlockHeight) -> Option<Block> {
            // with certain probability, this peer has received a new block
            if rng().random_bool(0.2_f64) && !self.coverage.is_complete() {
                let height = self.coverage.sample(rng().random());
                self.coverage.set(height);
            }

            // simulate flakiness
            if rng().random_bool(0.5_f64) {
                return None;
            }

            // if the block is not present then we certainly cannot provide it
            if !self.coverage.contains(block_height.value()) {
                return None;
            }

            // sample and return block
            let mut block = rng().random::<Block>();
            tokio::time::sleep(Duration::from_millis(1)).await;
            block.set_header_height(block_height);
            Some(block)
        }

        fn handle(&self) -> PeerHandle {
            self.peer_handle
        }

        fn coverage(&self) -> SynchronizationBitMask {
            self.coverage.clone()
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
        let mut current_tip = rng.random::<Block>();
        current_tip.set_header_height(BlockHeight::from(rng.random_range(0u64..10000)));
        let sync_target_height =
            BlockHeight::from(current_tip.header().height.value() + rng.random_range(0..200));
        let mut main_loop = MockMainLoop::new(current_tip, sync_target_height).await;

        main_loop.connect(MockPeer::Good(GoodPeer::new())).await;
        main_loop.start_sync_loop();
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
        let mut current_tip = rng.random::<Block>();
        current_tip.set_header_height(BlockHeight::from(rng.random_range(0u64..10000)));
        let sync_target_height =
            BlockHeight::from(current_tip.header().height.value() + rng.random_range(0..200));
        let mut main_loop = MockMainLoop::new(current_tip, sync_target_height).await;

        main_loop.connect(MockPeer::Good(GoodPeer::new())).await;
        main_loop.connect(MockPeer::Good(GoodPeer::new())).await;
        main_loop.connect(MockPeer::Good(GoodPeer::new())).await;
        main_loop.connect(MockPeer::Good(GoodPeer::new())).await;
        main_loop.connect(MockPeer::Good(GoodPeer::new())).await;
        main_loop.start_sync_loop();
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
        let mut current_tip = rng.random::<Block>();
        current_tip.set_header_height(BlockHeight::from(rng.random_range(0u64..10000)));

        let sync_target_height =
            BlockHeight::from(current_tip.header().height.value() + rng.random_range(0..200));
        let mut main_loop = MockMainLoop::new(current_tip, sync_target_height).await;

        main_loop.connect(MockPeer::Flaky(FlakyPeer::new())).await;
        main_loop.start_sync_loop();
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

        let mut current_tip = rng.random::<Block>();
        current_tip.set_header_height(BlockHeight::from(rng.random_range(0u64..10000)));
        let sync_target_height =
            BlockHeight::from(current_tip.header().height.value() + rng.random_range(0..100));
        let mut main_loop = MockMainLoop::new(current_tip, sync_target_height).await;

        main_loop.connect(MockPeer::Flaky(FlakyPeer::new())).await;
        main_loop.connect(MockPeer::Flaky(FlakyPeer::new())).await;
        main_loop.connect(MockPeer::Flaky(FlakyPeer::new())).await;
        main_loop.connect(MockPeer::Flaky(FlakyPeer::new())).await;
        main_loop.connect(MockPeer::Flaky(FlakyPeer::new())).await;

        main_loop.start_sync_loop();

        main_loop.run().await;
        assert!(
            main_loop.sync_is_finished(),
            "current tip height {} versus sync target height {}",
            main_loop.current_tip_height,
            main_loop.sync_target_height
        );
    }

    #[ignore = "cannot run in parallel with other tests"]
    #[tracing_test::traced_test]
    #[apply(shared_tokio_runtime)]
    async fn can_resume_sync_from_saved_state() {
        let mut rng = rng();
        tracing::info!("starting test ...");

        let mut current_tip = rng.random::<Block>();
        current_tip.set_header_height(BlockHeight::from(rng.random_range(0u64..10000)));
        let current_tip_height = current_tip.header().height;
        let sync_target_height =
            BlockHeight::from(current_tip.header().height.value() + rng.random_range(0..200));

        // set up first attempt
        let mut main_loop = MockMainLoop::new(current_tip.clone(), sync_target_height).await;

        // keep track of tip height
        let tip_tracker = Arc::new(Mutex::new(current_tip_height));
        main_loop.set_tip_tracker(tip_tracker.clone());

        // run
        main_loop.connect(MockPeer::Flaky(FlakyPeer::new())).await;
        main_loop.connect(MockPeer::Flaky(FlakyPeer::new())).await;
        main_loop.start_sync_loop();
        let sync_loop = main_loop.take_sync_loop_join_handle().unwrap();
        let main_loop_handle = tokio::spawn(async move {
            main_loop.run().await;
        });

        // after one second, interrupt
        tokio::time::sleep(Duration::from_secs(1)).await;
        sync_loop.abort();
        main_loop_handle.abort();

        // start second attempt
        // Reuse tip height from previous attempt, with one block margin due to
        // race conditions.
        let mut main_loop_b = MockMainLoop::new(current_tip, sync_target_height).await;

        assert!(
            !main_loop_b.sync_is_finished(),
            "current tip height {} versus sync target height {}",
            main_loop_b.current_tip_height,
            main_loop_b.sync_target_height
        );

        // run
        main_loop_b.connect(MockPeer::Flaky(FlakyPeer::new())).await;
        main_loop_b.connect(MockPeer::Flaky(FlakyPeer::new())).await;
        main_loop_b.start_sync_loop();
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

        let mut current_tip = rng.random::<Block>();
        current_tip.set_header_height(BlockHeight::from(rng.random_range(0u64..10000)));
        let sync_target_height =
            BlockHeight::from(current_tip.header().height.value() + rng.random_range(0..100));
        let mut main_loop = MockMainLoop::new(current_tip, sync_target_height).await;

        let mut peer_set = vec![];
        for _ in 0..5 {
            let peer = FlakyPeer::new();
            peer_set.push(peer.handle());
            main_loop.connect(MockPeer::Flaky(peer)).await;
        }

        main_loop.start_sync_loop();
        let moved_peer_control_sender = main_loop.peer_control_sender();
        let peer_set_changer_handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(1)).await;
            for _ in 0..100 {
                change_peer_set(&mut peer_set, moved_peer_control_sender.clone(), &mut rng).await;
                tokio::time::sleep(Duration::from_millis(500)).await;
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
    async fn can_sync_with_moving_target() {
        async fn disseminate_new_block(
            target_height: Arc<Mutex<BlockHeight>>,
            tip_control_sender: Sender<BlockchainTipControl>,
            rng: &mut StdRng,
        ) {
            let mut moved_rng = rng.clone();
            let mut block = tokio::task::spawn_blocking(move || moved_rng.random::<Block>())
                .await
                .unwrap();
            let mut target_height_lock = target_height.lock_owned().await;
            let old_height: BlockHeight = *target_height_lock;
            let new_height = old_height.next();
            *target_height_lock = new_height;
            drop(target_height_lock);
            tokio::task::yield_now().await;
            block.set_header_height(new_height);
            tip_control_sender
                .send(BlockchainTipControl::NewBlock(block))
                .await
                .unwrap();
        }

        let mut rng = StdRng::seed_from_u64(rng().next_u64());
        tracing::info!("starting test ...");

        let mut current_tip = rng.random::<Block>();
        current_tip.set_header_height(BlockHeight::from(rng.random_range(0u64..10000)));
        let original_sync_target_height =
            BlockHeight::from(current_tip.header().height.value() + rng.random_range(0..100));
        let mut main_loop = MockMainLoop::new(current_tip, original_sync_target_height).await;

        main_loop.connect(MockPeer::Flaky(FlakyPeer::new())).await;
        main_loop.connect(MockPeer::Flaky(FlakyPeer::new())).await;
        main_loop.connect(MockPeer::Flaky(FlakyPeer::new())).await;
        main_loop.connect(MockPeer::Flaky(FlakyPeer::new())).await;
        main_loop.connect(MockPeer::Flaky(FlakyPeer::new())).await;
        main_loop.start_sync_loop();

        let blockchain_tip_control_sender = main_loop.blockchain_tip_control_sender();
        let updated_sync_target_height = Arc::new(Mutex::new(original_sync_target_height));
        let moved_updated_sync_target_height = updated_sync_target_height.clone();
        let new_blocks_handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(1)).await;
            loop {
                disseminate_new_block(
                    moved_updated_sync_target_height.clone(),
                    blockchain_tip_control_sender.clone(),
                    &mut rng,
                )
                .await;
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        });

        main_loop.run().await;

        new_blocks_handle.abort();

        assert!(
            main_loop.sync_is_finished(),
            "current tip height {} versus sync target height {}",
            main_loop.current_tip_height,
            main_loop.sync_target_height
        );

        assert_eq!(
            main_loop.sync_target_height,
            *updated_sync_target_height.lock().await
        );
    }

    #[tracing_test::traced_test]
    #[apply(shared_tokio_runtime)]
    async fn can_sync_from_syncing_peers() {
        let mut rng = rng();
        tracing::info!("starting test ...");

        let mut current_tip = rng.random::<Block>();
        current_tip.set_header_height(BlockHeight::from(rng.random_range(0u64..10000)));
        let current_tip_height = current_tip.header().height;
        let sync_target_height =
            BlockHeight::from(current_tip_height.value() + rng.random_range(20..100));
        let mut main_loop = MockMainLoop::new(current_tip, sync_target_height).await;

        let mut cumulative_coverage = SynchronizationBitMask::new(
            current_tip_height.value() + 1,
            sync_target_height.next().value(),
        );
        for _ in 0..5 {
            let moved_tip_height = current_tip_height;
            let peer_coverage = tokio::task::spawn_blocking(move || {
                SynchronizationBitMask::random(
                    moved_tip_height.value(),
                    sync_target_height.next().value(),
                )
            })
            .await
            .unwrap();
            cumulative_coverage = cumulative_coverage | peer_coverage.clone();
            main_loop
                .connect(MockPeer::Syncing(SyncingPeer::new(peer_coverage)))
                .await;
        }
        main_loop
            .connect(MockPeer::Syncing(SyncingPeer::new(!cumulative_coverage)))
            .await;

        main_loop.start_sync_loop();
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
    async fn can_sync_with_moving_target_from_dynamic_set_of_flaky_syncing_peers() {
        async fn change_peer_set(
            target_height: Arc<Mutex<BlockHeight>>,
            peer_set: &mut Vec<PeerHandle>,
            peer_control_sender: Sender<PeerControl>,
            rng: &mut StdRng,
        ) {
            if (peer_set.is_empty() || rng.random_bool(0.5_f64)) && peer_set.len() < 5 {
                let height = *target_height.try_lock().unwrap();
                let bit_mask = tokio::task::spawn_blocking(move || {
                    SynchronizationBitMask::random(
                        height.value().saturating_sub(2000),
                        height.value(),
                    )
                })
                .await
                .unwrap();
                let new_peer = SyncingPeer::new(bit_mask);
                let handle = new_peer.handle();
                peer_set.push(handle);
                peer_control_sender
                    .send(PeerControl::AddPeer(MockPeer::Syncing(new_peer)))
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

        async fn disseminate_new_block(
            target_height: Arc<Mutex<BlockHeight>>,
            tip_control_sender: Sender<BlockchainTipControl>,
            rng: &mut StdRng,
        ) {
            let mut moved_rng = rng.clone();
            let mut block = tokio::task::spawn_blocking(move || moved_rng.random::<Block>())
                .await
                .unwrap();
            let mut target_height_lock = target_height.try_lock().unwrap();
            let old_height: BlockHeight = *target_height_lock;
            let new_height = old_height.next();
            block.set_header_height(new_height);
            *target_height_lock = new_height;
            drop(target_height_lock);
            tokio::task::yield_now().await;
            tip_control_sender
                .send(BlockchainTipControl::NewBlock(block))
                .await
                .unwrap();
        }

        let mut rng = StdRng::seed_from_u64(rng().next_u64());
        tracing::info!("starting test ...");

        let mut current_tip = rng.random::<Block>();
        current_tip.set_header_height(BlockHeight::from(u64::from(rng.next_u32() >> 20)));
        let original_sync_target_height =
            BlockHeight::from(current_tip.header().height.value() + 100);
        let mut main_loop = MockMainLoop::new(current_tip, original_sync_target_height).await;

        let mut peer_set = vec![];
        for _ in 0..1 {
            let peer = FlakyPeer::new();
            peer_set.push(peer.handle());
            main_loop.connect(MockPeer::Flaky(peer)).await;
        }

        main_loop.start_sync_loop();

        let moved_peer_control_sender = main_loop.peer_control_sender();
        let updated_sync_target_height = Arc::new(Mutex::new(original_sync_target_height));
        let moved_updated_sync_target_height = updated_sync_target_height.clone();
        let mut moved_rng = StdRng::seed_from_u64(rng.next_u64());
        let peer_set_changer_handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(2)).await;
            loop {
                change_peer_set(
                    moved_updated_sync_target_height.clone(),
                    &mut peer_set,
                    moved_peer_control_sender.clone(),
                    &mut moved_rng,
                )
                .await;
                tokio::time::sleep(Duration::from_millis(15)).await;
            }
        });

        let moved_updated_sync_target_height_ = updated_sync_target_height.clone();
        let blockchain_tip_control_sender = main_loop.blockchain_tip_control_sender();
        let mut moved_rng_ = StdRng::seed_from_u64(rng.next_u64());
        let new_blocks_handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(1)).await;
            loop {
                disseminate_new_block(
                    moved_updated_sync_target_height_.clone(),
                    blockchain_tip_control_sender.clone(),
                    &mut moved_rng_,
                )
                .await;
                tokio::time::sleep(Duration::from_millis(29)).await;
            }
        });

        main_loop.run().await;

        peer_set_changer_handle.abort();
        new_blocks_handle.abort();

        assert!(
            main_loop.sync_is_finished(),
            "current tip height {} versus sync target height {}",
            main_loop.current_tip_height,
            main_loop.sync_target_height
        );

        assert_ne!(
            original_sync_target_height,
            *updated_sync_target_height.lock().await
        );
    }
}
