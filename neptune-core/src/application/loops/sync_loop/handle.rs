use std::time::Duration;

use tokio::sync::mpsc::Receiver;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinHandle;

use crate::api::export::BlockHeight;
use crate::api::export::Network;
use crate::application::loops::sync_loop::block_validator::BlockValidator;
use crate::application::loops::sync_loop::channel::MainToSync;
use crate::application::loops::sync_loop::channel::SyncToMain;
use crate::application::loops::sync_loop::synchronization_bit_mask::SynchronizationBitMask;
use crate::application::loops::sync_loop::PeerHandle;
use crate::application::loops::sync_loop::SyncLoop;
use crate::protocol::consensus::block::Block;

/// Wraps a [`SyncLoop`] along with channels to an fro.
///
/// For use by the main loop. Defends against channel mis-use.
#[derive(Debug)]
pub(crate) struct SyncLoopHandle {
    task_state: Option<SyncLoop>,
    task_join_handle: Option<JoinHandle<()>>,
    sender: Sender<MainToSync>,
    receiver: Receiver<SyncToMain>,
    target_height: BlockHeight,
}

impl SyncLoopHandle {
    pub(crate) async fn new(
        genesis_block: Block,
        target_height: BlockHeight,
        network: Network,
        resume_if_possible: bool,
    ) -> Self {
        let block_validator = BlockValidator::from_network(network);
        let (state, sender, receiver) = SyncLoop::new(
            genesis_block,
            target_height,
            resume_if_possible,
            block_validator,
        )
        .await
        .unwrap();

        Self {
            task_state: Some(state),
            task_join_handle: None,
            sender,
            receiver,
            target_height,
        }
    }

    pub(crate) fn target_height(&self) -> BlockHeight {
        self.target_height
    }

    pub(crate) fn start(&mut self) {
        if let Some(state) = self.task_state.take() {
            self.task_join_handle = Some(state.start());
        }
    }

    pub(crate) fn send_block(&self, block: Box<Block>, peer: PeerHandle) {
        if let Err(e) = self.sender.try_send(MainToSync::ReceiveBlock {
            peer_handle: peer,
            block,
        }) {
            tracing::warn!("Error relaying block to sync loop: {e}.");
            tracing::debug!(
                "Note: channel capacity is at {}/{}.",
                self.sender.capacity(),
                self.sender.max_capacity()
            );
        }
    }

    pub(crate) async fn send_fast_forward_block(&self, block: Box<Block>) {
        let new_tip_height = block.header().height;
        if let Err(e) = self
            .sender
            .send(MainToSync::FastForward { new_tip: block })
            .await
        {
            tracing::error!(
                "Could not fast-forward sync to block {}: {e}.",
                new_tip_height
            );
        }
    }

    pub(crate) fn send_try_fetch_block(&self, peer: PeerHandle, height: BlockHeight) {
        if let Err(e) = self.sender.try_send(MainToSync::TryFetchBlock {
            peer_handle: peer,
            height,
        }) {
            tracing::warn!("Error sending try-fetch-block message to sync loop: {e}.");
            tracing::debug!(
                "Note: channel capacity is at {}/{}.",
                self.sender.capacity(),
                self.sender.max_capacity()
            );
        }
    }

    pub(crate) async fn send_new_target(&mut self, target: Box<Block>) {
        let new_target_height = target.header().height;
        if let Err(e) = self.sender.send(MainToSync::ExtendChain(target)).await {
            tracing::error!("Failed to send new target block to sync loop: {e}.");
        }
        self.target_height = new_target_height;
    }

    pub(crate) async fn send_add_peer(&self, peer: PeerHandle) {
        if let Err(e) = self.sender.send(MainToSync::AddPeer(peer)).await {
            tracing::error!(
                "Error sending AddPeer message to sync loop: {e} -- did the sync loop terminate?"
            );
        }
    }

    pub(crate) async fn send_remove_peer(&self, peer: PeerHandle) {
        if let Err(e) = self.sender.send(MainToSync::RemovePeer(peer)).await {
            tracing::error!("Error sending RemovePeer message to sync loop: {e} -- did the sync loop terminate?");
        }
    }

    pub(crate) fn send_sync_coverage(
        &self,
        peer_handle: PeerHandle,
        coverage: SynchronizationBitMask,
    ) {
        if let Err(e) = self.sender.try_send(MainToSync::SyncCoverage {
            peer_handle,
            coverage,
        }) {
            tracing::warn!("Error relaying sync coverage to sync loop: {e}.");
            tracing::debug!(
                "Note: channel capacity is at {}/{}.",
                self.sender.capacity(),
                self.sender.max_capacity()
            );
        }
    }

    pub(crate) fn send_status_request(&self) {
        // Insist: in case of failure, wait a while then try again. Do this in a
        // separate task so that control can return.
        let moved_sender = self.sender.clone();
        tokio::task::spawn(Self::weakly_insist_sending_status_request(moved_sender));
    }

    async fn weakly_insist_sending_status_request(sender: Sender<MainToSync>) {
        let max_number_of_attempts = 20;
        let mut counter = 1;
        loop {
            // Avoid contributing to reduce channel clog. Only attempt to send
            // if the channel queue is empty.
            let queue_is_empty = sender.capacity() == sender.max_capacity();
            let mut send_failed = true;
            if queue_is_empty {
                send_failed = sender.try_send(MainToSync::Status).is_err();
            }

            if send_failed {
                // failure: sleep a while and then try again
                tokio::time::sleep(Duration::from_millis(50)).await;
                counter += 1;
            } else {
                // success sending
                break;
            }

            // backstop: after too many failed attempts, just give up
            if counter == max_number_of_attempts {
                tracing::warn!("Failed to send status request message to sync loop.");
                tracing::debug!(
                    "Note: channel capacity is at {}/{}.",
                    sender.capacity(),
                    sender.max_capacity()
                );
                break;
            }
        }
    }

    pub(crate) async fn recv(&mut self) -> Option<SyncToMain> {
        self.receiver.recv().await
    }

    /// Wait on a received message, if there is a sync loop beneath this option.
    pub(crate) async fn maybe_recv(maybe_sync_loop: &mut Option<Self>) -> Option<SyncToMain> {
        if let Some(handle) = maybe_sync_loop {
            handle.recv().await
        } else {
            None
        }
    }

    pub(crate) async fn abort(&self) {
        if let Err(e) = self.sender.send(MainToSync::Abort).await {
            tracing::error!("Could not abort sync loop: {e}.");
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    impl SyncLoopHandle {
        pub(crate) fn take_join_handle(&mut self) -> Option<JoinHandle<()>> {
            self.task_join_handle.take()
        }
    }
}
