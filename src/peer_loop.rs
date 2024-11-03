use std::cmp;
use std::marker::Unpin;
use std::net::SocketAddr;
use std::time::SystemTime;

use anyhow::bail;
use anyhow::Result;
use futures::sink::Sink;
use futures::sink::SinkExt;
use futures::stream::TryStream;
use futures::stream::TryStreamExt;
use itertools::Itertools;
use tasm_lib::triton_vm::prelude::Digest;
use tokio::select;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::connect_to_peers::close_peer_connected_callback;
use crate::models::blockchain::block::block_height::BlockHeight;
use crate::models::blockchain::block::Block;
use crate::models::blockchain::transaction::Transaction;
use crate::models::channel::MainToPeerTask;
use crate::models::channel::PeerTaskToMain;
use crate::models::channel::PeerTaskToMainTransaction;
use crate::models::peer::transfer_block::TransferBlock;
use crate::models::peer::BlockRequestBatch;
use crate::models::peer::HandshakeData;
use crate::models::peer::MutablePeerState;
use crate::models::peer::PeerInfo;
use crate::models::peer::PeerMessage;
use crate::models::peer::PeerSanctionReason;
use crate::models::peer::PeerStanding;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::models::state::mempool::MEMPOOL_IGNORE_TRANSACTIONS_THIS_MANY_SECS_AHEAD;
use crate::models::state::mempool::MEMPOOL_TX_THRESHOLD_AGE_IN_SECS;
use crate::models::state::GlobalStateLock;

const STANDARD_BLOCK_BATCH_SIZE: usize = 50;
const MAX_PEER_LIST_LENGTH: usize = 10;
const MINIMUM_BLOCK_BATCH_SIZE: usize = 2;

const KEEP_CONNECTION_ALIVE: bool = false;
const DISCONNECT_CONNECTION: bool = true;

pub type PeerStandingNumber = i32;

/// Handles messages from peers via TCP
///
/// also handles messages from main task over the main-to-peer-tasks broadcast
/// channel.
pub struct PeerLoopHandler {
    to_main_tx: mpsc::Sender<PeerTaskToMain>,
    global_state_lock: GlobalStateLock,
    peer_address: SocketAddr,
    peer_handshake_data: HandshakeData,
    inbound_connection: bool,
    distance: u8,
    #[cfg(test)]
    mock_now: Option<Timestamp>,
}

impl PeerLoopHandler {
    pub(crate) fn new(
        to_main_tx: mpsc::Sender<PeerTaskToMain>,
        global_state_lock: GlobalStateLock,
        peer_address: SocketAddr,
        peer_handshake_data: HandshakeData,
        inbound_connection: bool,
        distance: u8,
    ) -> Self {
        Self {
            to_main_tx,
            global_state_lock,
            peer_address,
            peer_handshake_data,
            inbound_connection,
            distance,
            #[cfg(test)]
            mock_now: None,
        }
    }

    /// Allows for mocked timestamps such that time dependencies may be tested.
    #[cfg(test)]
    pub(crate) fn with_mocked_time(
        to_main_tx: mpsc::Sender<PeerTaskToMain>,
        global_state_lock: GlobalStateLock,
        peer_address: SocketAddr,
        peer_handshake_data: HandshakeData,
        inbound_connection: bool,
        distance: u8,
        mocked_time: Timestamp,
    ) -> Self {
        Self {
            to_main_tx,
            global_state_lock,
            peer_address,
            peer_handshake_data,
            inbound_connection,
            distance,
            mock_now: Some(mocked_time),
        }
    }

    fn now(&self) -> Timestamp {
        #[cfg(not(test))]
        {
            Timestamp::now()
        }
        #[cfg(test)]
        {
            self.mock_now.unwrap_or(Timestamp::now())
        }
    }

    // TODO: Add a reward function that mutates the peer status

    /// Locking:
    ///   * acquires `global_state_lock` for write
    async fn punish(&mut self, reason: PeerSanctionReason) -> Result<()> {
        let mut global_state_mut = self.global_state_lock.lock_guard_mut().await;
        warn!(
            "Sanctioning peer {} for {:?}",
            self.peer_address.ip(),
            reason
        );
        let new_standing = global_state_mut
            .net
            .peer_map
            .get_mut(&self.peer_address)
            .map(|p| p.standing.sanction(reason))
            .unwrap_or(0);

        if new_standing < -(global_state_mut.cli().peer_tolerance as PeerStandingNumber) {
            warn!("Banning peer");
            bail!("Banning peer");
        }

        Ok(())
    }

    /// Handle validation and send all blocks to the main task if they're all
    /// valid. Use with a list of blocks or a single block. When the
    /// `received_blocks` is a list, the parent of the `i+1`th block in the
    /// list is the `i`th block. The parent of element zero in this list is
    /// `parent_of_first_block`.
    ///
    /// Returns Err when the connection should be closed; returns Ok(None) if
    /// some block is invalid or if the last block is not canonical; returns
    /// Ok(Some(block_height)) otherwise, referring to the largest block height
    /// in the batch.
    ///
    /// # Locking
    ///   * acquires `global_state_lock` for write via Self::punish()
    ///
    /// # Panics
    ///
    ///  - Panics if called with the empty list.
    async fn handle_blocks(
        &mut self,
        received_blocks: Vec<Block>,
        parent_of_first_block: Block,
    ) -> Result<Option<BlockHeight>> {
        debug!(
            "attempting to validate {} {}",
            received_blocks.len(),
            if received_blocks.len() == 1 {
                "block"
            } else {
                "blocks"
            }
        );
        let now = self.now();
        let mut previous_block = &parent_of_first_block;
        for new_block in received_blocks.iter() {
            if !new_block.has_proof_of_work(previous_block) {
                warn!(
                    "Received invalid proof-of-work for block of height {} from peer with IP {}",
                    new_block.kernel.header.height, self.peer_address
                );
                warn!("Difficulty is {}.", previous_block.kernel.header.difficulty);
                warn!(
                    "Proof of work should be {} (or more) but was [{}].",
                    previous_block.kernel.header.difficulty.target(),
                    new_block.hash().values().iter().join(", ")
                );
                self.punish(PeerSanctionReason::InvalidBlock((
                    new_block.kernel.header.height,
                    new_block.hash(),
                )))
                .await?;
                warn!("Failed to validate block due to insufficient PoW");
                return Ok(None);
            } else if !new_block.is_valid(previous_block, now) {
                warn!(
                    "Received invalid block of height {} from peer with IP {}",
                    new_block.kernel.header.height, self.peer_address
                );
                self.punish(PeerSanctionReason::InvalidBlock((
                    new_block.kernel.header.height,
                    new_block.hash(),
                )))
                .await?;
                warn!("Failed to validate block: invalid block");
                return Ok(None);
            } else {
                info!(
                    "Block with height {} is valid. mined: {}",
                    new_block.kernel.header.height,
                    new_block.kernel.header.timestamp.standard_format()
                );
            }

            previous_block = new_block;
        }

        // evaluate the fork choice rule
        if !self
            .global_state_lock
            .lock_guard()
            .await
            .incoming_block_is_more_canonical(received_blocks.last().unwrap())
        {
            warn!(
                "Received {} blocks from peer but incoming blocks are less \
            canonical than current tip.",
                received_blocks.len()
            );
            return Ok(None);
        }

        // Send the new blocks to the main task which handles the state update
        // and storage to the database.
        let new_block_height = received_blocks.last().unwrap().header().height;
        self.to_main_tx
            .send(PeerTaskToMain::NewBlocks(received_blocks))
            .await?;
        info!(
            "Updated block info by block from peer. block height {}",
            new_block_height
        );

        Ok(Some(new_block_height))
    }

    /// Takes a single block received from a peer and (attempts to) find a path
    /// from some known stored block to the received block.
    ///
    /// This function attempts to find the parent of a new block, either by
    /// searching the database or, if necessary, by requesting it from a peer.
    ///  - If the parent is stored in the database, block handling continues.
    ///  - If the parent is not stored, it is requested from the peer and the
    ///    received block is pushed to the fork reconciliation list for later
    ///    handling by this function.
    ///
    /// If the parent is stored, the block and any fork reconciliation blocks
    /// are passed down the pipeline.
    ///
    /// Locking:
    ///   * acquires `global_state_lock` for write via Self::punish()
    async fn try_ensure_path<S>(
        &mut self,
        received_block: Box<Block>,
        peer: &mut S,
        peer_state: &mut MutablePeerState,
    ) -> Result<()>
    where
        S: Sink<PeerMessage> + TryStream<Ok = PeerMessage> + Unpin,
        <S as Sink<PeerMessage>>::Error: std::error::Error + Sync + Send + 'static,
        <S as TryStream>::Error: std::error::Error,
    {
        let parent_digest = received_block.kernel.header.prev_block_digest;
        debug!("Fetching parent block");
        let parent_block = self
            .global_state_lock
            .lock_guard()
            .await
            .chain
            .archival_state()
            .get_block(parent_digest)
            .await?;
        debug!(
            "Completed parent block fetching from DB: {}",
            if parent_block.is_some() {
                "found".to_string()
            } else {
                "not found".to_string()
            }
        );
        let parent_height = received_block.kernel.header.height.previous();

        // If parent is not known, request the parent, and add the current to
        // the peer fork resolution list
        if parent_block.is_none() && parent_height > BlockHeight::genesis() {
            info!(
                "Parent not known: Requesting previous block with height {} from peer",
                parent_height
            );

            // If the received block matches the block reconciliation state
            // push it there and request its parent
            if peer_state.fork_reconciliation_blocks.is_empty()
                || peer_state
                    .fork_reconciliation_blocks
                    .last()
                    .unwrap()
                    .kernel
                    .header
                    .height
                    .previous()
                    == received_block.kernel.header.height
                    && peer_state.fork_reconciliation_blocks.len() + 1
                        < self
                            .global_state_lock
                            .cli()
                            .max_number_of_blocks_before_syncing
            {
                peer_state.fork_reconciliation_blocks.push(*received_block);
            } else {
                // Blocks received out of order. Or more than allowed received without
                // going into sync mode. Give up on block resolution attempt.
                self.punish(PeerSanctionReason::ForkResolutionError((
                    received_block.kernel.header.height,
                    peer_state.fork_reconciliation_blocks.len() as u16,
                    received_block.hash(),
                )))
                .await?;
                warn!(
                    "Fork reconciliation failed after receiving {} blocks",
                    peer_state.fork_reconciliation_blocks.len() + 1
                );
                peer_state.fork_reconciliation_blocks = vec![];
                return Ok(());
            }

            peer.send(PeerMessage::BlockRequestByHash(parent_digest))
                .await?;

            return Ok(());
        }

        // We got all the way back to genesis, but disagree about genesis. Ban peer.
        if parent_block.is_none() && parent_height == BlockHeight::genesis() {
            self.punish(PeerSanctionReason::DifferentGenesis).await?;
            return Ok(());
        }

        // We want to treat the received fork reconciliation blocks (plus the
        // received block) in reverse order, from oldest to newest, because
        // they were requested from high to low block height.
        let mut new_blocks = peer_state.fork_reconciliation_blocks.clone();
        new_blocks.push(*received_block);
        new_blocks.reverse();

        // Reset the fork resolution state since we got all the way back to find a block that we have
        let fork_reconciliation_event = !peer_state.fork_reconciliation_blocks.is_empty();
        peer_state.fork_reconciliation_blocks = vec![];

        // Sanity check, that the blocks are correctly sorted (they should be)
        // TODO: This has failed: Investigate!
        // See: https://neptune.builders/core-team/neptune-core/issues/125
        // TODO: This assert should be replaced with something to punish or disconnect
        // from a peer instead. It can be used by a malevolent peer to crash peer nodes.
        let mut new_blocks_sorted_check = new_blocks.clone();
        new_blocks_sorted_check.sort_by(|a, b| a.kernel.header.height.cmp(&b.kernel.header.height));
        assert_eq!(
            new_blocks_sorted_check,
            new_blocks,
            "Block list in fork resolution must be sorted. Got blocks in this order: {}",
            new_blocks
                .iter()
                .map(|b| b.kernel.header.height.to_string())
                .join(", ")
        );

        // Parent block is guaranteed to be set here. Because: either it was fetched from the
        // database, or it's the genesis block.
        if let Some(new_block_height) = self
            .handle_blocks(new_blocks, parent_block.unwrap())
            .await?
        {
            // If `BlockNotification` was received during a block reconciliation
            // event, then the peer might have one (or more (unlikely)) blocks
            // that we do not have. We should thus request those blocks.
            if fork_reconciliation_event
                && peer_state.highest_shared_block_height > new_block_height
            {
                peer.send(PeerMessage::BlockRequestByHeight(
                    peer_state.highest_shared_block_height,
                ))
                .await?;
            }
        }

        Ok(())
    }

    /// Handle peer messages and returns Ok(true) if connection should be closed.
    /// Connection should also be closed if an error is returned.
    /// Otherwise returns OK(false).
    ///
    /// Locking:
    ///   * acquires `global_state_lock` for read
    ///   * acquires `global_state_lock` for write via Self::punish()
    async fn handle_peer_message<S>(
        &mut self,
        msg: PeerMessage,
        peer: &mut S,
        peer_state_info: &mut MutablePeerState,
    ) -> Result<bool>
    where
        S: Sink<PeerMessage> + TryStream<Ok = PeerMessage> + Unpin,
        <S as Sink<PeerMessage>>::Error: std::error::Error + Sync + Send + 'static,
        <S as TryStream>::Error: std::error::Error,
    {
        debug!(
            "Received {} from peer {}",
            msg.get_type(),
            self.peer_address
        );
        match msg {
            PeerMessage::Bye => {
                // Note that the current peer is not removed from the global_state.peer_map here
                // but that this is done by the caller.
                info!("Got bye. Closing connection to peer");
                Ok(DISCONNECT_CONNECTION)
            }
            PeerMessage::PeerListRequest => {
                let _ = crate::ScopeDurationLogger::new(
                    &(crate::macros::fn_name!() + "::PeerMessage::PeerListRequest"),
                );

                // We are interested in the address on which peers accept ingoing connections,
                // not in the address in which they are connected to us. We are only interested in
                // peers that accept incoming connections.
                let mut peer_info: Vec<(SocketAddr, u128)> = self
                    .global_state_lock
                    .lock_guard()
                    .await
                    .net
                    .peer_map
                    .values()
                    .filter(|peer_info| peer_info.listen_address().is_some())
                    .take(MAX_PEER_LIST_LENGTH) // limit length of response
                    .map(|peer_info| {
                        (
                            // unwrap is safe bc of above `filter`
                            peer_info.listen_address().unwrap(),
                            peer_info.instance_id,
                        )
                    })
                    .collect();

                // We sort the returned list, so this function is easier to test
                peer_info.sort_by_cached_key(|x| x.0);

                debug!("Responding with: {:?}", peer_info);
                peer.send(PeerMessage::PeerListResponse(peer_info)).await?;
                Ok(KEEP_CONNECTION_ALIVE)
            }
            PeerMessage::PeerListResponse(peers) => {
                let _ = crate::ScopeDurationLogger::new(
                    &(crate::macros::fn_name!() + "::PeerMessage::PeerListResponse"),
                );

                if peers.len() > MAX_PEER_LIST_LENGTH {
                    self.punish(PeerSanctionReason::FloodPeerListResponse)
                        .await?;
                }
                self.to_main_tx
                    .send(PeerTaskToMain::PeerDiscoveryAnswer((
                        peers,
                        self.peer_address,
                        // The distance to the revealed peers is 1 + this peer's distance
                        self.distance + 1,
                    )))
                    .await?;
                Ok(KEEP_CONNECTION_ALIVE)
            }
            PeerMessage::Block(t_block) => {
                let _ = crate::ScopeDurationLogger::new(
                    &(crate::macros::fn_name!() + "::PeerMessage::Block"),
                );

                info!(
                    "Got new block from peer {}, height {}, mined {}",
                    self.peer_address,
                    t_block.header.height,
                    t_block.header.timestamp.standard_format()
                );
                let new_block_height = t_block.header.height;

                let block: Box<Block> = Box::new((*t_block).into());

                // Update the value for the highest known height that peer possesses iff
                // we are not in a fork reconciliation state.
                if peer_state_info.fork_reconciliation_blocks.is_empty() {
                    peer_state_info.highest_shared_block_height = new_block_height;
                }

                self.try_ensure_path(block, peer, peer_state_info).await?;

                Ok(KEEP_CONNECTION_ALIVE)
            }
            PeerMessage::BlockRequestBatch(BlockRequestBatch {
                known_blocks,
                max_response_len,
            }) => {
                let _ = crate::ScopeDurationLogger::new(
                    &(crate::macros::fn_name!() + "::PeerMessage::BlockRequestBatch"),
                );

                // Find the block that the peer is requesting to start from
                let mut peers_preferred_canonical_block: Option<Block> = None;

                let tip_digest = self
                    .global_state_lock
                    .lock_guard()
                    .await
                    .chain
                    .light_state()
                    .hash();
                {
                    let global_state = self.global_state_lock.lock_guard().await;
                    // Find the 1st match (known and canonical block) of the
                    // request. break as soon as a match is found.
                    for digest in known_blocks {
                        debug!("Looking up block {} in batch request", digest);
                        let block_candidate = global_state
                            .chain
                            .archival_state()
                            .get_block(digest)
                            .await
                            .expect("Lookup must work");
                        if let Some(block_candidate) = block_candidate {
                            // Verify that this block is not only known but also belongs to the canonical
                            // chain. Also check if it's the genesis block.

                            if global_state
                                .chain
                                .archival_state()
                                .block_belongs_to_canonical_chain(
                                    block_candidate.hash(),
                                    tip_digest,
                                )
                                .await
                            {
                                peers_preferred_canonical_block = Some(block_candidate);
                                debug!("Found block in canonical chain: {}", digest);
                                break;
                            }
                        }
                    }
                }

                let peers_latest_canonical_block = match peers_preferred_canonical_block {
                    Some(plcb) => plcb,
                    None => {
                        self.punish(PeerSanctionReason::BatchBlocksUnknownRequest)
                            .await?;
                        return Ok(KEEP_CONNECTION_ALIVE);
                    }
                };

                // Get the relevant blocks, at most batch size many, descending from the
                // peer's most canonical block.
                let len_of_response = cmp::min(
                    max_response_len,
                    self.global_state_lock
                        .cli()
                        .max_number_of_blocks_before_syncing
                        / 2,
                );

                let responded_batch_size = cmp::max(len_of_response, MINIMUM_BLOCK_BATCH_SIZE);
                let mut returned_blocks: Vec<TransferBlock> =
                    Vec::with_capacity(responded_batch_size);

                let mut current_digest = peers_latest_canonical_block.hash();
                let global_state = self.global_state_lock.lock_guard().await;
                while returned_blocks.len() < responded_batch_size {
                    let children = global_state
                        .chain
                        .archival_state()
                        .get_children_block_digests(current_digest)
                        .await;

                    if children.is_empty() {
                        break;
                    }
                    let canonical_child_digest = if children.len() == 1 {
                        children[0]
                    } else {
                        // Excactly *one* of the children must be canonical,
                        // so we can just stop when we find it.
                        let mut canonical = children[0];
                        for child in children.into_iter().skip(1) {
                            if global_state
                                .chain
                                .archival_state()
                                .block_belongs_to_canonical_chain(child, tip_digest)
                                .await
                            {
                                canonical = child;
                                break;
                            }
                        }
                        canonical
                    };

                    // get block and append to list
                    let canonical_child: Block = global_state
                        .chain
                        .archival_state()
                        .get_block(canonical_child_digest)
                        .await?
                        .unwrap();
                    returned_blocks.push(canonical_child.try_into().unwrap());

                    // prepare for next iteration
                    current_digest = canonical_child_digest;
                }

                debug!(
                    "Returning {} blocks in batch response",
                    returned_blocks.len()
                );

                let response = PeerMessage::BlockResponseBatch(returned_blocks);
                peer.send(response).await?;

                Ok(KEEP_CONNECTION_ALIVE)
            }
            PeerMessage::BlockResponseBatch(t_blocks) => {
                let _ = crate::ScopeDurationLogger::new(
                    &(crate::macros::fn_name!() + "::PeerMessage::BlockResponseBatch"),
                );

                debug!(
                    "handling block response batch with {} blocks",
                    t_blocks.len()
                );
                if t_blocks.len() < MINIMUM_BLOCK_BATCH_SIZE {
                    warn!("Got smaller batch response than allowed");
                    self.punish(PeerSanctionReason::TooShortBlockBatch).await?;
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                // Verify that we are in fact in syncing mode
                // TODO: Seperate peer messages into those allowed under syncing
                // and those that are not
                if !self.global_state_lock.lock_guard().await.net.syncing {
                    warn!("Received a batch of blocks without being in syncing mode");
                    self.punish(PeerSanctionReason::ReceivedBatchBlocksOutsideOfSync)
                        .await?;
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                // Verify that the response matches the current state
                // We get the latest block from the DB here since this message is
                // only valid for archival nodes.
                let first_blocks_parent_digest: Digest = t_blocks[0].header.prev_block_digest;
                let most_canonical_own_block_match: Option<Block> = self
                    .global_state_lock
                    .lock_guard()
                    .await
                    .chain
                    .archival_state()
                    .get_block(first_blocks_parent_digest)
                    .await
                    .expect("Block lookup must succeed");
                let most_canonical_own_block_match: Block = match most_canonical_own_block_match {
                    Some(block) => block,
                    None => {
                        warn!("Got batch reponse with invalid start height");
                        self.punish(PeerSanctionReason::BatchBlocksInvalidStartHeight)
                            .await?;
                        return Ok(KEEP_CONNECTION_ALIVE);
                    }
                };

                // Convert all blocks to Block objects
                debug!(
                    "Found own block of height {} to match received batch",
                    most_canonical_own_block_match.kernel.header.height
                );
                let received_blocks: Vec<Block> = t_blocks.into_iter().map(|x| x.into()).collect();

                // Get the latest block that we know of and handle all received blocks
                self.handle_blocks(received_blocks, most_canonical_own_block_match)
                    .await?;

                Ok(KEEP_CONNECTION_ALIVE)
            }
            PeerMessage::BlockNotificationRequest => {
                let _ = crate::ScopeDurationLogger::new(
                    &(crate::macros::fn_name!() + "::PeerMessage::BlockNotificationRequest"),
                );

                debug!("Got BlockNotificationRequest");

                peer.send(PeerMessage::BlockNotification(
                    (&self
                        .global_state_lock
                        .lock_guard()
                        .await
                        .chain
                        .light_state()
                        .kernel
                        .header)
                        .into(),
                ))
                .await?;

                Ok(KEEP_CONNECTION_ALIVE)
            }
            PeerMessage::BlockNotification(block_notification) => {
                let _ = crate::ScopeDurationLogger::new(
                    &(crate::macros::fn_name!() + "::PeerMessage::BlockNotification"),
                );

                debug!(
                    "Got BlockNotification of height {}",
                    block_notification.height
                );
                peer_state_info.highest_shared_block_height = block_notification.height;
                {
                    let block_is_new = self
                        .global_state_lock
                        .lock_guard()
                        .await
                        .chain
                        .light_state()
                        .kernel
                        .header
                        .cumulative_proof_of_work
                        < block_notification.cumulative_proof_of_work;

                    debug!("block_is_new: {}", block_is_new);

                    // Only request block if it is new, and if we are not currently reconciling
                    // a fork. If we are reconciling, that is handled later, and the information
                    // about that is stored in `highest_shared_block_height`. If we are syncing
                    // we are also not requesting the block but instead updating the sync state.
                    if self.global_state_lock.lock_guard().await.net.syncing {
                        debug!(
                            "ignoring peer block with height {} because we are presently syncing",
                            block_notification.height
                        );

                        self.to_main_tx
                            .send(PeerTaskToMain::AddPeerMaxBlockHeight((
                                self.peer_address,
                                block_notification.height,
                                block_notification.cumulative_proof_of_work,
                            )))
                            .await
                            .expect("Sending to main task must succeed");
                    } else if block_is_new && peer_state_info.fork_reconciliation_blocks.is_empty()
                    {
                        debug!(
                            "sending BlockRequestByHeight to peer for block with height {}",
                            block_notification.height
                        );
                        peer.send(PeerMessage::BlockRequestByHeight(block_notification.height))
                            .await?;
                    } else {
                        debug!(
                            "ignoring peer block. height {}. new: {}, reconciling_fork: {}",
                            block_notification.height,
                            block_is_new,
                            !peer_state_info.fork_reconciliation_blocks.is_empty()
                        );
                    }
                }

                Ok(KEEP_CONNECTION_ALIVE)
            }
            PeerMessage::BlockRequestByHash(block_digest) => {
                let _ = crate::ScopeDurationLogger::new(
                    &(crate::macros::fn_name!() + "::PeerMessage::BlockRequestByHash"),
                );

                match self
                    .global_state_lock
                    .lock_guard()
                    .await
                    .chain
                    .archival_state()
                    .get_block(block_digest)
                    .await?
                {
                    None => {
                        // TODO: Consider punishing here
                        warn!("Peer requested unkown block with hash {}", block_digest);
                        Ok(KEEP_CONNECTION_ALIVE)
                    }
                    Some(b) => {
                        peer.send(PeerMessage::Block(Box::new(b.try_into().unwrap())))
                            .await?;
                        Ok(KEEP_CONNECTION_ALIVE)
                    }
                }
            }
            PeerMessage::BlockRequestByHeight(block_height) => {
                let _ = crate::ScopeDurationLogger::new(
                    &(crate::macros::fn_name!() + "::PeerMessage::BlockRequestByHeight"),
                );

                debug!("Got BlockRequestByHeight of height {}", block_height);

                let block_digests = self
                    .global_state_lock
                    .lock_guard()
                    .await
                    .chain
                    .archival_state()
                    .block_height_to_block_digests(block_height)
                    .await;
                debug!("Found {} blocks", block_digests.len());

                if block_digests.is_empty() {
                    warn!("Got block request by height for unknown block");
                    self.punish(PeerSanctionReason::BlockRequestUnknownHeight)
                        .await?;
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                // If more than one block is found, we need to find the one that's canonical
                let mut canonical_chain_block_digest = block_digests[0];
                if block_digests.len() > 1 {
                    let global_state = self.global_state_lock.lock_guard().await;
                    let tip_digest = global_state.chain.light_state().hash();
                    for block_digest in block_digests {
                        if global_state
                            .chain
                            .archival_state()
                            .block_belongs_to_canonical_chain(block_digest, tip_digest)
                            .await
                        {
                            canonical_chain_block_digest = block_digest;
                        }
                    }
                }

                let canonical_chain_block: Block = self
                    .global_state_lock
                    .lock_guard()
                    .await
                    .chain
                    .archival_state()
                    .get_block(canonical_chain_block_digest)
                    .await?
                    .unwrap();
                let block_response: PeerMessage =
                    PeerMessage::Block(Box::new(canonical_chain_block.try_into().unwrap()));

                debug!("Sending block");
                peer.send(block_response).await?;
                debug!("Sent block");
                Ok(KEEP_CONNECTION_ALIVE)
            }
            PeerMessage::Handshake(_) => {
                let _ = crate::ScopeDurationLogger::new(
                    &(crate::macros::fn_name!() + "::PeerMessage::Handshake"),
                );
                self.punish(PeerSanctionReason::InvalidMessage).await?;
                Ok(KEEP_CONNECTION_ALIVE)
            }
            PeerMessage::ConnectionStatus(_) => {
                let _ = crate::ScopeDurationLogger::new(
                    &(crate::macros::fn_name!() + "::PeerMessage::ConnectionStatus"),
                );

                self.punish(PeerSanctionReason::InvalidMessage).await?;
                Ok(KEEP_CONNECTION_ALIVE)
            }
            PeerMessage::Transaction(transaction) => {
                let _ = crate::ScopeDurationLogger::new(
                    &(crate::macros::fn_name!() + "::PeerMessage::Transaction"),
                );

                debug!(
                    "`peer_loop` received following transaction from peer. {} inputs, {} outputs. Synced to mutator set hash: {}",
                    transaction.kernel.inputs.len(),
                    transaction.kernel.outputs.len(),
                    transaction.kernel.mutator_set_hash
                );

                let transaction: Transaction = (*transaction).into();

                // 1. If transaction is invalid, punish.
                if !transaction.is_valid().await {
                    warn!("Received invalid tx");
                    self.punish(PeerSanctionReason::InvalidTransaction).await?;
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                // 2. If transaction has coinbase, punish.
                // Transactions received from peers have not been mined yet.
                // Only the miner is allowed to produce transactions with non-empty coinbase fields.
                if transaction.kernel.coinbase.is_some() {
                    warn!("Received non-mined transaction with coinbase.");
                    self.punish(PeerSanctionReason::NonMinedTransactionHasCoinbase)
                        .await?;
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                // 3. If transaction is already known, ignore.
                if self
                    .global_state_lock
                    .lock_guard()
                    .await
                    .mempool
                    .contains_with_higher_proof_quality(
                        transaction.kernel.txid(),
                        transaction.proof.proof_quality()?,
                    )
                {
                    warn!("Received transaction that was already known");

                    // We received a transaction that we *probably* haven't requested.
                    // Consider punishing here, if this is abused.
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                // 4 if transaction is not confirmable, punish.
                let confirmable = transaction.is_confirmable_relative_to(
                    &self
                        .global_state_lock
                        .lock_guard()
                        .await
                        .chain
                        .light_state()
                        .kernel
                        .body
                        .mutator_set_accumulator,
                );
                if !confirmable {
                    warn!("Received unconfirmable tx");
                    self.punish(PeerSanctionReason::UnconfirmableTransaction)
                        .await?;
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                let tx_timestamp = transaction.kernel.timestamp;

                // 5. Ignore if transaction is too old
                let now = self.now();
                if tx_timestamp < now - Timestamp::seconds(MEMPOOL_TX_THRESHOLD_AGE_IN_SECS) {
                    // TODO: Consider punishing here
                    warn!("Received too old tx");
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                // 6. Ignore if transaction is too far into the future
                if tx_timestamp
                    > now + Timestamp::seconds(MEMPOOL_IGNORE_TRANSACTIONS_THIS_MANY_SECS_AHEAD)
                {
                    // TODO: Consider punishing here
                    warn!("Received tx too far into the future. Got timestamp: {tx_timestamp:?}");
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                // Otherwise relay to main
                let pt2m_transaction = PeerTaskToMainTransaction {
                    transaction,
                    confirmable_for_block: self
                        .global_state_lock
                        .lock_guard()
                        .await
                        .chain
                        .light_state()
                        .hash(),
                };
                self.to_main_tx
                    .send(PeerTaskToMain::Transaction(Box::new(pt2m_transaction)))
                    .await?;

                Ok(KEEP_CONNECTION_ALIVE)
            }
            PeerMessage::TransactionNotification(tx_notification) => {
                let _ = crate::ScopeDurationLogger::new(
                    &(crate::macros::fn_name!() + "::PeerMessage::TransactionNotification"),
                );

                // 1. Ignore if we already know this transaction, and
                // the proof quality is not higher than what we already know.
                let state = self.global_state_lock.lock_guard().await;
                let transaction_of_same_or_higher_proof_quality_is_known =
                    state.mempool.contains_with_higher_proof_quality(
                        tx_notification.txid,
                        tx_notification.proof_quality,
                    );
                if transaction_of_same_or_higher_proof_quality_is_known {
                    debug!("transaction with same or higher proof quality was already known");
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                // Only accept transactions that do not require executing
                // `update`.
                if state
                    .chain
                    .light_state()
                    .body()
                    .mutator_set_accumulator
                    .hash()
                    != tx_notification.mutator_set_hash
                {
                    debug!("transaction refers to non-canonical mutator set state");
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                // 2. Request the actual `Transaction` from peer
                debug!("requesting transaction from peer");
                peer.send(PeerMessage::TransactionRequest(tx_notification.txid))
                    .await?;

                Ok(KEEP_CONNECTION_ALIVE)
            }
            PeerMessage::TransactionRequest(transaction_identifier) => {
                let _ = crate::ScopeDurationLogger::new(
                    &(crate::macros::fn_name!() + "::PeerMessage::TransasctionRequest"),
                );

                if let Some(transaction) = self
                    .global_state_lock
                    .lock_guard()
                    .await
                    .mempool
                    .get(transaction_identifier)
                {
                    if let Ok(transfer_transaction) = transaction.try_into() {
                        peer.send(PeerMessage::Transaction(Box::new(transfer_transaction)))
                            .await?;
                    } else {
                        warn!("Peer requested transaction that cannot be converted to transfer object");
                    }
                }

                Ok(KEEP_CONNECTION_ALIVE)
            }
        }
    }

    /// Handle message from main task. The boolean return value indicates if
    /// the connection should be closed.
    ///
    /// Locking:
    ///   * acquires `global_state_lock` for write via Self::punish()
    async fn handle_main_task_message<S>(
        &mut self,
        msg: MainToPeerTask,
        peer: &mut S,
        peer_state_info: &mut MutablePeerState,
    ) -> Result<bool>
    where
        S: Sink<PeerMessage> + TryStream<Ok = PeerMessage> + Unpin,
        <S as Sink<PeerMessage>>::Error: std::error::Error + Sync + Send + 'static,
        <S as TryStream>::Error: std::error::Error,
    {
        debug!("Handling {} message from main in peer loop", msg.get_type());
        match msg {
            MainToPeerTask::Block(block) => {
                let _ = crate::ScopeDurationLogger::new(
                    &(crate::macros::fn_name!() + "::MainToPeerTask::Block"),
                );

                // We don't currently differentiate whether a new block came from a peer, or from our
                // own miner. It's always shared through this logic.
                let new_block_height = block.kernel.header.height;
                if new_block_height > peer_state_info.highest_shared_block_height {
                    debug!("Sending PeerMessage::BlockNotification");
                    peer_state_info.highest_shared_block_height = new_block_height;
                    peer.send(PeerMessage::BlockNotification((*block).into()))
                        .await?;
                    debug!("Sent PeerMessage::BlockNotification");
                }
                Ok(KEEP_CONNECTION_ALIVE)
            }
            MainToPeerTask::RequestBlockBatch(batch_block_request) => {
                let _ = crate::ScopeDurationLogger::new(
                    &(crate::macros::fn_name!() + "::MainToPeerTask::RequestBlockBatch"),
                );

                // Only ask one of the peers about the batch of blocks
                if batch_block_request.peer_addr_target != self.peer_address {
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                let max_response_len = std::cmp::min(
                    STANDARD_BLOCK_BATCH_SIZE,
                    self.global_state_lock
                        .cli()
                        .max_number_of_blocks_before_syncing,
                );

                peer.send(PeerMessage::BlockRequestBatch(BlockRequestBatch {
                    known_blocks: batch_block_request.known_blocks,
                    max_response_len,
                }))
                .await?;

                Ok(KEEP_CONNECTION_ALIVE)
            }
            MainToPeerTask::PeerSynchronizationTimeout(socket_addr) => {
                let _ = crate::ScopeDurationLogger::new(
                    &(crate::macros::fn_name!() + "::MainToPeerTask::PeerSynchronizationTimeout"),
                );

                if self.peer_address != socket_addr {
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                self.punish(PeerSanctionReason::SynchronizationTimeout)
                    .await?;

                // If this peer failed the last synchronization attempt, we only
                // sanction, we don't disconnect.
                Ok(KEEP_CONNECTION_ALIVE)
            }
            MainToPeerTask::MakePeerDiscoveryRequest => {
                let _ = crate::ScopeDurationLogger::new(
                    &(crate::macros::fn_name!() + "::MainToPeerTask::MakePeerDiscoveryRequest"),
                );

                peer.send(PeerMessage::PeerListRequest).await?;
                Ok(KEEP_CONNECTION_ALIVE)
            }
            MainToPeerTask::Disconnect(target_socket_addr) => {
                let _ = crate::ScopeDurationLogger::new(
                    &(crate::macros::fn_name!() + "::MainToPeerTask::Disconnect"),
                );

                // Disconnect from this peer if its address matches that which the main
                // task requested to disconnect from.
                Ok(target_socket_addr == self.peer_address)
            }
            // Disconnect from this peer, no matter what.
            MainToPeerTask::DisconnectAll() => Ok(true),
            MainToPeerTask::MakeSpecificPeerDiscoveryRequest(target_socket_addr) => {
                let _ = crate::ScopeDurationLogger::new(
                    &(crate::macros::fn_name!()
                        + "::MainToPeerTask::MakeSpecificPeerDiscoveryRequest"),
                );

                if target_socket_addr == self.peer_address {
                    peer.send(PeerMessage::PeerListRequest).await?;
                }
                Ok(KEEP_CONNECTION_ALIVE)
            }
            MainToPeerTask::TransactionNotification(transaction_notification) => {
                let _ = crate::ScopeDurationLogger::new(
                    &(crate::macros::fn_name!() + "::MainToPeerTask::TransactionNotification"),
                );

                debug!("Sending PeerMessage::TransactionNotification");
                peer.send(PeerMessage::TransactionNotification(
                    transaction_notification,
                ))
                .await?;
                debug!("Sent PeerMessage::TransactionNotification");
                Ok(KEEP_CONNECTION_ALIVE)
            }
        }
    }

    /// Loop for the peer tasks. Awaits either a message from the peer over TCP,
    /// or a message from main over the main-to-peer-tasks broadcast channel.
    async fn run<S>(
        &mut self,
        mut peer: S,
        mut from_main_rx: broadcast::Receiver<MainToPeerTask>,
        peer_state_info: &mut MutablePeerState,
    ) -> Result<()>
    where
        S: Sink<PeerMessage> + TryStream<Ok = PeerMessage> + Unpin,
        <S as Sink<PeerMessage>>::Error: std::error::Error + Sync + Send + 'static,
        <S as TryStream>::Error: std::error::Error,
    {
        loop {
            select! {
                // Handle peer messages
                peer_message = peer.try_next() => {
                    match peer_message {
                        Ok(peer_message) => {
                            match peer_message {
                                None => {
                                    info!("Peer closed connection.");
                                    break;
                                }
                                Some(peer_msg) => {
                                    let syncing = self.global_state_lock.lock(|s| s.net.syncing).await;
                                    if peer_msg.ignore_during_sync() && syncing {
                                        debug!("Ignoring {} message during syncing, from {}", peer_msg.get_type(), self.peer_address);
                                        continue;
                                    }
                                    if peer_msg.ignore_when_not_sync() && !syncing {
                                        debug!("Ignoring {} message because we are not syncing, from {}", peer_msg.get_type(), self.peer_address);
                                        continue;
                                    }
                                    let close_connection: bool = match self.handle_peer_message(peer_msg, &mut peer, peer_state_info).await {
                                        Ok(close) => close,
                                        Err(err) => {
                                            warn!("{}. Closing connection.", err);
                                            bail!("{}", err);
                                        }
                                    };

                                    if close_connection {
                                        info!("Closing connection to {}", self.peer_address);
                                        break;
                                    }
                                }
                            }
                        }
                        Err(err) => {
                            error!("Error when receiving from peer: {}. Error: {err}", self.peer_address);
                            bail!("Error when receiving from peer: {}. Closing connection:", err);
                        }
                    }
                }

                // Handle messages from main task
                main_msg_res = from_main_rx.recv() => {
                    let close_connection = match main_msg_res {
                        Ok(main_msg) => match self.handle_main_task_message(main_msg, &mut peer, peer_state_info).await {
                            Ok(close) => close,

                            // If the handler of main-task messages returns error, the connection is closed.
                            // This might indicate that the peer got banned.
                            Err(err) => {
                                warn!("handle_main_task_message returned an eror: {}", err);
                                true
                            },
                        }
                        Err(e) => panic!("Failed to read from main loop: {}", e),
                    };

                    if close_connection {
                        info!("handle_main_task_message is closing the connection to {}", self.peer_address);
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    /// Function called before entering the peer loop. Reads the potentially stored
    /// peer standing from the database and does other book-keeping before entering
    /// its final resting place: the `peer_loop`. Note that the peer has already been
    /// accepted for a connection for this loop to be entered. So we don't need
    /// to check the standing again.
    ///
    /// Locking:
    ///   * acquires `global_state_lock` for write
    pub(crate) async fn run_wrapper<S>(
        &mut self,
        mut peer: S,
        from_main_rx: broadcast::Receiver<MainToPeerTask>,
    ) -> Result<()>
    where
        S: Sink<PeerMessage> + TryStream<Ok = PeerMessage> + Unpin,
        <S as Sink<PeerMessage>>::Error: std::error::Error + Sync + Send + 'static,
        <S as TryStream>::Error: std::error::Error,
    {
        let global_state = self.global_state_lock.lock_guard().await;
        // Check if peer standing exists in database, return default if it does not.
        let standing: PeerStanding = global_state
            .net
            .peer_databases
            .peer_standings
            .get(self.peer_address.ip())
            .await
            .unwrap_or_default();

        // Add peer to peer map
        let new_peer = PeerInfo {
            port_for_incoming_connections: self.peer_handshake_data.listen_port,
            connected_address: self.peer_address,
            inbound: self.inbound_connection,
            instance_id: self.peer_handshake_data.instance_id,
            last_seen: SystemTime::now(),
            standing,
            version: self.peer_handshake_data.version.clone(),
            is_archival_node: self.peer_handshake_data.is_archival_node,
        };

        // There is potential for a race-condition in the peer_map here, as we've previously
        // counted the number of entries and checked if instance ID was already connected. But
        // this check could have been invalidated by other tasks so we perform it again

        if global_state
            .net
            .peer_map
            .values()
            .any(|pi| pi.instance_id == self.peer_handshake_data.instance_id)
        {
            bail!("Attempted to connect to already connected peer. Aborting connection.");
        }

        if global_state.net.peer_map.len() >= global_state.cli().max_peers as usize {
            bail!("Attempted to connect to more peers than allowed. Aborting connection.");
        }

        if global_state.net.peer_map.contains_key(&self.peer_address) {
            // This shouldn't be possible, unless the peer reports a different instance ID than
            // for the other connection. Only a malignant client would do that.
            bail!("Already connected to peer. Aborting connection");
        }
        drop(global_state);

        self.global_state_lock
            .lock_mut(|s| s.net.peer_map.insert(self.peer_address, new_peer))
            .await;

        // This message is used to determine if we are to enter synchronization mode.
        self.to_main_tx
            .send(PeerTaskToMain::AddPeerMaxBlockHeight((
                self.peer_address,
                self.peer_handshake_data.tip_header.height,
                self.peer_handshake_data.tip_header.cumulative_proof_of_work,
            )))
            .await?;

        // `MutablePeerState` contains the part of the peer-loop's state that is mutable
        let mut peer_state = MutablePeerState::new(self.peer_handshake_data.tip_header.height);

        // If peer indicates more canonical block, request a block notification to catch up ASAP
        if self.peer_handshake_data.tip_header.cumulative_proof_of_work
            > self
                .global_state_lock
                .lock_guard()
                .await
                .chain
                .light_state()
                .kernel
                .header
                .cumulative_proof_of_work
        {
            peer.send(PeerMessage::BlockNotificationRequest).await?;
        }

        let res = self.run(peer, from_main_rx, &mut peer_state).await;
        debug!("Exited peer loop for {}", self.peer_address);

        close_peer_connected_callback(
            self.global_state_lock.clone(),
            self.peer_address,
            &self.to_main_tx,
        )
        .await?;

        debug!("Ending peer loop for {}", self.peer_address);

        // Return any error that `run` returned. Returning and not suppressing errors is a quite nice
        // feature to have for testing purposes.
        res
    }
}

#[cfg(test)]
mod peer_loop_tests {
    use num_traits::Zero;
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::SeedableRng;
    use tasm_lib::twenty_first::bfe;
    use tokio::sync::mpsc::error::TryRecvError;
    use tracing_test::traced_test;

    use super::*;
    use crate::config_models::network::Network;
    use crate::models::blockchain::transaction::transaction_output::UtxoNotificationMedium;
    use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
    use crate::models::peer::transaction_notification::TransactionNotification;
    use crate::models::proof_abstractions::tasm::program::TritonProverSync;
    use crate::models::state::tx_proving_capability::TxProvingCapability;
    use crate::models::state::wallet::WalletSecret;
    use crate::tests::shared::get_dummy_peer_connection_data_genesis;
    use crate::tests::shared::get_dummy_socket_address;
    use crate::tests::shared::get_test_genesis_setup;
    use crate::tests::shared::valid_block_for_tests;
    use crate::tests::shared::valid_sequence_of_blocks_for_tests;
    use crate::tests::shared::Action;
    use crate::tests::shared::Mock;
    use crate::BFieldElement;

    #[traced_test]
    #[tokio::test]
    async fn test_peer_loop_bye() -> Result<()> {
        let mock = Mock::new(vec![Action::Read(PeerMessage::Bye)]);

        let (peer_broadcast_tx, _from_main_rx_clone, to_main_tx, _to_main_rx1, state_lock, hsd) =
            get_test_genesis_setup(Network::Alpha, 2).await?;

        let peer_address = get_dummy_socket_address(2);
        let from_main_rx_clone = peer_broadcast_tx.subscribe();
        let mut peer_loop_handler =
            PeerLoopHandler::new(to_main_tx, state_lock.clone(), peer_address, hsd, true, 1);
        peer_loop_handler
            .run_wrapper(mock, from_main_rx_clone)
            .await?;

        assert_eq!(
            2,
            state_lock.lock_guard().await.net.peer_map.len(),
            "peer map length must be back to 2 after goodbye"
        );

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn test_peer_loop_peer_list() {
        let (peer_broadcast_tx, _from_main_rx_clone, to_main_tx, _to_main_rx1, state_lock, _hsd) =
            get_test_genesis_setup(Network::Alpha, 2).await.unwrap();

        let mut peer_infos = state_lock
            .lock_guard()
            .await
            .net
            .peer_map
            .clone()
            .into_values()
            .collect::<Vec<_>>();
        peer_infos.sort_by_cached_key(|x| x.connected_address);
        let (peer_address0, instance_id0) =
            (peer_infos[0].connected_address, peer_infos[0].instance_id);
        let (peer_address1, instance_id1) =
            (peer_infos[1].connected_address, peer_infos[1].instance_id);

        let (hsd2, sa2) = get_dummy_peer_connection_data_genesis(Network::Alpha, 2).await;
        let expected_response = vec![
            (peer_address0, instance_id0),
            (peer_address1, instance_id1),
            (sa2, hsd2.instance_id),
        ];
        let mock = Mock::new(vec![
            Action::Read(PeerMessage::PeerListRequest),
            Action::Write(PeerMessage::PeerListResponse(expected_response)),
            Action::Read(PeerMessage::Bye),
        ]);

        let from_main_rx_clone = peer_broadcast_tx.subscribe();

        let mut peer_loop_handler =
            PeerLoopHandler::new(to_main_tx, state_lock.clone(), sa2, hsd2, true, 0);
        peer_loop_handler
            .run_wrapper(mock, from_main_rx_clone)
            .await
            .unwrap();

        assert_eq!(
            2,
            state_lock.lock_guard().await.net.peer_map.len(),
            "peer map must have length 2 after saying goodbye to peer 2"
        );
    }

    #[traced_test]
    #[tokio::test]
    async fn different_genesis_test() -> Result<()> {
        // In this scenario a peer provides another genesis block than what has been
        // hardcoded. This should lead to the closing of the connection to this peer
        // and a ban.

        let network = Network::Main;
        let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, mut to_main_rx1, state_lock, hsd) =
            get_test_genesis_setup(network, 0).await?;
        let peer_address = get_dummy_socket_address(0);

        // Although the database is empty, `get_latest_block` still returns the genesis block,
        // since that block is hardcoded.
        let mut different_genesis_block = state_lock
            .lock_guard()
            .await
            .chain
            .archival_state()
            .get_tip()
            .await;
        let mut nonce = different_genesis_block.kernel.header.nonce;
        nonce[2].increment();
        different_genesis_block.set_header_nonce(nonce);
        let [block_1_with_different_genesis] = valid_sequence_of_blocks_for_tests(
            &different_genesis_block,
            Timestamp::hours(1),
            StdRng::seed_from_u64(5550001).gen(),
        )
        .await;
        let mock = Mock::new(vec![Action::Read(PeerMessage::Block(Box::new(
            block_1_with_different_genesis.try_into().unwrap(),
        )))]);

        let mut peer_loop_handler = PeerLoopHandler::new(
            to_main_tx.clone(),
            state_lock.clone(),
            peer_address,
            hsd,
            true,
            1,
        );
        let res = peer_loop_handler
            .run_wrapper(mock, from_main_rx_clone)
            .await;
        assert!(
            res.is_err(),
            "run_wrapper must return failure when genesis is different"
        );

        // Verify that max peer height was sent
        match to_main_rx1.recv().await {
            Some(PeerTaskToMain::AddPeerMaxBlockHeight(_)) => (),
            _ => bail!("Must receive add of peer block max height"),
        }

        match to_main_rx1.recv().await {
            Some(PeerTaskToMain::RemovePeerMaxBlockHeight(_)) => (),
            _ => bail!("Must receive remove of peer block max height"),
        }

        // Verify that no futher message was sent to main loop
        match to_main_rx1.try_recv() {
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => (),
            _ => bail!("Block notification must not be sent for block with invalid PoW"),
        };

        drop(to_main_tx);

        let peer_standing = state_lock
            .lock_guard()
            .await
            .net
            .get_peer_standing_from_database(peer_address.ip())
            .await;
        assert_eq!(-(u16::MAX as i32), peer_standing.unwrap().standing);
        assert_eq!(
            PeerSanctionReason::DifferentGenesis,
            peer_standing.unwrap().latest_sanction.unwrap()
        );

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn block_without_valid_pow_test() -> Result<()> {
        // In this scenario, a block without a valid PoW is received. This block should be rejected
        // by the peer loop and a notification should never reach the main loop.

        let network = Network::Main;
        let (peer_broadcast_tx, _from_main_rx_clone, to_main_tx, mut to_main_rx1, state_lock, hsd) =
            get_test_genesis_setup(network, 0).await?;
        let peer_address = get_dummy_socket_address(0);
        let genesis_block: Block = state_lock
            .lock_guard()
            .await
            .chain
            .archival_state()
            .get_tip()
            .await;

        // Make a with hash above what the implied threshold from
        let [mut block_without_valid_pow] = valid_sequence_of_blocks_for_tests(
            &genesis_block,
            Timestamp::hours(1),
            StdRng::seed_from_u64(5550001).gen(),
        )
        .await;

        // This *probably* is invalid PoW -- and needs to be for this test to
        // work.
        block_without_valid_pow.set_header_nonce([bfe!(1), bfe!(2), bfe!(3)]);

        // Sending an invalid block will not neccessarily result in a ban. This depends on the peer
        // tolerance that is set in the client. For this reason, we include a "Bye" here.
        let mock = Mock::new(vec![
            Action::Read(PeerMessage::Block(Box::new(
                block_without_valid_pow.clone().try_into().unwrap(),
            ))),
            Action::Read(PeerMessage::Bye),
        ]);

        let from_main_rx_clone = peer_broadcast_tx.subscribe();

        let mut peer_loop_handler = PeerLoopHandler::with_mocked_time(
            to_main_tx.clone(),
            state_lock.clone(),
            peer_address,
            hsd,
            true,
            1,
            block_without_valid_pow.header().timestamp,
        );
        peer_loop_handler
            .run_wrapper(mock, from_main_rx_clone)
            .await
            .expect("sending (one) invalid block should not result in closed connection");

        // Verify that max peer height was sent
        match to_main_rx1.recv().await {
            Some(PeerTaskToMain::AddPeerMaxBlockHeight(_)) => (),
            _ => bail!("Must receive add of peer block max height"),
        }

        match to_main_rx1.recv().await {
            Some(PeerTaskToMain::RemovePeerMaxBlockHeight(_)) => (),
            _ => bail!("Must receive remove of peer block max height"),
        }

        // Verify that no futher message was sent to main loop
        match to_main_rx1.try_recv() {
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => (),
            _ => bail!("Block notification must not be sent for block with invalid PoW"),
        };

        // We need to have the transmitter in scope until we have received from it
        // otherwise the receiver will report the disconnected error when we attempt
        // to read from it. And the purpose is to verify that the channel is empty,
        // not that it has been closed.
        drop(to_main_tx);

        // Verify that peer standing was stored in database
        let standing = state_lock
            .lock_guard()
            .await
            .net
            .peer_databases
            .peer_standings
            .get(peer_address.ip())
            .await
            .unwrap();
        assert!(
            standing.standing < 0,
            "Peer must be sanctioned for sending a bad block"
        );

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn test_peer_loop_block_with_block_in_db() -> Result<()> {
        // The scenario tested here is that a client receives a block that is already
        // known and stored. The expected behavior is to ignore the block and not send
        // a message to the main task.

        let network = Network::Main;
        let (peer_broadcast_tx, _from_main_rx_clone, to_main_tx, mut to_main_rx1, mut alice, hsd) =
            get_test_genesis_setup(network, 0).await?;
        let peer_address = get_dummy_socket_address(0);
        let genesis_block: Block = Block::genesis_block(network);

        let fee = NeptuneCoins::zero();
        let now = genesis_block.header().timestamp + Timestamp::hours(1);
        let block_1 =
            valid_block_for_tests(&alice, fee, now, StdRng::seed_from_u64(5550001).gen()).await;
        assert!(
            block_1.is_valid(&genesis_block, now),
            "Block must be valid for this test to make sense"
        );
        alice.set_new_tip(block_1.clone()).await?;

        let mock_peer_messages = Mock::new(vec![
            Action::Read(PeerMessage::Block(Box::new(
                block_1.clone().try_into().unwrap(),
            ))),
            Action::Read(PeerMessage::Bye),
        ]);

        let from_main_rx_clone = peer_broadcast_tx.subscribe();

        let mut alice_peer_loop_handler = PeerLoopHandler::with_mocked_time(
            to_main_tx.clone(),
            alice.clone(),
            peer_address,
            hsd,
            false,
            1,
            block_1.header().timestamp,
        );
        alice_peer_loop_handler
            .run_wrapper(mock_peer_messages, from_main_rx_clone)
            .await?;

        // Verify that no block was sent to main loop
        match to_main_rx1.recv().await {
            Some(PeerTaskToMain::AddPeerMaxBlockHeight(_)) => (),
            _ => bail!("Must receive add of peer block max height"),
        }
        match to_main_rx1.recv().await {
            Some(PeerTaskToMain::RemovePeerMaxBlockHeight(_)) => (),
            other => bail!("Must receive remove of peer block max height. Got:\n {other:?}"),
        }
        match to_main_rx1.try_recv() {
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => (),
            _ => bail!("Block notification must not be sent for block with invalid PoW"),
        };
        drop(to_main_tx);

        if !alice.lock_guard().await.net.peer_map.is_empty() {
            bail!("peer map must be empty after closing connection gracefully");
        }

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn block_request_batch_in_order_test() -> Result<()> {
        // Scenario: A fork began at block 2, node knows two blocks of height 2 and two of height 3.
        // A peer requests a batch of blocks starting from block 1. Ensure that the correct blocks
        // are returned.

        let network = Network::Main;
        let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, _to_main_rx1, mut state_lock, hsd) =
            get_test_genesis_setup(network, 0).await?;
        let genesis_block: Block = Block::genesis_block(network);
        let peer_address = get_dummy_socket_address(0);
        let [block_1, block_2_a, block_3_a] = valid_sequence_of_blocks_for_tests(
            &genesis_block,
            Timestamp::hours(1),
            StdRng::seed_from_u64(5550001).gen(),
        )
        .await;
        let [block_2_b, block_3_b] = valid_sequence_of_blocks_for_tests(
            &block_1,
            Timestamp::hours(1),
            StdRng::seed_from_u64(5550002).gen(),
        )
        .await;
        assert_ne!(block_2_b.hash(), block_2_a.hash());

        state_lock.set_new_tip(block_1.clone()).await?;
        state_lock.set_new_tip(block_2_a.clone()).await?;
        state_lock.set_new_tip(block_2_b.clone()).await?;
        state_lock.set_new_tip(block_3_b.clone()).await?;
        state_lock.set_new_tip(block_3_a.clone()).await?;

        let mut mock = Mock::new(vec![
            Action::Read(PeerMessage::BlockRequestBatch(BlockRequestBatch {
                known_blocks: vec![genesis_block.hash()],
                max_response_len: 14,
            })),
            Action::Write(PeerMessage::BlockResponseBatch(vec![
                block_1.clone().try_into().unwrap(),
                block_2_a.clone().try_into().unwrap(),
                block_3_a.clone().try_into().unwrap(),
            ])),
            Action::Read(PeerMessage::Bye),
        ]);

        let mut peer_loop_handler_1 = PeerLoopHandler::with_mocked_time(
            to_main_tx.clone(),
            state_lock.clone(),
            peer_address,
            hsd.clone(),
            false,
            1,
            block_3_a.header().timestamp,
        );

        peer_loop_handler_1
            .run_wrapper(mock, from_main_rx_clone.resubscribe())
            .await?;

        // Peer knows block 2_b, verify that canonical chain with 2_a is returned
        mock = Mock::new(vec![
            Action::Read(PeerMessage::BlockRequestBatch(BlockRequestBatch {
                known_blocks: vec![block_2_b.hash(), block_1.hash(), genesis_block.hash()],
                max_response_len: 14,
            })),
            Action::Write(PeerMessage::BlockResponseBatch(vec![
                block_2_a.try_into().unwrap(),
                block_3_a.clone().try_into().unwrap(),
            ])),
            Action::Read(PeerMessage::Bye),
        ]);

        let mut peer_loop_handler_2 = PeerLoopHandler::with_mocked_time(
            to_main_tx.clone(),
            state_lock.clone(),
            peer_address,
            hsd,
            false,
            1,
            block_3_a.header().timestamp,
        );

        peer_loop_handler_2
            .run_wrapper(mock, from_main_rx_clone)
            .await?;

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn block_request_batch_out_of_order_test() -> Result<()> {
        // Scenario: A fork began at block 2, node knows two blocks of height 2 and two of height 3.
        // A peer requests a batch of blocks starting from block 1, but the peer supplies their
        // hashes in a wrong order. Ensure that the correct blocks are returned, in the right order.
        // The blocks will be supplied in the correct order but starting from the first digest in
        // the list that is known and canonical.

        let network = Network::Main;
        let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, _to_main_rx1, mut state_lock, hsd) =
            get_test_genesis_setup(network, 0).await?;
        let genesis_block = Block::genesis_block(network);
        let peer_address = get_dummy_socket_address(0);
        let [block_1, block_2_a, block_3_a] = valid_sequence_of_blocks_for_tests(
            &genesis_block,
            Timestamp::hours(1),
            StdRng::seed_from_u64(5550001).gen(),
        )
        .await;
        let [block_2_b, block_3_b] = valid_sequence_of_blocks_for_tests(
            &block_1,
            Timestamp::hours(1),
            StdRng::seed_from_u64(5550002).gen(),
        )
        .await;
        assert_ne!(block_2_a.hash(), block_2_b.hash());

        state_lock.set_new_tip(block_1.clone()).await?;
        state_lock.set_new_tip(block_2_a.clone()).await?;
        state_lock.set_new_tip(block_2_b.clone()).await?;
        state_lock.set_new_tip(block_3_b.clone()).await?;
        state_lock.set_new_tip(block_3_a.clone()).await?;

        // Peer knows block 2_b, verify that canonical chain with 2_a is returned
        let mock = Mock::new(vec![
            Action::Read(PeerMessage::BlockRequestBatch(BlockRequestBatch {
                known_blocks: vec![block_2_b.hash(), genesis_block.hash(), block_1.hash()],
                max_response_len: 14,
            })),
            // Since genesis block is the 1st known in the list of known blocks,
            // it's immediate descendent, block_1, is the first one returned.
            Action::Write(PeerMessage::BlockResponseBatch(vec![
                block_1.try_into().unwrap(),
                block_2_a.try_into().unwrap(),
                block_3_a.clone().try_into().unwrap(),
            ])),
            Action::Read(PeerMessage::Bye),
        ]);

        let mut peer_loop_handler_2 = PeerLoopHandler::with_mocked_time(
            to_main_tx.clone(),
            state_lock.clone(),
            peer_address,
            hsd,
            false,
            1,
            block_3_a.header().timestamp,
        );

        peer_loop_handler_2
            .run_wrapper(mock, from_main_rx_clone)
            .await?;

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn find_canonical_chain_when_multiple_blocks_at_same_height_test() -> Result<()> {
        // Scenario: A fork began at block 2, node knows two blocks of height 2 and two of height 3.
        // A peer requests a block at height 2. Verify that the correct block at height 2 is
        // returned.

        let network = Network::Main;
        let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, _to_main_rx1, mut state_lock, hsd) =
            get_test_genesis_setup(network, 0).await?;
        let genesis_block = Block::genesis_block(network);
        let peer_address = get_dummy_socket_address(0);

        let [block_1, block_2_a, block_3_a] = valid_sequence_of_blocks_for_tests(
            &genesis_block,
            Timestamp::hours(1),
            StdRng::seed_from_u64(5550001).gen(),
        )
        .await;
        let [block_2_b, block_3_b] = valid_sequence_of_blocks_for_tests(
            &block_1,
            Timestamp::hours(1),
            StdRng::seed_from_u64(5550002).gen(),
        )
        .await;
        assert_ne!(block_2_a.hash(), block_2_b.hash());

        state_lock.set_new_tip(block_1.clone()).await?;
        state_lock.set_new_tip(block_2_a.clone()).await?;
        state_lock.set_new_tip(block_2_b.clone()).await?;
        state_lock.set_new_tip(block_3_b.clone()).await?;
        state_lock.set_new_tip(block_3_a.clone()).await?;

        let mock = Mock::new(vec![
            Action::Read(PeerMessage::BlockRequestByHeight(2.into())),
            Action::Write(PeerMessage::Block(Box::new(block_2_a.try_into().unwrap()))),
            Action::Read(PeerMessage::BlockRequestByHeight(3.into())),
            Action::Write(PeerMessage::Block(Box::new(
                block_3_a.clone().try_into().unwrap(),
            ))),
            Action::Read(PeerMessage::Bye),
        ]);

        let mut peer_loop_handler = PeerLoopHandler::with_mocked_time(
            to_main_tx.clone(),
            state_lock.clone(),
            peer_address,
            hsd,
            false,
            1,
            block_3_a.header().timestamp,
        );

        // This will return error if seen read/write order does not match that of the
        // mocked object.
        peer_loop_handler
            .run_wrapper(mock, from_main_rx_clone)
            .await?;

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn test_peer_loop_receival_of_first_block() -> Result<()> {
        // Scenario: client only knows genesis block. Then receives block 1.

        let network = Network::Main;
        let mut rng = StdRng::seed_from_u64(5550001);
        let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, mut to_main_rx1, state_lock, hsd) =
            get_test_genesis_setup(network, 0).await?;
        let peer_address = get_dummy_socket_address(0);
        let genesis_block: Block = state_lock
            .lock_guard()
            .await
            .chain
            .archival_state()
            .get_tip()
            .await;

        let now = genesis_block.header().timestamp + Timestamp::hours(2);
        let fee = NeptuneCoins::zero();
        let block_1 = valid_block_for_tests(&state_lock, fee, now, rng.gen()).await;

        let mock = Mock::new(vec![
            Action::Read(PeerMessage::Block(Box::new(
                block_1.clone().try_into().unwrap(),
            ))),
            Action::Read(PeerMessage::Bye),
        ]);

        let mut peer_loop_handler = PeerLoopHandler::with_mocked_time(
            to_main_tx.clone(),
            state_lock.clone(),
            peer_address,
            hsd,
            false,
            1,
            block_1.header().timestamp,
        );
        peer_loop_handler
            .run_wrapper(mock, from_main_rx_clone)
            .await?;

        // Verify that peer max block height was sent
        match to_main_rx1.recv().await {
            Some(PeerTaskToMain::AddPeerMaxBlockHeight(_)) => (),
            _ => bail!("Must receive add of peer block max height"),
        }

        // Verify that a block was sent to `main_loop`
        match to_main_rx1.recv().await {
            Some(PeerTaskToMain::NewBlocks(_block)) => (),
            _ => bail!("Did not find msg sent to main task"),
        };

        match to_main_rx1.recv().await {
            Some(PeerTaskToMain::RemovePeerMaxBlockHeight(_)) => (),
            _ => bail!("Must receive remove of peer block max height"),
        }

        if !state_lock.lock_guard().await.net.peer_map.is_empty() {
            bail!("peer map must be empty after closing connection gracefully");
        }

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn test_peer_loop_receival_of_second_block_no_blocks_in_db() -> Result<()> {
        // In this scenario, the client only knows the genesis block (block 0) and then
        // receives block 2, meaning that block 1 will have to be requested.

        let network = Network::Main;
        let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, mut to_main_rx1, state_lock, hsd) =
            get_test_genesis_setup(network, 0).await?;
        let peer_address = get_dummy_socket_address(0);
        let genesis_block: Block = state_lock
            .lock_guard()
            .await
            .chain
            .archival_state()
            .get_tip()
            .await;
        let [block_1, block_2] = valid_sequence_of_blocks_for_tests(
            &genesis_block,
            Timestamp::hours(1),
            StdRng::seed_from_u64(5550001).gen(),
        )
        .await;

        let mock = Mock::new(vec![
            Action::Read(PeerMessage::Block(Box::new(
                block_2.clone().try_into().unwrap(),
            ))),
            Action::Write(PeerMessage::BlockRequestByHash(block_1.hash())),
            Action::Read(PeerMessage::Block(Box::new(
                block_1.clone().try_into().unwrap(),
            ))),
            Action::Read(PeerMessage::Bye),
        ]);

        let mut peer_loop_handler = PeerLoopHandler::with_mocked_time(
            to_main_tx.clone(),
            state_lock.clone(),
            peer_address,
            hsd,
            true,
            1,
            block_2.header().timestamp,
        );
        peer_loop_handler
            .run_wrapper(mock, from_main_rx_clone)
            .await?;

        // Verify that peer max block height was sent
        match to_main_rx1.recv().await {
            Some(PeerTaskToMain::AddPeerMaxBlockHeight(_)) => (),
            _ => bail!("Must receive peer block max height"),
        }

        match to_main_rx1.recv().await {
            Some(PeerTaskToMain::NewBlocks(blocks)) => {
                if blocks[0].hash() != block_1.hash() {
                    bail!("1st received block by main loop must be block 1");
                }
                if blocks[1].hash() != block_2.hash() {
                    bail!("2nd received block by main loop must be block 2");
                }
            }
            _ => bail!("Did not find msg sent to main task 1"),
        };
        match to_main_rx1.recv().await {
            Some(PeerTaskToMain::RemovePeerMaxBlockHeight(_)) => (),
            _ => bail!("Must receive remove of peer block max height"),
        }

        if !state_lock.lock_guard().await.net.peer_map.is_empty() {
            bail!("peer map must be empty after closing connection gracefully");
        }

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn prevent_ram_exhaustion_test() -> Result<()> {
        // In this scenario the peer sends more blocks than the client allows to store in the
        // fork-reconciliation field. This should result in abandonment of the fork-reconciliation
        // process as the alternative is that the program will crash because it runs out of RAM.

        let network = Network::Main;
        let mut rng = StdRng::seed_from_u64(5550001);
        let (
            _peer_broadcast_tx,
            from_main_rx_clone,
            to_main_tx,
            mut to_main_rx1,
            mut state_lock,
            _hsd,
        ) = get_test_genesis_setup(network, 1).await?;
        let genesis_block = Block::genesis_block(network);

        // Restrict max number of blocks held in memory to 2.
        let mut cli = state_lock.cli().clone();
        cli.max_number_of_blocks_before_syncing = 2;
        state_lock.set_cli(cli).await;

        let (hsd1, peer_address1) = get_dummy_peer_connection_data_genesis(Network::Alpha, 1).await;
        let [block_1, _block_2, block_3, block_4] =
            valid_sequence_of_blocks_for_tests(&genesis_block, Timestamp::hours(1), rng.gen())
                .await;
        state_lock.set_new_tip(block_1.clone()).await?;

        let mock = Mock::new(vec![
            Action::Read(PeerMessage::Block(Box::new(
                block_4.clone().try_into().unwrap(),
            ))),
            Action::Write(PeerMessage::BlockRequestByHash(block_3.hash())),
            Action::Read(PeerMessage::Block(Box::new(
                block_3.clone().try_into().unwrap(),
            ))),
            Action::Read(PeerMessage::Bye),
        ]);

        let mut peer_loop_handler = PeerLoopHandler::with_mocked_time(
            to_main_tx.clone(),
            state_lock.clone(),
            peer_address1,
            hsd1,
            true,
            1,
            block_4.header().timestamp,
        );
        peer_loop_handler
            .run_wrapper(mock, from_main_rx_clone)
            .await?;

        // Verify that peer max block height was sent
        match to_main_rx1.recv().await {
            Some(PeerTaskToMain::AddPeerMaxBlockHeight(_)) => (),
            _ => bail!("Must receive add of peer block max height"),
        }
        match to_main_rx1.recv().await {
            Some(PeerTaskToMain::RemovePeerMaxBlockHeight(_)) => (),
            _ => bail!("Must receive remove of peer block max height"),
        }

        // Verify that no block is sent to main loop.
        match to_main_rx1.try_recv() {
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => (),
            _ => bail!("Peer must not handle more fork-reconciliation blocks than specified in CLI arguments"),
        };
        drop(to_main_tx);

        // Verify that peer is sanctioned for failed fork reconciliation attempt
        assert!(state_lock
            .lock_guard()
            .await
            .net
            .get_peer_standing_from_database(peer_address1.ip())
            .await
            .unwrap()
            .standing
            .is_negative());

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn test_peer_loop_receival_of_fourth_block_one_block_in_db() {
        // In this scenario, the client know the genesis block (block 0) and block 1, it
        // then receives block 4, meaning that block 3 and 2 will have to be requested.

        let network = Network::Main;
        let (
            _peer_broadcast_tx,
            from_main_rx_clone,
            to_main_tx,
            mut to_main_rx1,
            mut state_lock,
            hsd,
        ) = get_test_genesis_setup(network, 0).await.unwrap();
        let peer_address: SocketAddr = get_dummy_socket_address(0);
        let genesis_block = Block::genesis_block(network);
        let [block_1, block_2, block_3, block_4] = valid_sequence_of_blocks_for_tests(
            &genesis_block,
            Timestamp::hours(1),
            StdRng::seed_from_u64(5550001).gen(),
        )
        .await;
        state_lock.set_new_tip(block_1.clone()).await.unwrap();

        let mock = Mock::new(vec![
            Action::Read(PeerMessage::Block(Box::new(
                block_4.clone().try_into().unwrap(),
            ))),
            Action::Write(PeerMessage::BlockRequestByHash(block_3.hash())),
            Action::Read(PeerMessage::Block(Box::new(
                block_3.clone().try_into().unwrap(),
            ))),
            Action::Write(PeerMessage::BlockRequestByHash(block_2.hash())),
            Action::Read(PeerMessage::Block(Box::new(
                block_2.clone().try_into().unwrap(),
            ))),
            Action::Read(PeerMessage::Bye),
        ]);

        let mut peer_loop_handler = PeerLoopHandler::with_mocked_time(
            to_main_tx.clone(),
            state_lock.clone(),
            peer_address,
            hsd,
            true,
            1,
            block_4.header().timestamp,
        );
        peer_loop_handler
            .run_wrapper(mock, from_main_rx_clone)
            .await
            .unwrap();

        // Verify that peer max block height was sent
        match to_main_rx1.recv().await {
            Some(PeerTaskToMain::AddPeerMaxBlockHeight(_)) => (),
            _ => panic!("Must receive add of peer block max height"),
        }

        match to_main_rx1.recv().await {
            Some(PeerTaskToMain::NewBlocks(blocks)) => {
                if blocks[0].hash() != block_2.hash() {
                    panic!("1st received block by main loop must be block 1");
                }
                if blocks[1].hash() != block_3.hash() {
                    panic!("2nd received block by main loop must be block 2");
                }
                if blocks[2].hash() != block_4.hash() {
                    panic!("3rd received block by main loop must be block 3");
                }
            }
            _ => panic!("Did not find msg sent to main task"),
        };
        match to_main_rx1.recv().await {
            Some(PeerTaskToMain::RemovePeerMaxBlockHeight(_)) => (),
            _ => panic!("Must receive remove of peer block max height"),
        }

        assert!(
            state_lock.lock_guard().await.net.peer_map.is_empty(),
            "peer map must be empty after closing connection gracefully"
        );
    }

    #[traced_test]
    #[tokio::test]
    async fn test_peer_loop_receival_of_third_block_no_blocks_in_db() -> Result<()> {
        // In this scenario, the client only knows the genesis block (block 0) and then
        // receives block 3, meaning that block 2 and 1 will have to be requested.

        let network = Network::Main;
        let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, mut to_main_rx1, state_lock, hsd) =
            get_test_genesis_setup(network, 0).await?;
        let peer_address = get_dummy_socket_address(0);
        let genesis_block = Block::genesis_block(network);

        let [block_1, block_2, block_3] = valid_sequence_of_blocks_for_tests(
            &genesis_block,
            Timestamp::hours(1),
            StdRng::seed_from_u64(5550001).gen(),
        )
        .await;

        let mock = Mock::new(vec![
            Action::Read(PeerMessage::Block(Box::new(
                block_3.clone().try_into().unwrap(),
            ))),
            Action::Write(PeerMessage::BlockRequestByHash(block_2.hash())),
            Action::Read(PeerMessage::Block(Box::new(
                block_2.clone().try_into().unwrap(),
            ))),
            Action::Write(PeerMessage::BlockRequestByHash(block_1.hash())),
            Action::Read(PeerMessage::Block(Box::new(
                block_1.clone().try_into().unwrap(),
            ))),
            Action::Read(PeerMessage::Bye),
        ]);

        let mut peer_loop_handler = PeerLoopHandler::with_mocked_time(
            to_main_tx.clone(),
            state_lock.clone(),
            peer_address,
            hsd,
            true,
            1,
            block_3.header().timestamp,
        );
        peer_loop_handler
            .run_wrapper(mock, from_main_rx_clone)
            .await?;

        // Verify that peer max block height was sent
        match to_main_rx1.recv().await {
            Some(PeerTaskToMain::AddPeerMaxBlockHeight(_)) => (),
            _ => bail!("Must receive add of peer block max height"),
        }

        match to_main_rx1.recv().await {
            Some(PeerTaskToMain::NewBlocks(blocks)) => {
                if blocks[0].hash() != block_1.hash() {
                    bail!("1st received block by main loop must be block 1");
                }
                if blocks[1].hash() != block_2.hash() {
                    bail!("2nd received block by main loop must be block 2");
                }
                if blocks[2].hash() != block_3.hash() {
                    bail!("3rd received block by main loop must be block 3");
                }
            }
            _ => bail!("Did not find msg sent to main task"),
        };
        match to_main_rx1.recv().await {
            Some(PeerTaskToMain::RemovePeerMaxBlockHeight(_)) => (),
            _ => bail!("Must receive remove of peer block max height"),
        }

        if !state_lock.lock_guard().await.net.peer_map.is_empty() {
            bail!("peer map must be empty after closing connection gracefully");
        }

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn test_block_reconciliation_interrupted_by_block_notification() -> Result<()> {
        // In this scenario, the client know the genesis block (block 0) and block 1, it
        // then receives block 4, meaning that block 3, 2, and 1 will have to be requested.
        // But the requests are interrupted by the peer sending another message: a new block
        // notification.

        let network = Network::Main;
        let (
            _peer_broadcast_tx,
            from_main_rx_clone,
            to_main_tx,
            mut to_main_rx1,
            mut state_lock,
            hsd,
        ) = get_test_genesis_setup(network, 0).await?;
        let peer_socket_address: SocketAddr = get_dummy_socket_address(0);
        let genesis_block: Block = state_lock
            .lock_guard()
            .await
            .chain
            .archival_state()
            .get_tip()
            .await;

        let [block_1, block_2, block_3, block_4, block_5] = valid_sequence_of_blocks_for_tests(
            &genesis_block,
            Timestamp::hours(1),
            StdRng::seed_from_u64(5550001).gen(),
        )
        .await;
        state_lock.set_new_tip(block_1.clone()).await?;

        let mock = Mock::new(vec![
            Action::Read(PeerMessage::Block(Box::new(
                block_4.clone().try_into().unwrap(),
            ))),
            Action::Write(PeerMessage::BlockRequestByHash(block_3.hash())),
            Action::Read(PeerMessage::Block(Box::new(
                block_3.clone().try_into().unwrap(),
            ))),
            Action::Write(PeerMessage::BlockRequestByHash(block_2.hash())),
            //
            // Now make the interruption of the block reconciliation process
            Action::Read(PeerMessage::BlockNotification(block_5.clone().into())),
            //
            // Complete the block reconciliation process by requesting the last block
            // in this process, to get back to a mutually known block.
            Action::Read(PeerMessage::Block(Box::new(
                block_2.clone().try_into().unwrap(),
            ))),
            //
            // Then anticipate the request of the block that was announced
            // in the interruption.
            // Note that we cannot anticipate the response, as only the main
            // task writes to the database. And the database needs to be updated
            // for the handling of block 5 to be done correctly.
            Action::Write(PeerMessage::BlockRequestByHeight(
                block_5.kernel.header.height,
            )),
            Action::Read(PeerMessage::Bye),
        ]);

        let mut peer_loop_handler = PeerLoopHandler::with_mocked_time(
            to_main_tx.clone(),
            state_lock.clone(),
            peer_socket_address,
            hsd,
            false,
            1,
            block_5.header().timestamp,
        );
        peer_loop_handler
            .run_wrapper(mock, from_main_rx_clone)
            .await?;

        // Verify that peer max block height was sent
        match to_main_rx1.recv().await {
            Some(PeerTaskToMain::AddPeerMaxBlockHeight(_)) => (),
            _ => bail!("Must receive add of peer block max height"),
        }

        match to_main_rx1.recv().await {
            Some(PeerTaskToMain::NewBlocks(blocks)) => {
                if blocks[0].hash() != block_2.hash() {
                    bail!("1st received block by main loop must be block 1");
                }
                if blocks[1].hash() != block_3.hash() {
                    bail!("2nd received block by main loop must be block 2");
                }
                if blocks[2].hash() != block_4.hash() {
                    bail!("3rd received block by main loop must be block 3");
                }
            }
            _ => bail!("Did not find msg sent to main task"),
        };
        match to_main_rx1.recv().await {
            Some(PeerTaskToMain::RemovePeerMaxBlockHeight(_)) => (),
            _ => bail!("Must receive remove of peer block max height"),
        }

        if !state_lock.lock_guard().await.net.peer_map.is_empty() {
            bail!("peer map must be empty after closing connection gracefully");
        }

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn test_block_reconciliation_interrupted_by_peer_list_request() -> Result<()> {
        // In this scenario, the client knows the genesis block (block 0) and block 1, it
        // then receives block 4, meaning that block 3, 2, and 1 will have to be requested.
        // But the requests are interrupted by the peer sending another message: a request
        // for a list of peers.

        let network = Network::Main;
        let (
            _peer_broadcast_tx,
            from_main_rx_clone,
            to_main_tx,
            mut to_main_rx1,
            mut state_lock,
            _hsd,
        ) = get_test_genesis_setup(network, 1).await?;
        let genesis_block = Block::genesis_block(network);
        let peer_infos: Vec<PeerInfo> = state_lock
            .lock_guard()
            .await
            .net
            .peer_map
            .clone()
            .into_values()
            .collect::<Vec<_>>();

        let [block_1, block_2, block_3, block_4] = valid_sequence_of_blocks_for_tests(
            &genesis_block,
            Timestamp::hours(1),
            StdRng::seed_from_u64(5550001).gen(),
        )
        .await;
        state_lock.set_new_tip(block_1.clone()).await?;

        let (hsd_1, sa_1) = get_dummy_peer_connection_data_genesis(network, 1).await;
        let expected_peer_list_resp = vec![
            (
                peer_infos[0].listen_address().unwrap(),
                peer_infos[0].instance_id,
            ),
            (sa_1, hsd_1.instance_id),
        ];
        let mock = Mock::new(vec![
            Action::Read(PeerMessage::Block(Box::new(
                block_4.clone().try_into().unwrap(),
            ))),
            Action::Write(PeerMessage::BlockRequestByHash(block_3.hash())),
            Action::Read(PeerMessage::Block(Box::new(
                block_3.clone().try_into().unwrap(),
            ))),
            Action::Write(PeerMessage::BlockRequestByHash(block_2.hash())),
            //
            // Now make the interruption of the block reconciliation process
            Action::Read(PeerMessage::PeerListRequest),
            //
            // Answer the request for a peer list
            Action::Write(PeerMessage::PeerListResponse(expected_peer_list_resp)),
            //
            // Complete the block reconciliation process by requesting the last block
            // in this process, to get back to a mutually known block.
            Action::Read(PeerMessage::Block(Box::new(
                block_2.clone().try_into().unwrap(),
            ))),
            Action::Read(PeerMessage::Bye),
        ]);

        let mut peer_loop_handler = PeerLoopHandler::with_mocked_time(
            to_main_tx,
            state_lock.clone(),
            sa_1,
            hsd_1,
            true,
            1,
            block_4.header().timestamp,
        );
        peer_loop_handler
            .run_wrapper(mock, from_main_rx_clone)
            .await?;

        // Verify that peer max block height was sent
        match to_main_rx1.recv().await {
            Some(PeerTaskToMain::AddPeerMaxBlockHeight(_)) => (),
            _ => bail!("Must receive peer block max height"),
        }

        // Verify that blocks are sent to `main_loop` in expected ordering
        match to_main_rx1.recv().await {
            Some(PeerTaskToMain::NewBlocks(blocks)) => {
                if blocks[0].hash() != block_2.hash() {
                    bail!("1st received block by main loop must be block 1");
                }
                if blocks[1].hash() != block_3.hash() {
                    bail!("2nd received block by main loop must be block 2");
                }
                if blocks[2].hash() != block_4.hash() {
                    bail!("3rd received block by main loop must be block 3");
                }
            }
            _ => bail!("Did not find msg sent to main task"),
        };

        match to_main_rx1.recv().await {
            Some(PeerTaskToMain::RemovePeerMaxBlockHeight(_)) => (),
            _ => bail!("Must receive remove of peer block max height"),
        }

        assert_eq!(
            1,
            state_lock.lock_guard().await.net.peer_map.len(),
            "One peer must remain in peer list after peer_1 closed gracefully"
        );

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn empty_mempool_request_tx_test() {
        // In this scenerio the client receives a transaction notification from
        // a peer of a transaction it doesn't know; the client must then request it.

        let network = Network::Main;
        let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, mut to_main_rx1, state_lock, _hsd) =
            get_test_genesis_setup(network, 1).await.unwrap();

        let spending_key = state_lock
            .lock_guard()
            .await
            .wallet_state
            .wallet_secret
            .nth_symmetric_key_for_tests(0);
        let genesis_block = Block::genesis_block(network);
        let now = genesis_block.kernel.header.timestamp;
        let (transaction_1, _change_output) = state_lock
            .lock_guard()
            .await
            .create_transaction_with_prover_capability(
                Default::default(),
                spending_key.into(),
                UtxoNotificationMedium::OffChain,
                NeptuneCoins::new(0),
                now,
                TxProvingCapability::ProofCollection,
                &TritonProverSync::dummy(),
            )
            .await
            .unwrap();

        // Build the resulting transaction notification
        let tx_notification: TransactionNotification = (&transaction_1).try_into().unwrap();
        let mock = Mock::new(vec![
            Action::Read(PeerMessage::TransactionNotification(tx_notification)),
            Action::Write(PeerMessage::TransactionRequest(tx_notification.txid)),
            Action::Read(PeerMessage::Transaction(Box::new(
                (&transaction_1).try_into().unwrap(),
            ))),
            Action::Read(PeerMessage::Bye),
        ]);

        let (hsd_1, _sa_1) = get_dummy_peer_connection_data_genesis(network, 1).await;

        // Mock a timestamp to allow transaction to be considered valid
        let mut peer_loop_handler = PeerLoopHandler::with_mocked_time(
            to_main_tx,
            state_lock.clone(),
            get_dummy_socket_address(0),
            hsd_1.clone(),
            true,
            1,
            now,
        );

        let mut peer_state = MutablePeerState::new(hsd_1.tip_header.height);

        assert!(
            state_lock.lock_guard().await.mempool.is_empty(),
            "Mempool must be empty at init"
        );
        peer_loop_handler
            .run(mock, from_main_rx_clone, &mut peer_state)
            .await
            .unwrap();

        // Transaction must be sent to `main_loop`. The transaction is stored to the mempool
        // by the `main_loop`.
        match to_main_rx1.recv().await {
            Some(PeerTaskToMain::Transaction(_)) => (),
            _ => panic!("Must receive remove of peer block max height"),
        };
    }

    #[traced_test]
    #[tokio::test]
    async fn populated_mempool_request_tx_test() -> Result<()> {
        // In this scenario the peer is informed of a transaction that it already knows

        let network = Network::Main;
        let (
            _peer_broadcast_tx,
            from_main_rx_clone,
            to_main_tx,
            mut to_main_rx1,
            mut state_lock,
            _hsd,
        ) = get_test_genesis_setup(network, 1).await.unwrap();
        let spending_key = state_lock
            .lock_guard()
            .await
            .wallet_state
            .wallet_secret
            .nth_symmetric_key_for_tests(0);

        let genesis_block = Block::genesis_block(network);
        let now = genesis_block.kernel.header.timestamp;
        let (transaction_1, _change_output) = state_lock
            .lock_guard()
            .await
            .create_transaction_with_prover_capability(
                Default::default(),
                spending_key.into(),
                UtxoNotificationMedium::OffChain,
                NeptuneCoins::new(0),
                now,
                TxProvingCapability::ProofCollection,
                &TritonProverSync::dummy(),
            )
            .await
            .unwrap();

        let (hsd_1, _sa_1) = get_dummy_peer_connection_data_genesis(network, 1).await;
        let mut peer_loop_handler = PeerLoopHandler::new(
            to_main_tx,
            state_lock.clone(),
            get_dummy_socket_address(0),
            hsd_1.clone(),
            true,
            1,
        );
        let mut peer_state = MutablePeerState::new(hsd_1.tip_header.height);

        assert!(
            state_lock.lock_guard().await.mempool.is_empty(),
            "Mempool must be empty at init"
        );
        state_lock
            .lock_guard_mut()
            .await
            .mempool_insert(transaction_1.clone())
            .await;
        assert!(
            !state_lock.lock_guard().await.mempool.is_empty(),
            "Mempool must be non-empty after insertion"
        );

        // Run the peer loop and verify expected exchange -- namely that the
        // tx notification is received and the the transaction is *not*
        // requested.
        let tx_notification: TransactionNotification = (&transaction_1).try_into().unwrap();
        let mock = Mock::new(vec![
            Action::Read(PeerMessage::TransactionNotification(tx_notification)),
            Action::Read(PeerMessage::Bye),
        ]);
        peer_loop_handler
            .run(mock, from_main_rx_clone, &mut peer_state)
            .await
            .unwrap();

        // nothing is allowed to be sent to `main_loop`
        match to_main_rx1.try_recv() {
            Err(TryRecvError::Empty) => (),
            Err(TryRecvError::Disconnected) => panic!("to_main channel must still be open"),
            Ok(_) => panic!("to_main channel must be empty"),
        };
        Ok(())
    }

    mod proof_qualities {
        use strum::IntoEnumIterator;

        use super::*;
        use crate::models::blockchain::transaction::Transaction;
        use crate::models::peer::transfer_transaction::TransactionProofQuality;
        use crate::tests::shared::mock_genesis_global_state;

        async fn tx_of_proof_quality(
            network: Network,
            quality: TransactionProofQuality,
        ) -> Transaction {
            let wallet_secret = WalletSecret::devnet_wallet();
            let alice_key = wallet_secret.nth_generation_spending_key_for_tests(0);
            let alice = mock_genesis_global_state(network, 1, wallet_secret).await;
            let alice = alice.lock_guard().await;
            let genesis_block = alice.chain.light_state();
            let in_seven_months = genesis_block.header().timestamp + Timestamp::months(7);
            let prover_capability = match quality {
                TransactionProofQuality::ProofCollection => TxProvingCapability::ProofCollection,
                TransactionProofQuality::SingleProof => TxProvingCapability::SingleProof,
            };
            alice
                .create_transaction_with_prover_capability(
                    vec![].into(),
                    alice_key.into(),
                    UtxoNotificationMedium::OffChain,
                    NeptuneCoins::new(1),
                    in_seven_months,
                    prover_capability,
                    &TritonProverSync::dummy(),
                )
                .await
                .unwrap()
                .0
        }

        #[traced_test]
        #[tokio::test]
        async fn client_favors_higher_proof_quality() {
            // In this scenario the peer is informed of a transaction that it
            // already knows, and it's tested that it checks the proof quality
            // field and verifies that it exceeds the proof in the mempool
            // before requesting the transasction.
            let network = Network::Main;
            let proof_collection_tx =
                tx_of_proof_quality(network, TransactionProofQuality::ProofCollection).await;
            let single_proof_tx =
                tx_of_proof_quality(network, TransactionProofQuality::SingleProof).await;

            for (own_tx_pq, new_tx_pq) in
                TransactionProofQuality::iter().cartesian_product(TransactionProofQuality::iter())
            {
                let (
                    _peer_broadcast_tx,
                    from_main_rx_clone,
                    to_main_tx,
                    mut to_main_rx1,
                    mut alice,
                    handshake_data,
                ) = get_test_genesis_setup(network, 1).await.unwrap();

                use TransactionProofQuality::*;
                let (own_tx, new_tx) = match (own_tx_pq, new_tx_pq) {
                    (ProofCollection, ProofCollection) => {
                        (&proof_collection_tx, &proof_collection_tx)
                    }
                    (ProofCollection, SingleProof) => (&proof_collection_tx, &single_proof_tx),
                    (SingleProof, ProofCollection) => (&single_proof_tx, &proof_collection_tx),
                    (SingleProof, SingleProof) => (&single_proof_tx, &single_proof_tx),
                };

                alice
                    .lock_guard_mut()
                    .await
                    .mempool_insert(own_tx.to_owned())
                    .await;

                let tx_notification: TransactionNotification = new_tx.try_into().unwrap();

                let own_proof_is_supreme = own_tx_pq >= new_tx_pq;
                let mock = if own_proof_is_supreme {
                    Mock::new(vec![
                        Action::Read(PeerMessage::TransactionNotification(tx_notification)),
                        Action::Read(PeerMessage::Bye),
                    ])
                } else {
                    Mock::new(vec![
                        Action::Read(PeerMessage::TransactionNotification(tx_notification)),
                        Action::Write(PeerMessage::TransactionRequest(tx_notification.txid)),
                        Action::Read(PeerMessage::Transaction(Box::new(
                            new_tx.try_into().unwrap(),
                        ))),
                        Action::Read(PeerMessage::Bye),
                    ])
                };

                let now = proof_collection_tx.kernel.timestamp;
                let mut peer_loop_handler = PeerLoopHandler::with_mocked_time(
                    to_main_tx,
                    alice.clone(),
                    get_dummy_socket_address(0),
                    handshake_data.clone(),
                    true,
                    1,
                    now,
                );
                let mut peer_state = MutablePeerState::new(handshake_data.tip_header.height);

                peer_loop_handler
                    .run(mock, from_main_rx_clone, &mut peer_state)
                    .await
                    .unwrap();

                if own_proof_is_supreme {
                    match to_main_rx1.try_recv() {
                        Err(TryRecvError::Empty) => (),
                        Err(TryRecvError::Disconnected) => {
                            panic!("to_main channel must still be open")
                        }
                        Ok(_) => panic!("to_main channel must be empty"),
                    }
                } else {
                    match to_main_rx1.try_recv() {
                        Err(TryRecvError::Empty) => panic!("Transaction must be sent to main loop"),
                        Err(TryRecvError::Disconnected) => {
                            panic!("to_main channel must still be open")
                        }
                        Ok(PeerTaskToMain::Transaction(_)) => (),
                        _ => panic!("Unexpected result from channel"),
                    }
                }
            }
        }
    }
}
