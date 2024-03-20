use crate::models::consensus::mast_hash::MastHash;
use crate::prelude::twenty_first;

use crate::connect_to_peers::close_peer_connected_callback;
use crate::models::blockchain::block::block_height::BlockHeight;
use crate::models::blockchain::block::transfer_block::TransferBlock;
use crate::models::blockchain::block::Block;
use crate::models::channel::{MainToPeerThread, PeerThreadToMain, PeerThreadToMainTransaction};
use crate::models::peer::{
    HandshakeData, MutablePeerState, PeerInfo, PeerMessage, PeerSanctionReason, PeerStanding,
};
use crate::models::state::mempool::{
    MEMPOOL_IGNORE_TRANSACTIONS_THIS_MANY_SECS_AHEAD, MEMPOOL_TX_THRESHOLD_AGE_IN_SECS,
};
use crate::models::state::GlobalStateLock;
use anyhow::{bail, Result};
use futures::sink::{Sink, SinkExt};
use futures::stream::{TryStream, TryStreamExt};
use itertools::Itertools;
use std::cmp;
use std::marker::Unpin;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::select;
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, error, info, warn};
use twenty_first::shared_math::digest::Digest;

const STANDARD_BLOCK_BATCH_SIZE: usize = 50;
const MAX_PEER_LIST_LENGTH: usize = 10;
const MINIMUM_BLOCK_BATCH_SIZE: usize = 2;

const KEEP_CONNECTION_ALIVE: bool = false;
const _DISCONNECT_CONNECTION: bool = true;

pub type PeerStandingNumber = i32;

/// Contains the immutable data that this peer-loop needs. Does not contain the `peer` variable
/// since this needs to be a mutable variable in most methods.
pub struct PeerLoopHandler {
    to_main_tx: mpsc::Sender<PeerThreadToMain>,
    global_state_lock: GlobalStateLock,
    peer_address: SocketAddr,
    peer_handshake_data: HandshakeData,
    inbound_connection: bool,
    distance: u8,
}

impl PeerLoopHandler {
    pub fn new(
        to_main_tx: mpsc::Sender<PeerThreadToMain>,
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
        }
    }

    // TODO: Add a reward function that mutates the peer status

    /// Locking:
    ///   * acquires `global_state_lock` for write
    async fn punish(&self, reason: PeerSanctionReason) -> Result<()> {
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

    /// Handle validation and send all blocks to the main thread if they're all
    /// valid. Use with a list of blocks or a single block. When the
    /// `received_blocks` is a list, the parent of the `i+1`th block in the
    /// list is the `i`th block. The parent of element zero in this list is
    /// `parent_of_first_block`.
    ///
    /// Locking:
    ///   * acquires `global_state_lock` for write via Self::punish()
    async fn handle_blocks(
        &self,
        received_blocks: Vec<Block>,
        parent_of_first_block: Block,
    ) -> Result<BlockHeight> {
        debug!(
            "attempting to validate {} {}",
            received_blocks.len(),
            if received_blocks.len() == 1 {
                "block"
            } else {
                "blocks"
            }
        );
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
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
                    Block::difficulty_to_digest_threshold(previous_block.kernel.header.difficulty),
                    new_block.hash().values().iter().join(", ")
                );
                self.punish(PeerSanctionReason::InvalidBlock((
                    new_block.kernel.header.height,
                    new_block.hash(),
                )))
                .await?;
                bail!("Failed to validate block due to insufficient PoW");
            } else if !new_block.is_valid(previous_block, now).await {
                warn!(
                    "Received invalid block of height {} from peer with IP {}",
                    new_block.kernel.header.height, self.peer_address
                );
                self.punish(PeerSanctionReason::InvalidBlock((
                    new_block.kernel.header.height,
                    new_block.hash(),
                )))
                .await?;
                bail!("Failed to validate block: invalid block");
            } else {
                info!(
                    "Block with height {} is valid. mined: {}",
                    new_block.kernel.header.height,
                    crate::utc_timestamp_to_localtime(new_block.kernel.header.timestamp.value())
                        .to_string()
                );
            }

            previous_block = new_block;
        }

        // Send the new blocks to the main thread which handles the state update
        // and storage to the database.
        let new_block_height = received_blocks.last().unwrap().kernel.header.height;
        self.to_main_tx
            .send(PeerThreadToMain::NewBlocks(received_blocks))
            .await?;
        info!(
            "Updated block info by block from peer. block height {}",
            new_block_height
        );

        Ok(new_block_height)
    }

    /// Function for handling the receiving of single new block from a peer
    ///
    /// Locking:
    ///   * acquires `global_state_lock` for write via Self::punish()
    async fn receive_new_block<S>(
        &self,
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

        // If parent is not known, request the parent, and add the current to the peer fork resolution list
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

        // We want to treat the received blocks in reverse order, from oldest to newest
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
        let new_block_height = self
            .handle_blocks(new_blocks, parent_block.unwrap())
            .await?;

        // If `BlockNotification` was received during a block reconciliation
        // event, then the peer might have one (or more (unlikely)) blocks
        // that we do not have. We should thus request those blocks.
        if fork_reconciliation_event && peer_state.highest_shared_block_height > new_block_height {
            peer.send(PeerMessage::BlockRequestByHeight(
                peer_state.highest_shared_block_height,
            ))
            .await?;
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
        &self,
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
                Ok(true)
            }
            PeerMessage::PeerListRequest => {
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
                Ok(false)
            }
            PeerMessage::PeerListResponse(peers) => {
                if peers.len() > MAX_PEER_LIST_LENGTH {
                    self.punish(PeerSanctionReason::FloodPeerListResponse)
                        .await?;
                }
                self.to_main_tx
                    .send(PeerThreadToMain::PeerDiscoveryAnswer((
                        peers,
                        self.peer_address,
                        // The distance to the revealed peers is 1 + this peer's distance
                        self.distance + 1,
                    )))
                    .await?;
                Ok(false)
            }
            PeerMessage::Block(t_block) => {
                info!(
                    "Got new block from peer {}, height {}, mined {}",
                    self.peer_address,
                    t_block.header.height,
                    crate::utc_timestamp_to_localtime(t_block.header.timestamp.value()).to_string()
                );
                let new_block_height = t_block.header.height;

                let block: Box<Block> = Box::new((*t_block).into());

                // Update the value for the highest known height that peer possesses iff
                // we are not in a fork reconciliation state.
                if peer_state_info.fork_reconciliation_blocks.is_empty() {
                    peer_state_info.highest_shared_block_height = new_block_height;
                }

                let incoming_block_is_heavier = self
                    .global_state_lock
                    .lock_guard()
                    .await
                    .chain
                    .light_state()
                    .kernel
                    .header
                    .proof_of_work_family
                    < block.kernel.header.proof_of_work_family;
                let reconciliation_ongoing = match peer_state_info.fork_reconciliation_blocks.last()
                {
                    Some(last_block) => last_block.kernel.header.prev_block_digest == block.hash(),
                    None => false,
                };

                // Determine whether
                //  a) the incoming block's POW family is larger than what we have; or
                //  b) we are populating a fork reconciliation blocks list.
                if incoming_block_is_heavier || reconciliation_ongoing {
                    debug!("block is new");
                    self.receive_new_block(block, peer, peer_state_info).await?;
                } else {
                    info!(
                        "Got non-canonical block from peer, height: {}, PoW family: {:?}",
                        new_block_height, block.kernel.header.proof_of_work_family,
                    );
                }
                Ok(false)
            }
            PeerMessage::BlockRequestBatch(
                peers_suggested_starting_points,
                requested_batch_size,
            ) => {
                // Find the block that the peer is requesting to start from
                let mut peers_latest_canonical_block: Option<Block> = None;

                for digest in peers_suggested_starting_points {
                    debug!("Looking up block {} in batch request", digest);
                    let block_candidate = self
                        .global_state_lock
                        .lock_guard()
                        .await
                        .chain
                        .archival_state()
                        .get_block(digest)
                        .await
                        .expect("Lookup must work");
                    if let Some(block_candidate) = block_candidate {
                        // Verify that this block is not only known but also belongs to the canonical
                        // chain. Also check if it's the genesis block.

                        let global_state = self.global_state_lock.lock_guard().await;

                        let tip_digest = global_state.chain.light_state().kernel.mast_hash();

                        if global_state
                            .chain
                            .archival_state()
                            .block_belongs_to_canonical_chain(
                                block_candidate.kernel.mast_hash(),
                                tip_digest,
                            )
                            .await
                        {
                            peers_latest_canonical_block = match peers_latest_canonical_block {
                                None => Some(block_candidate),
                                Some(running_latest_block) => {
                                    if running_latest_block.kernel.header.height
                                        < block_candidate.kernel.header.height
                                    {
                                        Some(block_candidate)
                                    } else {
                                        Some(running_latest_block)
                                    }
                                }
                            };
                            debug!("Found block in canonical chain: {}", digest);
                        }
                    }
                }

                let peers_latest_canonical_block = match peers_latest_canonical_block {
                    Some(plcb) => plcb,
                    None => {
                        self.punish(PeerSanctionReason::BatchBlocksUnknownRequest)
                            .await?;
                        return Ok(false);
                    }
                };

                // Get the relevant blocks, at most batch size many, descending from the
                // peer's most canonical block.
                let responded_batch_size = cmp::min(
                    requested_batch_size,
                    self.global_state_lock
                        .cli()
                        .max_number_of_blocks_before_syncing
                        / 2,
                );
                let global_state = self.global_state_lock.lock_guard().await;
                let tip_digest = global_state.chain.light_state().kernel.mast_hash();

                let responded_batch_size = cmp::max(responded_batch_size, MINIMUM_BLOCK_BATCH_SIZE);
                let mut returned_blocks: Vec<TransferBlock> =
                    Vec::with_capacity(responded_batch_size);

                let mut current_digest = peers_latest_canonical_block.kernel.mast_hash();
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
                    returned_blocks.push(canonical_child.into());

                    // prepare for next iteration
                    current_digest = canonical_child_digest;
                }

                debug!(
                    "Returning {} blocks in batch response",
                    returned_blocks.len()
                );

                let response = PeerMessage::BlockResponseBatch(returned_blocks);
                peer.send(response).await?;

                Ok(false)
            }
            PeerMessage::BlockResponseBatch(t_blocks) => {
                debug!(
                    "handling block response batch with {} blocks",
                    t_blocks.len()
                );
                if t_blocks.len() < MINIMUM_BLOCK_BATCH_SIZE {
                    warn!("Got smaller batch response than allowed");
                    self.punish(PeerSanctionReason::TooShortBlockBatch).await?;
                    return Ok(false);
                }

                // Verify that we are in fact in syncing mode
                // TODO: Seperate peer messages into those allowed under syncing
                // and those that are not
                if !self.global_state_lock.lock_guard().await.net.syncing {
                    warn!("Received a batch of blocks without being in syncing mode");
                    self.punish(PeerSanctionReason::ReceivedBatchBlocksOutsideOfSync)
                        .await?;
                    return Ok(false);
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
                        return Ok(false);
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

                Ok(false)
            }
            PeerMessage::BlockNotificationRequest => {
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

                Ok(false)
            }
            PeerMessage::BlockNotification(block_notification) => {
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
                        .proof_of_work_family
                        < block_notification.proof_of_work_family;

                    // Only request block if it is new, and if we are not currently reconciling
                    // a fork. If we are reconciling, that is handled later, and the information
                    // about that is stored in `highest_shared_block_height`. If we are syncing
                    // we are also not requesting the block but instead updating the sync state.
                    if self.global_state_lock.lock_guard().await.net.syncing {
                        self.to_main_tx
                            .send(PeerThreadToMain::AddPeerMaxBlockHeight((
                                self.peer_address,
                                block_notification.height,
                                block_notification.proof_of_work_family,
                            )))
                            .await
                            .expect("Sending to main thread must succeed");
                    } else if block_is_new && peer_state_info.fork_reconciliation_blocks.is_empty()
                    {
                        peer.send(PeerMessage::BlockRequestByHeight(block_notification.height))
                            .await?;
                    }
                }

                Ok(false)
            }
            PeerMessage::BlockRequestByHash(block_digest) => {
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
                        Ok(false)
                    }
                    Some(b) => {
                        peer.send(PeerMessage::Block(Box::new(b.into()))).await?;
                        Ok(false)
                    }
                }
            }
            PeerMessage::BlockRequestByHeight(block_height) => {
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
                    return Ok(false);
                }

                // If more than one block is found, we need to find the one that's canonical
                let mut canonical_chain_block_digest = block_digests[0];
                if block_digests.len() > 1 {
                    let global_state = self.global_state_lock.lock_guard().await;
                    let tip_digest = global_state.chain.light_state().kernel.mast_hash();
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
                    PeerMessage::Block(Box::new(canonical_chain_block.into()));

                debug!("Sending block");
                peer.send(block_response).await?;
                debug!("Sent block");
                Ok(false)
            }
            PeerMessage::Handshake(_) => {
                self.punish(PeerSanctionReason::InvalidMessage).await?;
                Ok(false)
            }
            PeerMessage::ConnectionStatus(_) => {
                self.punish(PeerSanctionReason::InvalidMessage).await?;
                Ok(false)
            }
            PeerMessage::Transaction(transaction) => {
                debug!(
                    "`peer_loop` received following transaction from peer. {} inputs, {} outputs. Synced to mutator set hash: {}",
                    transaction.kernel.inputs.len(),
                    transaction.kernel.outputs.len(),
                    transaction.kernel.mutator_set_hash
                );

                // If transaction is invalid, punish
                if !transaction.is_valid() {
                    warn!("Received invalid tx");
                    self.punish(PeerSanctionReason::InvalidTransaction).await?;
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                // If transaction has coinbase, punish.
                // Transactions received from peers have not been mined yet.
                // Only the miner is allowed to produce transactions with non-empty coinbase fields.
                if transaction.kernel.coinbase.is_some() {
                    warn!("Received non-mined transaction with coinbase.");
                    self.punish(PeerSanctionReason::NonMinedTransactionHasCoinbase)
                        .await?;
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                // if transaction is not confirmable, punish
                let confirmable = transaction
                    .is_confirmable_relative_to(
                        &self
                            .global_state_lock
                            .lock_guard()
                            .await
                            .chain
                            .light_state()
                            .kernel
                            .body
                            .mutator_set_accumulator,
                    )
                    .await;
                if !confirmable {
                    warn!("Received unconfirmable tx");
                    self.punish(PeerSanctionReason::UnconfirmableTransaction)
                        .await?;
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                // Get transaction timestamp
                let tx_timestamp = match transaction.get_timestamp() {
                    Ok(ts) => ts,
                    Err(_) => {
                        warn!("Received tx with invalid timestamp");
                        return Ok(KEEP_CONNECTION_ALIVE);
                    }
                };

                // 2. Ignore if transaction is too old
                let now = SystemTime::now();
                if tx_timestamp
                    < now - std::time::Duration::from_secs(MEMPOOL_TX_THRESHOLD_AGE_IN_SECS)
                {
                    // TODO: Consider punishing here
                    warn!("Received too old tx");
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                // 3. Ignore if transaction is too far into the future
                if tx_timestamp
                    > now
                        + std::time::Duration::from_secs(
                            MEMPOOL_IGNORE_TRANSACTIONS_THIS_MANY_SECS_AHEAD,
                        )
                {
                    // TODO: Consider punishing here
                    warn!("Received tx too far into the future. Got timestamp: {tx_timestamp:?}");
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                // Otherwise relay to main
                let pt2m_transaction = PeerThreadToMainTransaction {
                    transaction: *transaction.to_owned(),
                    confirmable_for_block: self
                        .global_state_lock
                        .lock_guard()
                        .await
                        .chain
                        .light_state()
                        .hash(),
                };
                self.to_main_tx
                    .send(PeerThreadToMain::Transaction(Box::new(pt2m_transaction)))
                    .await?;

                Ok(KEEP_CONNECTION_ALIVE)
            }
            PeerMessage::TransactionNotification(transaction_notification) => {
                // 1. Ignore if we already know this transaction.
                let transaction_is_known = self
                    .global_state_lock
                    .lock_guard()
                    .await
                    .mempool
                    .contains(transaction_notification.transaction_digest);
                if transaction_is_known {
                    debug!("transaction was already known");
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                // Should we check a timestamp here?

                // 2. Request the actual `Transaction` from peer
                debug!("requesting transaction from peer");
                peer.send(PeerMessage::TransactionRequest(
                    transaction_notification.transaction_digest,
                ))
                .await?;

                Ok(KEEP_CONNECTION_ALIVE)
            }
            PeerMessage::TransactionRequest(transaction_identifier) => {
                if let Some(transaction) = self
                    .global_state_lock
                    .lock_guard()
                    .await
                    .mempool
                    .get(transaction_identifier)
                {
                    peer.send(PeerMessage::Transaction(Box::new(transaction.clone())))
                        .await?;
                }

                Ok(KEEP_CONNECTION_ALIVE)
            }
        }
    }

    /// Handle message from main thread. The boolean return value indicates if
    /// the connection should be closed.
    ///
    /// Locking:
    ///   * acquires `global_state_lock` for write via Self::punish()
    async fn handle_main_thread_message<S>(
        &self,
        msg: MainToPeerThread,
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
            MainToPeerThread::Block(block) => {
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
                Ok(false)
            }
            MainToPeerThread::RequestBlockBatch(most_canonical_block_digests, peer_addr_target) => {
                // Only ask one of the peers about the batch of blocks
                if peer_addr_target != self.peer_address {
                    return Ok(false);
                }

                let request_batch_size = std::cmp::min(
                    STANDARD_BLOCK_BATCH_SIZE,
                    self.global_state_lock
                        .cli()
                        .max_number_of_blocks_before_syncing,
                );

                peer.send(PeerMessage::BlockRequestBatch(
                    most_canonical_block_digests,
                    request_batch_size,
                ))
                .await?;

                Ok(false)
            }
            MainToPeerThread::PeerSynchronizationTimeout(socket_addr) => {
                if self.peer_address != socket_addr {
                    return Ok(false);
                }

                self.punish(PeerSanctionReason::SynchronizationTimeout)
                    .await?;

                // If this peer failed the last synchronization attempt, we only
                // sanction, we don't disconnect.
                Ok(false)
            }
            MainToPeerThread::MakePeerDiscoveryRequest => {
                peer.send(PeerMessage::PeerListRequest).await?;
                Ok(false)
            }
            MainToPeerThread::Disconnect(target_socket_addr) => {
                // Disconnect from this peer if its address matches that which the main
                // thread requested to disconnected from.
                Ok(target_socket_addr == self.peer_address)
            }
            // Disconnect from this peer, no matter what.
            MainToPeerThread::DisconnectAll() => Ok(true),
            MainToPeerThread::MakeSpecificPeerDiscoveryRequest(target_socket_addr) => {
                if target_socket_addr == self.peer_address {
                    peer.send(PeerMessage::PeerListRequest).await?;
                }
                Ok(false)
            }
            MainToPeerThread::TransactionNotification(transaction_notification) => {
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

    /// Loop for the peer threads. Awaits either a message from the peer over TCP,
    /// or a message from main over the main-to-peer-threads broadcast channel.
    async fn run<S>(
        &self,
        mut peer: S,
        mut from_main_rx: broadcast::Receiver<MainToPeerThread>,
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

                // Handle messages from main thread
                main_msg_res = from_main_rx.recv() => {
                    let close_connection = match main_msg_res {
                        Ok(main_msg) => match self.handle_main_thread_message(main_msg, &mut peer, peer_state_info).await {
                            Ok(close) => close,

                            // If the handler of main-thread messages returns error, the connection is closed.
                            // This might indicate that the peer got banned.
                            Err(err) => {
                                warn!("handle_main_thread_message returned an eror: {}", err);
                                true
                            },
                        }
                        Err(e) => panic!("Failed to read from main loop: {}", e),
                    };

                    if close_connection {
                        info!("handle_main_thread_message is closing the connection to {}", self.peer_address);
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
    pub async fn run_wrapper<S>(
        &self,
        mut peer: S,
        from_main_rx: broadcast::Receiver<MainToPeerThread>,
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
        // this check could have been invalidated by other threads so we perform it again

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
            .send(PeerThreadToMain::AddPeerMaxBlockHeight((
                self.peer_address,
                self.peer_handshake_data.tip_header.height,
                self.peer_handshake_data.tip_header.proof_of_work_family,
            )))
            .await?;

        // `MutablePeerState` contains the part of the peer-loop's state that is mutable
        let mut peer_state = MutablePeerState::new(self.peer_handshake_data.tip_header.height);

        // If peer indicates more canonical block, request a block notification to catch up ASAP
        if self.peer_handshake_data.tip_header.proof_of_work_family
            > self
                .global_state_lock
                .lock_guard()
                .await
                .chain
                .light_state()
                .kernel
                .header
                .proof_of_work_family
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
    use rand::{thread_rng, Rng};
    use tokio::sync::mpsc::error::TryRecvError;
    use tracing_test::traced_test;

    use crate::{
        config_models::network::Network,
        models::{peer::TransactionNotification, state::wallet::WalletSecret},
        tests::shared::{
            add_block, get_dummy_peer_connection_data_genesis, get_dummy_socket_address,
            get_test_genesis_setup, make_mock_block_with_invalid_pow,
            make_mock_block_with_valid_pow, make_mock_transaction, Action, Mock,
        },
    };

    use super::*;

    #[traced_test]
    #[tokio::test]
    async fn test_peer_loop_bye() -> Result<()> {
        let mock = Mock::new(vec![Action::Read(PeerMessage::Bye)]);

        let (peer_broadcast_tx, _from_main_rx_clone, to_main_tx, _to_main_rx1, state_lock, hsd) =
            get_test_genesis_setup(Network::Alpha, 2).await?;

        let peer_address = get_dummy_socket_address(2);
        let from_main_rx_clone = peer_broadcast_tx.subscribe();
        let peer_loop_handler =
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
    async fn test_peer_loop_peer_list() -> Result<()> {
        let (peer_broadcast_tx, _from_main_rx_clone, to_main_tx, _to_main_rx1, state_lock, _hsd) =
            get_test_genesis_setup(Network::Alpha, 2).await?;

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

        let peer_loop_handler =
            PeerLoopHandler::new(to_main_tx, state_lock.clone(), sa2, hsd2, true, 0);
        peer_loop_handler
            .run_wrapper(mock, from_main_rx_clone)
            .await?;

        assert_eq!(
            2,
            state_lock.lock_guard().await.net.peer_map.len(),
            "peer map must have length 2 after saying goodbye to peer 2"
        );

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn different_genesis_test() -> Result<()> {
        let mut rng = thread_rng();
        // In this scenario a peer provides another genesis block than what has been
        // hardcoded. This should lead to the closing of the connection to this peer
        // and a ban.
        let network = Network::Alpha;
        let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, mut to_main_rx1, state_lock, hsd) =
            get_test_genesis_setup(network, 0).await?;
        let peer_address = get_dummy_socket_address(0);

        // Although the database is empty, `get_latest_block` still returns the genesis block,
        // since that block is hardcoded.
        let mut different_genesis_block: Block = state_lock
            .lock_guard()
            .await
            .chain
            .archival_state()
            .get_latest_block()
            .await;
        different_genesis_block.kernel.header.nonce[2].increment();
        let a_wallet_secret = WalletSecret::new_random();
        let a_recipient_address = a_wallet_secret.nth_generation_spending_key(0).to_address();
        let (block_1_with_different_genesis, _, _) = make_mock_block_with_valid_pow(
            &different_genesis_block,
            None,
            a_recipient_address,
            rng.gen(),
        )
        .await;
        let mock = Mock::new(vec![Action::Read(PeerMessage::Block(Box::new(
            block_1_with_different_genesis.into(),
        )))]);

        let peer_loop_handler = PeerLoopHandler::new(
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
            Some(PeerThreadToMain::AddPeerMaxBlockHeight(_)) => (),
            _ => bail!("Must receive add of peer block max height"),
        }

        match to_main_rx1.recv().await {
            Some(PeerThreadToMain::RemovePeerMaxBlockHeight(_)) => (),
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
        let mut rng = thread_rng();
        // In this scenario, a block without a valid PoW is received. This block should be rejected
        // by the peer loop and a notification should never reach the main loop.
        let network = Network::Alpha;
        let (peer_broadcast_tx, _from_main_rx_clone, to_main_tx, mut to_main_rx1, state_lock, hsd) =
            get_test_genesis_setup(network, 0).await?;
        let peer_address = get_dummy_socket_address(0);
        let genesis_block: Block = state_lock
            .lock_guard()
            .await
            .chain
            .archival_state()
            .get_latest_block()
            .await;

        // Make a with hash above what the implied threshold from
        // `target_difficulty` requires
        let a_wallet_secret = WalletSecret::new_random();
        let a_recipient_address = a_wallet_secret.nth_generation_spending_key(0).to_address();
        let (block_without_valid_pow, _, _) =
            make_mock_block_with_invalid_pow(&genesis_block, None, a_recipient_address, rng.gen())
                .await;

        // Sending an invalid block will not neccessarily result in a ban. This depends on the peer
        // tolerance that is set in the client. For this reason, we include a "Bye" here.
        let mock = Mock::new(vec![
            Action::Read(PeerMessage::Block(Box::new(block_without_valid_pow.into()))),
            Action::Read(PeerMessage::Bye),
        ]);

        let from_main_rx_clone = peer_broadcast_tx.subscribe();

        let peer_loop_handler = PeerLoopHandler::new(
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
            "run_wrapper must return error when peer sends back block and is banned"
        );

        // Verify that max peer height was sent
        match to_main_rx1.recv().await {
            Some(PeerThreadToMain::AddPeerMaxBlockHeight(_)) => (),
            _ => bail!("Must receive add of peer block max height"),
        }

        match to_main_rx1.recv().await {
            Some(PeerThreadToMain::RemovePeerMaxBlockHeight(_)) => (),
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
        let mut rng = thread_rng();
        // The scenario tested here is that a client receives a block that is already
        // known and stored. The expected behavior is to ignore the block and not send
        // a message to the main thread.
        let network = Network::Alpha;
        let (peer_broadcast_tx, _from_main_rx_clone, to_main_tx, mut to_main_rx1, state_lock, hsd) =
            get_test_genesis_setup(network, 0).await?;
        let mut global_state_mut = state_lock.lock_guard_mut().await;
        let peer_address = get_dummy_socket_address(0);
        let genesis_block: Block = global_state_mut
            .chain
            .archival_state()
            .get_latest_block()
            .await;

        let a_wallet_secret = WalletSecret::new_random();
        let a_recipient_address = a_wallet_secret.nth_generation_spending_key(0).to_address();
        let (block_1, _, _) =
            make_mock_block_with_valid_pow(&genesis_block, None, a_recipient_address, rng.gen())
                .await;
        add_block(&mut global_state_mut, block_1.clone()).await?;
        drop(global_state_mut);

        let mock_peer_messages = Mock::new(vec![
            Action::Read(PeerMessage::Block(Box::new(block_1.into()))),
            Action::Read(PeerMessage::Bye),
        ]);

        let from_main_rx_clone = peer_broadcast_tx.subscribe();

        let peer_loop_handler = PeerLoopHandler::new(
            to_main_tx.clone(),
            state_lock.clone(),
            peer_address,
            hsd,
            false,
            1,
        );
        peer_loop_handler
            .run_wrapper(mock_peer_messages, from_main_rx_clone)
            .await?;

        // Verify that no block was sent to main loop
        match to_main_rx1.recv().await {
            Some(PeerThreadToMain::AddPeerMaxBlockHeight(_)) => (),
            _ => bail!("Must receive add of peer block max height"),
        }
        match to_main_rx1.recv().await {
            Some(PeerThreadToMain::RemovePeerMaxBlockHeight(_)) => (),
            _ => bail!("Must receive remove of peer block max height"),
        }
        match to_main_rx1.try_recv() {
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => (),
            _ => bail!("Block notification must not be sent for block with invalid PoW"),
        };
        drop(to_main_tx);

        if !state_lock.lock_guard().await.net.peer_map.is_empty() {
            bail!("peer map must be empty after closing connection gracefully");
        }

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn block_request_batch_in_order_test() -> Result<()> {
        let mut rng = thread_rng();
        // Scenario: A fork began at block 2, node knows two blocks of height 2 and two of height 3.
        // A peer requests a batch of blocks starting from block 1. Ensure that the correct blocks
        // are returned.
        let network = Network::Alpha;
        let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, _to_main_rx1, state_lock, hsd) =
            get_test_genesis_setup(network, 0).await?;
        let mut global_state_mut = state_lock.lock_guard_mut().await;
        let genesis_block: Block = global_state_mut
            .chain
            .archival_state()
            .get_latest_block()
            .await;
        let peer_address = get_dummy_socket_address(0);
        let a_wallet_secret = WalletSecret::new_random();
        let a_recipient_address = a_wallet_secret.nth_generation_spending_key(0).to_address();
        let (block_1, _, _) =
            make_mock_block_with_valid_pow(&genesis_block, None, a_recipient_address, rng.gen())
                .await;
        let (block_2_a, _, _) =
            make_mock_block_with_valid_pow(&block_1, None, a_recipient_address, rng.gen()).await;
        let (block_3_a, _, _) =
            make_mock_block_with_valid_pow(&block_2_a, None, a_recipient_address, rng.gen()).await; // <--- canonical
        let (block_2_b, _, _) =
            make_mock_block_with_valid_pow(&block_1, None, a_recipient_address, rng.gen()).await;
        let (block_3_b, _, _) =
            make_mock_block_with_valid_pow(&block_2_b, None, a_recipient_address, rng.gen()).await;

        add_block(&mut global_state_mut, block_1.clone()).await?;
        add_block(&mut global_state_mut, block_2_a.clone()).await?;
        add_block(&mut global_state_mut, block_3_a.clone()).await?;
        add_block(&mut global_state_mut, block_2_b.clone()).await?;
        add_block(&mut global_state_mut, block_3_b.clone()).await?;

        drop(global_state_mut);

        let mut mock = Mock::new(vec![
            Action::Read(PeerMessage::BlockRequestBatch(
                vec![genesis_block.hash()],
                14,
            )),
            Action::Write(PeerMessage::BlockResponseBatch(vec![
                block_1.clone().into(),
                block_2_a.clone().into(),
                block_3_a.clone().into(),
            ])),
            Action::Read(PeerMessage::Bye),
        ]);

        let peer_loop_handler_1 = PeerLoopHandler::new(
            to_main_tx.clone(),
            state_lock.clone(),
            peer_address,
            hsd.clone(),
            false,
            1,
        );

        peer_loop_handler_1
            .run_wrapper(mock, from_main_rx_clone.resubscribe())
            .await?;

        // Peer knows block 2_b, verify that canonical chain with 2_a is returned
        mock = Mock::new(vec![
            Action::Read(PeerMessage::BlockRequestBatch(
                vec![block_2_b.hash(), block_1.hash(), genesis_block.hash()],
                14,
            )),
            Action::Write(PeerMessage::BlockResponseBatch(vec![
                block_2_a.into(),
                block_3_a.into(),
            ])),
            Action::Read(PeerMessage::Bye),
        ]);

        let peer_loop_handler_2 = PeerLoopHandler::new(
            to_main_tx.clone(),
            state_lock.clone(),
            peer_address,
            hsd,
            false,
            1,
        );

        peer_loop_handler_2
            .run_wrapper(mock, from_main_rx_clone)
            .await?;

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn block_request_batch_out_of_order_test() -> Result<()> {
        let mut rng = thread_rng();
        // Scenario: Same as above, but the peer supplies their hashes in a wrong order.
        // Ensure that the correct blocks are returned, in the right order.
        let network = Network::Alpha;
        let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, _to_main_rx1, state_lock, hsd) =
            get_test_genesis_setup(network, 0).await?;
        let mut global_state_mut = state_lock.lock_guard_mut().await;
        let genesis_block: Block = global_state_mut
            .chain
            .archival_state()
            .get_latest_block()
            .await;
        let peer_address = get_dummy_socket_address(0);
        let a_wallet_secret = WalletSecret::new_random();
        let a_recipient_address = a_wallet_secret.nth_generation_spending_key(0).to_address();
        let (block_1, _, _) =
            make_mock_block_with_valid_pow(&genesis_block, None, a_recipient_address, rng.gen())
                .await;
        let (block_2_a, _, _) =
            make_mock_block_with_valid_pow(&block_1, None, a_recipient_address, rng.gen()).await;
        let (block_3_a, _, _) =
            make_mock_block_with_valid_pow(&block_2_a, None, a_recipient_address, rng.gen()).await; // <--- canonical
        let (block_2_b, _, _) =
            make_mock_block_with_valid_pow(&block_1, None, a_recipient_address, rng.gen()).await;
        let (block_3_b, _, _) =
            make_mock_block_with_valid_pow(&block_2_b, None, a_recipient_address, rng.gen()).await;

        add_block(&mut global_state_mut, block_1.clone()).await?;
        add_block(&mut global_state_mut, block_2_a.clone()).await?;
        add_block(&mut global_state_mut, block_3_a.clone()).await?;
        add_block(&mut global_state_mut, block_2_b.clone()).await?;
        add_block(&mut global_state_mut, block_3_b.clone()).await?;

        drop(global_state_mut);

        // Peer knows block 2_b, verify that canonical chain with 2_a is returned
        let mock = Mock::new(vec![
            Action::Read(PeerMessage::BlockRequestBatch(
                vec![block_2_b.hash(), genesis_block.hash(), block_1.hash()],
                14,
            )),
            Action::Write(PeerMessage::BlockResponseBatch(vec![
                block_2_a.into(),
                block_3_a.into(),
            ])),
            Action::Read(PeerMessage::Bye),
        ]);

        let peer_loop_handler_2 = PeerLoopHandler::new(
            to_main_tx.clone(),
            state_lock.clone(),
            peer_address,
            hsd,
            false,
            1,
        );

        peer_loop_handler_2
            .run_wrapper(mock, from_main_rx_clone)
            .await?;

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn find_canonical_chain_when_multiple_blocks_at_same_height_test() -> Result<()> {
        let mut rng = thread_rng();
        // Scenario: A fork began at block 2, node knows two blocks of height 2 and two of height 3.
        // A peer requests a block at height 2. Verify that the correct block at height 2 is returned.
        let network = Network::Alpha;
        let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, _to_main_rx1, state_lock, hsd) =
            get_test_genesis_setup(network, 0).await?;
        let mut global_state_mut = state_lock.lock_guard_mut().await;
        let genesis_block: Block = global_state_mut
            .chain
            .archival_state()
            .get_latest_block()
            .await;
        let peer_address = get_dummy_socket_address(0);
        let a_wallet_secret = WalletSecret::new_random();
        let a_recipient_address = a_wallet_secret.nth_generation_spending_key(0).to_address();
        let (block_1, _, _) =
            make_mock_block_with_valid_pow(&genesis_block, None, a_recipient_address, rng.gen())
                .await;
        let (block_2_a, _, _) =
            make_mock_block_with_valid_pow(&block_1, None, a_recipient_address, rng.gen()).await;
        let (block_3_a, _, _) =
            make_mock_block_with_valid_pow(&block_2_a, None, a_recipient_address, rng.gen()).await; // <--- canonical
        let (block_2_b, _, _) =
            make_mock_block_with_valid_pow(&block_1, None, a_recipient_address, rng.gen()).await;
        let (block_3_b, _, _) =
            make_mock_block_with_valid_pow(&block_2_b, None, a_recipient_address, rng.gen()).await;

        add_block(&mut global_state_mut, block_1.clone()).await?;
        add_block(&mut global_state_mut, block_2_a.clone()).await?;
        add_block(&mut global_state_mut, block_3_a.clone()).await?;
        add_block(&mut global_state_mut, block_2_b.clone()).await?;
        add_block(&mut global_state_mut, block_3_b.clone()).await?;

        drop(global_state_mut);

        let mock = Mock::new(vec![
            Action::Read(PeerMessage::BlockRequestByHeight(2.into())),
            Action::Write(PeerMessage::Block(Box::new(block_2_a.into()))),
            Action::Read(PeerMessage::BlockRequestByHeight(3.into())),
            Action::Write(PeerMessage::Block(Box::new(block_3_a.into()))),
            Action::Read(PeerMessage::Bye),
        ]);

        let peer_loop_handler = PeerLoopHandler::new(
            to_main_tx.clone(),
            state_lock.clone(),
            peer_address,
            hsd,
            false,
            1,
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
        let mut rng = thread_rng();
        // Scenario: client only knows genesis block. Then receives block 1.
        let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, mut to_main_rx1, state_lock, hsd) =
            get_test_genesis_setup(Network::Alpha, 0).await?;
        let a_wallet_secret = WalletSecret::new_random();
        let a_recipient_address = a_wallet_secret.nth_generation_spending_key(0).to_address();
        let peer_address = get_dummy_socket_address(0);
        let genesis_block: Block = state_lock
            .lock_guard()
            .await
            .chain
            .archival_state()
            .get_latest_block()
            .await;

        let (mock_block_1, _, _) =
            make_mock_block_with_valid_pow(&genesis_block, None, a_recipient_address, rng.gen())
                .await;
        let mock = Mock::new(vec![
            Action::Read(PeerMessage::Block(Box::new(mock_block_1.into()))),
            Action::Read(PeerMessage::Bye),
        ]);

        let peer_loop_handler = PeerLoopHandler::new(
            to_main_tx.clone(),
            state_lock.clone(),
            peer_address,
            hsd,
            false,
            1,
        );
        peer_loop_handler
            .run_wrapper(mock, from_main_rx_clone)
            .await?;

        // Verify that peer max block height was sent
        match to_main_rx1.recv().await {
            Some(PeerThreadToMain::AddPeerMaxBlockHeight(_)) => (),
            _ => bail!("Must receive add of peer block max height"),
        }

        // Verify that a block was sent to `main_loop`
        match to_main_rx1.recv().await {
            Some(PeerThreadToMain::NewBlocks(_block)) => (),
            _ => bail!("Did not find msg sent to main thread"),
        };

        match to_main_rx1.recv().await {
            Some(PeerThreadToMain::RemovePeerMaxBlockHeight(_)) => (),
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
        let mut rng = thread_rng();
        // In this scenario, the client only knows the genesis block (block 0) and then
        // receives block 2, meaning that block 1 will have to be requested.
        let network = Network::Testnet;
        let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, mut to_main_rx1, state_lock, hsd) =
            get_test_genesis_setup(network, 0).await?;
        let peer_address = get_dummy_socket_address(0);
        let genesis_block: Block = state_lock
            .lock_guard()
            .await
            .chain
            .archival_state()
            .get_latest_block()
            .await;
        let a_wallet_secret = WalletSecret::new_random();
        let a_recipient_address = a_wallet_secret.nth_generation_spending_key(0).to_address();
        let (block_1, _, _) =
            make_mock_block_with_valid_pow(&genesis_block, None, a_recipient_address, rng.gen())
                .await;
        let (block_2, _, _) =
            make_mock_block_with_valid_pow(&block_1.clone(), None, a_recipient_address, rng.gen())
                .await;

        let mock = Mock::new(vec![
            Action::Read(PeerMessage::Block(Box::new(block_2.clone().into()))),
            Action::Write(PeerMessage::BlockRequestByHash(block_1.hash())),
            Action::Read(PeerMessage::Block(Box::new(block_1.clone().into()))),
            Action::Read(PeerMessage::Bye),
        ]);

        let peer_loop_handler = PeerLoopHandler::new(
            to_main_tx.clone(),
            state_lock.clone(),
            peer_address,
            hsd,
            true,
            1,
        );
        peer_loop_handler
            .run_wrapper(mock, from_main_rx_clone)
            .await?;

        // Verify that peer max block height was sent
        match to_main_rx1.recv().await {
            Some(PeerThreadToMain::AddPeerMaxBlockHeight(_)) => (),
            _ => bail!("Must receive peer block max height"),
        }

        match to_main_rx1.recv().await {
            Some(PeerThreadToMain::NewBlocks(blocks)) => {
                if blocks[0].hash() != block_1.hash() {
                    bail!("1st received block by main loop must be block 1");
                }
                if blocks[1].hash() != block_2.hash() {
                    bail!("2nd received block by main loop must be block 2");
                }
            }
            _ => bail!("Did not find msg sent to main thread 1"),
        };
        match to_main_rx1.recv().await {
            Some(PeerThreadToMain::RemovePeerMaxBlockHeight(_)) => (),
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
        let mut rng = thread_rng();
        // In this scenario the peer sends more blocks than the client allows to store in the
        // fork-reconciliation field. This should result in abandonment of the fork-reconciliation
        // process as the alternative is that the program will crash because it runs out of RAM.
        let (
            _peer_broadcast_tx,
            from_main_rx_clone,
            to_main_tx,
            mut to_main_rx1,
            mut state_lock,
            _hsd,
        ) = get_test_genesis_setup(Network::Alpha, 1).await?;

        // Restrict max number of blocks held in memory to 2.
        let mut cli = state_lock.cli().clone();
        cli.max_number_of_blocks_before_syncing = 2;
        state_lock.set_cli(cli).await;

        let mut global_state_mut = state_lock.lock_guard_mut().await;

        let (hsd1, peer_address1) = get_dummy_peer_connection_data_genesis(Network::Alpha, 1).await;
        let genesis_block: Block = global_state_mut
            .chain
            .archival_state()
            .get_latest_block()
            .await;
        let own_recipient_address = global_state_mut
            .wallet_state
            .wallet_secret
            .nth_generation_spending_key(0)
            .to_address();
        let (block_1, _, _) = make_mock_block_with_valid_pow(
            &genesis_block.clone(),
            None,
            own_recipient_address,
            rng.gen(),
        )
        .await;
        let (block_2, _, _) = make_mock_block_with_valid_pow(
            &block_1.clone(),
            None,
            own_recipient_address,
            rng.gen(),
        )
        .await;
        let (block_3, _, _) = make_mock_block_with_valid_pow(
            &block_2.clone(),
            None,
            own_recipient_address,
            rng.gen(),
        )
        .await;
        let (block_4, _, _) = make_mock_block_with_valid_pow(
            &block_3.clone(),
            None,
            own_recipient_address,
            rng.gen(),
        )
        .await;
        add_block(&mut global_state_mut, block_1.clone()).await?;

        drop(global_state_mut);

        let mock = Mock::new(vec![
            Action::Read(PeerMessage::Block(Box::new(block_4.clone().into()))),
            Action::Write(PeerMessage::BlockRequestByHash(block_3.hash())),
            Action::Read(PeerMessage::Block(Box::new(block_3.clone().into()))),
            Action::Read(PeerMessage::Bye),
        ]);

        let peer_loop_handler = PeerLoopHandler::new(
            to_main_tx.clone(),
            state_lock.clone(),
            peer_address1,
            hsd1,
            true,
            1,
        );
        peer_loop_handler
            .run_wrapper(mock, from_main_rx_clone)
            .await?;

        // Verify that peer max block height was sent
        match to_main_rx1.recv().await {
            Some(PeerThreadToMain::AddPeerMaxBlockHeight(_)) => (),
            _ => bail!("Must receive add of peer block max height"),
        }
        match to_main_rx1.recv().await {
            Some(PeerThreadToMain::RemovePeerMaxBlockHeight(_)) => (),
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
    async fn test_peer_loop_receival_of_fourth_block_one_block_in_db() -> Result<()> {
        let mut rng = thread_rng();
        // In this scenario, the client know the genesis block (block 0) and block 1, it
        // then receives block 4, meaning that block 3 and 2 will have to be requested.
        let network = Network::Testnet;
        let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, mut to_main_rx1, state_lock, hsd) =
            get_test_genesis_setup(network, 0).await?;
        let mut global_state_mut = state_lock.lock_guard_mut().await;
        let peer_address: SocketAddr = get_dummy_socket_address(0);
        let genesis_block: Block = global_state_mut
            .chain
            .archival_state()
            .get_latest_block()
            .await;
        let a_wallet_secret = WalletSecret::new_random();
        let a_recipient_address = a_wallet_secret.nth_generation_spending_key(0).to_address();
        let (block_1, _, _) = make_mock_block_with_valid_pow(
            &genesis_block.clone(),
            None,
            a_recipient_address,
            rng.gen(),
        )
        .await;
        let (block_2, _, _) =
            make_mock_block_with_valid_pow(&block_1.clone(), None, a_recipient_address, rng.gen())
                .await;
        let (block_3, _, _) =
            make_mock_block_with_valid_pow(&block_2.clone(), None, a_recipient_address, rng.gen())
                .await;
        let (block_4, _, _) =
            make_mock_block_with_valid_pow(&block_3.clone(), None, a_recipient_address, rng.gen())
                .await;
        add_block(&mut global_state_mut, block_1.clone()).await?;
        drop(global_state_mut);

        let mock = Mock::new(vec![
            Action::Read(PeerMessage::Block(Box::new(block_4.clone().into()))),
            Action::Write(PeerMessage::BlockRequestByHash(block_3.hash())),
            Action::Read(PeerMessage::Block(Box::new(block_3.clone().into()))),
            Action::Write(PeerMessage::BlockRequestByHash(block_2.hash())),
            Action::Read(PeerMessage::Block(Box::new(block_2.clone().into()))),
            Action::Read(PeerMessage::Bye),
        ]);

        let peer_loop_handler = PeerLoopHandler::new(
            to_main_tx.clone(),
            state_lock.clone(),
            peer_address,
            hsd,
            true,
            1,
        );
        peer_loop_handler
            .run_wrapper(mock, from_main_rx_clone)
            .await?;

        // Verify that peer max block height was sent
        match to_main_rx1.recv().await {
            Some(PeerThreadToMain::AddPeerMaxBlockHeight(_)) => (),
            _ => bail!("Must receive add of peer block max height"),
        }

        match to_main_rx1.recv().await {
            Some(PeerThreadToMain::NewBlocks(blocks)) => {
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
            _ => bail!("Did not find msg sent to main thread"),
        };
        match to_main_rx1.recv().await {
            Some(PeerThreadToMain::RemovePeerMaxBlockHeight(_)) => (),
            _ => bail!("Must receive remove of peer block max height"),
        }

        if !state_lock.lock_guard().await.net.peer_map.is_empty() {
            bail!("peer map must be empty after closing connection gracefully");
        }

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn test_peer_loop_receival_of_third_block_no_blocks_in_db() -> Result<()> {
        let mut rng = thread_rng();
        // In this scenario, the client only knows the genesis block (block 0) and then
        // receives block 3, meaning that block 2 and 1 will have to be requested.
        let network = Network::RegTest;
        let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, mut to_main_rx1, state_lock, hsd) =
            get_test_genesis_setup(network, 0).await?;
        let global_state = state_lock.lock_guard().await;
        let peer_address = get_dummy_socket_address(0);

        let genesis_block: Block = global_state.chain.archival_state().get_latest_block().await;
        let a_wallet_secret = WalletSecret::new_random();
        let a_recipient_address = a_wallet_secret.nth_generation_spending_key(0).to_address();
        let (block_1, _, _) = make_mock_block_with_valid_pow(
            &genesis_block.clone(),
            None,
            a_recipient_address,
            rng.gen(),
        )
        .await;
        let (block_2, _, _) =
            make_mock_block_with_valid_pow(&block_1.clone(), None, a_recipient_address, rng.gen())
                .await;
        let (block_3, _, _) =
            make_mock_block_with_valid_pow(&block_2.clone(), None, a_recipient_address, rng.gen())
                .await;
        drop(global_state);

        let mock = Mock::new(vec![
            Action::Read(PeerMessage::Block(Box::new(block_3.clone().into()))),
            Action::Write(PeerMessage::BlockRequestByHash(block_2.hash())),
            Action::Read(PeerMessage::Block(Box::new(block_2.clone().into()))),
            Action::Write(PeerMessage::BlockRequestByHash(block_1.hash())),
            Action::Read(PeerMessage::Block(Box::new(block_1.clone().into()))),
            Action::Read(PeerMessage::Bye),
        ]);

        let peer_loop_handler = PeerLoopHandler::new(
            to_main_tx.clone(),
            state_lock.clone(),
            peer_address,
            hsd,
            true,
            1,
        );
        peer_loop_handler
            .run_wrapper(mock, from_main_rx_clone)
            .await?;

        // Verify that peer max block height was sent
        match to_main_rx1.recv().await {
            Some(PeerThreadToMain::AddPeerMaxBlockHeight(_)) => (),
            _ => bail!("Must receive add of peer block max height"),
        }

        match to_main_rx1.recv().await {
            Some(PeerThreadToMain::NewBlocks(blocks)) => {
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
            _ => bail!("Did not find msg sent to main thread"),
        };
        match to_main_rx1.recv().await {
            Some(PeerThreadToMain::RemovePeerMaxBlockHeight(_)) => (),
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
        let mut rng = thread_rng();
        // In this scenario, the client know the genesis block (block 0) and block 1, it
        // then receives block 4, meaning that block 3, 2, and 1 will have to be requested.
        // But the requests are interrupted by the peer sending another message: a new block
        // notification.
        let network = Network::RegTest;
        let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, mut to_main_rx1, state_lock, hsd) =
            get_test_genesis_setup(network, 0).await?;
        let mut global_state_mut = state_lock.lock_guard_mut().await;
        let a_wallet_secret = WalletSecret::new_random();
        let a_recipient_address = a_wallet_secret.nth_generation_spending_key(0).to_address();
        let peer_socket_address: SocketAddr = get_dummy_socket_address(0);
        let genesis_block: Block = global_state_mut
            .chain
            .archival_state()
            .get_latest_block()
            .await;
        let (block_1, _, _) = make_mock_block_with_valid_pow(
            &genesis_block.clone(),
            None,
            a_recipient_address,
            rng.gen(),
        )
        .await;
        let (block_2, _, _) =
            make_mock_block_with_valid_pow(&block_1.clone(), None, a_recipient_address, rng.gen())
                .await;
        let (block_3, _, _) =
            make_mock_block_with_valid_pow(&block_2.clone(), None, a_recipient_address, rng.gen())
                .await;
        let (block_4, _, _) =
            make_mock_block_with_valid_pow(&block_3.clone(), None, a_recipient_address, rng.gen())
                .await;
        let (block_5, _, _) =
            make_mock_block_with_valid_pow(&block_4.clone(), None, a_recipient_address, rng.gen())
                .await;
        add_block(&mut global_state_mut, block_1.clone()).await?;
        drop(global_state_mut);

        let mock = Mock::new(vec![
            Action::Read(PeerMessage::Block(Box::new(block_4.clone().into()))),
            Action::Write(PeerMessage::BlockRequestByHash(block_3.hash())),
            Action::Read(PeerMessage::Block(Box::new(block_3.clone().into()))),
            Action::Write(PeerMessage::BlockRequestByHash(block_2.hash())),
            //
            // Now make the interruption of the block reconciliation process
            Action::Read(PeerMessage::BlockNotification(block_5.clone().into())),
            //
            // Complete the block reconciliation process by requesting the last block
            // in this process, to get back to a mutually known block.
            Action::Read(PeerMessage::Block(Box::new(block_2.clone().into()))),
            //
            // Then anticipate the request of the block that was announced
            // in the interruption.
            // Note that we cannot anticipate the response, as only the main
            // thread writes to the database. And the database needs to be updated
            // for the handling of block 5 to be done correctly.
            Action::Write(PeerMessage::BlockRequestByHeight(
                block_5.kernel.header.height,
            )),
            Action::Read(PeerMessage::Bye),
        ]);

        let peer_loop_handler = PeerLoopHandler::new(
            to_main_tx.clone(),
            state_lock.clone(),
            peer_socket_address,
            hsd,
            false,
            1,
        );
        peer_loop_handler
            .run_wrapper(mock, from_main_rx_clone)
            .await?;

        // Verify that peer max block height was sent
        match to_main_rx1.recv().await {
            Some(PeerThreadToMain::AddPeerMaxBlockHeight(_)) => (),
            _ => bail!("Must receive add of peer block max height"),
        }

        match to_main_rx1.recv().await {
            Some(PeerThreadToMain::NewBlocks(blocks)) => {
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
            _ => bail!("Did not find msg sent to main thread"),
        };
        match to_main_rx1.recv().await {
            Some(PeerThreadToMain::RemovePeerMaxBlockHeight(_)) => (),
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
        let mut rng = thread_rng();
        // In this scenario, the client knows the genesis block (block 0) and block 1, it
        // then receives block 4, meaning that block 3, 2, and 1 will have to be requested.
        // But the requests are interrupted by the peer sending another message: a request
        // for a list of peers.
        let network = Network::RegTest;
        let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, mut to_main_rx1, state_lock, _hsd) =
            get_test_genesis_setup(network, 1).await?;
        let mut global_state_mut = state_lock.lock_guard_mut().await;
        let peer_infos: Vec<PeerInfo> = global_state_mut
            .net
            .peer_map
            .clone()
            .into_values()
            .collect::<Vec<_>>();

        let genesis_block: Block = global_state_mut
            .chain
            .archival_state()
            .get_latest_block()
            .await;
        let a_wallet_secret = WalletSecret::new_random();
        let a_recipient_address = a_wallet_secret.nth_generation_spending_key(0).to_address();
        let (block_1, _, _) = make_mock_block_with_valid_pow(
            &genesis_block.clone(),
            None,
            a_recipient_address,
            rng.gen(),
        )
        .await;
        let (block_2, _, _) =
            make_mock_block_with_valid_pow(&block_1.clone(), None, a_recipient_address, rng.gen())
                .await;
        let (block_3, _, _) =
            make_mock_block_with_valid_pow(&block_2.clone(), None, a_recipient_address, rng.gen())
                .await;
        let (block_4, _, _) =
            make_mock_block_with_valid_pow(&block_3.clone(), None, a_recipient_address, rng.gen())
                .await;
        add_block(&mut global_state_mut, block_1.clone()).await?;
        drop(global_state_mut);

        let (hsd_1, sa_1) = get_dummy_peer_connection_data_genesis(network, 1).await;
        let expected_peer_list_resp = vec![
            (
                peer_infos[0].listen_address().unwrap(),
                peer_infos[0].instance_id,
            ),
            (sa_1, hsd_1.instance_id),
        ];
        let mock = Mock::new(vec![
            Action::Read(PeerMessage::Block(Box::new(block_4.clone().into()))),
            Action::Write(PeerMessage::BlockRequestByHash(block_3.hash())),
            Action::Read(PeerMessage::Block(Box::new(block_3.clone().into()))),
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
            Action::Read(PeerMessage::Block(Box::new(block_2.clone().into()))),
            Action::Read(PeerMessage::Bye),
        ]);

        let peer_loop_handler =
            PeerLoopHandler::new(to_main_tx, state_lock.clone(), sa_1, hsd_1, true, 1);
        peer_loop_handler
            .run_wrapper(mock, from_main_rx_clone)
            .await?;

        // Verify that peer max block height was sent
        match to_main_rx1.recv().await {
            Some(PeerThreadToMain::AddPeerMaxBlockHeight(_)) => (),
            _ => bail!("Must receive peer block max height"),
        }

        // Verify that blocks are sent to `main_loop` in expected ordering
        match to_main_rx1.recv().await {
            Some(PeerThreadToMain::NewBlocks(blocks)) => {
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
            _ => bail!("Did not find msg sent to main thread"),
        };

        match to_main_rx1.recv().await {
            Some(PeerThreadToMain::RemovePeerMaxBlockHeight(_)) => (),
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
    async fn empty_mempool_request_tx_test() -> Result<()> {
        // In this scenerio the client receives a transaction notification from
        // a peer of a transaction it doesn't know; the client must then request it.
        let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, mut to_main_rx1, state_lock, _hsd) =
            get_test_genesis_setup(Network::Alpha, 1).await?;

        let transaction_1 = make_mock_transaction(vec![], vec![]);

        // Build the resulting transaction notification
        let tx_notification: TransactionNotification = transaction_1.clone().into();
        let mock = Mock::new(vec![
            Action::Read(PeerMessage::TransactionNotification(tx_notification)),
            Action::Write(PeerMessage::TransactionRequest(
                tx_notification.transaction_digest,
            )),
            Action::Read(PeerMessage::Transaction(Box::new(transaction_1))),
            Action::Read(PeerMessage::Bye),
        ]);

        let (hsd_1, _sa_1) = get_dummy_peer_connection_data_genesis(Network::Alpha, 1).await;
        let peer_loop_handler = PeerLoopHandler::new(
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
        peer_loop_handler
            .run(mock, from_main_rx_clone, &mut peer_state)
            .await?;

        // Transaction must be sent to `main_loop`. The transaction is stored to the mempool
        // by the `main_loop`.
        match to_main_rx1.recv().await {
            Some(PeerThreadToMain::Transaction(_)) => (),
            _ => bail!("Must receive remove of peer block max height"),
        }

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn populated_mempool_request_tx_test() -> Result<()> {
        // In this scenario the peer is informed of a transaction that it already knows
        let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, mut to_main_rx1, state_lock, _hsd) =
            get_test_genesis_setup(Network::Alpha, 1).await?;

        let transaction_1 = make_mock_transaction(vec![], vec![]);

        // Build the resulting transaction notification
        let tx_notification: TransactionNotification = transaction_1.clone().into();
        let mock = Mock::new(vec![
            Action::Read(PeerMessage::TransactionNotification(tx_notification)),
            Action::Read(PeerMessage::Bye),
        ]);

        let (hsd_1, _sa_1) = get_dummy_peer_connection_data_genesis(Network::Alpha, 1).await;
        let peer_loop_handler = PeerLoopHandler::new(
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
            .mempool
            .insert(&transaction_1);
        assert!(
            !state_lock.lock_guard().await.mempool.is_empty(),
            "Mempool must be non-empty after insertion"
        );

        peer_loop_handler
            .run(mock, from_main_rx_clone, &mut peer_state)
            .await?;

        // nothing may be sent to `main_loop`
        match to_main_rx1.try_recv() {
            Err(TryRecvError::Empty) => (),
            Err(TryRecvError::Disconnected) => bail!("to_main channel must still be open"),
            Ok(_) => bail!("to_main channel must be empty"),
        }

        Ok(())
    }
}
