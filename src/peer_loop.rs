use crate::database::leveldb::LevelDB;
use crate::models::blockchain::block::block_header::BlockHeader;
use crate::models::blockchain::block::block_height::BlockHeight;
use crate::models::blockchain::block::transfer_block::TransferBlock;
use crate::models::blockchain::block::Block;
use crate::models::blockchain::digest::{Digest, Hashable};
use crate::models::channel::{MainToPeerThread, PeerThreadToMain};
use crate::models::peer::{
    HandshakeData, MutablePeerState, PeerBlockNotification, PeerInfo, PeerMessage,
    PeerSanctionReason, PeerStanding,
};
use crate::models::state::State;
use anyhow::{bail, Result};
use futures::sink::{Sink, SinkExt};
use futures::stream::{TryStream, TryStreamExt};
use std::cmp;
use std::marker::Unpin;
use std::net::SocketAddr;
use std::time::SystemTime;
use tokio::select;
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, error, info, warn};

const STANDARD_BLOCK_BATCH_SIZE: usize = 50;
const MAX_PEER_LIST_LENGTH: usize = 10;
const MINIMUM_BLOCK_BATCH_SIZE: usize = 10;

/// Contains the immutable data that this peer-loop needs. Does not contain the `peer` variable
/// since this needs to be a mutable variable in most methods.
pub struct PeerLoopHandler {
    to_main_tx: mpsc::Sender<PeerThreadToMain>,
    state: State,
    peer_address: SocketAddr,
    peer_handshake_data: HandshakeData,
    inbound_connection: bool,
    distance: u8,
}

impl PeerLoopHandler {
    pub fn new(
        to_main_tx: mpsc::Sender<PeerThreadToMain>,
        state: State,
        peer_address: SocketAddr,
        peer_handshake_data: HandshakeData,
        inbound_connection: bool,
        distance: u8,
    ) -> Self {
        Self {
            to_main_tx,
            state,
            peer_address,
            peer_handshake_data,
            inbound_connection,
            distance,
        }
    }

    fn punish(&self, reason: PeerSanctionReason) -> Result<()> {
        warn!(
            "Sanctioning peer {} for {:?}",
            self.peer_address.ip(),
            reason
        );
        let mut peers = self
            .state
            .net
            .peer_map
            .lock()
            .unwrap_or_else(|e| panic!("Failed to lock peer map: {}", e));
        let new_standing: &mut u16 = &mut 0;
        peers
            .entry(self.peer_address)
            .and_modify(|p| *new_standing = p.standing.sanction(reason));

        if *new_standing > self.state.cli.peer_tolerance {
            warn!("Banning peer");
            bail!("Banning peer");
        }

        Ok(())
    }

    /// Function for handling a list of blocks. Used both when a single block
    /// is received and when a batch of blocks is received. Handles validation
    /// and sends all blocks to the main thread if they're all valid.
    async fn handle_blocks(
        &self,
        received_blocks: Vec<Block>,
        parent_block: Block,
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
        let mut previous_block = parent_block;
        for new_block in received_blocks.iter() {
            if !new_block.archival_is_valid(&previous_block) {
                warn!(
                    "Received invalid block of height {} from peer with IP {}",
                    new_block.header.height, self.peer_address
                );
                self.punish(PeerSanctionReason::InvalidBlock((
                    new_block.header.height,
                    new_block.hash,
                )))?;
                bail!("Failed to validated block");
            } else {
                info!("Block with height {} is valid", new_block.header.height);
            }

            previous_block = new_block.to_owned();
        }

        // Send the new blocks to the main thread which handles the state update
        // and storage to the database.
        let new_block_height = received_blocks.last().unwrap().header.height;
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
    async fn handle_new_block<S>(
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
        let parent_digest = received_block.header.prev_block_digest;
        debug!("Fetching parent block");
        let parent_block = self
            .state
            .chain
            .archival_state
            .as_ref()
            .unwrap()
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
        let parent_height = received_block.header.height.previous();

        // If parent is not known, request the parent, and add the current to the peer fork resolution list
        if parent_block.is_none() && parent_height > BlockHeight::genesis() {
            info!(
                "Parent not know: Requesting previous block with height {} from peer",
                parent_height
            );

            // If the received block matches the block reconciliation state
            // push it there and request its parent
            if peer_state.fork_reconciliation_blocks.is_empty()
                || peer_state
                    .fork_reconciliation_blocks
                    .last()
                    .unwrap()
                    .header
                    .height
                    .previous()
                    == received_block.header.height
                    && peer_state.fork_reconciliation_blocks.len() + 1
                        < self.state.cli.max_number_of_blocks_before_syncing
            {
                peer_state.fork_reconciliation_blocks.push(*received_block);
            } else {
                // Blocks received out of order. Or more than allowed received without
                // going into sync mode. Give up on block resolution attempt.
                self.punish(PeerSanctionReason::ForkResolutionError((
                    received_block.header.height,
                    peer_state.fork_reconciliation_blocks.len() as u16,
                    received_block.hash,
                )))?;
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
            self.punish(PeerSanctionReason::DifferentGenesis)?;
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
        let mut new_blocks_sorted_check = new_blocks.clone();
        new_blocks_sorted_check.sort_by(|a, b| a.header.height.cmp(&b.header.height));
        assert_eq!(
            new_blocks_sorted_check, new_blocks,
            "Block list in fork resolution must be sorted"
        );

        // Parent block is guaranteed to be set here, either it is fetched from the
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
                // Note that the current peer is not removed from the state.peer_map here
                // but that this is done by the caller.
                info!("Got bye. Closing connection to peer");
                Ok(true)
            }
            PeerMessage::PeerListRequest => {
                // We are interested in the address on which peers accept ingoing connections,
                // not in the address in which they are connected to us. We are only interested in
                // peers that accept incoming connections.
                let peer_info = self
                    .state
                    .net
                    .peer_map
                    .lock()
                    .unwrap_or_else(|e| panic!("Failed to lock peer map: {}", e))
                    .values()
                    .filter(|peer_info| peer_info.address_for_incoming_connections.is_some())
                    .take(MAX_PEER_LIST_LENGTH) // limit length of response
                    .map(|peer_info| {
                        (
                            peer_info.address_for_incoming_connections.unwrap(),
                            peer_info.instance_id,
                        )
                    })
                    .collect();
                peer.send(PeerMessage::PeerListResponse(peer_info)).await?;
                Ok(false)
            }
            PeerMessage::PeerListResponse(peers) => {
                if peers.len() > MAX_PEER_LIST_LENGTH {
                    self.punish(PeerSanctionReason::FloodPeerListResponse)?;
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
                    "Got new block from peer {} (listen: {:?}), block height {}",
                    self.peer_address,
                    self.peer_handshake_data.listen_address,
                    t_block.header.height
                );
                let new_block_height = t_block.header.height;

                let block: Box<Block> = Box::new((*t_block).into());

                // Update the value for the highest known height that peer possesses iff
                // we are not in a fork reconciliation state.
                if peer_state_info.fork_reconciliation_blocks.is_empty() {
                    peer_state_info.highest_shared_block_height = new_block_height;
                }

                // TODO: Handle the situation where peer_state_info.fork_resolution_blocks is not empty better.
                let block_is_new = self
                    .state
                    .chain
                    .light_state
                    .get_latest_block_header()
                    .proof_of_work_family
                    < block.header.proof_of_work_family
                    || !peer_state_info.fork_reconciliation_blocks.is_empty();

                if block_is_new {
                    debug!("block is new");
                    self.handle_new_block(block, peer, peer_state_info).await?;
                } else {
                    info!(
                        "Got non-canonical block from peer, height: {}, PoW family: {:?}",
                        new_block_height, block.header.proof_of_work_family,
                    );
                }
                Ok(false)
            }
            PeerMessage::BlockRequestBatch(most_canonical_digests, requested_batch_size) => {
                // Find the block that the peer is requesting to start from
                let mut peers_most_canonical_block: Option<Block> = None;
                let tip_header = self.state.chain.light_state.get_latest_block_header();
                for digest in most_canonical_digests {
                    debug!("Looking up block {} in batch request", digest);
                    let block_candidate = self
                        .state
                        .chain
                        .archival_state
                        .as_ref()
                        .unwrap()
                        .get_block(digest)
                        .await
                        .expect("Lookup must work");
                    if let Some(block_candidate) = block_candidate {
                        // Verify that this block is not only known but also belongs to the canonical
                        // chain. Also check if it's the genesis block.

                        if self
                            .state
                            .chain
                            .archival_state
                            .as_ref()
                            .unwrap()
                            .block_belongs_to_canonical_chain(&block_candidate.header, &tip_header)
                            .await
                        {
                            peers_most_canonical_block = Some(block_candidate);
                            debug!("Found block {}", digest);
                            break;
                        }
                    }
                }

                if peers_most_canonical_block.is_none() {
                    self.punish(PeerSanctionReason::BatchBlocksUnknownRequest)?;
                    return Ok(false);
                }

                let peers_most_canonical_block = peers_most_canonical_block.unwrap();

                // Get the relevant blocks, from the descendant of the peer's most canonical block
                // to that height plus the batch size.
                let responded_batch_size = cmp::min(
                    requested_batch_size,
                    self.state.cli.max_number_of_blocks_before_syncing / 2,
                );
                let responded_batch_size = cmp::max(responded_batch_size, MINIMUM_BLOCK_BATCH_SIZE);
                let mut returned_blocks: Vec<TransferBlock> =
                    Vec::with_capacity(responded_batch_size);

                let parent: BlockHeader = peers_most_canonical_block.header;
                while returned_blocks.len() < responded_batch_size {
                    let children = self
                        .state
                        .chain
                        .archival_state
                        .as_ref()
                        .unwrap()
                        .get_children_blocks(&parent)
                        .await;
                    if children.is_empty() {
                        break;
                    }
                    let header_of_canonical_child = if children.len() == 1 {
                        children[0].clone()
                    } else {
                        let mut canonical: BlockHeader = children[0].clone();
                        for child in children {
                            if self
                                .state
                                .chain
                                .archival_state
                                .as_ref()
                                .unwrap()
                                .block_belongs_to_canonical_chain(&child, &tip_header)
                                .await
                            {
                                canonical = child;
                                break;
                            }
                        }
                        canonical
                    };

                    let canonical_child: Block = self
                        .state
                        .chain
                        .archival_state
                        .as_ref()
                        .unwrap()
                        .get_block(header_of_canonical_child.hash())
                        .await?
                        .unwrap();

                    returned_blocks.push(canonical_child.into());
                }

                peer.send(PeerMessage::BlockResponseBatch(returned_blocks))
                    .await?;

                Ok(false)
            }
            PeerMessage::BlockResponseBatch(t_blocks) => {
                debug!(
                    "handling block response batch with {} blocks",
                    t_blocks.len()
                );
                if t_blocks.len() < MINIMUM_BLOCK_BATCH_SIZE {
                    warn!("Got smaller batch response than allowed");
                    self.punish(PeerSanctionReason::TooShortBlockBatch)?;
                    return Ok(false);
                }

                // Verify that we are in fact in syncing mode
                // TODO: Seperate peer messages into those allowed under syncing
                // and those that are not
                if !self.state.net.syncing.read().unwrap().to_owned() {
                    warn!("Received a batch of blocks without being in syncing mode");
                    self.punish(PeerSanctionReason::ReceivedBatchBlocksOutsideOfSync)?;
                    return Ok(false);
                }

                // Verify that the response matches the current state
                // We get the latest block from the DB here since this message is
                // only valid for archival nodes.
                let first_blocks_parent_digest: Digest = t_blocks[0].header.prev_block_digest;
                let most_canonical_own_block_match: Option<Block> = self
                    .state
                    .chain
                    .archival_state
                    .as_ref()
                    .unwrap()
                    .get_block(first_blocks_parent_digest)
                    .await
                    .expect("Block lookup must succeed");
                let most_canonical_own_block_match: Block = match most_canonical_own_block_match {
                    Some(block) => block,
                    None => {
                        warn!("Got batch reponse with invalid start height");
                        self.punish(PeerSanctionReason::BatchBlocksInvalidStartHeight)?;
                        return Ok(false);
                    }
                };

                // Convert all blocks to Block objects
                debug!(
                    "Found own block of height {} to match received batch",
                    most_canonical_own_block_match.header.height
                );
                let received_blocks: Vec<Block> = t_blocks.into_iter().map(|x| x.into()).collect();

                // Get the latest block that we know of and handle all received blocks
                self.handle_blocks(received_blocks, most_canonical_own_block_match)
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
                        .state
                        .chain
                        .light_state
                        .latest_block_header
                        .lock()
                        .unwrap()
                        .proof_of_work_family
                        < block_notification.proof_of_work_family;

                    // Only request block if it is new, and if we are not currently reconciling
                    // a fork. If we are reconciling, that is handled later, and the information
                    // about that is stored in `highest_shared_block_height`. If we are syncing
                    // we are also not requesting the block but instead updating the sync state.
                    if self.state.net.syncing.read().unwrap().to_owned() {
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
                    .state
                    .chain
                    .archival_state
                    .as_ref()
                    .unwrap()
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

                let block_headers: Vec<BlockHeader> = self
                    .state
                    .chain
                    .archival_state
                    .as_ref()
                    .unwrap()
                    .block_height_to_block_headers(block_height)
                    .await;
                debug!("Locked block database object");

                if block_headers.is_empty() {
                    warn!("Got block request by height for unknown block");
                    self.punish(PeerSanctionReason::BlockRequestUnknownHeight)?;
                    return Ok(false);
                }

                // If more than one block is found, we need to find the one that's canonical
                let mut canonical_chain_block_header = block_headers[0].clone();
                if block_headers.len() > 1 {
                    let tip_header = self
                        .state
                        .chain
                        .light_state
                        .latest_block_header
                        .lock()
                        .unwrap()
                        .to_owned();
                    for block_header in block_headers {
                        if self
                            .state
                            .chain
                            .archival_state
                            .as_ref()
                            .unwrap()
                            .block_belongs_to_canonical_chain(&block_header, &tip_header)
                            .await
                        {
                            canonical_chain_block_header = block_header;
                        }
                    }
                }

                let canonical_chain_block: Block = self
                    .state
                    .chain
                    .archival_state
                    .as_ref()
                    .unwrap()
                    .get_block(canonical_chain_block_header.hash())
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
                self.punish(PeerSanctionReason::InvalidMessage)?;
                Ok(false)
            }
            // PeerMessage::NewTransaction(_) => {
            //     self.punish(PeerSanctionReason::InvalidMessage)?;
            //     Ok(false)
            // }
            PeerMessage::ConnectionStatus(_) => {
                self.punish(PeerSanctionReason::InvalidMessage)?;
                Ok(false)
            }
        }
    }

    /// Handle message from main thread. The boolean return value indicates if
    /// the connection should be closed.
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
            MainToPeerThread::BlockFromMiner(block) => {
                // If this client found a block, we need to share it immediately
                // to reduce the risk that someone else finds another one and shares
                // it faster.
                let new_block_height = block.header.height;
                let block_notification: PeerBlockNotification = (&(*block)).into();
                let t_block: Box<TransferBlock> = Box::new((*block).into());
                peer.send(PeerMessage::Block(t_block)).await?;
                peer.send(PeerMessage::BlockNotification(block_notification))
                    .await?;
                peer_state_info.highest_shared_block_height = new_block_height;
                Ok(false)
            }
            MainToPeerThread::Block(block) => {
                let new_block_height = block.header.height;
                if new_block_height > peer_state_info.highest_shared_block_height {
                    debug!("Sending PeerMessage::BlockNotification");
                    peer_state_info.highest_shared_block_height = new_block_height;
                    peer.send(PeerMessage::BlockNotification((*block).into()))
                        .await?;
                    debug!("Sent PeerMessage::BlockNotification");
                }
                Ok(false)
            }
            // MainToPeerThread::Transaction(nt) => {
            //     debug!("peer_loop got Transaction message from main");
            //     peer.send(PeerMessage::NewTransaction(nt)).await?;
            //     Ok(false)
            // }
            MainToPeerThread::RequestBlockBatch(most_canonical_block_digests, peer_addr_target) => {
                // Only ask one of the peers about the batch of blocks
                if peer_addr_target != self.peer_address {
                    return Ok(false);
                }

                let request_batch_size = std::cmp::min(
                    STANDARD_BLOCK_BATCH_SIZE,
                    self.state.cli.max_number_of_blocks_before_syncing,
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

                self.punish(PeerSanctionReason::SynchronizationTimeout)?;

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
            MainToPeerThread::MakeSpecificPeerDiscoveryRequest(target_socket_addr) => {
                if target_socket_addr == self.peer_address {
                    peer.send(PeerMessage::PeerListRequest).await?;
                }
                Ok(false)
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
                                    let syncing = self.state.net.syncing.read().unwrap().to_owned();
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
                                            true
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
                            error!("Error when receiving from peer: {}. Closing connection.", err);

                            break;
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
                        warn!("handle_main_thread_message is closing the connection to {}", self.peer_address);
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
    pub async fn run_wrapper<S>(
        &self,
        peer: S,
        from_main_rx: broadcast::Receiver<MainToPeerThread>,
    ) -> Result<()>
    where
        S: Sink<PeerMessage> + TryStream<Ok = PeerMessage> + Unpin,
        <S as Sink<PeerMessage>>::Error: std::error::Error + Sync + Send + 'static,
        <S as TryStream>::Error: std::error::Error,
    {
        // Check if peer standing exists in database, return default if it does not.
        let standing: PeerStanding = self
            .state
            .net
            .peer_databases
            .lock()
            .await
            .peer_standings
            .get(self.peer_address.ip())
            .unwrap_or_else(PeerStanding::default);

        // Add peer to peer map
        let new_peer = PeerInfo {
            address_for_incoming_connections: self.peer_handshake_data.listen_address,
            connected_address: self.peer_address,
            inbound: self.inbound_connection,
            instance_id: self.peer_handshake_data.instance_id,
            last_seen: SystemTime::now(),
            standing,
            version: self.peer_handshake_data.version.clone(),
        };

        // There is potential for a race-condition in the peer_map here, as we've previously
        // counted the number of entries. That should be fixed.
        self.state
            .net
            .peer_map
            .lock()
            .unwrap()
            .entry(self.peer_address)
            .or_insert(new_peer);

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
        let _res = self.run(peer, from_main_rx, &mut peer_state).await;
        debug!("Exited peer loop for {}", self.peer_address);

        // TODO: Send message to main removing claimed max block height in case we are
        // syncing and we banned the peer for sending us bad blocks.
        let peer_info_writeback = self
            .state
            .net
            .peer_map
            .lock()
            .unwrap_or_else(|e| panic!("Failed to lock peer map: {}", e))
            .remove(&self.peer_address)
            .unwrap_or_else(|| {
                panic!(
                    "Failed to remove {} from peer map. Is peer map mangled?",
                    self.peer_address
                )
            });
        debug!("Fetched peer info standing for {}", self.peer_address);
        self.state
            .write_peer_standing_on_increase(self.peer_address.ip(), peer_info_writeback.standing)
            .await;
        debug!("Stored peer info standing for {}", self.peer_address);

        // This message is used to determine if we are to exit synchronization mode
        self.to_main_tx
            .send(PeerThreadToMain::RemovePeerMaxBlockHeight(
                self.peer_address,
            ))
            .await?;

        debug!("Ending peer loop for {}", self.peer_address);
        Ok(())
    }
}

#[cfg(test)]
mod peer_loop_tests {
    use clap::Parser;
    use tracing_test::traced_test;
    use twenty_first::amount::u32s::U32s;

    use crate::{
        config_models::{cli_args, network::Network},
        models::blockchain::{block::block_header::TARGET_DIFFICULTY_U32_SIZE, digest::Hashable},
        tests::shared::{add_block, get_genesis_setup, make_mock_block, Action, Mock},
    };

    use super::*;

    #[traced_test]
    #[tokio::test]
    async fn test_peer_loop_bye() -> Result<()> {
        let mock = Mock::new(vec![Action::Read(PeerMessage::Bye)]);

        let (peer_broadcast_tx, _from_main_rx_clone, to_main_tx, _to_main_rx1, state, hsd) =
            get_genesis_setup(Network::Main, 1)?;

        let peer_address = state
            .net
            .peer_map
            .lock()
            .unwrap()
            .values()
            .collect::<Vec<_>>()[0]
            .connected_address;
        let from_main_rx_clone = peer_broadcast_tx.subscribe();
        let peer_loop_handler =
            PeerLoopHandler::new(to_main_tx, state.clone(), peer_address, hsd, true, 1);
        peer_loop_handler
            .run_wrapper(mock, from_main_rx_clone)
            .await?;

        if !state.net.peer_map.lock().unwrap().is_empty() {
            bail!("peer map must be empty after closing connection gracefully");
        }

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn test_peer_loop_peer_list() -> Result<()> {
        let (peer_broadcast_tx, _from_main_rx_clone, to_main_tx, _to_main_rx1, state, hsd) =
            get_genesis_setup(Network::Main, 1)?;

        let peer_infos = state
            .net
            .peer_map
            .lock()
            .unwrap()
            .clone()
            .into_values()
            .collect::<Vec<_>>();
        let (peer_address, instance_id) =
            (peer_infos[0].connected_address, peer_infos[0].instance_id);

        let mock = Mock::new(vec![
            Action::Read(PeerMessage::PeerListRequest),
            Action::Write(PeerMessage::PeerListResponse(vec![(
                peer_address,
                instance_id,
            )])),
            Action::Read(PeerMessage::Bye),
        ]);

        let from_main_rx_clone = peer_broadcast_tx.subscribe();

        let peer_loop_handler =
            PeerLoopHandler::new(to_main_tx, state.clone(), peer_address, hsd, true, 1);
        peer_loop_handler
            .run_wrapper(mock, from_main_rx_clone)
            .await?;

        if !state.net.peer_map.lock().unwrap().is_empty() {
            bail!("peer map must be empty after closing connection gracefully");
        }

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn different_genesis_test() -> Result<()> {
        // In this scenario a peer provides another genesis block than what has been
        // hardcoded. This should lead to the closing of the connection to this peer
        // and a ban.
        let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, mut to_main_rx1, state, hsd) =
            get_genesis_setup(Network::Main, 1)?;
        let peer_address = state
            .net
            .peer_map
            .lock()
            .unwrap()
            .values()
            .collect::<Vec<_>>()[0]
            .connected_address;

        // Although the database is empty, `get_latest_block` still returns the genesis block,
        // since that block is hardcoded.
        let mut different_genesis_block: Block = state
            .clone()
            .chain
            .archival_state
            .unwrap()
            .get_latest_block()
            .await;
        different_genesis_block.header.nonce[2].increment();
        different_genesis_block.hash = different_genesis_block.header.hash();
        let block_1_with_different_genesis = make_mock_block(different_genesis_block, None);
        let mock = Mock::new(vec![Action::Read(PeerMessage::Block(Box::new(
            block_1_with_different_genesis.into(),
        )))]);

        let peer_loop_handler = PeerLoopHandler::new(
            to_main_tx.clone(),
            state.clone(),
            peer_address,
            hsd,
            true,
            1,
        );
        peer_loop_handler
            .run_wrapper(mock, from_main_rx_clone)
            .await?;

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

        let peer_standing = state
            .get_peer_standing_from_database(peer_address.ip())
            .await;
        assert_eq!(u16::MAX, peer_standing.unwrap().standing);
        assert_eq!(
            PeerSanctionReason::DifferentGenesis,
            peer_standing.unwrap().latest_sanction.unwrap()
        );

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn bad_block_test() -> Result<()> {
        // In this scenario, a block without a valid PoW is received. This block should be rejected
        // by the peer loop and a notification should never reach the main loop.
        let (peer_broadcast_tx, _from_main_rx_clone, to_main_tx, mut to_main_rx1, state, hsd) =
            get_genesis_setup(Network::Main, 1)?;
        let peer_address = state
            .net
            .peer_map
            .lock()
            .unwrap()
            .values()
            .collect::<Vec<_>>()[0]
            .connected_address;
        let genesis_block: Block = state
            .chain
            .archival_state
            .as_ref()
            .unwrap()
            .get_latest_block()
            .await;

        // Make a with hash above what the implied threshold from
        // `target_difficulty` requires
        let block_without_valid_pow = make_mock_block(
            genesis_block,
            Some(U32s::<TARGET_DIFFICULTY_U32_SIZE>::new([
                1_000_000, 0, 0, 0, 0,
            ])),
        );

        // Sending an invalid block will not neccessarily result in a ban. This depends on the peer
        // tolerance that is set in the client. For this reason, we include a "Bye" here.
        let mock = Mock::new(vec![
            Action::Read(PeerMessage::Block(Box::new(block_without_valid_pow.into()))),
            Action::Read(PeerMessage::Bye),
        ]);

        let from_main_rx_clone = peer_broadcast_tx.subscribe();

        let peer_loop_handler = PeerLoopHandler::new(
            to_main_tx.clone(),
            state.clone(),
            peer_address,
            hsd,
            true,
            1,
        );
        peer_loop_handler
            .run_wrapper(mock, from_main_rx_clone)
            .await?;

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
        let standing = state
            .net
            .peer_databases
            .lock()
            .await
            .peer_standings
            .get(peer_address.ip())
            .unwrap();
        assert!(
            standing.standing > 0,
            "Peer must be sanctioned for sending a bad block"
        );

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn test_peer_loop_block_with_block_in_db() -> Result<()> {
        // The scenario tested here is that a client receives a block that is already
        // in the database. The expected behavior is to ignore the block and not send
        // a message to the main thread.
        let (peer_broadcast_tx, _from_main_rx_clone, to_main_tx, mut to_main_rx1, state, hsd) =
            get_genesis_setup(Network::Main, 1)?;
        let peer_address = state
            .net
            .peer_map
            .lock()
            .unwrap()
            .values()
            .collect::<Vec<_>>()[0]
            .connected_address;
        let genesis_block: Block = state
            .chain
            .archival_state
            .as_ref()
            .unwrap()
            .get_latest_block()
            .await;

        let block_1 = make_mock_block(genesis_block, None);
        add_block(&state, block_1.clone()).await?;

        let mock = Mock::new(vec![
            Action::Read(PeerMessage::Block(Box::new(block_1.into()))),
            Action::Read(PeerMessage::Bye),
        ]);

        let from_main_rx_clone = peer_broadcast_tx.subscribe();

        let peer_loop_handler = PeerLoopHandler::new(
            to_main_tx.clone(),
            state.clone(),
            peer_address,
            hsd,
            false,
            1,
        );
        peer_loop_handler
            .run_wrapper(mock, from_main_rx_clone)
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

        if !state.net.peer_map.lock().unwrap().is_empty() {
            bail!("peer map must be empty after closing connection gracefully");
        }

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn test_peer_loop_receival_of_first_block() -> Result<()> {
        // Scenario: client only knows genesis block. Then receives block 1.
        let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, mut to_main_rx1, state, hsd) =
            get_genesis_setup(Network::Main, 1)?;
        let peer_address = state
            .net
            .peer_map
            .lock()
            .unwrap()
            .values()
            .collect::<Vec<_>>()[0]
            .connected_address;
        let genesis_block: Block = state
            .chain
            .archival_state
            .as_ref()
            .unwrap()
            .get_latest_block()
            .await;

        let mock = Mock::new(vec![
            Action::Read(PeerMessage::Block(Box::new(
                make_mock_block(genesis_block, None).into(),
            ))),
            Action::Read(PeerMessage::Bye),
        ]);

        let peer_loop_handler = PeerLoopHandler::new(
            to_main_tx.clone(),
            state.clone(),
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

        if !state.net.peer_map.lock().unwrap().is_empty() {
            bail!("peer map must be empty after closing connection gracefully");
        }

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn test_peer_loop_receival_of_second_block_no_blocks_in_db() -> Result<()> {
        // In this scenario, the client only knows the genesis block (block 0) and then
        // receives block 2, meaning that block 1 will have to be requested.
        let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, mut to_main_rx1, state, hsd) =
            get_genesis_setup(Network::Main, 1)?;
        let peer_address = state
            .net
            .peer_map
            .lock()
            .unwrap()
            .values()
            .collect::<Vec<_>>()[0]
            .connected_address;
        let genesis_block: Block = state
            .chain
            .archival_state
            .as_ref()
            .unwrap()
            .get_latest_block()
            .await;
        let block_1 = make_mock_block(genesis_block.clone(), None);
        let block_2 = make_mock_block(block_1.clone(), None);

        let mock = Mock::new(vec![
            Action::Read(PeerMessage::Block(Box::new(block_2.clone().into()))),
            Action::Write(PeerMessage::BlockRequestByHash(block_1.hash)),
            Action::Read(PeerMessage::Block(Box::new(block_1.clone().into()))),
            Action::Read(PeerMessage::Bye),
        ]);

        let peer_loop_handler = PeerLoopHandler::new(
            to_main_tx.clone(),
            state.clone(),
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
                if blocks[0].hash != block_1.hash {
                    bail!("1st received block by main loop must be block 1");
                }
                if blocks[1].hash != block_2.hash {
                    bail!("2nd received block by main loop must be block 2");
                }
            }
            _ => bail!("Did not find msg sent to main thread 1"),
        };
        match to_main_rx1.recv().await {
            Some(PeerThreadToMain::RemovePeerMaxBlockHeight(_)) => (),
            _ => bail!("Must receive remove of peer block max height"),
        }

        if !state.net.peer_map.lock().unwrap().is_empty() {
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
        let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, mut to_main_rx1, mut state, hsd) =
            get_genesis_setup(Network::Main, 1)?;

        // Restrict max number of blocks held in memory to 2.
        let mut a = cli_args::Args::from_iter::<Vec<String>, _>(vec![]);
        a.max_number_of_blocks_before_syncing = 2;
        state.cli = a;

        let peer_address = state
            .net
            .peer_map
            .lock()
            .unwrap()
            .values()
            .collect::<Vec<_>>()[0]
            .connected_address;
        let genesis_block: Block = state
            .chain
            .archival_state
            .as_ref()
            .unwrap()
            .get_latest_block()
            .await;
        let block_1 = make_mock_block(genesis_block.clone(), None);
        let block_2 = make_mock_block(block_1.clone(), None);
        let block_3 = make_mock_block(block_2.clone(), None);
        let block_4 = make_mock_block(block_3.clone(), None);
        add_block(&state, block_1.clone()).await?;

        let mock = Mock::new(vec![
            Action::Read(PeerMessage::Block(Box::new(block_4.clone().into()))),
            Action::Write(PeerMessage::BlockRequestByHash(block_3.hash)),
            Action::Read(PeerMessage::Block(Box::new(block_3.clone().into()))),
            Action::Read(PeerMessage::Bye),
        ]);

        let peer_loop_handler = PeerLoopHandler::new(
            to_main_tx.clone(),
            state.clone(),
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
        assert!(
            state
                .get_peer_standing_from_database(peer_address.ip())
                .await
                .unwrap()
                .standing
                > 0
        );

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn test_peer_loop_receival_of_fourth_block_one_block_in_db() -> Result<()> {
        // In this scenario, the client know the genesis block (block 0) and block 1, it
        // then receives block 4, meaning that block 3, 2, and 1 will have to be requested.
        let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, mut to_main_rx1, state, hsd) =
            get_genesis_setup(Network::Main, 1)?;
        let peer_address: SocketAddr = state
            .net
            .peer_map
            .lock()
            .unwrap()
            .values()
            .collect::<Vec<_>>()[0]
            .connected_address;
        let genesis_block: Block = state
            .chain
            .archival_state
            .as_ref()
            .unwrap()
            .get_latest_block()
            .await;
        let block_1 = make_mock_block(genesis_block.clone(), None);
        let block_2 = make_mock_block(block_1.clone(), None);
        let block_3 = make_mock_block(block_2.clone(), None);
        let block_4 = make_mock_block(block_3.clone(), None);
        add_block(&state, block_1.clone()).await?;

        let mock = Mock::new(vec![
            Action::Read(PeerMessage::Block(Box::new(block_4.clone().into()))),
            Action::Write(PeerMessage::BlockRequestByHash(block_3.hash)),
            Action::Read(PeerMessage::Block(Box::new(block_3.clone().into()))),
            Action::Write(PeerMessage::BlockRequestByHash(block_2.hash)),
            Action::Read(PeerMessage::Block(Box::new(block_2.clone().into()))),
            Action::Read(PeerMessage::Bye),
        ]);

        let peer_loop_handler = PeerLoopHandler::new(
            to_main_tx.clone(),
            state.clone(),
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
                if blocks[0].hash != block_2.hash {
                    bail!("1st received block by main loop must be block 1");
                }
                if blocks[1].hash != block_3.hash {
                    bail!("2nd received block by main loop must be block 2");
                }
                if blocks[2].hash != block_4.hash {
                    bail!("3rd received block by main loop must be block 3");
                }
            }
            _ => bail!("Did not find msg sent to main thread"),
        };
        match to_main_rx1.recv().await {
            Some(PeerThreadToMain::RemovePeerMaxBlockHeight(_)) => (),
            _ => bail!("Must receive remove of peer block max height"),
        }

        if !state.net.peer_map.lock().unwrap().is_empty() {
            bail!("peer map must be empty after closing connection gracefully");
        }

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn test_peer_loop_receival_of_third_block_no_blocks_in_db() -> Result<()> {
        // In this scenario, the client only knows the genesis block (block 0) and then
        // receives block 3, meaning that block 2 and 1 will have to be requested.
        let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, mut to_main_rx1, state, hsd) =
            get_genesis_setup(Network::Main, 1)?;
        let peer_address = state
            .net
            .peer_map
            .lock()
            .unwrap()
            .values()
            .collect::<Vec<_>>()[0]
            .connected_address;
        let genesis_block: Block = state
            .chain
            .archival_state
            .as_ref()
            .unwrap()
            .get_latest_block()
            .await;
        let block_1 = make_mock_block(genesis_block.clone(), None);
        let block_2 = make_mock_block(block_1.clone(), None);
        let block_3 = make_mock_block(block_2.clone(), None);

        let mock = Mock::new(vec![
            Action::Read(PeerMessage::Block(Box::new(block_3.clone().into()))),
            Action::Write(PeerMessage::BlockRequestByHash(block_2.hash)),
            Action::Read(PeerMessage::Block(Box::new(block_2.clone().into()))),
            Action::Write(PeerMessage::BlockRequestByHash(block_1.hash)),
            Action::Read(PeerMessage::Block(Box::new(block_1.clone().into()))),
            Action::Read(PeerMessage::Bye),
        ]);

        let peer_loop_handler = PeerLoopHandler::new(
            to_main_tx.clone(),
            state.clone(),
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
                if blocks[0].hash != block_1.hash {
                    bail!("1st received block by main loop must be block 1");
                }
                if blocks[1].hash != block_2.hash {
                    bail!("2nd received block by main loop must be block 2");
                }
                if blocks[2].hash != block_3.hash {
                    bail!("3rd received block by main loop must be block 3");
                }
            }
            _ => bail!("Did not find msg sent to main thread"),
        };
        match to_main_rx1.recv().await {
            Some(PeerThreadToMain::RemovePeerMaxBlockHeight(_)) => (),
            _ => bail!("Must receive remove of peer block max height"),
        }

        if !state.net.peer_map.lock().unwrap().is_empty() {
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
        let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, mut to_main_rx1, state, hsd) =
            get_genesis_setup(Network::Main, 1)?;
        let peer_address: SocketAddr = state
            .net
            .peer_map
            .lock()
            .unwrap()
            .values()
            .collect::<Vec<_>>()[0]
            .connected_address;
        let genesis_block: Block = state
            .chain
            .archival_state
            .as_ref()
            .unwrap()
            .get_latest_block()
            .await;
        let block_1 = make_mock_block(genesis_block.clone(), None);
        let block_2 = make_mock_block(block_1.clone(), None);
        let block_3 = make_mock_block(block_2.clone(), None);
        let block_4 = make_mock_block(block_3.clone(), None);
        let block_5 = make_mock_block(block_4.clone(), None);
        add_block(&state, block_1.clone()).await?;

        let mock = Mock::new(vec![
            Action::Read(PeerMessage::Block(Box::new(block_4.clone().into()))),
            Action::Write(PeerMessage::BlockRequestByHash(block_3.hash)),
            Action::Read(PeerMessage::Block(Box::new(block_3.clone().into()))),
            Action::Write(PeerMessage::BlockRequestByHash(block_2.hash)),
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
            Action::Write(PeerMessage::BlockRequestByHeight(block_5.header.height)),
            Action::Read(PeerMessage::Bye),
        ]);

        let peer_loop_handler = PeerLoopHandler::new(
            to_main_tx.clone(),
            state.clone(),
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

        match to_main_rx1.recv().await {
            Some(PeerThreadToMain::NewBlocks(blocks)) => {
                if blocks[0].hash != block_2.hash {
                    bail!("1st received block by main loop must be block 1");
                }
                if blocks[1].hash != block_3.hash {
                    bail!("2nd received block by main loop must be block 2");
                }
                if blocks[2].hash != block_4.hash {
                    bail!("3rd received block by main loop must be block 3");
                }
            }
            _ => bail!("Did not find msg sent to main thread"),
        };
        match to_main_rx1.recv().await {
            Some(PeerThreadToMain::RemovePeerMaxBlockHeight(_)) => (),
            _ => bail!("Must receive remove of peer block max height"),
        }

        if !state.net.peer_map.lock().unwrap().is_empty() {
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
        let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, mut to_main_rx1, state, hsd) =
            get_genesis_setup(Network::Main, 1)?;
        let peer_infos: Vec<PeerInfo> = state
            .net
            .peer_map
            .lock()
            .unwrap()
            .clone()
            .into_values()
            .collect::<Vec<_>>();
        let (peer_address, peer_instance_id) = (
            peer_infos[0].address_for_incoming_connections.unwrap(),
            peer_infos[0].instance_id,
        );
        let genesis_block: Block = state
            .chain
            .archival_state
            .as_ref()
            .unwrap()
            .get_latest_block()
            .await;
        let block_1 = make_mock_block(genesis_block.clone(), None);
        let block_2 = make_mock_block(block_1.clone(), None);
        let block_3 = make_mock_block(block_2.clone(), None);
        let block_4 = make_mock_block(block_3.clone(), None);
        add_block(&state, block_1.clone()).await?;

        let mock = Mock::new(vec![
            Action::Read(PeerMessage::Block(Box::new(block_4.clone().into()))),
            Action::Write(PeerMessage::BlockRequestByHash(block_3.hash)),
            Action::Read(PeerMessage::Block(Box::new(block_3.clone().into()))),
            Action::Write(PeerMessage::BlockRequestByHash(block_2.hash)),
            //
            // Now make the interruption of the block reconciliation process
            Action::Read(PeerMessage::PeerListRequest),
            //
            // Answer the request for a peer list
            Action::Write(PeerMessage::PeerListResponse(vec![(
                peer_address,
                peer_instance_id,
            )])),
            //
            // Complete the block reconciliation process by requesting the last block
            // in this process, to get back to a mutually known block.
            Action::Read(PeerMessage::Block(Box::new(block_2.clone().into()))),
            Action::Read(PeerMessage::Bye),
        ]);

        let peer_loop_handler =
            PeerLoopHandler::new(to_main_tx, state.clone(), peer_address, hsd, true, 1);
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
                if blocks[0].hash != block_2.hash {
                    bail!("1st received block by main loop must be block 1");
                }
                if blocks[1].hash != block_3.hash {
                    bail!("2nd received block by main loop must be block 2");
                }
                if blocks[2].hash != block_4.hash {
                    bail!("3rd received block by main loop must be block 3");
                }
            }
            _ => bail!("Did not find msg sent to main thread"),
        };

        match to_main_rx1.recv().await {
            Some(PeerThreadToMain::RemovePeerMaxBlockHeight(_)) => (),
            _ => bail!("Must receive remove of peer block max height"),
        }

        if !state.net.peer_map.lock().unwrap().is_empty() {
            bail!("peer map must be empty after closing connection gracefully");
        }

        Ok(())
    }
}
