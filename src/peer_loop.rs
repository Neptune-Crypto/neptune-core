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
use rand::rngs::StdRng;
use rand::thread_rng;
use rand::Rng;
use rand::SeedableRng;
use tasm_lib::triton_vm::prelude::Digest;
use tokio::select;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::connect_to_peers::close_peer_connected_callback;
use crate::macros::fn_name;
use crate::macros::log_slow_scope;
use crate::models::blockchain::block::block_height::BlockHeight;
use crate::models::blockchain::block::Block;
use crate::models::blockchain::transaction::Transaction;
use crate::models::channel::MainToPeerTask;
use crate::models::channel::PeerTaskToMain;
use crate::models::channel::PeerTaskToMainTransaction;
use crate::models::peer::transfer_block::TransferBlock;
use crate::models::peer::BlockProposalRequest;
use crate::models::peer::BlockRequestBatch;
use crate::models::peer::HandshakeData;
use crate::models::peer::IssuedSyncChallenge;
use crate::models::peer::MutablePeerState;
use crate::models::peer::NegativePeerSanction;
use crate::models::peer::PeerConnectionInfo;
use crate::models::peer::PeerInfo;
use crate::models::peer::PeerMessage;
use crate::models::peer::PeerSanction;
use crate::models::peer::PeerStanding;
use crate::models::peer::PositivePeerSanction;
use crate::models::peer::SyncChallenge;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::models::state::mempool::MEMPOOL_IGNORE_TRANSACTIONS_THIS_MANY_SECS_AHEAD;
use crate::models::state::mempool::MEMPOOL_TX_THRESHOLD_AGE_IN_SECS;
use crate::models::state::GlobalStateLock;

const STANDARD_BLOCK_BATCH_SIZE: usize = 250;
const MAX_PEER_LIST_LENGTH: usize = 10;
const MINIMUM_BLOCK_BATCH_SIZE: usize = 2;
pub(crate) const MIN_BLOCK_HEIGHT_FOR_SYNCING: u64 = 10;

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
    rng: StdRng,
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
            rng: StdRng::from_rng(thread_rng())
                .expect("should be able to seed new StdRng from thread_rng"),
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
            rng: StdRng::from_rng(thread_rng())
                .expect("should be able to seed new StdRng from thread_rng"),
        }
    }

    /// Overwrite the random number generator object with a specific one.
    ///
    /// Useful for derandomizing tests.
    #[cfg(test)]
    fn set_rng(&mut self, rng: StdRng) {
        self.rng = rng;
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

    /// Punish a peer for bad behavior.
    ///
    /// Return `Err` if the peer in question is (now) banned.
    ///
    /// # Locking:
    ///   * acquires `global_state_lock` for write
    async fn punish(&mut self, reason: NegativePeerSanction) -> Result<()> {
        let mut global_state_mut = self.global_state_lock.lock_guard_mut().await;
        warn!("Punishing peer {} for {:?}", self.peer_address.ip(), reason);
        debug!(
            "Peer standing before punishment is {}",
            global_state_mut
                .net
                .peer_map
                .get(&self.peer_address)
                .unwrap()
                .standing
        );
        match global_state_mut
            .net
            .peer_map
            .get_mut(&self.peer_address)
            .map(|p: &mut PeerInfo| p.standing.sanction(PeerSanction::Negative(reason)))
        {
            Some(Ok(_standing)) => Ok(()),
            Some(Err(_banned)) => {
                warn!("Banning peer");
                bail!("Banning peer");
            }
            None => {
                bail!("Could not read peer map.");
            }
        }
    }

    /// Reward a peer for good behavior.
    ///
    /// Return `Err` if the peer in question is banned.
    ///
    /// # Locking:
    ///   * acquires `global_state_lock` for write
    async fn reward(&mut self, reason: PositivePeerSanction) -> Result<()> {
        let mut global_state_mut = self.global_state_lock.lock_guard_mut().await;
        info!("Rewarding peer {} for {:?}", self.peer_address.ip(), reason);
        match global_state_mut
            .net
            .peer_map
            .get_mut(&self.peer_address)
            .map(|p| p.standing.sanction(PeerSanction::Positive(reason)))
        {
            Some(Ok(_standing)) => Ok(()),
            Some(Err(_banned)) => {
                error!("Cannot reward banned peer");
                bail!("Cannot reward banned peer");
            }
            None => {
                error!("Could not read peer map.");
                Ok(())
            }
        }
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
    ///   * Acquires `global_state_lock` for write via `self.punish(..)` and
    ///     `self.reward(..)`.
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
        debug!("validating with respect to current timestamp {now}");
        let mut previous_block = &parent_of_first_block;
        for new_block in received_blocks.iter() {
            let new_block_has_proof_of_work = new_block.has_proof_of_work(previous_block.header());
            debug!("new block has proof of work? {new_block_has_proof_of_work}");
            let new_block_is_valid = new_block.is_valid(previous_block, now).await;
            debug!("new block is valid? {new_block_is_valid}");
            if !new_block_has_proof_of_work {
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
                self.punish(NegativePeerSanction::InvalidBlock((
                    new_block.kernel.header.height,
                    new_block.hash(),
                )))
                .await?;
                warn!("Failed to validate block due to insufficient PoW");
                return Ok(None);
            } else if !new_block_is_valid {
                warn!(
                    "Received invalid block of height {} from peer with IP {}",
                    new_block.kernel.header.height, self.peer_address
                );
                self.punish(NegativePeerSanction::InvalidBlock((
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
        debug!("Checking last block's canonicity ...");
        let is_canonical = self
            .global_state_lock
            .lock_guard()
            .await
            .incoming_block_is_more_canonical(received_blocks.last().unwrap());
        debug!("is canonical? {is_canonical}");
        if !is_canonical {
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
        let number_of_received_blocks = received_blocks.len();
        self.to_main_tx
            .send(PeerTaskToMain::NewBlocks(received_blocks))
            .await?;
        info!(
            "Updated block info by block from peer. block height {}",
            new_block_height
        );

        // Valuable, new, hard-to-produce information. Reward peer.
        self.reward(PositivePeerSanction::ValidBlocks(number_of_received_blocks))
            .await?;

        Ok(Some(new_block_height))
    }

    /// Take a single block received from a peer and (attempt to) find a path
    /// between the received block and a common block stored in the blocks
    /// database.
    ///
    /// This function attempts to find the parent of the received block, either
    /// by searching the database or by requesting it from a peer.
    ///  - If the parent is not stored, it is requested from the peer and the
    ///    received block is pushed to the fork reconciliation list for later
    ///    handling by this function. The fork reconciliation list starts out
    ///    empty, but grows as more parents are requested and transmitted.
    ///  - If the parent is found in the database, block handling continues:
    ///    the entire list of fork reconciliation blocks are passed down the
    ///    pipeline, potentially leading to a state update.
    ///
    /// Locking:
    ///   * Acquires `global_state_lock` for write via `self.punish(..)` and
    ///     `self.reward(..)`.
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
        // Does the received block match the fork reconciliation list?
        //  - The list is empty, or
        //  - the list does not contain a successor (determined by block
        //     height); or
        //  - this successor is valid.
        // Note that blocks can arrive out of order due to network delays or due
        // to new blocks being found in the meantime. So we cannot assume the
        // order is correct.
        let received_block_matches_reconciliation_list = if let Some(successor) = peer_state
            .fork_reconciliation_blocks
            .iter()
            .find(|s| s.header().height == received_block.header().height.next())
        {
            if successor.header().prev_block_digest != received_block.hash() {
                warn!(
                    "Fork reconciliation failed after receiving {} blocks: hash mismatch",
                    peer_state.fork_reconciliation_blocks.len() + 1
                );
                false
            } else if !successor
                .is_valid(&received_block, successor.header().timestamp)
                .await
            {
                warn!(
                    "Fork reconciliation failed after receiving {} blocks: invalid successor block",
                    peer_state.fork_reconciliation_blocks.len() + 1
                );
                false
            } else {
                true
            }
        } else {
            true
        };

        // If we are getting blocks out of order, then it is possible that the
        // received block's predecessor is in the reconciliation list already.
        // If so, we can verify the received block.
        let received_block_is_invalid = if let Some(predecessor) = peer_state
            .fork_reconciliation_blocks
            .iter()
            .find(|p| p.header().height.next() == received_block.header().height)
        {
            if !received_block
                .is_valid(predecessor, received_block.header().timestamp)
                .await
            {
                warn!(
                    "Fork reconciliation failed after receiving {} blocks: invalid predecessor block",
                    peer_state.fork_reconciliation_blocks.len() + 1
                );
                true
            } else {
                false
            }
        } else {
            false
        };

        // Lastly, we might be on the happy path (all checks pass) but the
        // number of blocks to reconcile is too big. Then abort to save RAM.
        // The problem should be fixed through sync mode instead.
        let too_many_blocks = peer_state.fork_reconciliation_blocks.len() + 1
            >= self.global_state_lock.cli().sync_mode_threshold;
        if too_many_blocks {
            warn!(
                "Fork reconciliation failed after receiving {} blocks: block count exceeds sync mode threshold",
                peer_state.fork_reconciliation_blocks.len() + 1
            );
        }

        // Block mismatch or too many blocks: abort!
        if !received_block_matches_reconciliation_list
            || too_many_blocks
            || received_block_is_invalid
        {
            self.punish(NegativePeerSanction::ForkResolutionError((
                received_block.header().height,
                peer_state.fork_reconciliation_blocks.len() as u16,
                received_block.hash(),
            )))
            .await?;
            peer_state.fork_reconciliation_blocks = vec![];
            return Ok(());
        }

        // Add the block to the fork reconciliation list and sort it for good
        // measure, as though all block had come in the right order.
        let received_block_header = received_block.header().clone();
        peer_state.fork_reconciliation_blocks.push(*received_block);
        peer_state
            .fork_reconciliation_blocks
            .sort_by(|a, b| b.header().height.cmp(&a.header().height));

        // Get received block's parent.
        let parent_digest = received_block_header.prev_block_digest;
        let parent_height = received_block_header.height.previous()
            .expect("transferred block must have previous height because genesis block cannot be transferred");

        // Was the parent transmitted previously (out of order)?
        let parent = peer_state
            .fork_reconciliation_blocks
            .iter()
            .find(|p| p.header().height == parent_height)
            .cloned();

        // Does the parent live in the blocks database?
        let parent = parent.or({
            debug!("Try ensure path: fetching parent block");
            let global_state = self.global_state_lock.lock_guard().await;
            let parent_block = global_state
                .chain
                .archival_state()
                .get_block(parent_digest)
                .await?;
            drop(global_state);
            debug!(
                "Completed parent block fetching from DB: {}",
                if parent_block.is_some() {
                    "found".to_string()
                } else {
                    "not found".to_string()
                }
            );
            parent_block
        });

        // If the parent of the received block is not known, request it.
        if parent.is_none() && parent_height > BlockHeight::genesis() {
            info!(
                "Parent not known: Requesting previous block with height {} from peer",
                parent_height
            );

            peer.send(PeerMessage::BlockRequestByHash(parent_digest))
                .await?;

            return Ok(());
        }

        // We got all the way back to genesis, but disagree about genesis. Ban peer.
        if parent.is_none() && parent_height == BlockHeight::genesis() {
            self.punish(NegativePeerSanction::DifferentGenesis).await?;
            return Ok(());
        }

        // We want to treat the received fork reconciliation blocks (plus the
        // received block) in reverse order, from oldest to newest, because
        // they were requested from high to low block height.
        let mut new_blocks = peer_state.fork_reconciliation_blocks.clone();
        new_blocks.reverse();

        // Reset the fork resolution state since we went all the way back to
        // find a common block that was stored (or genesis)
        let fork_reconciliation_event = !peer_state.fork_reconciliation_blocks.is_empty();
        peer_state.fork_reconciliation_blocks = vec![];

        // Sanity check, that the blocks are correctly sorted (they should be)
        assert!(new_blocks
            .iter()
            .tuple_windows()
            .all(|(pred, succ)| pred.header().height.next() == succ.header().height));

        // Process all blocks
        if let Some(new_block_height) = self
            .handle_blocks(
                new_blocks,
                parent.expect(
                    "parent was successfully fetched from database or it is the genesis block",
                ),
            )
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
    ///   * Acquires `global_state_lock` for read.
    ///   * Acquires `global_state_lock` for write via `self.punish(..)` and
    ///     `self.reward(..)`.
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
                log_slow_scope!(fn_name!() + "::PeerMessage::PeerListRequest");

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
                            peer_info.instance_id(),
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
                log_slow_scope!(fn_name!() + "::PeerMessage::PeerListResponse");

                if peers.len() > MAX_PEER_LIST_LENGTH {
                    self.punish(NegativePeerSanction::FloodPeerListResponse)
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
            PeerMessage::BlockNotificationRequest => {
                log_slow_scope!(fn_name!() + "::PeerMessage::BlockNotificationRequest");

                debug!("Got BlockNotificationRequest");

                peer.send(PeerMessage::BlockNotification(
                    self.global_state_lock
                        .lock_guard()
                        .await
                        .chain
                        .light_state()
                        .into(),
                ))
                .await?;

                Ok(KEEP_CONNECTION_ALIVE)
            }
            PeerMessage::BlockNotification(block_notification) => {
                log_slow_scope!(fn_name!() + "::PeerMessage::BlockNotification");

                debug!(
                    "Got BlockNotification of height {}",
                    block_notification.height
                );
                let state = self.global_state_lock.lock_guard().await;
                if state.sync_mode_criterion(
                    block_notification.height,
                    block_notification.cumulative_proof_of_work,
                ) {
                    debug!("sync mode criterion satisfied.");

                    if peer_state_info.sync_challenge.is_some() {
                        warn!("Cannot launch new sync challenge because one is already on-going.");
                        return Ok(KEEP_CONNECTION_ALIVE);
                    }

                    info!(
                        "Peer indicates block which satisfies sync mode criterion, issuing challenge."
                    );
                    let challenge = SyncChallenge::generate(
                        &block_notification,
                        state.chain.light_state().header().height,
                        self.rng.gen(),
                    );
                    peer_state_info.sync_challenge = Some(IssuedSyncChallenge::new(
                        challenge,
                        block_notification.cumulative_proof_of_work,
                        self.now(),
                    ));

                    debug!("sending challenge ...");
                    peer.send(PeerMessage::SyncChallenge(challenge)).await?;

                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                peer_state_info.highest_shared_block_height = block_notification.height;
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

                if block_is_new
                    && peer_state_info.fork_reconciliation_blocks.is_empty()
                    && !self.global_state_lock.lock_guard().await.net.syncing
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

                Ok(KEEP_CONNECTION_ALIVE)
            }
            PeerMessage::SyncChallenge(sync_challenge) => {
                log_slow_scope!(fn_name!() + "::PeerMessage::SyncChallenge");

                info!("Got sync challenge from {}", self.peer_address.ip());

                let response = self
                    .global_state_lock
                    .lock_guard()
                    .await
                    .response_to_sync_challenge(sync_challenge)
                    .await;
                let response = match response {
                    Ok(resp) => resp,
                    Err(e) => {
                        warn!("could not generate sync challenge response:\n{e}");
                        self.punish(NegativePeerSanction::InvalidSyncChallenge)
                            .await?;
                        return Ok(KEEP_CONNECTION_ALIVE);
                    }
                };

                info!(
                    "Responding to sync challenge from {}",
                    self.peer_address.ip()
                );
                peer.send(PeerMessage::SyncChallengeResponse(Box::new(response)))
                    .await?;

                Ok(KEEP_CONNECTION_ALIVE)
            }
            PeerMessage::SyncChallengeResponse(challenge_response) => {
                log_slow_scope!(fn_name!() + "::PeerMessage::SyncChallengeResponse");
                info!(
                    "Got sync challenge response from {}",
                    self.peer_address.ip()
                );

                // Did we issue a challenge?
                let Some(issued_challenge) = peer_state_info.sync_challenge else {
                    warn!("Sync challenge response was not prompted.");
                    self.punish(NegativePeerSanction::UnexpectedSyncChallengeResponse)
                        .await?;
                    return Ok(KEEP_CONNECTION_ALIVE);
                };

                // Reset the challenge, regardless of the response's success.
                peer_state_info.sync_challenge = None;

                // Does response match issued challenge?
                if !challenge_response.matches(issued_challenge) {
                    self.punish(NegativePeerSanction::InvalidSyncChallengeResponse)
                        .await?;
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                // Does response verify?
                let claimed_tip_height = challenge_response.tip.header.height;
                let now = self.now();
                if !challenge_response.is_valid(now).await {
                    self.punish(NegativePeerSanction::InvalidSyncChallengeResponse)
                        .await?;
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                // Did it come in time?
                const SYNC_RESPONSE_TIMEOUT: Timestamp = Timestamp::seconds(30);
                if now - issued_challenge.issued_at > SYNC_RESPONSE_TIMEOUT {
                    self.punish(NegativePeerSanction::TimedOutSyncChallengeResponse)
                        .await?;
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                info!("Successful sync challenge response; relaying peer tip info to main loop.");

                // Inform main loop
                self.to_main_tx
                    .send(PeerTaskToMain::AddPeerMaxBlockHeight((
                        self.peer_address,
                        claimed_tip_height,
                        issued_challenge.accumulated_pow,
                    )))
                    .await?;

                Ok(KEEP_CONNECTION_ALIVE)
            }
            PeerMessage::BlockRequestByHash(block_digest) => {
                log_slow_scope!(fn_name!() + "::PeerMessage::BlockRequestByHash");

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
                log_slow_scope!(fn_name!() + "::PeerMessage::BlockRequestByHeight");

                debug!("Got BlockRequestByHeight of height {}", block_height);

                let canonical_block_digest = self
                    .global_state_lock
                    .lock_guard()
                    .await
                    .chain
                    .archival_state()
                    .archival_block_mmr
                    .try_get_leaf(block_height.into())
                    .await;

                let canonical_block_digest = match canonical_block_digest {
                    None => {
                        warn!("Got block request by height for unknown block");
                        self.punish(NegativePeerSanction::BlockRequestUnknownHeight)
                            .await?;
                        return Ok(KEEP_CONNECTION_ALIVE);
                    }
                    Some(digest) => digest,
                };

                let canonical_chain_block: Block = self
                    .global_state_lock
                    .lock_guard()
                    .await
                    .chain
                    .archival_state()
                    .get_block(canonical_block_digest)
                    .await?
                    .unwrap();
                let block_response: PeerMessage =
                    PeerMessage::Block(Box::new(canonical_chain_block.try_into().unwrap()));

                debug!("Sending block");
                peer.send(block_response).await?;
                debug!("Sent block");
                Ok(KEEP_CONNECTION_ALIVE)
            }
            PeerMessage::Block(t_block) => {
                log_slow_scope!(fn_name!() + "::PeerMessage::Block");

                info!(
                    "Got new block from peer {}, height {}, mined {}",
                    self.peer_address,
                    t_block.header.height,
                    t_block.header.timestamp.standard_format()
                );
                let new_block_height = t_block.header.height;

                let block = match Block::try_from(*t_block) {
                    Ok(block) => Box::new(block),
                    Err(e) => {
                        warn!("Peer sent invalid block: {e:?}");
                        self.punish(NegativePeerSanction::InvalidTransferBlock)
                            .await?;

                        return Ok(KEEP_CONNECTION_ALIVE);
                    }
                };

                // Update the value for the highest known height that peer possesses iff
                // we are not in a fork reconciliation state.
                if peer_state_info.fork_reconciliation_blocks.is_empty() {
                    peer_state_info.highest_shared_block_height = new_block_height;
                }

                self.try_ensure_path(block, peer, peer_state_info).await?;

                // Reward happens as part of `try_ensure_path`

                Ok(KEEP_CONNECTION_ALIVE)
            }
            PeerMessage::BlockRequestBatch(BlockRequestBatch {
                known_blocks,
                max_response_len,
            }) => {
                log_slow_scope!(fn_name!() + "::PeerMessage::BlockRequestBatch");
                debug!(
                    "Received BlockRequestBatch from peer {}, max_response_len: {max_response_len}",
                    self.peer_address
                );

                // The last block in the list of the peers known block is the
                // earliest block, block with lowest height, the peer has
                // requested. If it does not belong to canonical chain, none of
                // the later will. So we can do an early abort in that case.
                let least_preferred = match known_blocks.last() {
                    Some(least_preferred) => *least_preferred,
                    None => {
                        self.punish(NegativePeerSanction::BatchBlocksRequestEmpty)
                            .await?;

                        return Ok(KEEP_CONNECTION_ALIVE);
                    }
                };

                if !self
                    .global_state_lock
                    .lock_guard()
                    .await
                    .chain
                    .archival_state()
                    .block_belongs_to_canonical_chain(least_preferred)
                    .await
                {
                    self.punish(NegativePeerSanction::BatchBlocksUnknownRequest)
                        .await?;
                    peer.send(PeerMessage::UnableToSatisfyBatchRequest).await?;

                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                // Happy case: At least *one* of the blocks referenced by peer
                // is known to us.
                let mut first_block_in_response: Option<BlockHeight> = None;
                {
                    let global_state = self.global_state_lock.lock_guard().await;
                    for block_digest in known_blocks {
                        if global_state
                            .chain
                            .archival_state()
                            .block_belongs_to_canonical_chain(block_digest)
                            .await
                        {
                            let height = global_state
                                .chain
                                .archival_state()
                                .get_block_header(block_digest)
                                .await
                                .unwrap()
                                .height;
                            first_block_in_response = Some(height);
                            debug!(
                                "Found block in canonical chain for batch response: {}",
                                block_digest
                            );
                            break;
                        }
                    }
                }

                let peers_preferred_canonical_block = match first_block_in_response {
                    Some(block) => block,
                    None => {
                        self.punish(NegativePeerSanction::BatchBlocksUnknownRequest)
                            .await?;
                        return Ok(KEEP_CONNECTION_ALIVE);
                    }
                };

                debug!(
                    "Peer's most preferred block has height {peers_preferred_canonical_block}.\
                 Now building response from that height."
                );

                // Get the relevant blocks, at most batch-size many, descending from the
                // peer's (alleged) most canonical block. Don't exceed `max_response_len`
                // or `STANDARD_BLOCK_BATCH_SIZE` number of blocks in response.
                let len_of_response = cmp::min(
                    max_response_len,
                    self.global_state_lock.cli().sync_mode_threshold,
                );
                let len_of_response = cmp::max(len_of_response, MINIMUM_BLOCK_BATCH_SIZE);
                let len_of_response = cmp::min(len_of_response, STANDARD_BLOCK_BATCH_SIZE);

                let mut digests_of_returned_blocks = Vec::with_capacity(len_of_response);
                let response_start_height: u64 = peers_preferred_canonical_block.into();
                let mut i: u64 = 1;
                let global_state = self.global_state_lock.lock_guard().await;
                while digests_of_returned_blocks.len() < len_of_response {
                    match global_state
                        .chain
                        .archival_state()
                        .archival_block_mmr
                        .try_get_leaf(response_start_height + i)
                        .await
                    {
                        Some(digest) => {
                            digests_of_returned_blocks.push(digest);
                        }
                        None => break,
                    }
                    i += 1;
                }

                let mut returned_blocks: Vec<TransferBlock> =
                    Vec::with_capacity(digests_of_returned_blocks.len());
                for block_digest in digests_of_returned_blocks {
                    let block = global_state
                        .chain
                        .archival_state()
                        .get_block(block_digest)
                        .await?
                        .unwrap();
                    returned_blocks.push(block.try_into().unwrap());
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
                log_slow_scope!(fn_name!() + "::PeerMessage::BlockResponseBatch");

                debug!(
                    "handling block response batch with {} blocks",
                    t_blocks.len()
                );
                if t_blocks.len() < MINIMUM_BLOCK_BATCH_SIZE {
                    warn!("Got smaller batch response than allowed");
                    self.punish(NegativePeerSanction::TooShortBlockBatch)
                        .await?;
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                // Verify that we are in fact in syncing mode
                // TODO: Seperate peer messages into those allowed under syncing
                // and those that are not
                if !self.global_state_lock.lock_guard().await.net.syncing {
                    warn!("Received a batch of blocks without being in syncing mode");
                    self.punish(NegativePeerSanction::ReceivedBatchBlocksOutsideOfSync)
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
                        warn!("Got batch reponse with invalid start block");
                        self.punish(NegativePeerSanction::BatchBlocksInvalidStartHeight)
                            .await?;
                        return Ok(KEEP_CONNECTION_ALIVE);
                    }
                };

                // Convert all blocks to Block objects
                debug!(
                    "Found own block of height {} to match received batch",
                    most_canonical_own_block_match.kernel.header.height
                );
                let mut received_blocks = vec![];
                for t_block in t_blocks {
                    match Block::try_from(t_block) {
                        Ok(block) => {
                            received_blocks.push(block);
                        }
                        Err(e) => {
                            warn!("Received invalid transfer block from peer: {e:?}");
                            self.punish(NegativePeerSanction::InvalidTransferBlock)
                                .await?;
                            return Ok(KEEP_CONNECTION_ALIVE);
                        }
                    }
                }

                // Get the latest block that we know of and handle all received blocks
                self.handle_blocks(received_blocks, most_canonical_own_block_match)
                    .await?;

                // Reward happens as part of `handle_blocks`.

                Ok(KEEP_CONNECTION_ALIVE)
            }
            PeerMessage::UnableToSatisfyBatchRequest => {
                log_slow_scope!(fn_name!() + "::PeerMessage::UnableToSatisfyBatchRequest");
                warn!(
                    "Peer {} reports inability to satisfy batch request.",
                    self.peer_address
                );

                Ok(KEEP_CONNECTION_ALIVE)
            }
            PeerMessage::Handshake(_) => {
                log_slow_scope!(fn_name!() + "::PeerMessage::Handshake");

                // The handshake should have been sent during connection
                // initalization. Here it is out of order at best, malicious at
                // worst.
                self.punish(NegativePeerSanction::InvalidMessage).await?;
                Ok(KEEP_CONNECTION_ALIVE)
            }
            PeerMessage::ConnectionStatus(_) => {
                log_slow_scope!(fn_name!() + "::PeerMessage::ConnectionStatus");

                // The connection status should have been sent during connection
                // initalization. Here it is out of order at best, malicious at
                // worst.

                self.punish(NegativePeerSanction::InvalidMessage).await?;
                Ok(KEEP_CONNECTION_ALIVE)
            }
            PeerMessage::Transaction(transaction) => {
                log_slow_scope!(fn_name!() + "::PeerMessage::Transaction");

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
                    self.punish(NegativePeerSanction::InvalidTransaction)
                        .await?;
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                // 2. If transaction has coinbase, punish.
                // Transactions received from peers have not been mined yet.
                // Only the miner is allowed to produce transactions with non-empty coinbase fields.
                if transaction.kernel.coinbase.is_some() {
                    warn!("Received non-mined transaction with coinbase.");
                    self.punish(NegativePeerSanction::NonMinedTransactionHasCoinbase)
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
                let mutator_set_accumulator_after = self
                    .global_state_lock
                    .lock_guard()
                    .await
                    .chain
                    .light_state()
                    .mutator_set_accumulator_after();
                let confirmable =
                    transaction.is_confirmable_relative_to(&mutator_set_accumulator_after);
                if !confirmable {
                    warn!("Received unconfirmable tx");
                    self.punish(NegativePeerSanction::UnconfirmableTransaction)
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
                log_slow_scope!(fn_name!() + "::PeerMessage::TransactionNotification");

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
                    .mutator_set_accumulator_after()
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
                log_slow_scope!(fn_name!() + "::PeerMessage::TransasctionRequest");

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
            PeerMessage::BlockProposalNotification(block_proposal_notification) => {
                log_slow_scope!(fn_name!() + "::PeerMessage::BlockProposalNotification");

                let verdict = self
                    .global_state_lock
                    .lock_guard()
                    .await
                    .favor_incoming_block_proposal(
                        block_proposal_notification.height,
                        block_proposal_notification.guesser_fee,
                    );
                match verdict {
                    Ok(_) => {
                        peer.send(PeerMessage::BlockProposalRequest(
                            BlockProposalRequest::new(block_proposal_notification.body_mast_hash),
                        ))
                        .await?
                    }
                    Err(reject_reason) => info!(
                        "Got unfavorable block proposal notification from {} peer; rejecting. Reason:\n{reject_reason}",
                        self.peer_address
                    ),
                }

                Ok(KEEP_CONNECTION_ALIVE)
            }
            PeerMessage::BlockProposalRequest(block_proposal_request) => {
                log_slow_scope!(fn_name!() + "::PeerMessage::BlockProposalRequest");

                let matching_proposal = self
                    .global_state_lock
                    .lock_guard()
                    .await
                    .block_proposal
                    .filter(|x| x.body().mast_hash() == block_proposal_request.body_mast_hash)
                    .map(|x| x.to_owned());
                if let Some(proposal) = matching_proposal {
                    peer.send(PeerMessage::BlockProposal(Box::new(proposal)))
                        .await?;
                } else {
                    self.punish(NegativePeerSanction::BlockProposalNotFound)
                        .await?;
                }

                Ok(KEEP_CONNECTION_ALIVE)
            }
            PeerMessage::BlockProposal(block) => {
                log_slow_scope!(fn_name!() + "::PeerMessage::BlockProposal");

                info!("Got block proposal from peer.");
                let verdict = self
                    .global_state_lock
                    .lock_guard()
                    .await
                    .favor_incoming_block_proposal(
                        block.header().height,
                        block.total_guesser_reward(),
                    );
                if let Err(rejection_reason) = verdict {
                    warn!("Rejecting new block proposal:\n{rejection_reason}");
                    self.punish(NegativePeerSanction::NonFavorableBlockProposal)
                        .await?;

                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                // Verify validity and that proposal is child of current tip
                let tip = self
                    .global_state_lock
                    .lock_guard()
                    .await
                    .chain
                    .light_state()
                    .to_owned();
                if !block.is_valid(&tip, self.now()).await {
                    self.punish(NegativePeerSanction::InvalidBlockProposal)
                        .await?;

                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                self.to_main_tx
                    .send(PeerTaskToMain::BlockProposal(block))
                    .await?;

                // Valuable, new, hard-to-produce information. Reward peer.
                self.reward(PositivePeerSanction::NewBlockProposal).await?;

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
                log_slow_scope!(fn_name!() + "::MainToPeerTask::Block");

                // We don't currently differentiate whether a new block came from a peer, or from our
                // own miner. It's always shared through this logic.
                let new_block_height = block.kernel.header.height;
                if new_block_height > peer_state_info.highest_shared_block_height {
                    debug!("Sending PeerMessage::BlockNotification");
                    peer_state_info.highest_shared_block_height = new_block_height;
                    peer.send(PeerMessage::BlockNotification(block.as_ref().into()))
                        .await?;
                    debug!("Sent PeerMessage::BlockNotification");
                }
                Ok(KEEP_CONNECTION_ALIVE)
            }
            MainToPeerTask::RequestBlockBatch(batch_block_request) => {
                log_slow_scope!(fn_name!() + "::MainToPeerTask::RequestBlockBatch");

                // Only ask one of the peers about the batch of blocks
                if batch_block_request.peer_addr_target != self.peer_address {
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                let max_response_len = std::cmp::min(
                    STANDARD_BLOCK_BATCH_SIZE,
                    self.global_state_lock.cli().sync_mode_threshold,
                );

                peer.send(PeerMessage::BlockRequestBatch(BlockRequestBatch {
                    known_blocks: batch_block_request.known_blocks,
                    max_response_len,
                }))
                .await?;

                Ok(KEEP_CONNECTION_ALIVE)
            }
            MainToPeerTask::PeerSynchronizationTimeout(socket_addr) => {
                log_slow_scope!(fn_name!() + "::MainToPeerTask::PeerSynchronizationTimeout");

                if self.peer_address != socket_addr {
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                self.punish(NegativePeerSanction::SynchronizationTimeout)
                    .await?;

                // If this peer failed the last synchronization attempt, we only
                // sanction, we don't disconnect.
                Ok(KEEP_CONNECTION_ALIVE)
            }
            MainToPeerTask::MakePeerDiscoveryRequest => {
                log_slow_scope!(fn_name!() + "::MainToPeerTask::MakePeerDiscoveryRequest");

                peer.send(PeerMessage::PeerListRequest).await?;
                Ok(KEEP_CONNECTION_ALIVE)
            }
            MainToPeerTask::Disconnect(target_socket_addr) => {
                log_slow_scope!(fn_name!() + "::MainToPeerTask::Disconnect");

                // Disconnect from this peer if its address matches that which the main
                // task requested to disconnect from.
                Ok(target_socket_addr == self.peer_address)
            }
            // Disconnect from this peer, no matter what.
            MainToPeerTask::DisconnectAll() => Ok(true),
            MainToPeerTask::MakeSpecificPeerDiscoveryRequest(target_socket_addr) => {
                log_slow_scope!(
                    (crate::macros::fn_name!()
                        + "::MainToPeerTask::MakeSpecificPeerDiscoveryRequest")
                );

                if target_socket_addr == self.peer_address {
                    peer.send(PeerMessage::PeerListRequest).await?;
                }
                Ok(KEEP_CONNECTION_ALIVE)
            }
            MainToPeerTask::TransactionNotification(transaction_notification) => {
                log_slow_scope!(fn_name!() + "::MainToPeerTask::TransactionNotification");

                debug!("Sending PeerMessage::TransactionNotification");
                peer.send(PeerMessage::TransactionNotification(
                    transaction_notification,
                ))
                .await?;
                debug!("Sent PeerMessage::TransactionNotification");
                Ok(KEEP_CONNECTION_ALIVE)
            }
            MainToPeerTask::BlockProposalNotification(block_proposal_notification) => {
                log_slow_scope!(fn_name!() + "::MainToPeerTask::BlockProposalNotification");

                debug!("Sending PeerMessage::BlockProposalNotification");
                peer.send(PeerMessage::BlockProposalNotification(
                    block_proposal_notification,
                ))
                .await?;
                debug!("Sent PeerMessage::BlockProposalNotification");
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
        let cli_args = self.global_state_lock.cli().clone();
        let global_state = self.global_state_lock.lock_guard().await;

        let standing = global_state
            .net
            .peer_databases
            .peer_standings
            .get(self.peer_address.ip())
            .await
            .unwrap_or_else(|| PeerStanding::new(cli_args.peer_tolerance));

        // Add peer to peer map
        let peer_connection_info = PeerConnectionInfo::new(
            self.peer_handshake_data.listen_port,
            self.peer_address,
            self.inbound_connection,
        );
        let new_peer = PeerInfo::new(
            peer_connection_info,
            self.peer_handshake_data.instance_id,
            SystemTime::now(),
            self.peer_handshake_data.version.clone(),
            self.peer_handshake_data.is_archival_node,
            cli_args.peer_tolerance,
        )
        .with_standing(standing);

        // There is potential for a race-condition in the peer_map here, as we've previously
        // counted the number of entries and checked if instance ID was already connected. But
        // this check could have been invalidated by other tasks so we perform it again

        if global_state
            .net
            .peer_map
            .values()
            .any(|pi| pi.instance_id() == self.peer_handshake_data.instance_id)
        {
            bail!("Attempted to connect to already connected peer. Aborting connection.");
        }

        if global_state.net.peer_map.len() >= cli_args.max_num_peers as usize {
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
            // Send block notification request to catch up ASAP, in case we're
            // behind the newly-connected peer.
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
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::SeedableRng;
    use tokio::sync::mpsc::error::TryRecvError;
    use tracing_test::traced_test;

    use super::*;
    use crate::config_models::cli_args;
    use crate::config_models::network::Network;
    use crate::job_queue::triton_vm::TritonVmJobQueue;
    use crate::models::blockchain::block::block_header::TARGET_BLOCK_INTERVAL;
    use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
    use crate::models::peer::peer_block_notifications::PeerBlockNotification;
    use crate::models::peer::transaction_notification::TransactionNotification;
    use crate::models::state::mempool::TransactionOrigin;
    use crate::models::state::tx_proving_capability::TxProvingCapability;
    use crate::models::state::wallet::utxo_notification::UtxoNotificationMedium;
    use crate::models::state::wallet::WalletSecret;
    use crate::tests::shared::fake_valid_block_for_tests;
    use crate::tests::shared::fake_valid_sequence_of_blocks_for_tests;
    use crate::tests::shared::get_dummy_peer_connection_data_genesis;
    use crate::tests::shared::get_dummy_socket_address;
    use crate::tests::shared::get_test_genesis_setup;
    use crate::tests::shared::Action;
    use crate::tests::shared::Mock;

    #[traced_test]
    #[tokio::test]
    async fn test_peer_loop_bye() -> Result<()> {
        let mock = Mock::new(vec![Action::Read(PeerMessage::Bye)]);

        let (peer_broadcast_tx, _from_main_rx_clone, to_main_tx, _to_main_rx1, state_lock, hsd) =
            get_test_genesis_setup(Network::Alpha, 2, cli_args::Args::default()).await?;

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
            get_test_genesis_setup(Network::Alpha, 2, cli_args::Args::default())
                .await
                .unwrap();

        let mut peer_infos = state_lock
            .lock_guard()
            .await
            .net
            .peer_map
            .clone()
            .into_values()
            .collect::<Vec<_>>();
        peer_infos.sort_by_cached_key(|x| x.connected_address());
        let (peer_address0, instance_id0) = (
            peer_infos[0].connected_address(),
            peer_infos[0].instance_id(),
        );
        let (peer_address1, instance_id1) = (
            peer_infos[1].connected_address(),
            peer_infos[1].instance_id(),
        );

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
            get_test_genesis_setup(network, 0, cli_args::Args::default()).await?;
        assert_eq!(1000, state_lock.cli().peer_tolerance);
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

        different_genesis_block.set_header_nonce(StdRng::seed_from_u64(5550001).gen());
        let [block_1_with_different_genesis] = fake_valid_sequence_of_blocks_for_tests(
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
        assert_eq!(
            -i32::from(state_lock.cli().peer_tolerance),
            peer_standing.unwrap().standing
        );
        assert_eq!(
            NegativePeerSanction::DifferentGenesis,
            peer_standing.unwrap().latest_punishment.unwrap().0
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
            get_test_genesis_setup(network, 0, cli_args::Args::default()).await?;
        let peer_address = get_dummy_socket_address(0);
        let genesis_block: Block = state_lock
            .lock_guard()
            .await
            .chain
            .archival_state()
            .get_tip()
            .await;

        // Make a with hash above what the implied threshold from
        let [mut block_without_valid_pow] = fake_valid_sequence_of_blocks_for_tests(
            &genesis_block,
            Timestamp::hours(1),
            StdRng::seed_from_u64(5550001).gen(),
        )
        .await;

        // This *probably* is invalid PoW -- and needs to be for this test to
        // work.
        block_without_valid_pow.set_header_nonce(Digest::default());

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
            get_test_genesis_setup(network, 0, cli_args::Args::default()).await?;
        let peer_address = get_dummy_socket_address(0);
        let genesis_block: Block = Block::genesis_block(network);

        let now = genesis_block.header().timestamp + Timestamp::hours(1);
        let block_1 =
            fake_valid_block_for_tests(&alice, StdRng::seed_from_u64(5550001).gen()).await;
        assert!(
            block_1.is_valid(&genesis_block, now).await,
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
    async fn block_request_batch_simple() {
        // Scenario: Six blocks (including genesis) are known. Peer requests
        // from all possible starting points, and client responds with the
        // correct list of blocks.
        let network = Network::Main;
        let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, _to_main_rx1, mut state_lock, hsd) =
            get_test_genesis_setup(network, 0, cli_args::Args::default())
                .await
                .unwrap();
        let genesis_block: Block = Block::genesis_block(network);
        let peer_address = get_dummy_socket_address(0);
        let [block_1, block_2, block_3, block_4, block_5] =
            fake_valid_sequence_of_blocks_for_tests(
                &genesis_block,
                Timestamp::hours(1),
                StdRng::seed_from_u64(5550001).gen(),
            )
            .await;
        let blocks = vec![genesis_block, block_1, block_2, block_3, block_4, block_5];
        for block in blocks.iter().skip(1) {
            state_lock.set_new_tip(block.to_owned()).await.unwrap();
        }

        for i in 0..=4 {
            let response = (i + 1..=5)
                .map(|j| blocks[j].clone().try_into().unwrap())
                .collect_vec();
            let mock = Mock::new(vec![
                Action::Read(PeerMessage::BlockRequestBatch(BlockRequestBatch {
                    known_blocks: vec![blocks[i].hash()],
                    max_response_len: 14,
                })),
                Action::Write(PeerMessage::BlockResponseBatch(response)),
                Action::Read(PeerMessage::Bye),
            ]);
            let mut peer_loop_handler = PeerLoopHandler::new(
                to_main_tx.clone(),
                state_lock.clone(),
                peer_address,
                hsd.clone(),
                false,
                1,
            );

            peer_loop_handler
                .run_wrapper(mock, from_main_rx_clone.resubscribe())
                .await
                .unwrap();
        }
    }

    #[traced_test]
    #[tokio::test]
    async fn block_request_batch_in_order_test() -> Result<()> {
        // Scenario: A fork began at block 2, node knows two blocks of height 2 and two of height 3.
        // A peer requests a batch of blocks starting from block 1. Ensure that the correct blocks
        // are returned.

        let network = Network::Main;
        let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, _to_main_rx1, mut state_lock, hsd) =
            get_test_genesis_setup(network, 0, cli_args::Args::default()).await?;
        let genesis_block: Block = Block::genesis_block(network);
        let peer_address = get_dummy_socket_address(0);
        let [block_1, block_2_a, block_3_a] = fake_valid_sequence_of_blocks_for_tests(
            &genesis_block,
            Timestamp::hours(1),
            StdRng::seed_from_u64(5550001).gen(),
        )
        .await;
        let [block_2_b, block_3_b] = fake_valid_sequence_of_blocks_for_tests(
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
            get_test_genesis_setup(network, 0, cli_args::Args::default()).await?;
        let genesis_block = Block::genesis_block(network);
        let peer_address = get_dummy_socket_address(0);
        let [block_1, block_2_a, block_3_a] = fake_valid_sequence_of_blocks_for_tests(
            &genesis_block,
            Timestamp::hours(1),
            StdRng::seed_from_u64(5550001).gen(),
        )
        .await;
        let [block_2_b, block_3_b] = fake_valid_sequence_of_blocks_for_tests(
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
    async fn request_unknown_height_doesnt_crash() {
        // Scenario: Only genesis block is known. Peer requests block of height
        // 2.
        let network = Network::Main;
        let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, _to_main_rx1, state_lock, hsd) =
            get_test_genesis_setup(network, 0, cli_args::Args::default())
                .await
                .unwrap();
        let peer_address = get_dummy_socket_address(0);
        let mock = Mock::new(vec![
            Action::Read(PeerMessage::BlockRequestByHeight(2.into())),
            Action::Read(PeerMessage::Bye),
        ]);

        let mut peer_loop_handler = PeerLoopHandler::new(
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
            .await
            .unwrap();

        // Verify that peer is sanctioned for this nonsense.
        assert!(state_lock
            .lock_guard()
            .await
            .net
            .get_peer_standing_from_database(peer_address.ip())
            .await
            .unwrap()
            .standing
            .is_negative());
    }

    #[traced_test]
    #[tokio::test]
    async fn find_canonical_chain_when_multiple_blocks_at_same_height_test() -> Result<()> {
        // Scenario: A fork began at block 2, node knows two blocks of height 2 and two of height 3.
        // A peer requests a block at height 2. Verify that the correct block at height 2 is
        // returned.

        let network = Network::Main;
        let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, _to_main_rx1, mut state_lock, hsd) =
            get_test_genesis_setup(network, 0, cli_args::Args::default()).await?;
        let genesis_block = Block::genesis_block(network);
        let peer_address = get_dummy_socket_address(0);

        let [block_1, block_2_a, block_3_a] = fake_valid_sequence_of_blocks_for_tests(
            &genesis_block,
            Timestamp::hours(1),
            StdRng::seed_from_u64(5550001).gen(),
        )
        .await;
        let [block_2_b, block_3_b] = fake_valid_sequence_of_blocks_for_tests(
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
            get_test_genesis_setup(network, 0, cli_args::Args::default()).await?;
        let peer_address = get_dummy_socket_address(0);

        let block_1 = fake_valid_block_for_tests(&state_lock, rng.gen()).await;
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
            get_test_genesis_setup(network, 0, cli_args::Args::default()).await?;
        let peer_address = get_dummy_socket_address(0);
        let genesis_block: Block = state_lock
            .lock_guard()
            .await
            .chain
            .archival_state()
            .get_tip()
            .await;
        let [block_1, block_2] = fake_valid_sequence_of_blocks_for_tests(
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
        // In this scenario the peer sends more blocks than the client allows to
        // store in the fork-reconciliation field. This should result in
        // abandonment of the fork-reconciliation process as the alternative is
        // that the program will crash because it runs out of RAM.

        let network = Network::Main;
        let mut rng = StdRng::seed_from_u64(5550001);
        let (
            _peer_broadcast_tx,
            from_main_rx_clone,
            to_main_tx,
            mut to_main_rx1,
            mut state_lock,
            _hsd,
        ) = get_test_genesis_setup(network, 1, cli_args::Args::default()).await?;
        let genesis_block = Block::genesis_block(network);

        // Restrict max number of blocks held in memory to 2.
        let mut cli = state_lock.cli().clone();
        cli.sync_mode_threshold = 2;
        state_lock.set_cli(cli).await;

        let (hsd1, peer_address1) = get_dummy_peer_connection_data_genesis(network, 1).await;
        let [block_1, _block_2, block_3, block_4] =
            fake_valid_sequence_of_blocks_for_tests(&genesis_block, Timestamp::hours(1), rng.gen())
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
        ) = get_test_genesis_setup(network, 0, cli_args::Args::default())
            .await
            .unwrap();
        let peer_address: SocketAddr = get_dummy_socket_address(0);
        let genesis_block = Block::genesis_block(network);
        let [block_1, block_2, block_3, block_4] = fake_valid_sequence_of_blocks_for_tests(
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
            get_test_genesis_setup(network, 0, cli_args::Args::default()).await?;
        let peer_address = get_dummy_socket_address(0);
        let genesis_block = Block::genesis_block(network);

        let [block_1, block_2, block_3] = fake_valid_sequence_of_blocks_for_tests(
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
        ) = get_test_genesis_setup(network, 0, cli_args::Args::default()).await?;
        let peer_socket_address: SocketAddr = get_dummy_socket_address(0);
        let genesis_block: Block = state_lock
            .lock_guard()
            .await
            .chain
            .archival_state()
            .get_tip()
            .await;

        let [block_1, block_2, block_3, block_4, block_5] =
            fake_valid_sequence_of_blocks_for_tests(
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
            Action::Read(PeerMessage::BlockNotification((&block_5).into())),
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
        ) = get_test_genesis_setup(network, 1, cli_args::Args::default()).await?;
        let genesis_block = Block::genesis_block(network);
        let peer_infos: Vec<PeerInfo> = state_lock
            .lock_guard()
            .await
            .net
            .peer_map
            .clone()
            .into_values()
            .collect::<Vec<_>>();

        let [block_1, block_2, block_3, block_4] = fake_valid_sequence_of_blocks_for_tests(
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
                peer_infos[0].instance_id(),
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
            get_test_genesis_setup(network, 1, cli_args::Args::default())
                .await
                .unwrap();

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
                &TritonVmJobQueue::dummy(),
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
        ) = get_test_genesis_setup(network, 1, cli_args::Args::default())
            .await
            .unwrap();
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
                &TritonVmJobQueue::dummy(),
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
            .mempool_insert(transaction_1.clone(), TransactionOrigin::Foreign)
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

    mod block_proposals {
        use super::*;
        use crate::tests::shared::get_dummy_handshake_data_for_genesis;

        struct TestSetup {
            peer_loop_handler: PeerLoopHandler,
            to_main_rx: mpsc::Receiver<PeerTaskToMain>,
            from_main_rx: broadcast::Receiver<MainToPeerTask>,
            peer_state: MutablePeerState,
            to_main_tx: mpsc::Sender<PeerTaskToMain>,
            genesis_block: Block,
            peer_broadcast_tx: broadcast::Sender<MainToPeerTask>,
        }

        async fn genesis_setup(network: Network) -> TestSetup {
            let (peer_broadcast_tx, from_main_rx, to_main_tx, to_main_rx, alice, _hsd) =
                get_test_genesis_setup(network, 0, cli_args::Args::default())
                    .await
                    .unwrap();
            let peer_hsd = get_dummy_handshake_data_for_genesis(network).await;
            let peer_loop_handler = PeerLoopHandler::new(
                to_main_tx.clone(),
                alice.clone(),
                get_dummy_socket_address(0),
                peer_hsd.clone(),
                true,
                1,
            );
            let peer_state = MutablePeerState::new(peer_hsd.tip_header.height);

            // (peer_loop_handler, to_main_rx1)
            TestSetup {
                peer_broadcast_tx,
                peer_loop_handler,
                to_main_rx,
                from_main_rx,
                peer_state,
                to_main_tx,
                genesis_block: Block::genesis_block(network),
            }
        }

        #[traced_test]
        #[tokio::test]
        async fn accept_block_proposal_height_one() {
            // Node knows genesis block, receives a block proposal for block 1
            // and must accept this. Verify that main loop is informed of block
            // proposal.
            let TestSetup {
                peer_broadcast_tx,
                mut peer_loop_handler,
                mut to_main_rx,
                from_main_rx,
                mut peer_state,
                to_main_tx,
                genesis_block,
            } = genesis_setup(Network::Main).await;
            let block1 = fake_valid_block_for_tests(
                &peer_loop_handler.global_state_lock,
                StdRng::seed_from_u64(5550001).gen(),
            )
            .await;

            let mock = Mock::new(vec![
                Action::Read(PeerMessage::BlockProposal(Box::new(block1))),
                Action::Read(PeerMessage::Bye),
            ]);
            peer_loop_handler
                .run(mock, from_main_rx, &mut peer_state)
                .await
                .unwrap();

            match to_main_rx.try_recv().unwrap() {
                PeerTaskToMain::BlockProposal(block) => {
                    assert_eq!(genesis_block.hash(), block.header().prev_block_digest);
                }
                _ => panic!("Expected main loop to be informed of block proposal"),
            };

            drop(to_main_tx);
            drop(peer_broadcast_tx);
        }

        #[traced_test]
        #[tokio::test]
        async fn accept_block_proposal_notification_height_one() {
            // Node knows genesis block, receives a block proposal notification
            // for block 1 and must accept this by requesting the block
            // proposal from peer.
            let TestSetup {
                peer_broadcast_tx,
                mut peer_loop_handler,
                to_main_rx: _,
                from_main_rx,
                mut peer_state,
                to_main_tx,
                ..
            } = genesis_setup(Network::Main).await;
            let block1 = fake_valid_block_for_tests(
                &peer_loop_handler.global_state_lock,
                StdRng::seed_from_u64(5550001).gen(),
            )
            .await;

            let mock = Mock::new(vec![
                Action::Read(PeerMessage::BlockProposalNotification((&block1).into())),
                Action::Write(PeerMessage::BlockProposalRequest(
                    BlockProposalRequest::new(block1.body().mast_hash()),
                )),
                Action::Read(PeerMessage::Bye),
            ]);
            peer_loop_handler
                .run(mock, from_main_rx, &mut peer_state)
                .await
                .unwrap();

            drop(to_main_tx);
            drop(peer_broadcast_tx);
        }
    }

    mod proof_qualities {
        use strum::IntoEnumIterator;

        use super::*;
        use crate::config_models::cli_args;
        use crate::models::blockchain::transaction::Transaction;
        use crate::models::peer::transfer_transaction::TransactionProofQuality;
        use crate::tests::shared::mock_genesis_global_state;

        async fn tx_of_proof_quality(
            network: Network,
            quality: TransactionProofQuality,
        ) -> Transaction {
            let wallet_secret = WalletSecret::devnet_wallet();
            let alice_key = wallet_secret.nth_generation_spending_key_for_tests(0);
            let alice =
                mock_genesis_global_state(network, 1, wallet_secret, cli_args::Args::default())
                    .await;
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
                    &TritonVmJobQueue::dummy(),
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
                ) = get_test_genesis_setup(network, 1, cli_args::Args::default())
                    .await
                    .unwrap();

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
                    .mempool_insert(own_tx.to_owned(), TransactionOrigin::Foreign)
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

    mod sync_challenges {
        use super::*;

        #[traced_test]
        #[tokio::test]
        async fn bad_sync_challenge_height_greater_than_tip() {
            // Criterium: Challenge height may not exceed that of tip in the
            // request.

            let network = Network::Main;
            let (
                _alice_main_to_peer_tx,
                alice_main_to_peer_rx,
                alice_peer_to_main_tx,
                alice_peer_to_main_rx,
                mut alice,
                alice_hsd,
            ) = get_test_genesis_setup(network, 0, cli_args::Args::default())
                .await
                .unwrap();
            let genesis_block: Block = Block::genesis_block(network);
            let blocks: [Block; 11] = fake_valid_sequence_of_blocks_for_tests(
                &genesis_block,
                Timestamp::hours(1),
                [0u8; 32],
            )
            .await;
            for block in blocks.iter() {
                alice.set_new_tip(block.clone()).await.unwrap();
            }

            let bh12 = blocks.last().unwrap().header().height;
            let sync_challenge = SyncChallenge {
                tip_digest: blocks[9].hash(),
                challenges: [bh12; 10],
            };
            let alice_p2p_messages = Mock::new(vec![
                Action::Read(PeerMessage::SyncChallenge(sync_challenge)),
                Action::Read(PeerMessage::Bye),
            ]);

            let peer_address = get_dummy_socket_address(0);
            let mut alice_peer_loop_handler = PeerLoopHandler::new(
                alice_peer_to_main_tx.clone(),
                alice.clone(),
                peer_address,
                alice_hsd,
                false,
                1,
            );
            alice_peer_loop_handler
                .run_wrapper(alice_p2p_messages, alice_main_to_peer_rx)
                .await
                .unwrap();

            drop(alice_peer_to_main_rx);

            let latest_sanction = alice
                .lock_guard()
                .await
                .net
                .get_peer_standing_from_database(peer_address.ip())
                .await
                .unwrap();
            assert_eq!(
                NegativePeerSanction::InvalidSyncChallenge,
                latest_sanction
                    .latest_punishment
                    .expect("peer must be sanctioned")
                    .0
            );
        }

        #[traced_test]
        #[tokio::test]
        async fn bad_sync_challenge_genesis_block_doesnt_crash_client() {
            // Criterium: Challenge may not point to genesis block, or block 1, as
            // tip.

            let network = Network::Main;
            let genesis_block: Block = Block::genesis_block(network);

            let alice_cli = cli_args::Args::default();
            let (
                _alice_main_to_peer_tx,
                alice_main_to_peer_rx,
                alice_peer_to_main_tx,
                alice_peer_to_main_rx,
                alice,
                alice_hsd,
            ) = get_test_genesis_setup(network, 0, alice_cli).await.unwrap();

            let sync_challenge = SyncChallenge {
                tip_digest: genesis_block.hash(),
                challenges: [BlockHeight::genesis(); 10],
            };

            let alice_p2p_messages = Mock::new(vec![
                Action::Read(PeerMessage::SyncChallenge(sync_challenge)),
                Action::Read(PeerMessage::Bye),
            ]);

            let peer_address = get_dummy_socket_address(0);
            let mut alice_peer_loop_handler = PeerLoopHandler::new(
                alice_peer_to_main_tx.clone(),
                alice.clone(),
                peer_address,
                alice_hsd,
                false,
                1,
            );
            alice_peer_loop_handler
                .run_wrapper(alice_p2p_messages, alice_main_to_peer_rx)
                .await
                .unwrap();

            drop(alice_peer_to_main_rx);

            let latest_sanction = alice
                .lock_guard()
                .await
                .net
                .get_peer_standing_from_database(peer_address.ip())
                .await
                .unwrap();
            assert_eq!(
                NegativePeerSanction::InvalidSyncChallenge,
                latest_sanction
                    .latest_punishment
                    .expect("peer must be sanctioned")
                    .0
            );
        }

        #[traced_test]
        #[tokio::test]
        async fn sync_challenge_happy_path() -> Result<()> {
            // Bob notifies Alice of a block whose parameters satisfy the sync mode
            // criterion. Alice issues a challenge. Bob responds. Alice enters into
            // sync mode.

            let mut rng = StdRng::seed_from_u64(5550001);
            let network = Network::Main;
            let genesis_block: Block = Block::genesis_block(network);

            let alice_cli = cli_args::Args {
                sync_mode_threshold: 10,
                ..Default::default()
            };
            let (
                _alice_main_to_peer_tx,
                alice_main_to_peer_rx,
                alice_peer_to_main_tx,
                mut alice_peer_to_main_rx,
                mut alice,
                alice_hsd,
            ) = get_test_genesis_setup(network, 0, alice_cli).await?;
            let _alice_socket_address = get_dummy_socket_address(0);

            let (
                _bob_main_to_peer_tx,
                _bob_main_to_peer_rx,
                _bob_peer_to_main_tx,
                _bob_peer_to_main_rx,
                mut bob,
                _bob_hsd,
            ) = get_test_genesis_setup(network, 0, cli_args::Args::default()).await?;
            let bob_socket_address = get_dummy_socket_address(0);

            let now = genesis_block.header().timestamp + Timestamp::hours(1);
            let block_1 = fake_valid_block_for_tests(&alice, rng.gen()).await;
            assert!(
                block_1.is_valid(&genesis_block, now).await,
                "Block must be valid for this test to make sense"
            );
            let alice_tip = &block_1;
            alice.set_new_tip(block_1.clone()).await?;
            bob.set_new_tip(block_1.clone()).await?;

            let blocks: [Block; 11] =
                fake_valid_sequence_of_blocks_for_tests(&block_1, TARGET_BLOCK_INTERVAL, rng.gen())
                    .await;
            for block in &blocks {
                bob.set_new_tip(block.clone()).await?;
            }
            let bob_tip = blocks.last().unwrap();

            let block_notification_from_bob = PeerBlockNotification {
                hash: bob_tip.hash(),
                height: bob_tip.header().height,
                cumulative_proof_of_work: bob_tip.header().cumulative_proof_of_work,
            };

            let alice_rng_seed = rng.gen::<[u8; 32]>();
            let mut alice_rng_clone = StdRng::from_seed(alice_rng_seed);
            let sync_challenge_from_alice = SyncChallenge::generate(
                &block_notification_from_bob,
                alice_tip.header().height,
                alice_rng_clone.gen(),
            );

            println!(
                "sync challenge from alice:\n{:?}",
                sync_challenge_from_alice
            );

            let sync_challenge_response_from_bob = bob
                .lock_guard()
                .await
                .response_to_sync_challenge(sync_challenge_from_alice)
                .await
                .expect("should be able to respond to sync challenge");

            let alice_p2p_messages = Mock::new(vec![
                Action::Read(PeerMessage::BlockNotification(block_notification_from_bob)),
                Action::Write(PeerMessage::SyncChallenge(sync_challenge_from_alice)),
                Action::Read(PeerMessage::SyncChallengeResponse(Box::new(
                    sync_challenge_response_from_bob,
                ))),
                Action::Read(PeerMessage::Bye),
            ]);

            let mut alice_peer_loop_handler = PeerLoopHandler::with_mocked_time(
                alice_peer_to_main_tx.clone(),
                alice.clone(),
                bob_socket_address,
                alice_hsd,
                false,
                1,
                bob_tip.header().timestamp,
            );
            alice_peer_loop_handler.set_rng(StdRng::from_seed(alice_rng_seed));
            alice_peer_loop_handler
                .run_wrapper(alice_p2p_messages, alice_main_to_peer_rx)
                .await?;

            // AddPeerMaxBlockHeight message triggered *after* sync challenge
            let expected_message_from_alice_peer_loop = PeerTaskToMain::AddPeerMaxBlockHeight((
                bob_socket_address,
                bob_tip.header().height,
                bob_tip.header().cumulative_proof_of_work,
            ));
            let observed_message_from_alice_peer_loop = alice_peer_to_main_rx.recv().await.unwrap();
            assert_eq!(
                expected_message_from_alice_peer_loop,
                observed_message_from_alice_peer_loop
            );

            Ok(())
        }
    }
}
