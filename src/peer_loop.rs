use crate::models::blockchain::block::block_height::BlockHeight;
use crate::models::blockchain::block::transfer_block::TransferBlock;
use crate::models::blockchain::block::Block;
use crate::models::blockchain::digest::keyable_digest::KeyableDigest;
use crate::models::blockchain::digest::{Digest, RESCUE_PRIME_DIGEST_SIZE_IN_BYTES};
use crate::models::channel::{MainToPeerThread, PeerThreadToMain};
use crate::models::peer::{PeerInfo, PeerMessage, PeerSanctionReason, PeerState};
use crate::models::state::State;
use anyhow::{bail, Result};
use futures::sink::{Sink, SinkExt};
use futures::stream::{TryStream, TryStreamExt};
use leveldb::kv::KV;
use leveldb::options::ReadOptions;
use std::convert::TryInto;
use std::marker::Unpin;
use std::net::SocketAddr;
use tokio::select;
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, error, info, warn};

// TODO: Move peer tolerance to a parameter in CLI arguments
const PEER_TOLERANCE: u16 = 50;

pub fn punish(state: &State, peer_address: &SocketAddr, reason: PeerSanctionReason) -> Result<()> {
    let mut peers = state
        .peer_map
        .lock()
        .unwrap_or_else(|e| panic!("Failed to lock peer map: {}", e));
    let new_standing: &mut u16 = &mut 0;
    peers
        .entry(*peer_address)
        .and_modify(|p| *new_standing = p.standing.sanction(reason));

    if *new_standing > PEER_TOLERANCE {
        warn!("Banning peer");
        bail!("Banning peer");
    }

    Ok(())
}

/// Function for handling the receiving of a new block from a peer
async fn handle_new_block<S>(
    received_block: Box<Block>,
    peer_address: &SocketAddr,
    state: &State,
    to_main_tx: &mpsc::Sender<PeerThreadToMain>,
    peer: &mut S,
    peer_state: &mut PeerState,
) -> Result<()>
where
    S: Sink<PeerMessage> + TryStream<Ok = PeerMessage> + Unpin,
    <S as Sink<PeerMessage>>::Error: std::error::Error + Sync + Send + 'static,
    <S as TryStream>::Error: std::error::Error,
{
    let parent_digest = received_block.header.prev_block_digest;
    let parent_block = state.get_block(parent_digest).await?;
    let parent_height = received_block.header.height.previous();

    // If parent is not known, request the parent, and add the current to the peer fork resolution list
    if parent_block.is_none() && parent_height > BlockHeight::genesis() {
        info!(
            "Parent not know: Requesting previous block with height {} from peer",
            parent_height
        );
        if peer_state.fork_reconciliation_blocks.is_empty()
            || peer_state
                .fork_reconciliation_blocks
                .last()
                .unwrap()
                .header
                .height
                .previous()
                == received_block.header.height
        {
            peer_state.fork_reconciliation_blocks.push(*received_block);
        } else {
            // Blocks received out of order. Give up on block resolution attempt.
            // TODO: Consider punishing here
            peer_state.fork_reconciliation_blocks = vec![];
            return Ok(());
        }

        peer.send(PeerMessage::BlockRequestByHash(parent_digest))
            .await?;

        return Ok(());
    }

    // We got all the way back to genesis, but disagree about genesis. Ban peer.
    if parent_block.is_none() && parent_height == BlockHeight::genesis() {
        punish(state, peer_address, PeerSanctionReason::DifferentGenesis)?;
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
    let mut previous_block = parent_block.unwrap();
    for new_block in new_blocks.iter() {
        if !new_block.archival_is_valid(&previous_block) {
            warn!(
                "Received invalid block of height {} from peer with IP {}",
                new_block.header.height, peer_address
            );
            punish(
                state,
                peer_address,
                PeerSanctionReason::InvalidBlock((new_block.header.height, new_block.hash)),
            )?;
            return Ok(());
        } else {
            info!("Block with height {} is valid", new_block.header.height);
        }

        previous_block = new_block.to_owned();
    }

    // Send the new blocks to the main thread which handles the state update
    // and storage to the database.
    let new_block_height = new_blocks.last().unwrap().header.height;
    to_main_tx
        .send(PeerThreadToMain::NewBlocks(new_blocks))
        .await?;
    info!(
        "Updated block info by block from peer. block height {}",
        new_block_height
    );

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
    msg: PeerMessage,
    state: &State,
    peer_address: &SocketAddr,
    peer: &mut S,
    peer_state_info: &mut PeerState,
    to_main_tx: &mpsc::Sender<PeerThreadToMain>,
) -> Result<bool>
where
    S: Sink<PeerMessage> + TryStream<Ok = PeerMessage> + Unpin,
    <S as Sink<PeerMessage>>::Error: std::error::Error + Sync + Send + 'static,
    <S as TryStream>::Error: std::error::Error,
{
    match msg {
        PeerMessage::Bye => {
            // Note that the current peer is not removed from the state.peer_map here
            // but that this is done by the caller.
            info!("Got bye. Closing connection to peer");
            Ok(true)
        }
        PeerMessage::PeerListRequest => {
            debug!("Got PeerListRequest");
            let peer_addresses = state
                .peer_map
                .lock()
                .unwrap_or_else(|e| panic!("Failed to lock peer map: {}", e))
                .keys()
                .cloned()
                .collect();
            peer.send(PeerMessage::PeerListResponse(peer_addresses))
                .await?;
            Ok(false)
        }
        PeerMessage::Block(t_block) => {
            debug!(
                "Got new block from peer {}, block height {}",
                peer_address, t_block.header.height
            );
            let new_block_height = t_block.header.height;

            let block: Box<Block> = Box::new((*t_block).into());

            // Update the value for the highest known height that peer possesses iff
            // we are not in a fork reconciliation state.
            if peer_state_info.fork_reconciliation_blocks.is_empty() {
                peer_state_info.highest_shared_block_height = new_block_height;
            }

            // TODO: Handle the situation where peer_state_info.fork_resolution_blocks is not empty better.
            let block_is_new = state
                .latest_block_header
                .lock()
                .unwrap()
                .proof_of_work_family
                < block.header.proof_of_work_family
                || !peer_state_info.fork_reconciliation_blocks.is_empty();

            if block_is_new {
                handle_new_block(
                    block,
                    peer_address,
                    state,
                    to_main_tx,
                    peer,
                    peer_state_info,
                )
                .await?;
            } else {
                info!(
                    "Got non canonical block from peer, height: {}, PoW family: {:?}",
                    new_block_height, block.header.proof_of_work_family,
                );
            }
            Ok(false)
        }
        PeerMessage::BlockNotification(block_notification) => {
            debug!(
                "Got BlockNotification of height {}",
                block_notification.height
            );
            peer_state_info.highest_shared_block_height = block_notification.height;
            {
                let block_is_new = state
                    .latest_block_header
                    .lock()
                    .unwrap()
                    .proof_of_work_family
                    < block_notification.proof_of_work_family;

                // Only request block if it is new, and if we are not currently reconciling
                // a fork. If we are reconciling, that is handled later, and the information
                // about that is stored in `highest_shared_block_height`.
                if block_is_new && peer_state_info.fork_reconciliation_blocks.is_empty() {
                    peer.send(PeerMessage::BlockRequestByHeight(block_notification.height))
                        .await?;
                }
            }

            Ok(false)
        }
        PeerMessage::BlockRequestByHash(block_digest) => {
            match state.get_block(block_digest).await? {
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
            debug!("Got BlockRequestByHeight");

            let block_response;
            {
                let databases = state.block_databases.lock().await;
                let hash_res = databases
                    .block_height_to_hash
                    .get(ReadOptions::new(), block_height)
                    .expect("Failed to read from database");
                match hash_res {
                    None => {
                        warn!("Got block request by height for unknown block");
                        // TODO: Consider punishing here
                        return Ok(false);
                    }
                    Some(digest) => {
                        let read_opts_block = ReadOptions::new();
                        let hash_array: [u8; RESCUE_PRIME_DIGEST_SIZE_IN_BYTES] =
                            digest.try_into().unwrap_or_else(|v: Vec<u8>| {
                                panic!(
                                    "Expected a Vec of length {} but it was {}",
                                    RESCUE_PRIME_DIGEST_SIZE_IN_BYTES,
                                    v.len()
                                )
                            });

                        let block_digest: Digest = hash_array.into();
                        block_response = match databases
                            .block_hash_to_block
                            .get::<KeyableDigest>(read_opts_block, block_digest.into())
                            .expect("Failed to read from database")
                        {
                            // I think it makes sense to panic here since we found the block in the height to digest
                            // database. So it should be in the hash to block database.
                            None => panic!("Failed to find block with hash {:?}", hash_array),
                            Some(block_bytes) => {
                                let deserialized: Block = bincode::deserialize(&block_bytes)?;
                                PeerMessage::Block(Box::new(deserialized.into()))
                            }
                        };
                    }
                }
            }

            peer.send(block_response).await?;
            Ok(false)
        }
        msg => {
            warn!("Unimplemented peer message received. Got: {:?}", msg);
            Ok(false)
        }
    }
}

async fn handle_main_thread_message<S>(
    msg: MainToPeerThread,
    peer: &mut S,
    peer_state_info: &mut PeerState,
) -> Result<()>
where
    S: Sink<PeerMessage> + TryStream<Ok = PeerMessage> + Unpin,
    <S as Sink<PeerMessage>>::Error: std::error::Error + Sync + Send + 'static,
    <S as TryStream>::Error: std::error::Error,
{
    match msg {
        MainToPeerThread::BlockFromMiner(block) => {
            // If this client found a block, we need to share it immediately
            // to reduce the risk that someone else finds another one and shares
            // it faster.
            info!("peer_loop got NewBlockFromMiner message from main");
            let new_block_height = block.header.height;
            let t_block: Box<TransferBlock> = Box::new((*block).into());
            peer.send(PeerMessage::Block(t_block)).await?;
            peer_state_info.highest_shared_block_height = new_block_height;
        }
        MainToPeerThread::Block(block) => {
            info!("NewBlock message from main");
            let new_block_height = block.header.height;
            if new_block_height > peer_state_info.highest_shared_block_height {
                debug!("Sending PeerMessage::BlockNotification");
                peer_state_info.highest_shared_block_height = new_block_height;
                peer.send(PeerMessage::BlockNotification((*block).into()))
                    .await?;
            }
        }
        MainToPeerThread::Transaction(nt) => {
            info!("peer_loop got NetTransaction message from main");
            peer.send(PeerMessage::NewTransaction(nt)).await?;
        }
    }

    Ok(())
}

/// Loop for the peer threads. Awaits either a message from the peer over TCP,
/// or a message from main over the main-to-peer-threads broadcast channel.
pub async fn peer_loop<S>(
    mut peer: S,
    mut from_main_rx: broadcast::Receiver<MainToPeerThread>,
    to_main_tx: mpsc::Sender<PeerThreadToMain>,
    state: State,
    peer_address: &SocketAddr,
    peer_state_info: &mut PeerState,
) -> Result<()>
where
    S: Sink<PeerMessage> + TryStream<Ok = PeerMessage> + Unpin,
    <S as Sink<PeerMessage>>::Error: std::error::Error + Sync + Send + 'static,
    <S as TryStream>::Error: std::error::Error,
{
    let peer_info_writeback: PeerInfo;
    loop {
        select! {
            // Handle peer messages
            peer_message = peer.try_next() => {
                match peer_message {
                    Ok(peer_message) => {
                        match peer_message {
                            None => {
                                info!("Peer closed connection.");
                                peer_info_writeback = state.peer_map
                                    .lock()
                                    .unwrap_or_else(|e| panic!("Failed to lock peer map: {}", e))
                                    .remove(peer_address)
                                    .unwrap_or_else(|| panic!("Failed to remove {} from peer map. Is peer map mangled?",
                                                              peer_address));


                                break;
                            }
                            Some(peer_msg) => {
                                let close_connection: bool = match handle_peer_message(peer_msg, &state, peer_address, &mut peer, peer_state_info, &to_main_tx).await {
                                    Ok(close) => close,
                                    Err(err) => {
                                        error!("{}. Closing connection.", err);
                                        true
                                    }
                                };

                                if close_connection {
                                    peer_info_writeback = state.peer_map
                                    .lock()
                                    .unwrap_or_else(|e| panic!("Failed to lock peer map: {}", e))
                                    .remove(peer_address)
                                    .unwrap_or_else(|| panic!("Failed to remove {} from peer map. Is peer map mangled?",
                                                              peer_address));

                                    break;
                                }
                            }
                        }
                    }
                    Err(err) => {
                        peer_info_writeback = state.peer_map
                            .lock()
                            .unwrap_or_else(|e| panic!("Failed to lock peer map: {}", e))
                            .remove(peer_address)
                            .unwrap_or_else(|| panic!("Failed to remove {} from peer map. Is peer map mangled?",
                                                      peer_address));
                        error!("Error when receiving from peer: {}. Closing connection.", err);

                        break;
                    }
                }
            }

            // Handle messages from main thread
            main_msg_res = from_main_rx.recv() => {
                match main_msg_res {
                    Ok(main_msg) => handle_main_thread_message(main_msg, &mut peer, peer_state_info).await?,
                    Err(e) => panic!("Failed to read from main loop: {}", e),
                }
            }
        }
    }

    state
        .write_peer_standing_to_database(peer_address.ip(), peer_info_writeback.standing)
        .await;

    Ok(())
}
