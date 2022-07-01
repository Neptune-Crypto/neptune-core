use crate::models::blockchain::block::block_height::BlockHeight;
use crate::models::blockchain::block::transfer_block::TransferBlock;
use crate::models::blockchain::block::Block;
use crate::models::blockchain::digest::keyable_digest::KeyableDigest;
use crate::models::blockchain::digest::{Digest, RESCUE_PRIME_DIGEST_SIZE_IN_BYTES};
use crate::models::channel::{MainToPeerThread, PeerThreadToMain};
use crate::models::peer::{PeerMessage, PeerStateData};
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
use tracing::{debug, info, warn};

const PEER_TOLERANCE: u8 = 50;
const INVALID_BLOCK_SEVERITY: u8 = 10;
const BAD_BLOCK_RESPONSE_BY_HEIGHT_SEVERITY: u8 = 3;
const DIFFERENT_GENESIS_SEVERITY: u8 = u8::MAX;

pub fn punish(state: &State, peer_address: &SocketAddr, severity: u8) {
    // (state: State, peer_address: &SocketAddr, severity: u8) => {
    let mut peers = state
        .peer_map
        .lock()
        .unwrap_or_else(|e| panic!("Failed to lock peer map: {}", e));
    peers
        .entry(*peer_address)
        .and_modify(|p| p.banscore += severity);

    if peers[peer_address].banscore > PEER_TOLERANCE {
        warn!("Banning peer");
        todo!();
    }
}

/// Function for handling the receiving of a new block from a peer
async fn handle_new_block<S>(
    received_tip_block: Box<Block>,
    peer_address: &SocketAddr,
    state: &State,
    to_main_tx: &mpsc::Sender<PeerThreadToMain>,
    peer: &mut S,
) -> Result<()>
where
    S: Sink<PeerMessage> + TryStream<Ok = PeerMessage> + Unpin,
    <S as Sink<PeerMessage>>::Error: std::error::Error + Sync + Send + 'static,
    <S as TryStream>::Error: std::error::Error,
{
    let mut new_blocks: Vec<Block> = vec![*received_tip_block.clone()];
    let mut parent_digest = received_tip_block.header.prev_block_digest;
    let mut parent_block = state.get_block(parent_digest).await?;
    let mut parent_height = received_tip_block.header.height.previous();

    // If parent is not known, request all blocks until we find a parent that is known.
    while parent_block.is_none() && parent_height > BlockHeight::genesis() {
        info!(
            "Parent not know: Requesting previous block with height {} from peer",
            parent_height
        );
        peer.send(PeerMessage::BlockRequestByHash(parent_digest))
            .await?;
        let received_block: Block = match peer.try_next().await {
            Ok(Some(PeerMessage::BlockResponseByHash(Some(received_transfer_block)))) => {
                let received_block_res: Block = (*received_transfer_block).into();

                debug!("Got BlockResponseByHash");
                if parent_height != received_block_res.header.height
                    || parent_digest != received_block_res.hash
                {
                    warn!("Bad BlockResponseByHeight received");
                    punish(state, peer_address, BAD_BLOCK_RESPONSE_BY_HEIGHT_SEVERITY);
                    return Ok(());
                }

                received_block_res
            }
            _ => {
                warn!("Got invalid block response");
                return Ok(());
            }
        };

        parent_digest = received_block.header.prev_block_digest;
        parent_height = parent_height.previous();
        new_blocks.push(received_block);
        parent_block = state.get_block(parent_digest).await?;
    }

    // We got all the way back to genesis, but disagree about genesis. Ban peer.
    if parent_block.is_none() && parent_height == BlockHeight::genesis() {
        punish(state, peer_address, DIFFERENT_GENESIS_SEVERITY);
        return Ok(());
    }

    // We want to treat the received blocks in reverse order, from oldest to newest
    new_blocks.reverse();

    for new_block in new_blocks.iter() {
        if !new_block.archival_is_valid() {
            warn!("Received invalid block from peer with IP {}", peer_address);
            punish(state, peer_address, INVALID_BLOCK_SEVERITY);
            return Ok(());
        } else {
            info!("Block is valid");
        }
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

    Ok(())
}

/// Handle peer messages and returns Ok(true) if connection should be closed.
/// Otherwise returns OK(false).
async fn handle_peer_message<S>(
    msg: PeerMessage,
    state: &State,
    peer_address: &SocketAddr,
    peer: &mut S,
    peer_state_info: &mut PeerStateData,
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

            // TODO: Add validation of block, increase ban score if block is bad.
            // This includes checking that the block hash is below a threshold etc.
            let block: Box<Block> = Box::new((*t_block).into());
            peer_state_info.highest_shared_block_height = new_block_height;
            let block_is_new = state
                .latest_block_header
                .lock()
                .unwrap()
                .proof_of_work_family
                < block.header.proof_of_work_family;

            if block_is_new {
                handle_new_block(block, peer_address, state, to_main_tx, peer).await?;
            } else {
                info!(
                    "Got non canonical block from peer, height: {}, PoW family: {:?}",
                    new_block_height, block.header.proof_of_work_family,
                );
            }
            Ok(false)
        }
        PeerMessage::BlockNotification(block_notification) => {
            debug!("Got BlockNotification");
            peer_state_info.highest_shared_block_height = block_notification.height;
            {
                let block_is_new = state
                    .latest_block_header
                    .lock()
                    .unwrap()
                    .proof_of_work_family
                    < block_notification.proof_of_work_family;

                if block_is_new {
                    peer.send(PeerMessage::BlockRequestByHeight(block_notification.height))
                        .await?;
                    debug!("Sent BlockRequestByHeight to peer");

                    match peer.try_next().await {
                        Ok(Some(PeerMessage::BlockResponseByHeight(Some(received_block)))) => {
                            debug!("Got BlockResponseByHeight");
                            if block_notification.height != received_block.header.height {
                                warn!("Bad BlockResponseByHeight received");
                                punish(state, peer_address, BAD_BLOCK_RESPONSE_BY_HEIGHT_SEVERITY);
                                return Ok(false);
                            }

                            let block: Box<Block> = Box::new((*received_block).into());
                            handle_new_block(block, peer_address, state, to_main_tx, peer).await?;
                        }
                        _ => {
                            warn!("Got invalid block response");
                        }
                    }
                }
            }
            Ok(false)
        }
        PeerMessage::BlockRequestByHash(block_digest) => {
            let resp;
            {
                let block = state.get_block(block_digest).await?;
                resp = PeerMessage::BlockResponseByHash(block.map(|b| Box::new(b.into())));
            }

            peer.send(resp).await?;
            Ok(false)
        }
        PeerMessage::BlockRequestByHeight(block_height) => {
            debug!("Got BlockRequestByHeight");

            let resp;
            {
                let databases = state.databases.lock().await;
                let hash_res = databases
                    .block_height_to_hash
                    .get(ReadOptions::new(), block_height)
                    .expect("Failed to read from database");
                resp = match hash_res {
                    None => PeerMessage::BlockResponseByHeight(None),
                    Some(hash) => {
                        let read_opts_block = ReadOptions::new();
                        let hash_array: [u8; RESCUE_PRIME_DIGEST_SIZE_IN_BYTES] =
                            hash.try_into().unwrap_or_else(|v: Vec<u8>| {
                                panic!(
                                    "Expected a Vec of length {} but it was {}",
                                    RESCUE_PRIME_DIGEST_SIZE_IN_BYTES,
                                    v.len()
                                )
                            });
                        let block_digest: Digest = hash_array.into();
                        let block_response = match databases
                            .block_hash_to_block
                            .get::<KeyableDigest>(read_opts_block, block_digest.into())
                            .expect("Failed to read from database")
                        {
                            // I think it makes sense to panic here since we found the block in the height to digest
                            // database. So it should be in the hash to block database.
                            None => panic!("Failed to find block with hash {:?}", hash_array),
                            Some(block_bytes) => {
                                let deserialized: Block = bincode::deserialize(&block_bytes)?;
                                PeerMessage::BlockResponseByHeight(Some(Box::new(
                                    deserialized.into(),
                                )))
                            }
                        };
                        block_response
                    }
                };
            }

            // Print a warning if the response we're about to send is empty
            if let PeerMessage::BlockResponseByHeight(None) = resp {
                warn!("Returning bad result from BlockRequestByHeight");
            }

            peer.send(resp).await?;
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
    peer_state_info: &mut PeerStateData,
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
) -> Result<()>
where
    S: Sink<PeerMessage> + TryStream<Ok = PeerMessage> + Unpin,
    <S as Sink<PeerMessage>>::Error: std::error::Error + Sync + Send + 'static,
    <S as TryStream>::Error: std::error::Error,
{
    let mut peer_state_info = PeerStateData {
        highest_shared_block_height: 0.into(),
    };

    loop {
        select! {
            // Handle peer messages
            peer_message = peer.try_next() => {
                match peer_message {
                    Ok(peer_message) => {
                        match peer_message {
                            None => {
                                info!("Peer closed connection.");
                                state.peer_map
                                    .lock()
                                    .unwrap_or_else(|e| panic!("Failed to lock peer map: {}", e))
                                    .remove(peer_address)
                                    .unwrap_or_else(|| panic!("Failed to remove {} from peer map. Is peer map mangled?",
                                                              peer_address));
                                break;
                            }
                            Some(peer_msg) => {
                                let close_connection: bool = handle_peer_message(peer_msg, &state, peer_address, &mut peer, &mut peer_state_info, &to_main_tx).await?;
                                if close_connection {
                                    state.peer_map
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
                    Err(e) => {
                        state.peer_map
                            .lock()
                            .unwrap_or_else(|e| panic!("Failed to lock peer map: {}", e))
                            .remove(peer_address)
                            .unwrap_or_else(|| panic!("Failed to remove {} from peer map. Is peer map mangled?",
                                                      peer_address));
                        bail!("Error when receiving from peer: {}. Closing connection.", e);
                    }
                }
            }

            // Handle messages from main thread
            main_msg_res = from_main_rx.recv() => {
                match main_msg_res {
                    Ok(main_msg) => handle_main_thread_message(main_msg, &mut peer, &mut peer_state_info).await?,
                    Err(e) => panic!("Failed to read from main loop: {}", e),
                }
            }
        }
    }

    Ok(())
}
