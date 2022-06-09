use crate::models::blockchain::block::{Block, TransferBlock};
use crate::models::blockchain::digest::{RescuePrimeDigest, RESCUE_PRIME_DIGEST_SIZE_IN_BYTES};
use crate::models::channel::{MainToPeerThread, PeerThreadToMain};
use crate::models::database::DatabaseUnit;
use crate::models::peer::{PeerMessage, PeerStateData};
use crate::models::shared::LatestBlockInfo;
use crate::models::State;
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
const BAD_BLOCK_RESPONSE_BY_HEIGHT_SEVERITY: u8 = 3;

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

/// Handle peer messages and return Ok(true) iff connection should be closed.
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
            {
                let databases = state.databases.lock().await;
                let own_block_info = databases
                    .latest_block
                    .get(ReadOptions::new(), DatabaseUnit())
                    .expect("Failed to read from 'latest' database");
                let block_is_new = match own_block_info {
                    None => true,
                    Some(bytes) => {
                        let own_latest_block_info: LatestBlockInfo = bincode::deserialize(&bytes)?;
                        own_latest_block_info.height < block.header.height
                    }
                };
                if block_is_new {
                    to_main_tx.send(PeerThreadToMain::NewBlock(block)).await?;
                    info!(
                        "Updated block info by block from peer. block height {}",
                        new_block_height
                    );
                } else {
                    info!("Got non-new block from peer, height: {}", new_block_height);
                }
            }
            Ok(false)
        }
        PeerMessage::BlockNotification(block_notification) => {
            debug!("Got BlockNotification");
            peer_state_info.highest_shared_block_height = block_notification.height;
            {
                let databases = state.databases.lock().await;
                let own_block_info = databases
                    .latest_block
                    .get(ReadOptions::new(), DatabaseUnit())
                    .expect("Failed to read from 'latest' database");
                let block_is_new = match own_block_info {
                    None => true,
                    Some(bytes) => {
                        let own_latest_block_info: LatestBlockInfo = bincode::deserialize(&bytes)?;
                        own_latest_block_info.height < block_notification.height
                    }
                };

                if block_is_new {
                    peer.send(PeerMessage::BlockRequestByHeight(block_notification.height))
                        .await?;
                    debug!("Sent BlockRequestByHeight to peer");

                    // The response should be caught by `PeerMessage::Block` above
                    match peer.try_next().await {
                        Ok(Some(PeerMessage::BlockResponseByHeight(Some(received_block)))) => {
                            debug!("Got BlockResponseByHeight");
                            if block_notification.height != received_block.header.height {
                                warn!("Bad BlockResponseByHeight received");
                                punish(state, peer_address, BAD_BLOCK_RESPONSE_BY_HEIGHT_SEVERITY);
                                return Ok(false);
                            }

                            // TODO: Verify received block, hash etc.
                            let block: Box<Block> = Box::new((*received_block).into());
                            match to_main_tx.send(PeerThreadToMain::NewBlock(block)).await {
                                Ok(()) => (),
                                Err(e) => panic!("{}", e),
                            };
                            debug!(
                                "Updated block info by block from peer. block height {}",
                                block_notification.height
                            );
                        }
                        _ => {
                            warn!("Got invalid block response");
                        }
                    }
                }
            }
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
                        let block_digest: RescuePrimeDigest = hash_array.into();
                        let block_response = match databases
                            .block_hash_to_block
                            .get(read_opts_block, block_digest)
                            .expect("Failed to read from database")
                        {
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

            match resp {
                PeerMessage::BlockResponseByHeight(None) => {
                    warn!("Returning bad result from BlockRequestByHeight")
                }
                _ => (),
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
                                let close_connection = handle_peer_message(peer_msg, &state, peer_address, &mut peer, &mut peer_state_info, &to_main_tx).await?;
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
