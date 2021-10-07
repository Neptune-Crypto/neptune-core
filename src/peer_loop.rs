use crate::database::block_hash_to_block::BlockHash;
use crate::database::block_height_to_hash::BlockHeight;
use crate::model::{MainToPeerThread, PeerMessage, PeerStateData, PeerThreadToMain, State};
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
use tracing::{info, warn};

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
        highest_shared_block_height: 0,
    };

    // TODO: THV: own_state_info should be shared among all threads, I think.
    let mut own_state_info = PeerStateData {
        highest_shared_block_height: 0,
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
                            Some(PeerMessage::Bye) => {
                                info!("Got bye. Closing connection to peer");
                                state.peer_map
                                    .lock()
                                    .unwrap_or_else(|e| panic!("Failed to lock peer map: {}", e))
                                    .remove(peer_address)
                                    .unwrap_or_else(|| panic!("Failed to remove {} from peer map. Is peer map mangled?",
                                                              peer_address));
                                break;
                            }
                            Some(PeerMessage::PeerListRequest) => {
                                let peer_addresses = state.peer_map
                                    .lock()
                                    .unwrap_or_else(|e| panic!("Failed to lock peer map: {}", e))
                                    .keys()
                                    .cloned()
                                    .collect();
                                peer.send(PeerMessage::PeerListResponse(peer_addresses)).await?;
                            }
                            Some(PeerMessage::Block(block)) => {
                                info!("Got new block from peer, block height {}", block.height);
                                let new_block_height = block.height;
                                peer_state_info.highest_shared_block_height = new_block_height;
                                // TODO: All validation of block, increase ban score if block is bad
                                if own_state_info.highest_shared_block_height < new_block_height {
                                    own_state_info.highest_shared_block_height = new_block_height;
                                    // TODO: The following line *has* produced stack overflows on a lightweight
                                    // computer. Why?
                                    to_main_tx.send(PeerThreadToMain::NewBlock(block)).await?;
                                    info!("Updated block info by block from peer. block height {}", new_block_height);
                                }
                            }
                            Some(PeerMessage::BlockNotification(block_notification)) => {
                                peer_state_info.highest_shared_block_height = block_notification.height;
                                if own_state_info.highest_shared_block_height < block_notification.height {
                                    peer.send(PeerMessage::BlockRequestByHeight(block_notification.height)).await?;

                                    // The response should be caught by `PeerMessage::Block` above

                                    // TODO: Add logic to fetch, verify, and store response from peer
                                    info!("Sent BlockRequestByHeight to peer");
                                }
                            }
                            Some(PeerMessage::BlockRequestByHeight(block_height)) => {
                                {
                                    let db = state.databases.lock().unwrap_or_else(|e| panic!("Failed to lock database ARC: {}", e));
                                    let read_opts_hash = ReadOptions::new();
                                    let hash_res = db.block_height_to_hash.get(read_opts_hash, BlockHeight::from(block_height)).expect("Failed to read from database");
                                    let _resp = match hash_res {
                                        None => PeerMessage::BlockResponseByHeight(None),
                                        Some(hash) => {
                                            let read_opts_block = ReadOptions::new();
                                            let hash_array: [u8; 32] = hash.try_into().unwrap_or_else(|v: Vec<u8>| panic!("Expected a Vec of length {} but it was {}", 32, v.len()));
                                            let block_response = match db.block_hash_to_block.get(read_opts_block, BlockHash::from(hash_array)).expect("Failed to read from database") {
                                                None => panic!("Failed to find block with hash {:?}", hash_array),
                                                Some(block_bytes) => PeerMessage::BlockResponseByHeight(bincode::deserialize(&block_bytes)?),
                                            };
                                            block_response
                                        }
                                    };
                                }
                                // TODO: Fetch block from database and send this to peer
                                // also update peer_info with this block height
                            }
                            Some(msg) => {
                                warn!("Uninplemented peer message received. Got: {:?}", msg);
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
            Ok(main_msg) = from_main_rx.recv() => {
                match main_msg {
                    // Handle the case where a block was found in this program instance
                    MainToPeerThread::BlockFromMiner(block) => {
                        // If this client found a block, we need to share it immediately
                        // to reduce the risk that someone else finds another one and shares
                        // it faster.
                        info!("peer_loop got NewBlockFromMiner message from main");
                        let new_block_height = block.height;
                        if new_block_height > own_state_info.highest_shared_block_height {
                            peer.send(PeerMessage::Block(block)).await?;
                            peer_state_info.highest_shared_block_height = new_block_height;
                            own_state_info.highest_shared_block_height = new_block_height;
                        }
                    }
                    MainToPeerThread::Block(block) => {
                        info!("peer_loop got NewBlock message from main");
                        let new_block_height = block.height;
                        if new_block_height > peer_state_info.highest_shared_block_height {
                            peer_state_info.highest_shared_block_height = new_block_height;
                            peer.send(PeerMessage::BlockNotification((*block).into())).await?;
                        }
                    }
                    MainToPeerThread::Transaction(nt) => {
                        info!("peer_loop got NetTransaction message from main");
                        peer.send(PeerMessage::NewTransaction(nt)).await?;
                    }
                }
            }
        }
    }

    Ok(())
}
