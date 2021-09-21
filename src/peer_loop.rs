use crate::model::{MainToPeerThread, PeerMessage, PeerStateData, PeerThreadToMain};
use crate::peer::Peer;
use anyhow::Result;
use futures::sink::{Sink, SinkExt};
use futures::stream::{TryStream, TryStreamExt};
use std::collections::HashMap;
use std::marker::Unpin;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::select;
use tokio::sync::{broadcast, mpsc};
use tracing::{info, warn};

/// Loop for the peer threads. Awaits either a message from the peer over TCP,
/// or a message from main over the main-to-peer-threads broadcast channel.
pub async fn peer_loop<S>(
    mut peer: S,
    mut from_main_rx: broadcast::Receiver<MainToPeerThread>,
    to_main_tx: mpsc::Sender<PeerThreadToMain>,
    peer_map: Arc<Mutex<HashMap<SocketAddr, Peer>>>,
    peer_address: &SocketAddr,
) -> Result<()>
where
    S: Sink<PeerMessage> + TryStream<Ok = PeerMessage> + Unpin,
    <S as Sink<PeerMessage>>::Error: std::error::Error + Sync + Send + 'static,
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
            Ok(peer_message) = peer.try_next() => {
                match peer_message {
                    None => {
                        info!("Peer closed connection.");
                        peer_map
                            .lock()
                            .unwrap_or_else(|e| panic!("Failed to lock peer map: {}", e))
                            .remove(peer_address)
                            .unwrap_or_else(|| panic!("Failed to remove {} from peer map. Is peer map mangled?",
                                                      peer_address));
                        break;
                    }
                    Some(PeerMessage::Bye) => {
                        info!("Got bye. Closing connection to peer");
                        peer_map
                            .lock()
                            .unwrap_or_else(|e| panic!("Failed to lock peer map: {}", e))
                            .remove(peer_address)
                            .unwrap_or_else(|| panic!("Failed to remove {} from peer map. Is peer map mangled?",
                                                       peer_address));
                        break;
                    }
                    Some(PeerMessage::PeerListRequest) => {
                        let peer_addresses = peer_map
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
                            // TODO: Add logic to fetch, verify, and store response from peer
                            info!("Sent BlockRequestByHeight to peer");
                        }
                    }
                    Some(msg) => {
                        warn!("Uninplemented peer message received. Got: {:?}", msg);
                    }
                }
            }
            Ok(main_msg) = from_main_rx.recv() => {
                // info!("Got message from main: {:?}", main_msg);
                match main_msg {
                    // If this client found a block, we need to share it ASAP.
                    MainToPeerThread::BlockFromMiner(block) => {
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
