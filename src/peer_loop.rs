use crate::database::leveldb::LevelDB;
use crate::models::blockchain::block::block_height::BlockHeight;
use crate::models::blockchain::block::transfer_block::TransferBlock;
use crate::models::blockchain::block::Block;
use crate::models::channel::{MainToPeerThread, PeerThreadToMain};
use crate::models::peer::{
    HandshakeData, PeerInfo, PeerMessage, PeerSanctionReason, PeerStanding, PeerState,
};
use crate::models::state::{State, SyncState};
use crate::models::utils::BoolFuture;
use anyhow::{bail, Result};
use core::time;
use futures::future::MaybeDone;
use futures::sink::{Sink, SinkExt};
use futures::stream::{TryStream, TryStreamExt};
use futures::{future, stream};
use futures::{pin_mut, Future};
use std::marker::Unpin;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::thread;
use std::time::SystemTime;
use tokio::select;
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, error, info, warn};

const STANDARD_BLOCK_BATCH_SIZE: usize = 50;

pub fn punish(state: &State, peer_address: &SocketAddr, reason: PeerSanctionReason) -> Result<()> {
    warn!("Sanctioning peer {} for {:?}", peer_address.ip(), reason);
    let mut peers = state
        .peer_map
        .lock()
        .unwrap_or_else(|e| panic!("Failed to lock peer map: {}", e));
    let new_standing: &mut u16 = &mut 0;
    peers
        .entry(*peer_address)
        .and_modify(|p| *new_standing = p.standing.sanction(reason));

    if *new_standing > state.cli_args.peer_tolerance {
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
                    < state.cli_args.max_number_of_blocks_before_syncing
        {
            peer_state.fork_reconciliation_blocks.push(*received_block);
        } else {
            // Blocks received out of order. Or more than allowed received without
            // going into sync mode. Give up on block resolution attempt.
            punish(
                state,
                peer_address,
                PeerSanctionReason::ForkResolutionError((
                    received_block.header.height,
                    peer_state.fork_reconciliation_blocks.len() as u16,
                    received_block.hash,
                )),
            )?;
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
                    "Got non-canonical block from peer, height: {}, PoW family: {:?}",
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
                let mut databases = state.block_databases.lock().await;
                let hash_res = databases.block_height_to_hash.get(block_height);
                match hash_res {
                    None => {
                        warn!("Got block request by height for unknown block");
                        // TODO: Consider punishing here
                        return Ok(false);
                    }
                    Some(digest) => {
                        // let hash_array: [u8; RESCUE_PRIME_DIGEST_SIZE_IN_BYTES] =
                        // digest.try_into().unwrap_or_else(|v: Vec<u8>| {
                        // panic!(
                        // "Expected a Vec of length {} but it was {}",
                        // RESCUE_PRIME_DIGEST_SIZE_IN_BYTES,
                        // v.len()
                        // )
                        // });

                        block_response = match databases.block_hash_to_block.get(digest) {
                            // I think it makes sense to panic here since we found the block in the height to digest
                            // database. So it should be in the hash to block database.
                            None => panic!("Failed to find block with hash {:?}", digest),
                            Some(block) => PeerMessage::Block(Box::new(block.into())),
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

async fn request_a_batch_of_blocks<S>(peer: &mut S, state: &State) -> Result<()>
where
    S: Sink<PeerMessage> + TryStream<Ok = PeerMessage> + Unpin,
    <S as Sink<PeerMessage>>::Error: std::error::Error + Sync + Send + 'static,
    <S as TryStream>::Error: std::error::Error,
{
    // I'm afraid locking the block header value in state could lead to a deadlock
    // as we're already holding a lock on the sync value in state. Therefore we instead
    // request a lock on this in a non-blocking manner. If we can't get that lock we just
    // exit this function and try again later.
    let latest_bh: BlockHeight = match state.latest_block_header.try_lock() {
        Ok(lock) => lock.height,
        Err(_) => return Ok(()),
    };
    let request_batch_size = std::cmp::min(
        STANDARD_BLOCK_BATCH_SIZE,
        state.cli_args.max_number_of_blocks_before_syncing,
    );
    peer.send(PeerMessage::BlockRequestBatch(
        latest_bh,
        request_batch_size,
    ))
    .await?;

    Ok(())
}

/// Loop for the peer threads. Awaits either a message from the peer over TCP,
/// or a message from main over the main-to-peer-threads broadcast channel.
pub async fn peer_loop<S>(
    mut peer: S,
    mut from_main_rx: broadcast::Receiver<MainToPeerThread>,
    to_main_tx: mpsc::Sender<PeerThreadToMain>,
    state: &State,
    peer_address: &SocketAddr,
    peer_state_info: &mut PeerState,
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
                                let close_connection: bool = match handle_peer_message(peer_msg, &state, peer_address, &mut peer, peer_state_info, &to_main_tx).await {
                                    Ok(close) => close,
                                    Err(err) => {
                                        warn!("{}. Closing connection.", err);
                                        true
                                    }
                                };

                                if close_connection {
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
                match main_msg_res {
                    Ok(main_msg) => handle_main_thread_message(main_msg, &mut peer, peer_state_info).await?,
                    Err(e) => panic!("Failed to read from main loop: {}", e),
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
pub async fn peer_loop_wrapper<S>(
    peer: S,
    from_main_rx: broadcast::Receiver<MainToPeerThread>,
    to_main_tx: mpsc::Sender<PeerThreadToMain>,
    state: State,
    peer_address: SocketAddr,
    peer_handshake_data: HandshakeData,
) -> Result<()>
where
    S: Sink<PeerMessage> + TryStream<Ok = PeerMessage> + Unpin,
    <S as Sink<PeerMessage>>::Error: std::error::Error + Sync + Send + 'static,
    <S as TryStream>::Error: std::error::Error,
{
    // Check if peer standing exists in database, return default if it does not.
    let standing: PeerStanding = state
        .peer_databases
        .lock()
        .await
        .peer_standings
        .get(peer_address.ip())
        .unwrap_or_else(PeerStanding::default);

    // Add peer to peer map
    let new_peer = PeerInfo {
        address: peer_address,
        inbound: false,
        instance_id: peer_handshake_data.instance_id,
        last_seen: SystemTime::now(),
        standing,
        version: peer_handshake_data.version,
    };
    state
        .peer_map
        .lock()
        .unwrap_or_else(|e| panic!("Failed to lock peer map: {}", e))
        .entry(peer_address)
        .or_insert(new_peer);

    // TODO: Send message to main about peers claimed max block height
    // This message is used to determine if we are to enter synchronization mode.

    let mut peer_state = PeerState::new(peer_handshake_data.latest_block_info.height);
    let _res = peer_loop(
        peer,
        from_main_rx,
        to_main_tx,
        &state,
        &peer_address,
        &mut peer_state,
    )
    .await;

    // TODO: Send message to main removing claimed max block height in case we are
    // syncing and we banned the peer for sending us bad blocks.
    let peer_info_writeback = state
        .peer_map
        .lock()
        .unwrap_or_else(|e| panic!("Failed to lock peer map: {}", e))
        .remove(&peer_address)
        .unwrap_or_else(|| {
            panic!(
                "Failed to remove {} from peer map. Is peer map mangled?",
                peer_address
            )
        });
    state
        .write_peer_standing_on_increase(peer_address.ip(), peer_info_writeback.standing)
        .await;

    Ok(())
}

#[cfg(test)]
mod peer_loop_tests {
    use std::sync::Arc;

    use anyhow::{bail, Result};
    use clap::Parser;
    use tokio::sync::{
        broadcast::{self, error::TryRecvError},
        mpsc,
    };
    use tracing_test::traced_test;
    use twenty_first::amount::u32s::U32s;

    use crate::{
        config_models::{cli_args, network::Network},
        database::leveldb::LevelDB,
        models::{
            blockchain::{
                block::{block_header::TARGET_DIFFICULTY_U32_SIZE, Block},
                digest::Hashable,
            },
            channel::{MainToPeerThread, PeerThreadToMain},
            peer::{PeerMessage, PeerSanctionReason, PeerState},
        },
        peer_loop,
        tests::shared::{get_genesis_setup, make_mock_block, Action, Mock},
    };

    #[traced_test]
    #[tokio::test]
    async fn test_peer_loop_bye() -> Result<()> {
        let mock = Mock::new(vec![Action::Read(PeerMessage::Bye)]);

        let (peer_broadcast_tx, mut _from_main_rx1) = broadcast::channel::<MainToPeerThread>(1);
        let (_to_main_tx, mut _to_main_rx1) = mpsc::channel::<PeerThreadToMain>(1);
        let (
            _peer_broadcast_tx,
            _from_main_rx_clone,
            to_main_tx,
            _to_main_rx1,
            state,
            peer_map,
            hsd,
        ) = get_genesis_setup(Network::Main, 1)?;

        let peer_address = peer_map.lock().unwrap().values().collect::<Vec<_>>()[0].address;
        let from_main_rx_clone = peer_broadcast_tx.subscribe();
        peer_loop::peer_loop_wrapper(
            mock,
            from_main_rx_clone,
            to_main_tx,
            state,
            peer_address,
            hsd,
        )
        .await?;

        if !peer_map.lock().unwrap().is_empty() {
            bail!("peer map must be empty after closing connection gracefully");
        }

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn test_peer_loop_peer_list() -> Result<()> {
        let (
            _peer_broadcast_tx,
            _from_main_rx_clone,
            _to_main_tx,
            _to_main_rx1,
            state,
            peer_map,
            hsd,
        ) = get_genesis_setup(Network::Main, 1)?;
        let peer_address = peer_map.lock().unwrap().values().collect::<Vec<_>>()[0].address;

        let mock = Mock::new(vec![
            Action::Read(PeerMessage::PeerListRequest),
            Action::Write(PeerMessage::PeerListResponse(vec![peer_address])),
            Action::Read(PeerMessage::Bye),
        ]);

        let (peer_broadcast_tx, mut _from_main_rx1) = broadcast::channel::<MainToPeerThread>(1);
        let (to_main_tx, mut _to_main_rx1) = mpsc::channel::<PeerThreadToMain>(1);
        let from_main_rx_clone = peer_broadcast_tx.subscribe();

        peer_loop::peer_loop_wrapper(
            mock,
            from_main_rx_clone,
            to_main_tx,
            state,
            peer_address,
            hsd,
        )
        .await?;

        if !peer_map.lock().unwrap().is_empty() {
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
        let (
            _peer_broadcast_tx,
            from_main_rx_clone,
            to_main_tx,
            mut to_main_rx1,
            mut state,
            peer_map,
            hsd,
        ) = get_genesis_setup(Network::Main, 1)?;
        let peer_address = peer_map.lock().unwrap().values().collect::<Vec<_>>()[0].address;

        // Although the database is empty, `get_latest_block` still returns the genesis block,
        // since that block is hardcoded.
        let mut different_genesis_block: Block = state.get_latest_block().await;
        different_genesis_block.header.nonce[2].increment();
        different_genesis_block.hash = different_genesis_block.header.hash();
        let block_1_with_different_genesis = make_mock_block(different_genesis_block, None);
        let mock = Mock::new(vec![Action::Read(PeerMessage::Block(Box::new(
            block_1_with_different_genesis.into(),
        )))]);

        peer_loop::peer_loop_wrapper(
            mock,
            from_main_rx_clone,
            to_main_tx.clone(),
            state.clone(),
            peer_address,
            hsd,
        )
        .await?;

        // Verify that no message was sent to main loop
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
        let (
            _peer_broadcast_tx,
            _from_main_rx_clone,
            _to_main_tx,
            _to_main_rx1,
            mut state,
            peer_map,
            hsd,
        ) = get_genesis_setup(Network::Main, 1)?;
        let peer_address = peer_map.lock().unwrap().values().collect::<Vec<_>>()[0].address;
        let genesis_block: Block = state.get_latest_block().await;

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

        let (peer_broadcast_tx, mut _from_main_rx1) = broadcast::channel::<MainToPeerThread>(1);
        let (to_main_tx, mut to_main_rx1) = mpsc::channel::<PeerThreadToMain>(1);
        let from_main_rx_clone = peer_broadcast_tx.subscribe();

        peer_loop::peer_loop_wrapper(
            mock,
            from_main_rx_clone,
            to_main_tx.clone(),
            state.clone(),
            peer_address,
            hsd,
        )
        .await?;

        // Verify that no message was sent to main loop
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
        let (
            _peer_broadcast_tx,
            _from_main_rx_clone,
            _to_main_tx,
            _to_main_rx1,
            mut state,
            peer_map,
            hsd,
        ) = get_genesis_setup(Network::Main, 1)?;
        let peer_address = peer_map.lock().unwrap().values().collect::<Vec<_>>()[0].address;
        let genesis_block: Block = state.get_latest_block().await;

        let block_1 = make_mock_block(genesis_block, None);
        state.update_latest_block(Box::new(block_1.clone())).await?;

        let mock = Mock::new(vec![
            Action::Read(PeerMessage::Block(Box::new(block_1.into()))),
            Action::Read(PeerMessage::Bye),
        ]);

        let (peer_broadcast_tx, mut _from_main_rx1) = broadcast::channel::<MainToPeerThread>(1);
        let (to_main_tx, mut to_main_rx1) = mpsc::channel::<PeerThreadToMain>(1);
        let from_main_rx_clone = peer_broadcast_tx.subscribe();

        peer_loop::peer_loop_wrapper(
            mock,
            from_main_rx_clone,
            to_main_tx.clone(),
            state,
            peer_address,
            hsd,
        )
        .await?;

        // Verify that no message was sent to main loop
        match to_main_rx1.try_recv() {
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => (),
            _ => bail!("Block notification must not be sent for block with invalid PoW"),
        };
        drop(to_main_tx);

        if !peer_map.lock().unwrap().is_empty() {
            bail!("peer map must be empty after closing connection gracefully");
        }

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn test_peer_loop_receival_of_first_block() -> Result<()> {
        // Scenario: client only knows genesis block. Then receives block 1.
        let (
            _peer_broadcast_tx,
            from_main_rx_clone,
            to_main_tx,
            mut to_main_rx1,
            mut state,
            peer_map,
            hsd,
        ) = get_genesis_setup(Network::Main, 1)?;
        let peer_address = peer_map.lock().unwrap().values().collect::<Vec<_>>()[0].address;
        let genesis_block: Block = state.get_latest_block().await;

        let mock = Mock::new(vec![
            Action::Read(PeerMessage::Block(Box::new(
                make_mock_block(genesis_block, None).into(),
            ))),
            Action::Read(PeerMessage::Bye),
        ]);

        peer_loop::peer_loop_wrapper(
            mock,
            from_main_rx_clone,
            to_main_tx.clone(),
            state,
            peer_address,
            hsd,
        )
        .await?;

        // Verify that a message was sent to `main_loop`?
        match to_main_rx1.recv().await {
            Some(PeerThreadToMain::NewBlocks(_block)) => (),
            _ => bail!("Did not find msg sent to main thread"),
        };

        if !peer_map.lock().unwrap().is_empty() {
            bail!("peer map must be empty after closing connection gracefully");
        }

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn test_peer_loop_receival_of_second_block_no_blocks_in_db() -> Result<()> {
        // In this scenario, the client only knows the genesis block (block 0) and then
        // receives block 2, meaning that block 1 will have to be requested.
        let (
            _peer_broadcast_tx,
            from_main_rx_clone,
            to_main_tx,
            mut to_main_rx1,
            mut state,
            peer_map,
            hsd,
        ) = get_genesis_setup(Network::Main, 1)?;
        let peer_address = peer_map.lock().unwrap().values().collect::<Vec<_>>()[0].address;
        let genesis_block: Block = state.get_latest_block().await;
        let block_1 = make_mock_block(genesis_block.clone(), None);
        let block_2 = make_mock_block(block_1.clone(), None);

        let mock = Mock::new(vec![
            Action::Read(PeerMessage::Block(Box::new(block_2.clone().into()))),
            Action::Write(PeerMessage::BlockRequestByHash(block_1.hash)),
            Action::Read(PeerMessage::Block(Box::new(block_1.clone().into()))),
            Action::Read(PeerMessage::Bye),
        ]);

        peer_loop::peer_loop_wrapper(
            mock,
            from_main_rx_clone,
            to_main_tx,
            state,
            peer_address,
            hsd,
        )
        .await?;

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

        if !peer_map.lock().unwrap().is_empty() {
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
        let (
            _peer_broadcast_tx,
            from_main_rx_clone,
            to_main_tx,
            mut to_main_rx1,
            mut state,
            peer_map,
            hsd,
        ) = get_genesis_setup(Network::Main, 1)?;

        // Restrict max number of blocks held in memory to 2.
        let mut a = cli_args::Args::from_iter::<Vec<String>, _>(vec![]);
        a.max_number_of_blocks_before_syncing = 2;
        state.cli_args = Arc::new(a);

        let peer_address = peer_map.lock().unwrap().values().collect::<Vec<_>>()[0].address;
        let genesis_block: Block = state.get_latest_block().await;
        let block_1 = make_mock_block(genesis_block.clone(), None);
        let block_2 = make_mock_block(block_1.clone(), None);
        let block_3 = make_mock_block(block_2.clone(), None);
        let block_4 = make_mock_block(block_3.clone(), None);
        state.update_latest_block(Box::new(block_1)).await?;

        let mock = Mock::new(vec![
            Action::Read(PeerMessage::Block(Box::new(block_4.clone().into()))),
            Action::Write(PeerMessage::BlockRequestByHash(block_3.hash)),
            Action::Read(PeerMessage::Block(Box::new(block_3.clone().into()))),
            Action::Read(PeerMessage::Bye),
        ]);

        peer_loop::peer_loop_wrapper(
            mock,
            from_main_rx_clone,
            to_main_tx.clone(),
            state.clone(),
            peer_address,
            hsd,
        )
        .await?;

        // Verify that nothing is sent to main loop.
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
        let (
            _peer_broadcast_tx,
            from_main_rx_clone,
            to_main_tx,
            mut to_main_rx1,
            mut state,
            peer_map,
            hsd,
        ) = get_genesis_setup(Network::Main, 1)?;
        let peer_address = peer_map.lock().unwrap().values().collect::<Vec<_>>()[0].address;
        let genesis_block: Block = state.get_latest_block().await;
        let block_1 = make_mock_block(genesis_block.clone(), None);
        let block_2 = make_mock_block(block_1.clone(), None);
        let block_3 = make_mock_block(block_2.clone(), None);
        let block_4 = make_mock_block(block_3.clone(), None);
        state.update_latest_block(Box::new(block_1)).await?;

        let mock = Mock::new(vec![
            Action::Read(PeerMessage::Block(Box::new(block_4.clone().into()))),
            Action::Write(PeerMessage::BlockRequestByHash(block_3.hash)),
            Action::Read(PeerMessage::Block(Box::new(block_3.clone().into()))),
            Action::Write(PeerMessage::BlockRequestByHash(block_2.hash)),
            Action::Read(PeerMessage::Block(Box::new(block_2.clone().into()))),
            Action::Read(PeerMessage::Bye),
        ]);

        peer_loop::peer_loop_wrapper(
            mock,
            from_main_rx_clone,
            to_main_tx,
            state,
            peer_address,
            hsd,
        )
        .await?;

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

        if !peer_map.lock().unwrap().is_empty() {
            bail!("peer map must be empty after closing connection gracefully");
        }

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn test_peer_loop_receival_of_third_block_no_blocks_in_db() -> Result<()> {
        // In this scenario, the client only knows the genesis block (block 0) and then
        // receives block 3, meaning that block 2 and 1 will have to be requested.
        let (
            _peer_broadcast_tx,
            from_main_rx_clone,
            to_main_tx,
            mut to_main_rx1,
            mut state,
            peer_map,
            hsd,
        ) = get_genesis_setup(Network::Main, 1)?;
        let peer_address = peer_map.lock().unwrap().values().collect::<Vec<_>>()[0].address;
        let genesis_block: Block = state.get_latest_block().await;
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

        peer_loop::peer_loop_wrapper(
            mock,
            from_main_rx_clone,
            to_main_tx,
            state,
            peer_address,
            hsd,
        )
        .await?;

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

        if !peer_map.lock().unwrap().is_empty() {
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
        let (
            _peer_broadcast_tx,
            from_main_rx_clone,
            to_main_tx,
            mut to_main_rx1,
            mut state,
            peer_map,
            hsd,
        ) = get_genesis_setup(Network::Main, 1)?;
        let peer_address = peer_map.lock().unwrap().values().collect::<Vec<_>>()[0].address;
        let genesis_block: Block = state.get_latest_block().await;
        let block_1 = make_mock_block(genesis_block.clone(), None);
        let block_2 = make_mock_block(block_1.clone(), None);
        let block_3 = make_mock_block(block_2.clone(), None);
        let block_4 = make_mock_block(block_3.clone(), None);
        let block_5 = make_mock_block(block_4.clone(), None);
        state.update_latest_block(Box::new(block_1)).await?;

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

        peer_loop::peer_loop_wrapper(
            mock,
            from_main_rx_clone,
            to_main_tx,
            state,
            peer_address,
            hsd,
        )
        .await?;

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

        if !peer_map.lock().unwrap().is_empty() {
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
        let (
            _peer_broadcast_tx,
            from_main_rx_clone,
            to_main_tx,
            mut to_main_rx1,
            mut state,
            peer_map,
            hsd,
        ) = get_genesis_setup(Network::Main, 1)?;
        let peer_address = peer_map.lock().unwrap().values().collect::<Vec<_>>()[0].address;
        let genesis_block: Block = state.get_latest_block().await;
        let block_1 = make_mock_block(genesis_block.clone(), None);
        let block_2 = make_mock_block(block_1.clone(), None);
        let block_3 = make_mock_block(block_2.clone(), None);
        let block_4 = make_mock_block(block_3.clone(), None);
        state.update_latest_block(Box::new(block_1)).await?;

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
            Action::Write(PeerMessage::PeerListResponse(vec![peer_address])),
            //
            // Complete the block reconciliation process by requesting the last block
            // in this process, to get back to a mutually known block.
            Action::Read(PeerMessage::Block(Box::new(block_2.clone().into()))),
            Action::Read(PeerMessage::Bye),
        ]);

        peer_loop::peer_loop_wrapper(
            mock,
            from_main_rx_clone,
            to_main_tx,
            state,
            peer_address,
            hsd,
        )
        .await?;

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

        if !peer_map.lock().unwrap().is_empty() {
            bail!("peer map must be empty after closing connection gracefully");
        }

        Ok(())
    }
}
