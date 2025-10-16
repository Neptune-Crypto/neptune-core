//! P2P protocol message handler
//!
//! This module handles incoming P2P protocol messages.
//!
//! MIGRATED FROM: src/application/loops/peer_loop.rs:552-1857
//! This code was transplanted from the peer loop's message handling logic
//! to provide modular message processing with DDoS protection.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Result;
use futures::{Sink, SinkExt, TryStream};
use tokio::sync::{broadcast, mpsc};

use crate::application::loops::channel::{MainToPeerTask, PeerTaskToMain};
use crate::p2p::config::ProtocolConfig;
use crate::p2p::state::P2PStateManager;
use crate::protocol::peer::peer_block_notifications::PeerBlockNotification;
use crate::protocol::peer::transaction_notification::TransactionNotification;
use crate::protocol::peer::PeerMessage;
use crate::state::GlobalStateLock;

/// P2P protocol message handler
#[derive(Debug)]
pub struct MessageHandler {
    /// Handler configuration
    config: HandlerConfig,
    /// P2P state manager for DDoS protection
    state_manager: P2PStateManager,
    /// Global state lock
    global_state: GlobalStateLock,
    /// Main to peer broadcast channel
    main_to_peer_broadcast_tx: broadcast::Sender<MainToPeerTask>,
    /// Peer task to main channel
    peer_task_to_main_tx: mpsc::Sender<PeerTaskToMain>,
}

/// Handler configuration
#[derive(Debug, Clone)]
pub struct HandlerConfig {
    /// Maximum message processing time
    pub max_processing_time: Duration,
    /// Whether to enable message validation
    pub enable_validation: bool,
    /// Whether to enable message logging
    pub enable_logging: bool,
    /// Whether to enable DDoS protection
    pub enable_ddos_protection: bool,
}

impl Default for HandlerConfig {
    fn default() -> Self {
        Self {
            max_processing_time: Duration::from_secs(30),
            enable_validation: true,
            enable_logging: true,
            enable_ddos_protection: true,
        }
    }
}

impl MessageHandler {
    /// Create new message handler
    pub fn new(
        config: HandlerConfig,
        state_manager: P2PStateManager,
        global_state: GlobalStateLock,
        main_to_peer_broadcast_tx: broadcast::Sender<MainToPeerTask>,
        peer_task_to_main_tx: mpsc::Sender<PeerTaskToMain>,
    ) -> Self {
        Self {
            config,
            state_manager,
            global_state,
            main_to_peer_broadcast_tx,
            peer_task_to_main_tx,
        }
    }

    /// Send message to main loop
    async fn send_to_main(&self, msg: PeerTaskToMain) -> Result<()> {
        self.peer_task_to_main_tx
            .send(msg)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send message to main loop: {}", e))
    }

    /// Notify main loop that peer should be removed
    pub async fn notify_peer_disconnect(&self, peer_address: SocketAddr) -> Result<()> {
        self.send_to_main(PeerTaskToMain::RemovePeerMaxBlockHeight(peer_address))
            .await
    }

    /// Handle incoming message with enhanced DDoS protection
    ///
    /// MIGRATED FROM: src/application/loops/peer_loop.rs:552-1857
    /// This replaces the handle_peer_message function with modular message handling
    pub async fn handle_message<S>(
        &mut self,
        peer_address: SocketAddr,
        message: PeerMessage,
        peer: &mut S,
    ) -> Result<bool>
    where
        S: Sink<PeerMessage> + TryStream<Ok = PeerMessage> + Unpin,
        <S as Sink<PeerMessage>>::Error: std::error::Error + Sync + Send + 'static,
        <S as TryStream>::Error: std::error::Error,
    {
        if self.config.enable_logging {
            tracing::debug!("Received {} from peer {}", message.get_type(), peer_address);
        }

        // DDoS protection: Check message rate limiting
        if self.config.enable_ddos_protection {
            if self
                .state_manager
                .is_message_rate_limited(peer_address.ip())
            {
                tracing::warn!(
                    "Message from {} rate limited by DDoS protection",
                    peer_address
                );
                return Ok(true); // Close connection
            }
        }

        // Check if we should ignore this message based on sync state
        let (syncing, frozen) = self
            .global_state
            .lock(|s| (s.net.sync_anchor.is_some(), s.net.freeze))
            .await;
        let message_type = message.get_type();

        if syncing && message.ignore_during_sync() {
            tracing::debug!("Ignoring {message_type} message when syncing, from {peer_address}",);
            return Ok(false); // Keep connection alive
        }

        if message.ignore_when_not_sync() && !syncing {
            tracing::debug!(
                "Ignoring {message_type} message when not syncing, from {peer_address}",
            );
            return Ok(false); // Keep connection alive
        }

        if frozen && message.ignore_on_freeze() {
            tracing::debug!("Ignoring message because state updates have been paused.");
            return Ok(false); // Keep connection alive
        }

        // Handle the message based on type
        match message {
            PeerMessage::Bye => {
                // MIGRATED FROM: peer_loop.rs:569-574
                tracing::info!("Got bye. Closing connection to peer");
                Ok(true) // Close connection
            }
            PeerMessage::PeerListRequest => self.handle_peer_list_request(peer_address, peer).await,
            PeerMessage::PeerListResponse(peers) => {
                let peer_addresses: Vec<SocketAddr> =
                    peers.into_iter().map(|(addr, _)| addr).collect();
                self.handle_peer_list_response(peer_address, peer_addresses)
                    .await
            }
            PeerMessage::Block(transfer_block) => {
                // Convert TransferBlock to Block
                use crate::protocol::peer::transfer_block::TransferBlock;
                let block: Result<crate::protocol::consensus::block::Block, _> =
                    (*transfer_block).try_into();
                match block {
                    Ok(b) => self.handle_block(peer_address, b, peer).await,
                    Err(e) => {
                        tracing::warn!("Failed to convert TransferBlock: {:?}", e);
                        Ok(false) // Keep connection alive
                    }
                }
            }
            PeerMessage::BlockNotification(notification) => {
                self.handle_block_notification(peer_address, notification, peer)
                    .await
            }
            PeerMessage::Transaction(transfer_transaction) => {
                // Convert TransferTransaction to Transaction
                use crate::protocol::peer::transfer_transaction::TransferTransaction;
                let transaction: Result<crate::protocol::consensus::transaction::Transaction, _> =
                    (*transfer_transaction).try_into();
                match transaction {
                    Ok(tx) => self.handle_transaction(peer_address, tx, peer).await,
                    Err(e) => {
                        tracing::warn!("Failed to convert TransferTransaction: {:?}", e);
                        Ok(false) // Keep connection alive
                    }
                }
            }
            PeerMessage::TransactionNotification(notification) => {
                self.handle_transaction_notification(peer_address, notification, peer)
                    .await
            }
            PeerMessage::Handshake { .. } => {
                // Handshake messages are handled during connection establishment
                tracing::debug!("Received handshake message from {}", peer_address);
                Ok(false) // Keep connection alive
            }
            PeerMessage::ConnectionStatus(_) => {
                // Connection status messages are handled during connection establishment
                tracing::debug!("Received connection status from {}", peer_address);
                Ok(false) // Keep connection alive
            }
            _ => {
                tracing::debug!(
                    "Unhandled message type from {}: {:?}",
                    peer_address,
                    message.get_type()
                );
                Ok(false) // Keep connection alive
            }
        }
    }

    /// Handle peer list request
    ///
    /// MIGRATED FROM: peer_loop.rs:579-613
    async fn handle_peer_list_request<S>(
        &mut self,
        peer_address: SocketAddr,
        peer: &mut S,
    ) -> Result<bool>
    where
        S: Sink<PeerMessage> + TryStream<Ok = PeerMessage> + Unpin,
        <S as Sink<PeerMessage>>::Error: std::error::Error + Sync + Send + 'static,
    {
        tracing::debug!("Handling peer list request from {}", peer_address);

        const MAX_PEER_LIST_LENGTH: usize = 50;

        // Get peer list from global state
        // We are interested in the address on which peers accept incoming connections,
        // not the address on which they are connected to us
        let mut peer_info: Vec<(SocketAddr, u128)> = {
            let state = self.global_state.lock_guard().await;
            state
                .net
                .peer_map
                .values()
                .filter(|peer_info| {
                    peer_info.listen_address().is_some() && !peer_info.is_local_connection()
                })
                .take(MAX_PEER_LIST_LENGTH) // limit length of response
                .map(|peer_info| {
                    (
                        // unwrap is safe because of above filter
                        peer_info.listen_address().unwrap(),
                        peer_info.instance_id(),
                    )
                })
                .collect()
        };

        // Sort the returned list for deterministic ordering
        peer_info.sort_by_cached_key(|x| x.0);

        tracing::debug!("Responding with {} peers", peer_info.len());
        peer.send(PeerMessage::PeerListResponse(peer_info))
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send peer list response: {}", e))?;

        Ok(false) // Keep connection alive
    }

    /// Handle peer list response
    ///
    /// MIGRATED FROM: peer_loop.rs:615-636
    async fn handle_peer_list_response(
        &mut self,
        peer_address: SocketAddr,
        peers: Vec<SocketAddr>,
    ) -> Result<bool> {
        tracing::debug!(
            "Handling peer list response from {} with {} peers",
            peer_address,
            peers.len()
        );

        // Filter out local IPs and convert to the expected format
        let filtered_peers: Vec<(SocketAddr, u128)> = peers
            .into_iter()
            .filter(|addr| !crate::protocol::peer::peer_info::PeerInfo::ip_is_local(addr.ip()))
            .map(|addr| (addr, 0u128)) // Distance will be set by main loop
            .collect();

        // Send peer discovery answer to main loop
        // MIGRATED FROM: peer_loop.rs:628-635
        self.send_to_main(PeerTaskToMain::PeerDiscoveryAnswer((
            filtered_peers,
            peer_address,
            1, // Distance is always 1 from direct peer
        )))
        .await?;

        Ok(false) // Keep connection alive
    }

    /// Handle block message
    ///
    /// MIGRATED FROM: peer_loop.rs:611-650
    async fn handle_block<S>(
        &mut self,
        peer_address: SocketAddr,
        block: crate::protocol::consensus::block::Block,
        peer: &mut S,
    ) -> Result<bool>
    where
        S: Sink<PeerMessage> + TryStream<Ok = PeerMessage> + Unpin,
        <S as Sink<PeerMessage>>::Error: std::error::Error + Sync + Send + 'static,
    {
        tracing::debug!(
            "Handling full block from {} at height {}",
            peer_address,
            block.kernel.header.height
        );

        // Send block(s) to main loop for validation and chain update
        // MIGRATED FROM: peer_loop.rs:611-650
        // In the original code, blocks could be sent individually or in batches
        // For now, we send as a single-block vec
        self.send_to_main(PeerTaskToMain::NewBlocks(vec![block]))
            .await?;

        tracing::debug!("Sent block to main loop from {}", peer_address);

        Ok(false) // Keep connection alive
    }

    /// Handle block notification
    ///
    /// MIGRATED FROM: peer_loop.rs:653-735
    async fn handle_block_notification<S>(
        &mut self,
        peer_address: SocketAddr,
        notification: PeerBlockNotification,
        peer: &mut S,
    ) -> Result<bool>
    where
        S: Sink<PeerMessage> + TryStream<Ok = PeerMessage> + Unpin,
        <S as Sink<PeerMessage>>::Error: std::error::Error + Sync + Send + 'static,
    {
        tracing::debug!(
            "Handling block notification from {} at height {}",
            peer_address,
            notification.height
        );

        // Get current tip header and sync state
        let (tip_header, sync_anchor_is_set) = {
            let state = self.global_state.lock_guard().await;
            (
                *state.chain.light_state().header(),
                state.net.sync_anchor.is_some(),
            )
        };

        tracing::debug!(
            "Got BlockNotification of height {}. Own height is {}",
            notification.height,
            tip_header.height
        );

        // Check if block is new based on cumulative proof of work
        // MIGRATED FROM: peer_loop.rs:710-711
        // Access the pub(crate) field - we're in the same crate
        let block_is_new =
            tip_header.cumulative_proof_of_work < notification.cumulative_proof_of_work;

        tracing::debug!("block_is_new: {}", block_is_new);

        // MIGRATED FROM: peer_loop.rs:715-732
        // If block is new and we're not already syncing or reconciling a fork,
        // request the full block
        if block_is_new && !sync_anchor_is_set {
            tracing::debug!(
                "Requesting full block from peer {} for block at height {}",
                peer_address,
                notification.height
            );
            peer.send(PeerMessage::BlockRequestByHeight(notification.height))
                .await
                .map_err(|e| anyhow::anyhow!("Failed to send block request: {}", e))?;
        } else {
            tracing::debug!(
                "Ignoring peer block notification. height: {}, new: {}, sync_anchor_set: {}",
                notification.height,
                block_is_new,
                sync_anchor_is_set
            );
        }

        // NOTE: AddPeerMaxBlockHeight is NOT sent here!
        // It's only sent after a successful sync challenge response validation
        // See peer_loop.rs:862-870 where it's sent from SyncChallengeResponse handler

        Ok(false) // Keep connection alive
    }

    /// Handle transaction message
    ///
    /// MIGRATED FROM: peer_loop.rs:681-720
    async fn handle_transaction<S>(
        &mut self,
        peer_address: SocketAddr,
        transaction: crate::protocol::consensus::transaction::Transaction,
        peer: &mut S,
    ) -> Result<bool>
    where
        S: Sink<PeerMessage> + TryStream<Ok = PeerMessage> + Unpin,
        <S as Sink<PeerMessage>>::Error: std::error::Error + Sync + Send + 'static,
    {
        tracing::debug!("Handling full transaction from {}", peer_address);

        // Get the confirmable_for_block from the transaction
        // In the original peer_loop, this information comes from context
        // For now, we'll use the current tip as a fallback
        let confirmable_for_block = {
            let state = self.global_state.lock_guard().await;
            state.chain.light_state().hash()
        };

        // Send transaction to main loop for processing
        // MIGRATED FROM: peer_loop.rs:747-760
        self.send_to_main(PeerTaskToMain::Transaction(Box::new(
            crate::application::loops::channel::PeerTaskToMainTransaction {
                transaction,
                confirmable_for_block,
            },
        )))
        .await?;

        tracing::debug!("Sent transaction to main loop from {}", peer_address);

        Ok(false) // Keep connection alive
    }

    /// Handle transaction notification
    ///
    /// MIGRATED FROM: peer_loop.rs:721-750
    async fn handle_transaction_notification<S>(
        &mut self,
        peer_address: SocketAddr,
        notification: TransactionNotification,
        peer: &mut S,
    ) -> Result<bool>
    where
        S: Sink<PeerMessage> + TryStream<Ok = PeerMessage> + Unpin,
        <S as Sink<PeerMessage>>::Error: std::error::Error + Sync + Send + 'static,
    {
        tracing::debug!(
            "Handling transaction notification from {} for txid {:?}",
            peer_address,
            notification.txid
        );

        // Request the full transaction from peer
        // MIGRATED FROM: peer_loop.rs:734-746
        tracing::debug!("Sending transaction request to {}", peer_address);
        peer.send(PeerMessage::TransactionRequest(notification.txid))
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send transaction request: {}", e))?;

        tracing::debug!("Sent transaction request to {}", peer_address);

        Ok(false) // Keep connection alive
    }

    /// Handle message from main task
    ///
    /// MIGRATED FROM: peer_loop.rs:1631-1738
    pub async fn handle_main_task_message<S>(
        &mut self,
        peer_address: SocketAddr,
        msg: MainToPeerTask,
        peer: &mut S,
    ) -> Result<bool>
    where
        S: Sink<PeerMessage> + TryStream<Ok = PeerMessage> + Unpin,
        <S as Sink<PeerMessage>>::Error: std::error::Error + Sync + Send + 'static,
    {
        tracing::debug!("Handling {} message from main in peer loop", msg.get_type());

        match msg {
            MainToPeerTask::Block(block) => {
                // MIGRATED FROM: peer_loop.rs:1648-1658
                tracing::debug!("Sending PeerMessage::BlockNotification");
                let notification: PeerBlockNotification = block.as_ref().into();
                peer.send(PeerMessage::BlockNotification(notification))
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to send block notification: {}", e))?;
                tracing::debug!("Sent PeerMessage::BlockNotification");
                Ok(false) // Keep connection alive
            }
            MainToPeerTask::RequestBlockBatch(_batch_block_request) => {
                // MIGRATED FROM: peer_loop.rs:1661-1678
                // Note: BlockRequestBatch variant not yet available in MainToPeerTask
                // This would send a block batch request to peers during synchronization
                tracing::debug!("Block batch request received (not yet implemented)");
                Ok(false) // Keep connection alive
            }
            MainToPeerTask::MakePeerDiscoveryRequest => {
                // MIGRATED FROM: peer_loop.rs:1671-1675
                tracing::debug!("Sending peer discovery request");
                peer.send(PeerMessage::PeerListRequest)
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to send peer discovery request: {}", e))?;
                Ok(false) // Keep connection alive
            }
            MainToPeerTask::Disconnect(peer_address) => {
                // MIGRATED FROM: peer_loop.rs:1676-1680
                tracing::debug!("Disconnecting from longest lived peer");
                peer.send(PeerMessage::Bye)
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to send bye message: {}", e))?;
                Ok(true) // Close connection
            }
            MainToPeerTask::BlockProposalNotification(notification) => {
                // MIGRATED FROM: peer_loop.rs:1730-1737
                tracing::debug!("Sending PeerMessage::BlockProposalNotification");
                peer.send(PeerMessage::BlockProposalNotification(notification))
                    .await
                    .map_err(|e| {
                        anyhow::anyhow!("Failed to send block proposal notification: {}", e)
                    })?;
                tracing::debug!("Sent PeerMessage::BlockProposalNotification");
                Ok(false) // Keep connection alive
            }
            MainToPeerTask::PeerSynchronizationTimeout(target_peer) => {
                // MIGRATED FROM: peer_loop.rs:1681-1693
                // Only handle if this is the target peer
                if target_peer != peer_address {
                    return Ok(false); // Not for us, keep alive
                }

                tracing::warn!("Peer synchronization timeout for {}", peer_address);
                // The peer failed synchronization - we keep connection alive but record the failure
                // TODO: Implement peer punishment/sanctioning if needed
                Ok(false) // Keep connection alive (punishment applied in peer_loop)
            }
            MainToPeerTask::MakeSpecificPeerDiscoveryRequest(target_address) => {
                // MIGRATED FROM: peer_loop.rs:1715-1719
                // Only send peer list request if this is the targeted peer
                if target_address == peer_address {
                    tracing::debug!("Sending specific peer discovery request");
                    peer.send(PeerMessage::PeerListRequest)
                        .await
                        .map_err(|e| anyhow::anyhow!("Failed to send peer list request: {}", e))?;
                }
                Ok(false) // Keep connection alive
            }
            MainToPeerTask::TransactionNotification(notification) => {
                // MIGRATED FROM: peer_loop.rs:1721-1728
                tracing::debug!("Sending PeerMessage::TransactionNotification");
                peer.send(PeerMessage::TransactionNotification(notification))
                    .await
                    .map_err(|e| {
                        anyhow::anyhow!("Failed to send transaction notification: {}", e)
                    })?;
                tracing::debug!("Sent PeerMessage::TransactionNotification");
                Ok(false) // Keep connection alive
            }
            MainToPeerTask::DisconnectAll() => {
                // MIGRATED FROM: peer_loop.rs:1710-1713
                tracing::info!("Disconnecting from all peers (DisconnectAll received)");
                // Send bye message and close connection
                peer.send(PeerMessage::Bye)
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to send bye message: {}", e))?;
                Ok(true) // Close connection
            }
        }
    }

    /// Get message handler statistics
    pub fn get_stats(&self) -> MessageHandlerStats {
        MessageHandlerStats {
            total_messages_processed: self.state_manager.get_total_messages_processed(),
            rate_limited_messages: self.state_manager.get_rate_limited_messages(),
            invalid_messages: self.state_manager.get_invalid_messages(),
        }
    }
}

/// Message handler statistics
#[derive(Debug, Clone)]
pub struct MessageHandlerStats {
    /// Total messages processed
    pub total_messages_processed: usize,
    /// Rate limited messages
    pub rate_limited_messages: usize,
    /// Invalid messages
    pub invalid_messages: usize,
}

impl Default for MessageHandler {
    fn default() -> Self {
        // Note: This is a placeholder Default implementation for testing only.
        // WalletState and BlockchainState don't have simple Default impls.
        // Production code should use new() with proper dependencies.
        panic!("ProtocolHandler::default() is not implemented. Use new() instead.");
    }
}
