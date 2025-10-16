//! Main loop integration
//!
//! This module provides integration between the P2P service and the main loop,
//! handling incoming connections, peer discovery, and message routing.

use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc};

use crate::application::loops::channel::{MainToPeerTask, PeerTaskToMain};
use crate::p2p::peer::PeerInfo;
use crate::p2p::protocol::PeerMessage;
use crate::p2p::service::{
    P2PService, P2PServiceCommand, P2PServiceEvent, P2PServiceInterface, P2PServiceResponse,
};
use crate::state::GlobalStateLock;

/// Integration layer between P2P service and main loop
#[derive(Debug)]
pub struct MainLoopIntegration {
    /// P2P service
    p2p_service: P2PService,
    /// Global state lock
    global_state: GlobalStateLock,
    /// Main to peer broadcast channel
    main_to_peer_broadcast_tx: broadcast::Sender<MainToPeerTask>,
    /// Peer task to main channel
    peer_task_to_main_tx: mpsc::Sender<PeerTaskToMain>,
}

impl MainLoopIntegration {
    /// Create new main loop integration
    pub fn new(
        p2p_service: P2PService,
        global_state: GlobalStateLock,
        main_to_peer_broadcast_tx: broadcast::Sender<MainToPeerTask>,
        peer_task_to_main_tx: mpsc::Sender<PeerTaskToMain>,
    ) -> Self {
        Self {
            p2p_service,
            global_state,
            main_to_peer_broadcast_tx,
            peer_task_to_main_tx,
        }
    }

    /// Handle incoming connection from main loop
    ///
    /// This replaces the direct answer_peer call in main_loop.rs:1698-1723
    pub async fn handle_incoming_connection(
        &mut self,
        stream: TcpStream,
        peer_address: SocketAddr,
    ) -> Result<(), String> {
        tracing::debug!(
            "P2P service handling incoming connection from {}",
            peer_address
        );

        // Use P2P service to handle the connection
        self.p2p_service
            .handle_incoming_connection(stream, peer_address)
            .await
            .map_err(|e| format!("Failed to handle incoming connection: {}", e))
    }

    /// Handle peer discovery from main loop
    ///
    /// This replaces the peer discovery logic in main_loop.rs:1758-1785
    pub async fn handle_peer_discovery(&mut self) -> Result<(), String> {
        tracing::debug!("P2P service handling peer discovery");

        // Use P2P service to handle peer discovery
        self.p2p_service
            .handle_peer_discovery()
            .await
            .map_err(|e| format!("Failed to handle peer discovery: {}", e))
    }

    /// Handle peer task message from main loop
    ///
    /// This replaces the peer task message handling in main_loop.rs:1726-1733
    pub async fn handle_peer_task_message(
        &mut self,
        message: PeerTaskToMain,
    ) -> Result<(), String> {
        tracing::debug!("P2P service handling peer task message: {:?}", message);

        // Use P2P service to handle the message
        self.p2p_service
            .handle_peer_task_message(message)
            .await
            .map_err(|e| format!("Failed to handle peer task message: {}", e))
    }

    /// Connect to a peer
    ///
    /// This replaces the direct call_peer call in lib.rs:200-217
    pub async fn connect_to_peer(&mut self, peer_address: SocketAddr) -> Result<(), String> {
        tracing::debug!("P2P service connecting to peer: {}", peer_address);

        // Use P2P service to connect to peer
        self.p2p_service
            .connect_to_peer(peer_address)
            .await
            .map_err(|e| format!("Failed to connect to peer: {}", e))
    }

    /// Get P2P service status
    pub async fn get_status(&self) -> Result<crate::p2p::service::P2PServiceStatus, String> {
        Ok(self.p2p_service.get_status().await)
    }

    /// Get all connected peers
    pub async fn get_all_peers(&self) -> Result<Vec<PeerInfo>, String> {
        Ok(self.p2p_service.get_all_peers().await)
    }

    /// Send message to peer
    pub async fn send_message_to_peer(
        &mut self,
        peer_address: SocketAddr,
        message: PeerMessage,
    ) -> Result<(), String> {
        self.p2p_service
            .send_message(peer_address, message)
            .await
            .map_err(|e| format!("Failed to send message to peer: {}", e))
    }

    /// Broadcast message to all peers
    pub async fn broadcast_message(&mut self, message: PeerMessage) -> Result<(), String> {
        self.p2p_service
            .broadcast_message(message)
            .await
            .map_err(|e| format!("Failed to broadcast message: {}", e))
    }

    /// Get the P2P service (for direct access if needed)
    pub fn get_p2p_service(&self) -> &P2PService {
        &self.p2p_service
    }

    /// Get mutable P2P service (for direct access if needed)
    pub fn get_p2p_service_mut(&mut self) -> &mut P2PService {
        &mut self.p2p_service
    }
}
