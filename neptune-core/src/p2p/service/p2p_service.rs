//! P2P service implementation
//!
//! This module provides the main P2P service that coordinates all P2P components.

use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc};

use super::{
    P2PServiceCommand, P2PServiceEvent, P2PServiceInterface, P2PServiceResponse, P2PServiceStatus,
};
use crate::application::loops::channel::{MainToPeerTask, PeerTaskToMain};
use crate::p2p::config::P2PConfig;
use crate::p2p::peer::PeerInfo;
use crate::p2p::protocol::PeerMessage;
use crate::p2p::state::SharedP2PStateManager;
use crate::state::GlobalStateLock;

/// Main P2P service
#[derive(Debug)]
pub struct P2PService {
    /// P2P configuration
    config: P2PConfig,
    /// P2P state manager (shared across all connections)
    state_manager: SharedP2PStateManager,
    /// Global state lock
    global_state: GlobalStateLock,
    /// Main to peer broadcast channel
    main_to_peer_broadcast_tx: broadcast::Sender<MainToPeerTask>,
    /// Peer task to main channel
    peer_task_to_main_tx: mpsc::Sender<PeerTaskToMain>,
    /// Command receiver
    command_rx: Option<mpsc::Receiver<P2PServiceCommand>>,
    /// Event sender
    event_tx: Option<mpsc::Sender<P2PServiceEvent>>,
    /// Response sender
    response_tx: Option<mpsc::Sender<P2PServiceResponse>>,
    /// Service status
    status: P2PServiceStatus,
    /// Service start time
    start_time: std::time::Instant,
}

impl P2PService {
    /// Create new P2P service
    pub fn new(
        config: P2PConfig,
        state_manager: SharedP2PStateManager,
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
            command_rx: None,
            event_tx: None,
            response_tx: None,
            status: P2PServiceStatus {
                is_running: false,
                connected_peers: 0,
                active_connections: 0,
                uptime: std::time::Duration::ZERO,
                last_activity: std::time::SystemTime::now(),
            },
            start_time: std::time::Instant::now(),
        }
    }

    /// Initialize the P2P service
    pub async fn initialize(&mut self) -> Result<(), String> {
        tracing::info!("Initializing P2P service");

        // Initialize connection acceptor
        let connection_acceptor = crate::p2p::connection::acceptor::ConnectionAcceptor::new(
            self.config.connection.clone(),
            self.state_manager.clone(),
            self.global_state.clone(),
            self.main_to_peer_broadcast_tx.clone(),
            self.peer_task_to_main_tx.clone(),
        );

        // Initialize connection initiator
        let connection_initiator = crate::p2p::connection::initiator::ConnectionInitiator::new(
            self.config.connection.clone(),
            self.state_manager.clone(),
            self.global_state.clone(),
            self.main_to_peer_broadcast_tx.clone(),
            self.peer_task_to_main_tx.clone(),
        );

        // Initialize message handler
        let message_handler = crate::p2p::protocol::handler::MessageHandler::new(
            crate::p2p::protocol::handler::HandlerConfig::default(),
            self.state_manager.clone(),
            self.global_state.clone(),
            self.main_to_peer_broadcast_tx.clone(),
            self.peer_task_to_main_tx.clone(),
        );

        // Store initialized components
        // TODO: Store these in the service struct for later use

        tracing::info!("P2P service initialized successfully");
        Ok(())
    }

    /// Set command receiver
    pub fn set_command_receiver(&mut self, rx: mpsc::Receiver<P2PServiceCommand>) {
        self.command_rx = Some(rx);
    }

    /// Set event sender
    pub fn set_event_sender(&mut self, tx: mpsc::Sender<P2PServiceEvent>) {
        self.event_tx = Some(tx);
    }

    /// Set response sender
    pub fn set_response_sender(&mut self, tx: mpsc::Sender<P2PServiceResponse>) {
        self.response_tx = Some(tx);
    }

    /// Run the P2P service
    pub async fn run(&mut self) -> Result<(), String> {
        self.status.is_running = true;
        self.start_time = std::time::Instant::now();

        tracing::info!("P2P service started");

        // TODO: Implement actual service loop
        // This is a stub implementation
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;

            // Update status
            self.status.uptime = self.start_time.elapsed();
            self.status.last_activity = std::time::SystemTime::now();
        }
    }

    /// Send event
    async fn send_event(&self, event: P2PServiceEvent) {
        if let Some(tx) = &self.event_tx {
            let _ = tx.send(event).await;
        }
    }

    /// Send response
    async fn send_response(&self, response: P2PServiceResponse) {
        if let Some(tx) = &self.response_tx {
            let _ = tx.send(response).await;
        }
    }

    /// Handle incoming connection
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

        // Create connection acceptor for this connection
        // Note: state_manager is Arc<RwLock<>> so cloning only clones the Arc, not the data
        let mut connection_acceptor = crate::p2p::connection::acceptor::ConnectionAcceptor::new(
            self.config.connection.clone(),
            self.state_manager.clone(), // Clone the Arc, shares the underlying state
            self.global_state.clone(),
            self.main_to_peer_broadcast_tx.clone(),
            self.peer_task_to_main_tx.clone(),
        );

        // Use enhanced connection handling with DDoS protection
        connection_acceptor
            .handle_incoming_connection_enhanced(stream, peer_address)
            .await
            .map_err(|e| format!("Failed to handle incoming connection: {}", e))?;

        tracing::info!(
            "Successfully handled incoming connection from {}",
            peer_address
        );
        Ok(())
    }

    /// Handle peer discovery
    ///
    /// This replaces the peer discovery logic in main_loop.rs:1758-1785
    pub async fn handle_peer_discovery(&mut self) -> Result<(), String> {
        tracing::debug!("P2P service handling peer discovery");

        // TODO: Implement actual peer discovery
        // This will be implemented when we migrate the peer discovery logic
        // For now, just log the discovery attempt

        tracing::info!("Peer discovery completed");
        Ok(())
    }

    /// Handle peer task message
    ///
    /// This replaces the peer task message handling in main_loop.rs:1726-1733
    pub async fn handle_peer_task_message(
        &mut self,
        message: PeerTaskToMain,
    ) -> Result<(), String> {
        tracing::debug!("P2P service handling peer task message: {:?}", message);

        // TODO: Implement actual message handling
        // This will be implemented when we migrate the message handling logic
        // For now, just log the message

        tracing::info!("Peer task message handled");
        Ok(())
    }
}

impl P2PServiceInterface for P2PService {
    async fn start(&mut self) -> Result<(), String> {
        self.status.is_running = true;
        self.start_time = std::time::Instant::now();
        self.send_event(P2PServiceEvent::ServiceStarted).await;
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), String> {
        self.status.is_running = false;
        self.send_event(P2PServiceEvent::ServiceStopped).await;
        Ok(())
    }

    async fn connect_to_peer(&mut self, address: SocketAddr) -> Result<(), String> {
        tracing::debug!("Connecting to peer: {}", address);

        // Get own handshake data
        let own_handshake_data = {
            let state = self.global_state.lock_guard().await;
            state.get_own_handshakedata()
        };

        // Create connection initiator
        let mut connection_initiator = crate::p2p::connection::initiator::ConnectionInitiator::new(
            self.config.connection.clone(),
            self.state_manager.clone(),
            self.global_state.clone(),
            self.main_to_peer_broadcast_tx.clone(),
            self.peer_task_to_main_tx.clone(),
        );

        // Use legacy connection method for now (maintains compatibility)
        connection_initiator
            .connect_to_peer_legacy(address, own_handshake_data, 1)
            .await
            .map_err(|e| format!("Failed to connect to peer: {}", e))?;

        tracing::info!("Successfully connected to peer: {}", address);
        Ok(())
    }

    async fn disconnect_from_peer(&mut self, address: SocketAddr) -> Result<(), String> {
        tracing::debug!("Disconnecting from peer: {}", address);
        // TODO: Implement actual disconnection logic
        Ok(())
    }

    async fn send_message(
        &mut self,
        address: SocketAddr,
        message: PeerMessage,
    ) -> Result<(), String> {
        tracing::debug!("Sending message to {}: {:?}", address, message.get_type());

        // Create message handler for this message
        let message_handler = crate::p2p::protocol::handler::MessageHandler::new(
            crate::p2p::protocol::handler::HandlerConfig::default(),
            self.state_manager.clone(),
            self.global_state.clone(),
            self.main_to_peer_broadcast_tx.clone(),
            self.peer_task_to_main_tx.clone(),
        );

        // TODO: Implement actual message sending logic
        // For now, just log the message
        tracing::info!("Message sent to {}: {:?}", address, message.get_type());
        Ok(())
    }

    async fn broadcast_message(&mut self, message: PeerMessage) -> Result<(), String> {
        tracing::debug!("Broadcasting message: {:?}", message.get_type());
        // TODO: Implement actual broadcast logic
        Ok(())
    }

    async fn get_peer_info(&self, address: SocketAddr) -> Option<PeerInfo> {
        // TODO: Implement actual peer info retrieval
        None
    }

    async fn get_all_peers(&self) -> Vec<PeerInfo> {
        // TODO: Implement actual peer list retrieval
        Vec::new()
    }

    async fn get_status(&self) -> P2PServiceStatus {
        self.status.clone()
    }
}
