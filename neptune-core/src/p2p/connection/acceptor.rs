//! Connection acceptor implementation
//!
//! This module handles accepting incoming P2P connections.
//!
//! MIGRATED FROM: src/application/loops/main_loop.rs:1698-1723
//! This code was transplanted from the main loop's incoming connection handling
//! to provide modular connection acceptance with DDoS protection.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use futures::{SinkExt, TryStreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;

use super::{ConnectionInfo, ConnectionResult, ConnectionState};
use crate::application::config::cli_args;
use crate::application::loops::channel::{MainToPeerTask, PeerTaskToMain};
use crate::application::loops::connect_to_peers::{
    answer_peer, precheck_incoming_connection_is_allowed,
};
use crate::p2p::config::ConnectionConfig;
use crate::p2p::connection::handshake::HandshakeManager;
use crate::p2p::state::P2PStateManager;
use crate::protocol::peer::handshake_data::HandshakeData;
use crate::state::GlobalStateLock;

/// Connection acceptor for handling incoming connections
#[derive(Debug)]
pub struct ConnectionAcceptor {
    /// Connection configuration
    config: ConnectionConfig,
    /// TCP listener
    listener: Option<TcpListener>,
    /// P2P state manager for DDoS protection
    state_manager: P2PStateManager,
    /// Global state lock
    global_state: GlobalStateLock,
    /// Main to peer broadcast channel
    main_to_peer_broadcast_tx: broadcast::Sender<MainToPeerTask>,
    /// Peer task to main channel
    peer_task_to_main_tx: mpsc::Sender<PeerTaskToMain>,
}

impl ConnectionAcceptor {
    /// Create new connection acceptor
    pub fn new(
        config: ConnectionConfig,
        state_manager: P2PStateManager,
        global_state: GlobalStateLock,
        main_to_peer_broadcast_tx: broadcast::Sender<MainToPeerTask>,
        peer_task_to_main_tx: mpsc::Sender<PeerTaskToMain>,
    ) -> Self {
        Self {
            config,
            listener: None,
            state_manager,
            global_state,
            main_to_peer_broadcast_tx,
            peer_task_to_main_tx,
        }
    }

    /// Start accepting connections
    pub async fn start(&mut self) -> Result<(), String> {
        if !self.config.allows_incoming_connections() {
            return Err("Incoming connections not allowed".to_string());
        }

        let port = self
            .config
            .own_listen_port
            .ok_or("No listen port configured")?;

        let addr = format!("{}:{}", self.config.peer_listen_addr, port);
        let listener = TcpListener::bind(&addr)
            .await
            .map_err(|e| format!("Failed to bind to {}: {}", addr, e))?;

        self.listener = Some(listener);
        tracing::info!("P2P connection acceptor started on {}", addr);
        Ok(())
    }

    /// Stop accepting connections
    pub fn stop(&mut self) {
        self.listener = None;
        tracing::info!("P2P connection acceptor stopped");
    }

    /// Handle incoming connection with enhanced DDoS protection
    ///
    /// This method replaces the direct answer_peer call and adds comprehensive DDoS protection
    /// including rate limiting, reputation checks, and connection validation.
    pub async fn handle_incoming_connection_enhanced(
        &mut self,
        stream: TcpStream,
        peer_address: SocketAddr,
    ) -> Result<(), String> {
        tracing::debug!("🔍 Validating incoming connection from {}", peer_address);

        // Phase 1: Basic precheck (static bans, etc.)
        if !precheck_incoming_connection_is_allowed(self.global_state.cli(), peer_address.ip()) {
            tracing::warn!(
                "🛡️ Connection from {} blocked by static precheck",
                peer_address
            );
            return Err(format!(
                "Connection from {} blocked by static configuration",
                peer_address
            ));
        }

        // Phase 2: DDoS protection checks (rate limiting, reputation)
        if !self.state_manager.is_connection_allowed(peer_address) {
            tracing::warn!(
                "🛡️ DDOS PROTECTION: Connection from {} blocked by DDoS protection",
                peer_address
            );
            return Err(format!(
                "Connection from {} blocked by DDoS protection",
                peer_address
            ));
        }

        // Phase 3: Record connection attempt
        self.state_manager
            .record_connection_attempt(peer_address, true, None);

        tracing::info!(
            "✅ Connection from {} passed DDoS validation, proceeding with handshake",
            peer_address
        );

        // Phase 4: Handle the connection using the standard answer_peer logic
        let state = self.global_state.lock_guard().await;
        let main_to_peer_broadcast_rx_clone: broadcast::Receiver<MainToPeerTask> =
            self.main_to_peer_broadcast_tx.subscribe();
        let peer_task_to_main_tx_clone: mpsc::Sender<PeerTaskToMain> =
            self.peer_task_to_main_tx.clone();
        let own_handshake_data: HandshakeData = state.get_own_handshakedata();
        let global_state_lock = self.global_state.clone();
        drop(state); // Release lock before spawning task

        // Spawn task to handle the connection
        tokio::task::spawn(async move {
            match answer_peer(
                stream,
                global_state_lock,
                peer_address,
                main_to_peer_broadcast_rx_clone,
                peer_task_to_main_tx_clone,
                own_handshake_data,
            )
            .await
            {
                Ok(()) => {
                    tracing::info!(
                        "✅ Successfully handled peer connection from {}",
                        peer_address
                    );
                }
                Err(err) => {
                    tracing::warn!(
                        "❌ Error handling peer connection from {}: {:?}",
                        peer_address,
                        err
                    );
                }
            }
        });

        Ok(())
    }

    /// Accept a new connection with DDoS protection
    ///
    /// MIGRATED FROM: src/application/loops/main_loop.rs:1698-1723
    /// This replaces the main loop's incoming connection handling with modular acceptance
    pub async fn accept_connection(&mut self) -> Result<Option<JoinHandle<()>>, String> {
        let listener = self.listener.as_mut().ok_or("Listener not started")?;

        match listener.accept().await {
            Ok((stream, peer_address)) => {
                // MIGRATED FROM: main_loop.rs:1699-1701
                // Pre-check if connection is allowed (DDoS protection)
                if !precheck_incoming_connection_is_allowed(
                    self.global_state.cli(),
                    peer_address.ip(),
                ) {
                    tracing::debug!("Connection from {} rejected by precheck", peer_address);
                    return Ok(None); // Connection rejected, but not an error
                }

                // MIGRATED FROM: main_loop.rs:1703-1707
                // Get necessary data from global state
                let state = self.global_state.lock_guard().await;
                let main_to_peer_broadcast_rx_clone: broadcast::Receiver<MainToPeerTask> =
                    self.main_to_peer_broadcast_tx.subscribe();
                let peer_task_to_main_tx_clone: mpsc::Sender<PeerTaskToMain> =
                    self.peer_task_to_main_tx.clone();
                let own_handshake_data: HandshakeData = state.get_own_handshakedata();
                let global_state_lock = self.global_state.clone(); // bump arc refcount

                // MIGRATED FROM: main_loop.rs:1708-1720
                // Spawn task to handle the connection
                let incoming_peer_task_handle = tokio::task::spawn(async move {
                    match answer_peer(
                        stream,
                        global_state_lock,
                        peer_address,
                        main_to_peer_broadcast_rx_clone,
                        peer_task_to_main_tx_clone,
                        own_handshake_data,
                    )
                    .await
                    {
                        Ok(()) => {
                            tracing::debug!("Peer connection completed successfully");
                        }
                        Err(err) => {
                            tracing::debug!("Peer connection failed: {:?}", err);
                        }
                    }
                });

                tracing::info!("Accepted incoming connection from {}", peer_address);
                Ok(Some(incoming_peer_task_handle))
            }
            Err(e) => Err(format!("Failed to accept connection: {}", e)),
        }
    }

    /// Check if connection is allowed (enhanced DDoS protection)
    async fn is_connection_allowed(&mut self, peer_address: SocketAddr) -> bool {
        // Use existing precheck
        if !precheck_incoming_connection_is_allowed(self.global_state.cli(), peer_address.ip()) {
            return false;
        }

        // Additional DDoS protection checks
        if !self.state_manager.is_connection_allowed(peer_address) {
            return false;
        }

        // Check rate limiting
        if self.state_manager.is_rate_limited(peer_address.ip()) {
            return false;
        }

        true
    }

    /// Check if acceptor is running
    pub fn is_running(&self) -> bool {
        self.listener.is_some()
    }

    /// Get connection statistics
    pub fn get_connection_stats(&self) -> ConnectionStats {
        ConnectionStats {
            is_running: self.is_running(),
            total_connections: self.state_manager.get_total_connections(),
            failed_connections: self.state_manager.get_failed_connections(),
            rate_limited_connections: self.state_manager.get_rate_limited_connections(),
        }
    }
}

/// Connection statistics
#[derive(Debug, Clone)]
pub struct ConnectionStats {
    /// Whether the acceptor is running
    pub is_running: bool,
    /// Total connections accepted
    pub total_connections: usize,
    /// Failed connections
    pub failed_connections: usize,
    /// Rate limited connections
    pub rate_limited_connections: usize,
}
