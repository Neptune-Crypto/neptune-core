//! P2P event loop implementation
//!
//! This module provides the main event loop for P2P service.

use tokio::sync::mpsc;

use super::P2PServiceEvent;
use crate::p2p::connection::ConnectionEvent;
use crate::p2p::peer::PeerEvent;
use crate::p2p::protocol::ProtocolEvent;
use crate::p2p::state::P2PStateEvent;

/// P2P event loop
#[derive(Debug)]
pub struct EventLoop {
    /// Connection events receiver
    connection_events: mpsc::Receiver<ConnectionEvent>,
    /// Peer events receiver
    peer_events: mpsc::Receiver<PeerEvent>,
    /// Protocol events receiver
    protocol_events: mpsc::Receiver<ProtocolEvent>,
    /// P2P state events receiver
    state_events: mpsc::Receiver<P2PStateEvent>,
    /// Service events sender
    service_events: mpsc::Sender<P2PServiceEvent>,
}

impl EventLoop {
    /// Create new event loop
    pub fn new(
        connection_events: mpsc::Receiver<ConnectionEvent>,
        peer_events: mpsc::Receiver<PeerEvent>,
        protocol_events: mpsc::Receiver<ProtocolEvent>,
        state_events: mpsc::Receiver<P2PStateEvent>,
        service_events: mpsc::Sender<P2PServiceEvent>,
    ) -> Self {
        Self {
            connection_events,
            peer_events,
            protocol_events,
            state_events,
            service_events,
        }
    }

    /// Run the event loop
    pub async fn run(&mut self) -> Result<(), String> {
        tracing::info!("P2P event loop started");

        loop {
            tokio::select! {
                // Handle connection events
                event = self.connection_events.recv() => {
                    if let Some(event) = event {
                        self.handle_connection_event(event).await;
                    } else {
                        tracing::warn!("Connection events channel closed");
                        break;
                    }
                }

                // Handle peer events
                event = self.peer_events.recv() => {
                    if let Some(event) = event {
                        self.handle_peer_event(event).await;
                    } else {
                        tracing::warn!("Peer events channel closed");
                        break;
                    }
                }

                // Handle protocol events
                event = self.protocol_events.recv() => {
                    if let Some(event) = event {
                        self.handle_protocol_event(event).await;
                    } else {
                        tracing::warn!("Protocol events channel closed");
                        break;
                    }
                }

                // Handle state events
                event = self.state_events.recv() => {
                    if let Some(event) = event {
                        self.handle_state_event(event).await;
                    } else {
                        tracing::warn!("State events channel closed");
                        break;
                    }
                }
            }
        }

        tracing::info!("P2P event loop stopped");
        Ok(())
    }

    /// Handle connection event
    async fn handle_connection_event(&mut self, event: ConnectionEvent) {
        tracing::debug!("Handling connection event: {:?}", event);

        match event {
            ConnectionEvent::Connected(connection_info) => {
                tracing::info!("Connection established: {}", connection_info.peer_address);
                // TODO: Update connection statistics
            }
            ConnectionEvent::Failed(address, reason) => {
                tracing::warn!("Connection failed: {} - {}", address, reason);
                // TODO: Update connection statistics
            }
            ConnectionEvent::Disconnected(address) => {
                tracing::info!("Connection closed: {}", address);
                // TODO: Update connection statistics
            }
            ConnectionEvent::Timeout(address) => {
                tracing::warn!("Connection timeout: {}", address);
                // TODO: Update connection statistics
            }
        }
    }

    /// Handle peer event
    async fn handle_peer_event(&mut self, event: PeerEvent) {
        tracing::debug!("Handling peer event: {:?}", event);

        match event {
            PeerEvent::Discovered(address) => {
                tracing::info!("Peer discovered: {}", address);
                // TODO: Update peer statistics
            }
            PeerEvent::Connected(peer_info) => {
                tracing::info!("Peer connected: {}", peer_info.connected_address());
                // TODO: Update peer statistics
            }
            PeerEvent::Disconnected(address) => {
                tracing::info!("Peer disconnected: {}", address);
                // TODO: Update peer statistics
            }
            PeerEvent::Banned(address, reason) => {
                tracing::warn!("Peer banned: {} - {}", address, reason);
                // TODO: Update peer statistics
            }
            PeerEvent::ReputationChanged(address, standing) => {
                tracing::debug!("Peer reputation changed: {} - {:?}", address, standing);
                // TODO: Update peer statistics
            }
        }
    }

    /// Handle protocol event
    async fn handle_protocol_event(&mut self, event: ProtocolEvent) {
        tracing::debug!("Handling protocol event: {:?}", event);

        match event {
            ProtocolEvent::MessageReceived(peer_address, message) => {
                tracing::debug!("Message received from {}: {:?}", peer_address, message);
                // TODO: Update protocol statistics
            }
            ProtocolEvent::MessageSent(peer_address, message) => {
                tracing::debug!("Message sent to {}: {:?}", peer_address, message);
                // TODO: Update protocol statistics
            }
            ProtocolEvent::HandshakeCompleted(peer_address, _handshake_data) => {
                tracing::info!("Handshake completed with {}", peer_address);
                // TODO: Update protocol statistics
            }
            ProtocolEvent::HandshakeFailed(peer_address, reason) => {
                tracing::warn!("Handshake failed with {}: {}", peer_address, reason);
                // TODO: Update protocol statistics
            }
            ProtocolEvent::ProtocolError(peer_address, reason) => {
                tracing::warn!("Protocol error with {}: {}", peer_address, reason);
                // TODO: Update protocol statistics
            }
        }
    }

    /// Handle state event
    async fn handle_state_event(&mut self, event: P2PStateEvent) {
        tracing::debug!("Handling state event: {:?}", event);

        match event {
            P2PStateEvent::PeerAdded(peer_info) => {
                tracing::debug!("Peer added: {}", peer_info.connected_address());
                // TODO: Update state statistics
            }
            P2PStateEvent::PeerRemoved(address) => {
                tracing::debug!("Peer removed: {}", address);
                // TODO: Update state statistics
            }
            P2PStateEvent::StateFrozen => {
                tracing::debug!("State frozen");
                // TODO: Update state statistics
            }
            P2PStateEvent::StateUnfrozen => {
                tracing::debug!("State unfrozen");
                // TODO: Update state statistics
            }
            P2PStateEvent::ReputationUpdated(address, reputation) => {
                tracing::debug!("Reputation updated for {}: {}", address, reputation);
                // TODO: Update state statistics
            }
        }
    }
}
