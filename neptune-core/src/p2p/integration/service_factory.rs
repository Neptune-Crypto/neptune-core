//! P2P service factory
//!
//! This module creates and initializes the P2P service with all necessary
//! dependencies from the existing Neptune Core system.

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc, RwLock};

use crate::application::loops::channel::{MainToPeerTask, PeerTaskToMain};
use crate::p2p::config::P2PConfig;
use crate::p2p::service::P2PService;
use crate::p2p::state::P2PStateManager;
use crate::state::GlobalStateLock;

/// Factory for creating P2P services with proper initialization
#[derive(Debug)]
pub struct P2PServiceFactory {
    /// P2P configuration
    config: P2PConfig,
    /// Global state lock
    global_state: GlobalStateLock,
    /// Main to peer broadcast channel
    main_to_peer_broadcast_tx: broadcast::Sender<MainToPeerTask>,
    /// Peer task to main channel
    peer_task_to_main_tx: mpsc::Sender<PeerTaskToMain>,
}

impl P2PServiceFactory {
    /// Create new P2P service factory
    pub fn new(
        config: P2PConfig,
        global_state: GlobalStateLock,
        main_to_peer_broadcast_tx: broadcast::Sender<MainToPeerTask>,
        peer_task_to_main_tx: mpsc::Sender<PeerTaskToMain>,
    ) -> Self {
        Self {
            config,
            global_state,
            main_to_peer_broadcast_tx,
            peer_task_to_main_tx,
        }
    }

    /// Create and initialize P2P service
    pub async fn create_service(&self) -> Result<P2PService, String> {
        // Get instance ID from global state
        let instance_id = {
            let state = self.global_state.lock_guard().await;
            state.net.instance_id
        };

        // Create P2P state manager (wrapped in Arc<RwLock<>> for shared access)
        let p2p_state_manager =
            P2PServiceFactory::create_p2p_state_manager(&self.config, instance_id).await?;

        // Wrap in Arc<RwLock<>> for shared, thread-safe access across all connections
        let shared_state_manager = Arc::new(RwLock::new(p2p_state_manager));

        // Create event channels
        let (event_tx, _event_rx) = mpsc::channel(1000);
        let (_command_tx, command_rx) = mpsc::channel(1000);
        let (response_tx, _response_rx) = mpsc::channel(1000);

        // Create P2P service with shared state manager
        let mut p2p_service = P2PService::new(
            self.config.clone(),
            shared_state_manager,
            self.global_state.clone(),
            self.main_to_peer_broadcast_tx.clone(),
            self.peer_task_to_main_tx.clone(),
        );

        // Set up channels
        p2p_service.set_event_sender(event_tx);
        p2p_service.set_command_receiver(command_rx);
        p2p_service.set_response_sender(response_tx);

        // Initialize service
        p2p_service.initialize().await?;

        Ok(p2p_service)
    }

    /// Create P2P state manager from global state
    async fn create_p2p_state_manager(
        config: &P2PConfig,
        instance_id: u128,
    ) -> Result<P2PStateManager, String> {
        // Create new P2P state manager
        let p2p_state_manager = P2PStateManager::new(config.clone(), instance_id);

        // TODO: Migrate existing peer data from global state
        // This will be implemented when we migrate the state management
        // For now, start with empty state

        Ok(p2p_state_manager)
    }

    /// Get known peers from CLI arguments
    pub fn get_known_peers(&self) -> Vec<SocketAddr> {
        self.config.peer.known_peers.clone()
    }

    /// Get P2P configuration
    pub fn get_config(&self) -> &P2PConfig {
        &self.config
    }
}
