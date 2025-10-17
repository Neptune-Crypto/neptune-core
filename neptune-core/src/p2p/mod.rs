//! P2P networking module for Neptune Core
//!
//! This module provides a modular, well-organized P2P networking implementation
//! with clear separation of concerns and easy extensibility for features like
//! DDoS protection.

pub mod config;
pub mod connection;
pub mod integration;
pub mod peer;
pub mod protocol;
pub mod service;
pub mod state;
pub mod transport;

// Re-export main public interfaces
pub use config::P2PConfig;
pub use integration::{MainLoopIntegration, P2PServiceFactory};
pub use service::P2PService;

// Re-export commonly used types
pub use peer::PeerInfo;
pub use protocol::PeerMessage;
pub use state::P2PStateManager;

/// P2P module version for compatibility checking
pub const P2P_MODULE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Maximum number of peers that can be connected simultaneously
pub const DEFAULT_MAX_PEERS: usize = 10;

/// Default connection timeout in seconds
pub const DEFAULT_CONNECTION_TIMEOUT_SECS: u64 = 30;

/// Default handshake timeout in seconds
pub const DEFAULT_HANDSHAKE_TIMEOUT_SECS: u64 = 10;

/// Default peer discovery interval in seconds
pub const DEFAULT_PEER_DISCOVERY_INTERVAL_SECS: u64 = 120;

/// Default maximum connections per IP address
pub const DEFAULT_MAX_CONNECTIONS_PER_IP: usize = 3;

/// Default rate limit for connection attempts per IP per minute
pub const DEFAULT_CONNECTION_RATE_LIMIT_PER_MINUTE: usize = 10;
