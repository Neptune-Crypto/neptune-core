//! Transport layer module for P2P networking
//!
//! This module handles the transport layer including TCP connections,
//! message framing, and codec operations.

pub mod codec;
pub mod framing;
pub mod tcp;

// Re-export main types
pub use codec::TransportCodec;
pub use framing::MessageFraming;
pub use tcp::TcpTransport;

use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};

/// Transport trait for P2P communication
pub trait Transport: AsyncRead + AsyncWrite + Send + Sync + Unpin {
    /// Get the remote peer address
    fn peer_address(&self) -> SocketAddr;

    /// Check if the transport is connected
    fn is_connected(&self) -> bool;

    /// Close the transport connection
    fn close(&mut self);
}

/// Transport event
#[derive(Debug, Clone)]
pub enum TransportEvent {
    /// Connection established
    Connected(SocketAddr),
    /// Connection lost
    Disconnected(SocketAddr),
    /// Data received
    DataReceived(SocketAddr, Vec<u8>),
    /// Data sent
    DataSent(SocketAddr, Vec<u8>),
    /// Transport error
    Error(SocketAddr, String),
}

/// Transport configuration
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Connection timeout
    pub connection_timeout: std::time::Duration,
    /// Read timeout
    pub read_timeout: std::time::Duration,
    /// Write timeout
    pub write_timeout: std::time::Duration,
    /// Keep-alive interval
    pub keep_alive_interval: std::time::Duration,
    /// Maximum message size
    pub max_message_size: usize,
    /// Buffer size for reading
    pub read_buffer_size: usize,
    /// Buffer size for writing
    pub write_buffer_size: usize,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            connection_timeout: std::time::Duration::from_secs(30),
            read_timeout: std::time::Duration::from_secs(60),
            write_timeout: std::time::Duration::from_secs(30),
            keep_alive_interval: std::time::Duration::from_secs(30),
            max_message_size: 500 * 1024 * 1024, // 500MB
            read_buffer_size: 8192,
            write_buffer_size: 8192,
        }
    }
}
