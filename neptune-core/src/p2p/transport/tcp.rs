//! TCP transport implementation
//!
//! This module provides TCP-based transport for P2P communication.

use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use super::{Transport, TransportConfig};

/// TCP transport implementation
#[derive(Debug)]
pub struct TcpTransport {
    /// TCP stream
    stream: TcpStream,
    /// Remote peer address
    peer_address: SocketAddr,
    /// Transport configuration
    config: TransportConfig,
    /// Whether the transport is connected
    connected: bool,
}

impl TcpTransport {
    /// Create new TCP transport
    pub fn new(stream: TcpStream, peer_address: SocketAddr, config: TransportConfig) -> Self {
        Self {
            stream,
            peer_address,
            config,
            connected: true,
        }
    }

    /// Get the underlying TCP stream
    pub fn into_stream(self) -> TcpStream {
        self.stream
    }
}

impl Transport for TcpTransport {
    fn peer_address(&self) -> SocketAddr {
        self.peer_address
    }

    fn is_connected(&self) -> bool {
        self.connected
    }

    fn close(&mut self) {
        self.connected = false;
        // The stream will be closed when dropped
    }
}

impl AsyncRead for TcpTransport {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        std::pin::Pin::new(&mut this.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for TcpTransport {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        let this = self.get_mut();
        std::pin::Pin::new(&mut this.stream).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let this = self.get_mut();
        std::pin::Pin::new(&mut this.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let this = self.get_mut();
        std::pin::Pin::new(&mut this.stream).poll_shutdown(cx)
    }
}
