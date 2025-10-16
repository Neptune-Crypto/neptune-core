//! P2P metrics implementation
//!
//! This module provides metrics and monitoring for P2P service.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime};

/// P2P metrics
#[derive(Debug, Clone)]
pub struct P2PMetrics {
    /// Service start time
    pub start_time: SystemTime,
    /// Total connections established
    pub total_connections: u64,
    /// Total connections failed
    pub total_connection_failures: u64,
    /// Total messages sent
    pub total_messages_sent: u64,
    /// Total messages received
    pub total_messages_received: u64,
    /// Total bytes sent
    pub total_bytes_sent: u64,
    /// Total bytes received
    pub total_bytes_received: u64,
    /// Current active connections
    pub active_connections: usize,
    /// Current connected peers
    pub connected_peers: usize,
    /// Connection attempts per IP
    pub connection_attempts_per_ip: HashMap<SocketAddr, u64>,
    /// Message rates per peer
    pub message_rates_per_peer: HashMap<SocketAddr, MessageRate>,
    /// Last activity time
    pub last_activity: SystemTime,
}

/// Message rate information
#[derive(Debug, Clone)]
pub struct MessageRate {
    /// Messages per second
    pub messages_per_second: f64,
    /// Bytes per second
    pub bytes_per_second: f64,
    /// Last update time
    pub last_update: Instant,
}

impl P2PMetrics {
    /// Create new P2P metrics
    pub fn new() -> Self {
        Self {
            start_time: SystemTime::now(),
            total_connections: 0,
            total_connection_failures: 0,
            total_messages_sent: 0,
            total_messages_received: 0,
            total_bytes_sent: 0,
            total_bytes_received: 0,
            active_connections: 0,
            connected_peers: 0,
            connection_attempts_per_ip: HashMap::new(),
            message_rates_per_peer: HashMap::new(),
            last_activity: SystemTime::now(),
        }
    }

    /// Record connection established
    pub fn record_connection_established(&mut self, peer_address: SocketAddr) {
        self.total_connections += 1;
        self.active_connections += 1;
        self.connected_peers += 1;
        self.last_activity = SystemTime::now();

        self.connection_attempts_per_ip
            .entry(peer_address)
            .and_modify(|count| *count += 1)
            .or_insert(1);
    }

    /// Record connection failed
    pub fn record_connection_failed(&mut self, peer_address: SocketAddr) {
        self.total_connection_failures += 1;
        self.last_activity = SystemTime::now();

        self.connection_attempts_per_ip
            .entry(peer_address)
            .and_modify(|count| *count += 1)
            .or_insert(1);
    }

    /// Record connection closed
    pub fn record_connection_closed(&mut self) {
        if self.active_connections > 0 {
            self.active_connections -= 1;
        }
        if self.connected_peers > 0 {
            self.connected_peers -= 1;
        }
        self.last_activity = SystemTime::now();
    }

    /// Record message sent
    pub fn record_message_sent(&mut self, peer_address: SocketAddr, bytes: usize) {
        self.total_messages_sent += 1;
        self.total_bytes_sent += bytes as u64;
        self.last_activity = SystemTime::now();

        self.update_message_rate(peer_address, bytes);
    }

    /// Record message received
    pub fn record_message_received(&mut self, peer_address: SocketAddr, bytes: usize) {
        self.total_messages_received += 1;
        self.total_bytes_received += bytes as u64;
        self.last_activity = SystemTime::now();

        self.update_message_rate(peer_address, bytes);
    }

    /// Update message rate for a peer
    fn update_message_rate(&mut self, peer_address: SocketAddr, bytes: usize) {
        let now = Instant::now();
        let rate = self
            .message_rates_per_peer
            .entry(peer_address)
            .or_insert(MessageRate {
                messages_per_second: 0.0,
                bytes_per_second: 0.0,
                last_update: now,
            });

        let elapsed = now.duration_since(rate.last_update).as_secs_f64();
        if elapsed > 0.0 {
            rate.messages_per_second = 1.0 / elapsed;
            rate.bytes_per_second = bytes as f64 / elapsed;
        }
        rate.last_update = now;
    }

    /// Get uptime
    pub fn uptime(&self) -> Duration {
        self.start_time.elapsed().unwrap_or(Duration::ZERO)
    }

    /// Get connection success rate
    pub fn connection_success_rate(&self) -> f64 {
        let total = self.total_connections + self.total_connection_failures;
        if total == 0 {
            0.0
        } else {
            self.total_connections as f64 / total as f64
        }
    }

    /// Get average messages per second
    pub fn average_messages_per_second(&self) -> f64 {
        let uptime = self.uptime().as_secs_f64();
        if uptime == 0.0 {
            0.0
        } else {
            (self.total_messages_sent + self.total_messages_received) as f64 / uptime
        }
    }

    /// Get average bytes per second
    pub fn average_bytes_per_second(&self) -> f64 {
        let uptime = self.uptime().as_secs_f64();
        if uptime == 0.0 {
            0.0
        } else {
            (self.total_bytes_sent + self.total_bytes_received) as f64 / uptime
        }
    }

    /// Reset metrics
    pub fn reset(&mut self) {
        self.start_time = SystemTime::now();
        self.total_connections = 0;
        self.total_connection_failures = 0;
        self.total_messages_sent = 0;
        self.total_messages_received = 0;
        self.total_bytes_sent = 0;
        self.total_bytes_received = 0;
        self.active_connections = 0;
        self.connected_peers = 0;
        self.connection_attempts_per_ip.clear();
        self.message_rates_per_peer.clear();
        self.last_activity = SystemTime::now();
    }
}

impl Default for P2PMetrics {
    fn default() -> Self {
        Self::new()
    }
}
