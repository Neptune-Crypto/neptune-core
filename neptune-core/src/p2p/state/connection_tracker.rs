//! Connection tracker implementation
//!
//! This module tracks connection attempts and provides rate limiting.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant, SystemTime};

/// Connection attempt information
#[derive(Debug, Clone)]
pub struct ConnectionAttempt {
    /// Timestamp of the attempt
    pub timestamp: Instant,
    /// Whether the attempt was successful
    pub successful: bool,
    /// Reason for failure (if unsuccessful)
    pub failure_reason: Option<String>,
}

/// Connection history for an IP address
#[derive(Debug, Clone)]
pub struct ConnectionHistory {
    /// List of connection attempts
    pub attempts: VecDeque<ConnectionAttempt>,
    /// Last connection time
    pub last_connection: Option<SystemTime>,
    /// Number of successful connections
    pub successful_connections: u32,
    /// Number of failed connections
    pub failed_connections: u32,
}

impl ConnectionHistory {
    /// Create new connection history
    pub fn new() -> Self {
        Self {
            attempts: VecDeque::new(),
            last_connection: None,
            successful_connections: 0,
            failed_connections: 0,
        }
    }

    /// Add a connection attempt
    pub fn add_attempt(&mut self, attempt: ConnectionAttempt) {
        let successful = attempt.successful;
        self.attempts.push_back(attempt);

        // Keep only recent attempts (last hour)
        let cutoff = Instant::now() - Duration::from_secs(3600);
        while let Some(front) = self.attempts.front() {
            if front.timestamp < cutoff {
                self.attempts.pop_front();
            } else {
                break;
            }
        }

        if successful {
            self.successful_connections += 1;
            self.last_connection = Some(SystemTime::now());
        } else {
            self.failed_connections += 1;
        }
    }

    /// Get recent attempt count within time window
    pub fn get_recent_attempts(&self, window: Duration) -> usize {
        let cutoff = Instant::now() - window;
        self.attempts
            .iter()
            .filter(|attempt| attempt.timestamp > cutoff)
            .count()
    }

    /// Check if IP is rate limited
    pub fn is_rate_limited(&self, max_attempts: usize, window: Duration) -> bool {
        self.get_recent_attempts(window) >= max_attempts
    }
}

impl Default for ConnectionHistory {
    fn default() -> Self {
        Self::new()
    }
}

/// Connection tracker for monitoring connection attempts
#[derive(Debug, Clone)]
pub struct ConnectionTracker {
    /// Connection history by IP address
    connection_history: HashMap<IpAddr, ConnectionHistory>,
    /// Rate limiting configuration
    rate_limit_config: RateLimitConfig,
}

/// Rate limiting configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum connection attempts per minute
    pub max_attempts_per_minute: usize,
    /// Maximum connection attempts per hour
    pub max_attempts_per_hour: usize,
    /// Rate limit window
    pub rate_limit_window: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_attempts_per_minute: 10,
            max_attempts_per_hour: 100,
            rate_limit_window: Duration::from_secs(60),
        }
    }
}

impl ConnectionTracker {
    /// Create new connection tracker
    pub fn new() -> Self {
        Self {
            connection_history: HashMap::new(),
            rate_limit_config: RateLimitConfig::default(),
        }
    }

    /// Record a connection attempt
    pub fn record_attempt(&mut self, ip: IpAddr, successful: bool, failure_reason: Option<String>) {
        let attempt = ConnectionAttempt {
            timestamp: Instant::now(),
            successful,
            failure_reason,
        };

        self.connection_history
            .entry(ip)
            .or_insert_with(ConnectionHistory::new)
            .add_attempt(attempt);
    }

    /// Check if IP is rate limited
    pub fn is_rate_limited(&self, ip: IpAddr) -> bool {
        if let Some(history) = self.connection_history.get(&ip) {
            history.is_rate_limited(
                self.rate_limit_config.max_attempts_per_minute,
                self.rate_limit_config.rate_limit_window,
            )
        } else {
            false
        }
    }

    /// Get connection history for IP
    pub fn get_connection_history(&self, ip: IpAddr) -> Option<&ConnectionHistory> {
        self.connection_history.get(&ip)
    }

    /// Get rate limit configuration
    pub fn get_rate_limit_config(&self) -> &RateLimitConfig {
        &self.rate_limit_config
    }

    /// Update rate limit configuration
    pub fn update_rate_limit_config(&mut self, config: RateLimitConfig) {
        self.rate_limit_config = config;
    }

    /// Get total connections
    pub fn get_total_connections(&self) -> usize {
        self.connection_history.len()
    }

    /// Get failed connections
    pub fn get_failed_connections(&self) -> usize {
        self.connection_history
            .values()
            .map(|history| history.failed_connections as usize)
            .sum()
    }

    /// Get rate limited connections
    pub fn get_rate_limited_connections(&self) -> usize {
        self.connection_history
            .values()
            .filter(|history| {
                history.is_rate_limited(
                    self.rate_limit_config.max_attempts_per_minute,
                    Duration::from_secs(60),
                )
            })
            .count()
    }

    /// Clear old connection history
    pub fn cleanup_old_history(&mut self) {
        let cutoff = Instant::now() - Duration::from_secs(3600); // 1 hour
        self.connection_history.retain(|_, history| {
            history
                .attempts
                .retain(|attempt| attempt.timestamp > cutoff);
            !history.attempts.is_empty()
        });
    }
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}
