//! Connection tracker implementation
//!
//! This module tracks connection attempts and provides comprehensive rate limiting
//! with both per-IP and global limits using sliding window and token bucket algorithms.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant, SystemTime};
use tracing::{debug, warn};

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
    /// Per-IP rate limiting state
    ip_rate_limits: HashMap<IpAddr, IpRateLimitState>,
    /// Global token bucket
    global_token_bucket: TokenBucket,
    /// Global connection attempt counter
    global_attempts: VecDeque<Instant>,
}

/// Rate limiting configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum connection attempts per IP per minute
    pub max_attempts_per_ip_per_minute: usize,
    /// Maximum connection attempts per IP per hour
    pub max_attempts_per_ip_per_hour: usize,
    /// Global maximum connection attempts per minute
    pub global_max_attempts_per_minute: usize,
    /// Global maximum connection attempts per hour
    pub global_max_attempts_per_hour: usize,
    /// Rate limit window for per-minute checks
    pub minute_window: Duration,
    /// Rate limit window for per-hour checks
    pub hour_window: Duration,
    /// Cooldown period after rate limit violation
    pub cooldown_period: Duration,
    /// Enable token bucket rate limiting
    pub enable_token_bucket: bool,
    /// Token bucket refill rate (tokens per second)
    pub token_refill_rate: f64,
    /// Token bucket capacity
    pub token_bucket_capacity: usize,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            // Per-IP limits: 30/min, 200/hour (reasonable for legitimate reconnects)
            max_attempts_per_ip_per_minute: 30,
            max_attempts_per_ip_per_hour: 200,
            // Global limits: 500/min, 3000/hour (protects against distributed attacks)
            global_max_attempts_per_minute: 500,
            global_max_attempts_per_hour: 3000,
            minute_window: Duration::from_secs(60),
            hour_window: Duration::from_secs(3600),
            // 5 minute cooldown after violation
            cooldown_period: Duration::from_secs(300),
            // Token bucket enabled by default
            enable_token_bucket: true,
            // 10 tokens per second refill rate
            token_refill_rate: 10.0,
            // Bucket can hold 50 tokens (allows bursts)
            token_bucket_capacity: 50,
        }
    }
}

impl RateLimitConfig {
    /// Create strict rate limiting configuration for high-security environments
    pub fn strict() -> Self {
        Self {
            max_attempts_per_ip_per_minute: 10,
            max_attempts_per_ip_per_hour: 50,
            global_max_attempts_per_minute: 200,
            global_max_attempts_per_hour: 1000,
            minute_window: Duration::from_secs(60),
            hour_window: Duration::from_secs(3600),
            cooldown_period: Duration::from_secs(600), // 10 minutes
            enable_token_bucket: true,
            token_refill_rate: 5.0,
            token_bucket_capacity: 20,
        }
    }

    /// Create permissive rate limiting configuration for development/testing
    pub fn permissive() -> Self {
        Self {
            max_attempts_per_ip_per_minute: 100,
            max_attempts_per_ip_per_hour: 1000,
            global_max_attempts_per_minute: 2000,
            global_max_attempts_per_hour: 10000,
            minute_window: Duration::from_secs(60),
            hour_window: Duration::from_secs(3600),
            cooldown_period: Duration::from_secs(60),
            enable_token_bucket: false,
            token_refill_rate: 50.0,
            token_bucket_capacity: 200,
        }
    }
}

/// Token bucket for rate limiting with burst support
#[derive(Debug, Clone)]
pub struct TokenBucket {
    /// Current number of tokens
    tokens: f64,
    /// Maximum token capacity
    capacity: usize,
    /// Token refill rate (tokens per second)
    refill_rate: f64,
    /// Last refill time
    last_refill: Instant,
}

impl TokenBucket {
    /// Create new token bucket
    pub fn new(capacity: usize, refill_rate: f64) -> Self {
        Self {
            tokens: capacity as f64,
            capacity,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    /// Try to consume a token
    pub fn try_consume(&mut self) -> bool {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Refill tokens based on elapsed time
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        let tokens_to_add = elapsed * self.refill_rate;

        self.tokens = (self.tokens + tokens_to_add).min(self.capacity as f64);
        self.last_refill = now;
    }

    /// Get current token count
    pub fn available_tokens(&mut self) -> f64 {
        self.refill();
        self.tokens
    }
}

/// IP-specific rate limiting state
#[derive(Debug, Clone)]
pub struct IpRateLimitState {
    /// Token bucket for this IP
    token_bucket: TokenBucket,
    /// Last violation time
    last_violation: Option<Instant>,
    /// Number of violations
    violation_count: u32,
}

impl IpRateLimitState {
    /// Create new IP rate limit state
    pub fn new(config: &RateLimitConfig) -> Self {
        Self {
            token_bucket: TokenBucket::new(config.token_bucket_capacity, config.token_refill_rate),
            last_violation: None,
            violation_count: 0,
        }
    }

    /// Check if IP is in cooldown
    pub fn is_in_cooldown(&self, cooldown_period: Duration) -> bool {
        if let Some(last_violation) = self.last_violation {
            Instant::now().duration_since(last_violation) < cooldown_period
        } else {
            false
        }
    }

    /// Record a rate limit violation
    pub fn record_violation(&mut self) {
        self.last_violation = Some(Instant::now());
        self.violation_count += 1;
    }
}

impl ConnectionTracker {
    /// Create new connection tracker
    pub fn new() -> Self {
        let config = RateLimitConfig::default();
        Self {
            connection_history: HashMap::new(),
            ip_rate_limits: HashMap::new(),
            global_token_bucket: TokenBucket::new(
                config.token_bucket_capacity,
                config.token_refill_rate,
            ),
            global_attempts: VecDeque::new(),
            rate_limit_config: config,
        }
    }

    /// Create connection tracker with custom configuration
    pub fn with_config(config: RateLimitConfig) -> Self {
        Self {
            connection_history: HashMap::new(),
            ip_rate_limits: HashMap::new(),
            global_token_bucket: TokenBucket::new(
                config.token_bucket_capacity,
                config.token_refill_rate,
            ),
            global_attempts: VecDeque::new(),
            rate_limit_config: config,
        }
    }

    /// Record a connection attempt
    pub fn record_attempt(&mut self, ip: IpAddr, successful: bool, failure_reason: Option<String>) {
        let attempt = ConnectionAttempt {
            timestamp: Instant::now(),
            successful,
            failure_reason,
        };

        // Record in connection history
        self.connection_history
            .entry(ip)
            .or_insert_with(ConnectionHistory::new)
            .add_attempt(attempt);

        // Record global attempt
        self.global_attempts.push_back(Instant::now());

        // Cleanup old global attempts
        self.cleanup_global_attempts();
    }

    /// Check if connection attempt should be allowed (comprehensive check)
    pub fn should_allow_connection(&mut self, ip: IpAddr) -> Result<(), String> {
        // 1. Check if IP is in cooldown period
        if let Some(ip_state) = self.ip_rate_limits.get(&ip) {
            if ip_state.is_in_cooldown(self.rate_limit_config.cooldown_period) {
                warn!(
                    "🛡️ DDOS PROTECTION: IP {} blocked - cooldown period active (violation count: {})",
                    ip, ip_state.violation_count
                );
                return Err(format!(
                    "IP {} is in cooldown period after rate limit violation",
                    ip
                ));
            }
        }

        // 2. Check global rate limits (sliding window)
        if !self.check_global_rate_limits() {
            warn!("🛡️ DDOS PROTECTION: Global rate limit exceeded - blocking new connections");
            return Err("Global rate limit exceeded".to_string());
        }

        // 3. Check global token bucket
        if self.rate_limit_config.enable_token_bucket && !self.global_token_bucket.try_consume() {
            warn!("🛡️ DDOS PROTECTION: Global token bucket exhausted - blocking connection");
            return Err("Global token bucket exhausted".to_string());
        }

        // 4. Check per-IP rate limits (sliding window)
        if let Some(history) = self.connection_history.get(&ip) {
            // Check minute window
            let minute_rate_limited = history.is_rate_limited(
                self.rate_limit_config.max_attempts_per_ip_per_minute,
                self.rate_limit_config.minute_window,
            );
            let hour_rate_limited = history.is_rate_limited(
                self.rate_limit_config.max_attempts_per_ip_per_hour,
                self.rate_limit_config.hour_window,
            );
            let attempts_count = history.attempts.len();

            // Drop the immutable borrow before calling record_ip_violation
            if minute_rate_limited {
                self.record_ip_violation(ip);
                warn!(
                    "🛡️ DDOS PROTECTION: IP {} blocked - exceeded {}/min limit (current: ~{})",
                    ip, self.rate_limit_config.max_attempts_per_ip_per_minute, attempts_count
                );
                return Err(format!(
                    "IP {} exceeded {} connections per minute limit",
                    ip, self.rate_limit_config.max_attempts_per_ip_per_minute
                ));
            }

            // Check hour window
            if hour_rate_limited {
                self.record_ip_violation(ip);
                warn!(
                    "🛡️ DDOS PROTECTION: IP {} blocked - exceeded {}/hour limit",
                    ip, self.rate_limit_config.max_attempts_per_ip_per_hour
                );
                return Err(format!(
                    "IP {} exceeded {} connections per hour limit",
                    ip, self.rate_limit_config.max_attempts_per_ip_per_hour
                ));
            }
        }

        // 5. Check per-IP token bucket
        if self.rate_limit_config.enable_token_bucket {
            let ip_state = self
                .ip_rate_limits
                .entry(ip)
                .or_insert_with(|| IpRateLimitState::new(&self.rate_limit_config));

            if !ip_state.token_bucket.try_consume() {
                self.record_ip_violation(ip);
                warn!(
                    "🛡️ DDOS PROTECTION: IP {} blocked - token bucket exhausted",
                    ip
                );
                return Err(format!("IP {} token bucket exhausted", ip));
            }
        }

        debug!("✅ Connection allowed from {}", ip);
        Ok(())
    }

    /// Check global rate limits
    fn check_global_rate_limits(&self) -> bool {
        let now = Instant::now();

        // Check minute window
        let minute_cutoff = now - self.rate_limit_config.minute_window;
        let minute_count = self
            .global_attempts
            .iter()
            .filter(|&&t| t > minute_cutoff)
            .count();

        if minute_count >= self.rate_limit_config.global_max_attempts_per_minute {
            return false;
        }

        // Check hour window
        let hour_cutoff = now - self.rate_limit_config.hour_window;
        let hour_count = self
            .global_attempts
            .iter()
            .filter(|&&t| t > hour_cutoff)
            .count();

        hour_count < self.rate_limit_config.global_max_attempts_per_hour
    }

    /// Record an IP rate limit violation
    fn record_ip_violation(&mut self, ip: IpAddr) {
        self.ip_rate_limits
            .entry(ip)
            .or_insert_with(|| IpRateLimitState::new(&self.rate_limit_config))
            .record_violation();
    }

    /// Check if IP is rate limited (legacy method for backward compatibility)
    pub fn is_rate_limited(&mut self, ip: IpAddr) -> bool {
        self.should_allow_connection(ip).is_err()
    }

    /// Cleanup old global attempts
    fn cleanup_global_attempts(&mut self) {
        let cutoff = Instant::now() - self.rate_limit_config.hour_window;
        while let Some(&front) = self.global_attempts.front() {
            if front < cutoff {
                self.global_attempts.pop_front();
            } else {
                break;
            }
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
                    self.rate_limit_config.max_attempts_per_ip_per_minute,
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

        // Also cleanup IP rate limit states for IPs with no recent violations
        let violation_cutoff = Instant::now() - self.rate_limit_config.cooldown_period;
        self.ip_rate_limits.retain(|_, state| {
            if let Some(last_violation) = state.last_violation {
                last_violation > violation_cutoff
            } else {
                false // Remove states with no violations
            }
        });
    }

    /// Get IP violation count
    pub fn get_ip_violation_count(&self, ip: IpAddr) -> u32 {
        self.ip_rate_limits
            .get(&ip)
            .map(|state| state.violation_count)
            .unwrap_or(0)
    }

    /// Get IPs currently in cooldown
    pub fn get_ips_in_cooldown(&self) -> Vec<IpAddr> {
        self.ip_rate_limits
            .iter()
            .filter_map(|(ip, state)| {
                if state.is_in_cooldown(self.rate_limit_config.cooldown_period) {
                    Some(*ip)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Get global connection attempt rate (per minute)
    pub fn get_global_connection_rate(&self) -> usize {
        let cutoff = Instant::now() - Duration::from_secs(60);
        self.global_attempts.iter().filter(|&&t| t > cutoff).count()
    }

    /// Get available global tokens
    pub fn get_available_global_tokens(&mut self) -> f64 {
        self.global_token_bucket.available_tokens()
    }

    /// Get available tokens for IP
    pub fn get_available_ip_tokens(&mut self, ip: IpAddr) -> Option<f64> {
        self.ip_rate_limits
            .get_mut(&ip)
            .map(|state| state.token_bucket.available_tokens())
    }

    /// Reset IP rate limit state (for testing or manual intervention)
    pub fn reset_ip_rate_limit(&mut self, ip: IpAddr) {
        self.ip_rate_limits.remove(&ip);
    }

    /// Get rate limit statistics
    pub fn get_rate_limit_stats(&self) -> RateLimitStats {
        RateLimitStats {
            total_ips_tracked: self.connection_history.len(),
            ips_in_cooldown: self.get_ips_in_cooldown().len(),
            total_violations: self
                .ip_rate_limits
                .values()
                .map(|state| state.violation_count as usize)
                .sum(),
            global_attempts_last_minute: {
                let cutoff = Instant::now() - Duration::from_secs(60);
                self.global_attempts.iter().filter(|&&t| t > cutoff).count()
            },
            global_attempts_last_hour: self.global_attempts.len(),
        }
    }
}

/// Rate limit statistics
#[derive(Debug, Clone)]
pub struct RateLimitStats {
    /// Total number of IPs being tracked
    pub total_ips_tracked: usize,
    /// Number of IPs currently in cooldown
    pub ips_in_cooldown: usize,
    /// Total number of rate limit violations
    pub total_violations: usize,
    /// Global connection attempts in last minute
    pub global_attempts_last_minute: usize,
    /// Global connection attempts in last hour
    pub global_attempts_last_hour: usize,
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}
