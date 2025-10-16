//! Reputation management implementation
//!
//! This module handles comprehensive peer reputation and IP reputation systems
//! with behavior tracking, automatic scoring, and dynamic ban management.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant, SystemTime};

use crate::p2p::peer::standing::{PeerStanding, ReputationScore};

/// Behavior event types for reputation scoring
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BehaviorEvent {
    /// Successful connection
    SuccessfulConnection,
    /// Failed connection attempt
    FailedConnection,
    /// Malformed handshake
    MalformedHandshake,
    /// Rate limit violation
    RateLimitViolation,
    /// Sent invalid message
    InvalidMessage,
    /// Successful block propagation
    BlockPropagation,
    /// Successful transaction relay
    TransactionRelay,
    /// Connection timeout
    ConnectionTimeout,
    /// Unexpected disconnect
    UnexpectedDisconnect,
    /// Protocol violation
    ProtocolViolation,
}

impl BehaviorEvent {
    /// Get reputation impact score for this event
    pub fn reputation_impact(&self) -> f64 {
        match self {
            // Positive events
            BehaviorEvent::SuccessfulConnection => 0.01,
            BehaviorEvent::BlockPropagation => 0.05,
            BehaviorEvent::TransactionRelay => 0.02,

            // Negative events
            BehaviorEvent::FailedConnection => -0.02,
            BehaviorEvent::MalformedHandshake => -0.10,
            BehaviorEvent::RateLimitViolation => -0.15,
            BehaviorEvent::InvalidMessage => -0.20,
            BehaviorEvent::ConnectionTimeout => -0.05,
            BehaviorEvent::UnexpectedDisconnect => -0.03,
            BehaviorEvent::ProtocolViolation => -0.25,
        }
    }

    /// Check if this event should trigger immediate action
    pub fn is_severe(&self) -> bool {
        matches!(
            self,
            BehaviorEvent::RateLimitViolation
                | BehaviorEvent::InvalidMessage
                | BehaviorEvent::ProtocolViolation
        )
    }
}

/// Timestamped behavior event
#[derive(Debug, Clone)]
pub struct TimestampedEvent {
    /// Event type
    pub event: BehaviorEvent,
    /// Event timestamp
    pub timestamp: Instant,
}

/// Enhanced IP reputation data
#[derive(Debug, Clone)]
pub struct IpReputationData {
    /// Current reputation score (0.0 - 1.0)
    pub score: f64,
    /// Behavior history
    pub behavior_history: VecDeque<TimestampedEvent>,
    /// First seen time
    pub first_seen: Instant,
    /// Last seen time
    pub last_seen: Instant,
    /// Number of connections
    pub connection_count: u32,
    /// Number of violations
    pub violation_count: u32,
    /// Whether IP is temporarily banned
    pub temp_banned: bool,
    /// Temporary ban expiration
    pub temp_ban_until: Option<Instant>,
    /// Whether IP is permanently banned
    pub perm_banned: bool,
}

impl IpReputationData {
    /// Create new IP reputation data
    pub fn new() -> Self {
        Self {
            score: 0.5, // Start with neutral score
            behavior_history: VecDeque::new(),
            first_seen: Instant::now(),
            last_seen: Instant::now(),
            connection_count: 0,
            violation_count: 0,
            temp_banned: false,
            temp_ban_until: None,
            perm_banned: false,
        }
    }

    /// Record a behavior event
    pub fn record_event(&mut self, event: BehaviorEvent) {
        // Add to history
        self.behavior_history.push_back(TimestampedEvent {
            event,
            timestamp: Instant::now(),
        });

        // Keep only last 100 events
        if self.behavior_history.len() > 100 {
            self.behavior_history.pop_front();
        }

        // Update score
        let impact = event.reputation_impact();
        self.score = (self.score + impact).clamp(0.0, 1.0);

        // Update last seen
        self.last_seen = Instant::now();

        // Track violations
        if impact < 0.0 {
            self.violation_count += 1;
        }
    }

    /// Check if IP is currently banned (temp or perm)
    pub fn is_banned(&self) -> bool {
        if self.perm_banned {
            return true;
        }

        if self.temp_banned {
            if let Some(until) = self.temp_ban_until {
                return Instant::now() < until;
            }
        }

        false
    }

    /// Apply temporary ban
    pub fn apply_temp_ban(&mut self, duration: Duration) {
        self.temp_banned = true;
        self.temp_ban_until = Some(Instant::now() + duration);
    }

    /// Apply permanent ban
    pub fn apply_perm_ban(&mut self) {
        self.perm_banned = true;
    }

    /// Lift temporary ban
    pub fn lift_temp_ban(&mut self) {
        self.temp_banned = false;
        self.temp_ban_until = None;
    }

    /// Get recent violation count (last hour)
    pub fn get_recent_violations(&self, window: Duration) -> usize {
        let cutoff = Instant::now() - window;
        self.behavior_history
            .iter()
            .filter(|e| e.timestamp > cutoff && e.event.reputation_impact() < 0.0)
            .count()
    }

    /// Get reputation standing
    pub fn get_standing(&self) -> PeerStanding {
        if self.is_banned() {
            return PeerStanding::Bad;
        }

        if self.score >= 0.7 {
            PeerStanding::Good
        } else if self.score >= 0.3 {
            PeerStanding::Neutral
        } else {
            PeerStanding::Bad
        }
    }

    /// Apply time-based reputation decay
    pub fn apply_decay(&mut self, decay_rate: f64) {
        // Gradual decay towards neutral (0.5)
        if self.score > 0.5 {
            self.score = (self.score - decay_rate).max(0.5);
        } else if self.score < 0.5 {
            self.score = (self.score + decay_rate).min(0.5);
        }
    }
}

impl Default for IpReputationData {
    fn default() -> Self {
        Self::new()
    }
}

/// Reputation manager for peer reputation
#[derive(Debug, Clone)]
pub struct ReputationManager {
    /// IP reputation data
    ip_reputations: HashMap<IpAddr, IpReputationData>,
    /// Reputation configuration
    config: ReputationConfig,
}

/// Reputation configuration
#[derive(Debug, Clone)]
pub struct ReputationConfig {
    /// Minimum reputation score to accept connections
    pub min_reputation_score: f64,
    /// Reputation decay rate (per decay cycle)
    pub reputation_decay_rate: f64,
    /// Whether to enable automatic temporary banning
    pub enable_auto_temp_ban: bool,
    /// Whether to enable automatic permanent banning
    pub enable_auto_perm_ban: bool,
    /// Reputation threshold for temporary ban
    pub temp_ban_threshold: f64,
    /// Reputation threshold for permanent ban
    pub perm_ban_threshold: f64,
    /// Temporary ban duration
    pub temp_ban_duration: Duration,
    /// Violations in window to trigger temp ban
    pub temp_ban_violation_threshold: usize,
    /// Violations in window to trigger perm ban
    pub perm_ban_violation_threshold: usize,
    /// Violation tracking window
    pub violation_window: Duration,
}

impl Default for ReputationConfig {
    fn default() -> Self {
        Self {
            // Require at least neutral standing (0.3)
            min_reputation_score: 0.3,
            // Slow decay rate (per hour)
            reputation_decay_rate: 0.01,
            // Enable automatic temporary banning
            enable_auto_temp_ban: true,
            // Disable automatic permanent banning by default (requires manual review)
            enable_auto_perm_ban: false,
            // Temp ban at 0.2 reputation
            temp_ban_threshold: 0.2,
            // Perm ban at 0.1 reputation
            perm_ban_threshold: 0.1,
            // 1 hour temporary ban
            temp_ban_duration: Duration::from_secs(3600),
            // 10 violations in 1 hour triggers temp ban
            temp_ban_violation_threshold: 10,
            // 50 violations in 1 hour triggers perm ban
            perm_ban_violation_threshold: 50,
            // 1 hour violation tracking window
            violation_window: Duration::from_secs(3600),
        }
    }
}

impl ReputationConfig {
    /// Create strict reputation configuration
    pub fn strict() -> Self {
        Self {
            min_reputation_score: 0.5,
            reputation_decay_rate: 0.005,
            enable_auto_temp_ban: true,
            enable_auto_perm_ban: true,
            temp_ban_threshold: 0.3,
            perm_ban_threshold: 0.15,
            temp_ban_duration: Duration::from_secs(7200), // 2 hours
            temp_ban_violation_threshold: 5,
            perm_ban_violation_threshold: 20,
            violation_window: Duration::from_secs(3600),
        }
    }

    /// Create permissive reputation configuration
    pub fn permissive() -> Self {
        Self {
            min_reputation_score: 0.1,
            reputation_decay_rate: 0.02,
            enable_auto_temp_ban: true,
            enable_auto_perm_ban: false,
            temp_ban_threshold: 0.05,
            perm_ban_threshold: 0.01,
            temp_ban_duration: Duration::from_secs(600), // 10 minutes
            temp_ban_violation_threshold: 20,
            perm_ban_violation_threshold: 100,
            violation_window: Duration::from_secs(3600),
        }
    }
}

impl ReputationManager {
    /// Create new reputation manager
    pub fn new() -> Self {
        Self {
            ip_reputations: HashMap::new(),
            config: ReputationConfig::default(),
        }
    }

    /// Create reputation manager with custom configuration
    pub fn with_config(config: ReputationConfig) -> Self {
        Self {
            ip_reputations: HashMap::new(),
            config,
        }
    }

    /// Record a behavior event for an IP
    pub fn record_behavior(&mut self, ip: IpAddr, event: BehaviorEvent) {
        let rep_data = self
            .ip_reputations
            .entry(ip)
            .or_insert_with(IpReputationData::new);

        rep_data.record_event(event);

        // Check for automatic banning
        self.check_automatic_banning(ip);
    }

    /// Check and apply automatic banning based on reputation and violations
    fn check_automatic_banning(&mut self, ip: IpAddr) {
        let should_ban = if let Some(rep_data) = self.ip_reputations.get(ip) {
            let recent_violations = rep_data.get_recent_violations(self.config.violation_window);

            // Check for temporary ban
            let should_temp_ban = self.config.enable_auto_temp_ban
                && (rep_data.score <= self.config.temp_ban_threshold
                    || recent_violations >= self.config.temp_ban_violation_threshold);

            // Check for permanent ban
            let should_perm_ban = self.config.enable_auto_perm_ban
                && (rep_data.score <= self.config.perm_ban_threshold
                    || recent_violations >= self.config.perm_ban_violation_threshold);

            (should_temp_ban, should_perm_ban)
        } else {
            (false, false)
        };

        if should_ban.1 {
            // Permanent ban
            self.apply_permanent_ban(ip);
        } else if should_ban.0 {
            // Temporary ban
            self.apply_temporary_ban(ip, self.config.temp_ban_duration);
        }
    }

    /// Apply temporary ban to an IP
    pub fn apply_temporary_ban(&mut self, ip: IpAddr, duration: Duration) {
        if let Some(rep_data) = self.ip_reputations.get_mut(&ip) {
            rep_data.apply_temp_ban(duration);
            tracing::warn!("Applied temporary ban to IP {} for {:?}", ip, duration);
        }
    }

    /// Apply permanent ban to an IP
    pub fn apply_permanent_ban(&mut self, ip: IpAddr) {
        self.ip_reputations
            .entry(ip)
            .or_insert_with(IpReputationData::new)
            .apply_perm_ban();
        tracing::warn!("Applied permanent ban to IP {}", ip);
    }

    /// Lift temporary ban from an IP
    pub fn lift_temporary_ban(&mut self, ip: IpAddr) {
        if let Some(rep_data) = self.ip_reputations.get_mut(&ip) {
            rep_data.lift_temp_ban();
            tracing::info!("Lifted temporary ban from IP {}", ip);
        }
    }

    /// Check if IP is currently banned
    pub fn is_banned(&self, ip: IpAddr) -> bool {
        self.ip_reputations
            .get(&ip)
            .map(|data| data.is_banned())
            .unwrap_or(false)
    }

    /// Check if connection should be allowed based on reputation
    pub fn should_allow_connection(&mut self, ip: IpAddr) -> Result<(), String> {
        // Check for existing reputation data
        if let Some(rep_data) = self.ip_reputations.get_mut(&ip) {
            // Check if banned
            if rep_data.is_banned() {
                return Err(format!("IP {} is banned", ip));
            }

            // Check minimum reputation
            if rep_data.score < self.config.min_reputation_score {
                return Err(format!(
                    "IP {} has insufficient reputation: {:.2} < {:.2}",
                    ip, rep_data.score, self.config.min_reputation_score
                ));
            }

            // Update connection count
            rep_data.connection_count += 1;
            rep_data.last_seen = Instant::now();
        }
        // else: unknown IP, allow (will start with neutral score)

        Ok(())
    }

    /// Get reputation score for IP
    pub fn get_reputation_score(&self, ip: IpAddr) -> f64 {
        self.ip_reputations
            .get(&ip)
            .map(|data| data.score)
            .unwrap_or(0.5) // Neutral for unknown IPs
    }

    /// Get reputation data for IP
    pub fn get_reputation_data(&self, ip: IpAddr) -> Option<&IpReputationData> {
        self.ip_reputations.get(&ip)
    }

    /// Get standing for IP
    pub fn get_standing(&self, ip: IpAddr) -> PeerStanding {
        self.ip_reputations
            .get(&ip)
            .map(|data| data.get_standing())
            .unwrap_or(PeerStanding::Neutral)
    }

    /// Get all banned IPs
    pub fn get_banned_ips(&self) -> Vec<IpAddr> {
        self.ip_reputations
            .iter()
            .filter_map(|(ip, data)| if data.is_banned() { Some(*ip) } else { None })
            .collect()
    }

    /// Get all temporarily banned IPs
    pub fn get_temp_banned_ips(&self) -> Vec<IpAddr> {
        self.ip_reputations
            .iter()
            .filter_map(|(ip, data)| {
                if data.temp_banned && !data.perm_banned {
                    Some(*ip)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Get all permanently banned IPs
    pub fn get_perm_banned_ips(&self) -> Vec<IpAddr> {
        self.ip_reputations
            .iter()
            .filter_map(|(ip, data)| if data.perm_banned { Some(*ip) } else { None })
            .collect()
    }

    /// Apply reputation decay to all IPs
    pub fn apply_decay(&mut self) {
        let decay_rate = self.config.reputation_decay_rate;
        for rep_data in self.ip_reputations.values_mut() {
            rep_data.apply_decay(decay_rate);
        }
    }

    /// Clean up old reputation data
    pub fn cleanup_old_data(&mut self) {
        let cutoff = Instant::now() - Duration::from_secs(86400 * 7); // 7 days

        self.ip_reputations.retain(|_, data| {
            // Keep if:
            // - Permanently banned
            // - Temporarily banned
            // - Recently seen (within 7 days)
            // - Has significant reputation (very good or very bad)
            data.perm_banned
                || data.temp_banned
                || data.last_seen > cutoff
                || data.score > 0.8
                || data.score < 0.2
        });
    }

    /// Get reputation statistics
    pub fn get_stats(&self) -> ReputationStats {
        let mut good_count = 0;
        let mut neutral_count = 0;
        let mut bad_count = 0;
        let mut temp_banned = 0;
        let mut perm_banned = 0;

        for data in self.ip_reputations.values() {
            match data.get_standing() {
                PeerStanding::Good => good_count += 1,
                PeerStanding::Neutral => neutral_count += 1,
                PeerStanding::Bad => bad_count += 1,
            }

            if data.perm_banned {
                perm_banned += 1;
            } else if data.temp_banned {
                temp_banned += 1;
            }
        }

        ReputationStats {
            total_ips_tracked: self.ip_reputations.len(),
            good_reputation_count: good_count,
            neutral_reputation_count: neutral_count,
            bad_reputation_count: bad_count,
            temp_banned_count: temp_banned,
            perm_banned_count: perm_banned,
        }
    }

    /// Get configuration
    pub fn get_config(&self) -> &ReputationConfig {
        &self.config
    }

    /// Update configuration
    pub fn update_config(&mut self, config: ReputationConfig) {
        self.config = config;
    }
}

/// Reputation statistics
#[derive(Debug, Clone)]
pub struct ReputationStats {
    /// Total IPs being tracked
    pub total_ips_tracked: usize,
    /// IPs with good reputation
    pub good_reputation_count: usize,
    /// IPs with neutral reputation
    pub neutral_reputation_count: usize,
    /// IPs with bad reputation
    pub bad_reputation_count: usize,
    /// Temporarily banned IPs
    pub temp_banned_count: usize,
    /// Permanently banned IPs
    pub perm_banned_count: usize,
}

impl Default for ReputationManager {
    fn default() -> Self {
        Self::new()
    }
}
