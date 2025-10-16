//! Reputation management implementation
//!
//! This module handles peer reputation and IP reputation systems.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::SystemTime;

use crate::p2p::peer::standing::{PeerStanding, ReputationScore};

/// Reputation manager for peer reputation
#[derive(Debug, Clone)]
pub struct ReputationManager {
    /// Reputation scores by IP address
    reputation_scores: HashMap<IpAddr, ReputationScore>,
    /// Banned IP addresses
    banned_ips: HashSet<IpAddr>,
    /// Reputation configuration
    config: ReputationConfig,
}

/// Reputation configuration
#[derive(Debug, Clone)]
pub struct ReputationConfig {
    /// Minimum reputation score to accept connections
    pub min_reputation_score: f64,
    /// Reputation decay rate (per hour)
    pub reputation_decay_rate: f64,
    /// Whether to enable automatic banning
    pub enable_automatic_banning: bool,
    /// Reputation threshold for automatic banning
    pub ban_threshold: f64,
}

impl Default for ReputationConfig {
    fn default() -> Self {
        Self {
            min_reputation_score: 0.5,
            reputation_decay_rate: 0.1,
            enable_automatic_banning: true,
            ban_threshold: 0.1,
        }
    }
}

impl ReputationManager {
    /// Create new reputation manager
    pub fn new() -> Self {
        Self {
            reputation_scores: HashMap::new(),
            banned_ips: HashSet::new(),
            config: ReputationConfig::default(),
        }
    }

    /// Get reputation score for IP
    pub fn get_reputation(&self, ip: IpAddr) -> Option<&ReputationScore> {
        self.reputation_scores.get(&ip)
    }

    /// Update reputation with positive interaction
    pub fn add_positive_interaction(&mut self, ip: IpAddr) {
        self.reputation_scores
            .entry(ip)
            .or_insert_with(ReputationScore::new)
            .add_positive_interaction();
    }

    /// Update reputation with negative interaction
    pub fn add_negative_interaction(&mut self, ip: IpAddr) {
        self.reputation_scores
            .entry(ip)
            .or_insert_with(ReputationScore::new)
            .add_negative_interaction();

        // Check for automatic banning
        if self.config.enable_automatic_banning {
            if let Some(score) = self.reputation_scores.get(&ip) {
                if score.score <= self.config.ban_threshold {
                    self.ban_ip(ip);
                }
            }
        }
    }

    /// Ban an IP address
    pub fn ban_ip(&mut self, ip: IpAddr) {
        self.banned_ips.insert(ip);
    }

    /// Unban an IP address
    pub fn unban_ip(&mut self, ip: IpAddr) {
        self.banned_ips.remove(&ip);
    }

    /// Check if IP is banned
    pub fn is_banned(&self, ip: IpAddr) -> bool {
        self.banned_ips.contains(&ip)
    }

    /// Get standing for IP
    pub fn get_standing(&self, ip: IpAddr) -> PeerStanding {
        if self.is_banned(ip) {
            return PeerStanding::Bad;
        }

        self.reputation_scores
            .get(&ip)
            .map(|score| score.get_standing())
            .unwrap_or(PeerStanding::Neutral)
    }

    /// Check if IP meets minimum reputation requirement
    pub fn meets_minimum_reputation(&self, ip: IpAddr) -> bool {
        if self.is_banned(ip) {
            return false;
        }

        self.reputation_scores
            .get(&ip)
            .map(|score| score.score >= self.config.min_reputation_score)
            .unwrap_or(true) // Allow unknown IPs
    }

    /// Get reputation configuration
    pub fn get_config(&self) -> &ReputationConfig {
        &self.config
    }

    /// Update reputation configuration
    pub fn update_config(&mut self, config: ReputationConfig) {
        self.config = config;
    }

    /// Get all banned IPs
    pub fn get_banned_ips(&self) -> &HashSet<IpAddr> {
        &self.banned_ips
    }

    /// Apply reputation decay
    pub fn apply_decay(&mut self) {
        let decay_rate = self.config.reputation_decay_rate;
        for score in self.reputation_scores.values_mut() {
            // Apply exponential decay
            score.score *= 1.0 - decay_rate;

            // Ensure score stays within bounds
            score.score = score.score.max(0.0).min(1.0);
        }
    }

    /// Clean up old reputation data
    pub fn cleanup_old_data(&mut self) {
        // Remove reputation scores that are too low and not banned
        self.reputation_scores
            .retain(|ip, score| score.score > 0.01 || self.banned_ips.contains(ip));
    }
}

impl Default for ReputationManager {
    fn default() -> Self {
        Self::new()
    }
}
