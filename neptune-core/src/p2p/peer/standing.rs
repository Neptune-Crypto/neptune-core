//! Peer standing and reputation system
//!
//! This module handles peer reputation, sanctions, and standing management.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::SystemTime;

/// Peer standing enumeration
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerStanding {
    /// Good standing
    Good,
    /// Bad standing
    Bad,
    /// Neutral standing
    Neutral,
}

impl PeerStanding {
    /// Check if standing is bad
    pub fn is_bad(&self) -> bool {
        matches!(self, PeerStanding::Bad)
    }

    /// Check if standing is good
    pub fn is_good(&self) -> bool {
        matches!(self, PeerStanding::Good)
    }

    /// Check if standing is neutral
    pub fn is_neutral(&self) -> bool {
        matches!(self, PeerStanding::Neutral)
    }
}

/// Peer reputation score
#[derive(Debug, Clone)]
pub struct ReputationScore {
    /// Current score (0.0 to 1.0)
    pub score: f64,
    /// Last updated time
    pub last_updated: SystemTime,
    /// Number of positive interactions
    pub positive_interactions: u32,
    /// Number of negative interactions
    pub negative_interactions: u32,
}

impl ReputationScore {
    /// Create new reputation score
    pub fn new() -> Self {
        Self {
            score: 0.5, // Start with neutral score
            last_updated: SystemTime::now(),
            positive_interactions: 0,
            negative_interactions: 0,
        }
    }

    /// Update reputation with positive interaction
    pub fn add_positive_interaction(&mut self) {
        self.positive_interactions += 1;
        self.update_score();
        self.last_updated = SystemTime::now();
    }

    /// Update reputation with negative interaction
    pub fn add_negative_interaction(&mut self) {
        self.negative_interactions += 1;
        self.update_score();
        self.last_updated = SystemTime::now();
    }

    /// Update the reputation score based on interactions
    fn update_score(&mut self) {
        let total = self.positive_interactions + self.negative_interactions;
        if total > 0 {
            self.score = f64::from(self.positive_interactions) / f64::from(total);
        }
    }

    /// Get current standing based on score
    pub fn get_standing(&self) -> PeerStanding {
        if self.score >= 0.7 {
            PeerStanding::Good
        } else if self.score <= 0.3 {
            PeerStanding::Bad
        } else {
            PeerStanding::Neutral
        }
    }
}

impl Default for ReputationScore {
    fn default() -> Self {
        Self::new()
    }
}

/// Peer reputation manager
#[derive(Debug, Clone)]
pub struct PeerReputationManager {
    /// Reputation scores by IP address
    reputation_scores: HashMap<IpAddr, ReputationScore>,
    /// Banned IP addresses
    banned_ips: std::collections::HashSet<IpAddr>,
}

impl PeerReputationManager {
    /// Create new reputation manager
    pub fn new() -> Self {
        Self {
            reputation_scores: HashMap::new(),
            banned_ips: std::collections::HashSet::new(),
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
            .or_default()
            .add_positive_interaction();
    }

    /// Update reputation with negative interaction
    pub fn add_negative_interaction(&mut self, ip: IpAddr) {
        self.reputation_scores
            .entry(ip)
            .or_default()
            .add_negative_interaction();
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
}

impl Default for PeerReputationManager {
    fn default() -> Self {
        Self::new()
    }
}
