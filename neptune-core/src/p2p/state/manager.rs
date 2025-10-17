//! P2P state manager implementation
//!
//! This module provides centralized P2P state management.
//!
//! MIGRATED FROM: src/state/networking_state.rs:77-218
//! This code was transplanted from the NetworkingState struct to provide
//! modular P2P state management with enhanced DDoS protection.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::RwLock;

use anyhow::Result;
use tasm_lib::prelude::Digest;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;

use super::{ConnectionTracker, PeerMap, ReputationManager};
use crate::application::config::data_directory::DataDirectory;
use crate::p2p::config::P2PConfig;
use crate::protocol::consensus::block::block_height::BlockHeight;
use crate::protocol::consensus::block::difficulty_control::ProofOfWork;
use crate::protocol::peer::peer_info::PeerInfo;
use crate::protocol::peer::InstanceId;
use crate::protocol::peer::PeerStanding;
// use crate::state::database::PeerDatabases; // Temporarily disabled for type compatibility
use crate::state::GlobalState;

/// Shared P2P state manager type for thread-safe access
pub type SharedP2PStateManager = Arc<RwLock<P2PStateManager>>;

/// Temporary PeerDatabases struct for type compatibility
#[derive(Debug, Clone)]
pub struct PeerDatabases {
    pub peer_standings: HashMap<IpAddr, PeerStanding>,
}

/// Information about a foreign tip towards which the client is syncing.
///
/// MIGRATED FROM: src/state/networking_state.rs:25-72
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SyncAnchor {
    /// Cumulative proof-of-work number of the target fork that we are syncing
    /// towards. This number is immutable for each `SyncAnchor`.
    pub cumulative_proof_of_work: ProofOfWork,

    /// The block MMR accumulator *after* appending the claimed tip digest. This
    /// value is immutable for each `SyncAnchor`.
    pub block_mmr: MmrAccumulator,

    /// Indicates the block that we have currently synced to under this anchor.
    pub champion: Option<(BlockHeight, Digest)>,

    /// The last time this anchor was either created or updated.
    pub updated: SystemTime,
}

impl SyncAnchor {
    /// Create new sync anchor
    ///
    /// MIGRATED FROM: src/state/networking_state.rs:43-54
    pub fn new(claimed_cumulative_pow: ProofOfWork, claimed_block_mmra: MmrAccumulator) -> Self {
        Self {
            cumulative_proof_of_work: claimed_cumulative_pow,
            block_mmr: claimed_block_mmra,
            champion: None,
            updated: SystemTime::now(),
        }
    }

    /// Update sync anchor with new champion
    ///
    /// MIGRATED FROM: src/state/networking_state.rs:56-71
    pub fn catch_up(&mut self, height: BlockHeight, block_hash: Digest) {
        let new_champion = Some((height, block_hash));
        let updated = SystemTime::now();
        match self.champion {
            Some((current_height, _)) => {
                if current_height < height {
                    self.champion = new_champion;
                    self.updated = updated;
                }
            }
            None => {
                self.champion = new_champion;
                self.updated = updated;
            }
        };
    }
}

/// P2P state manager
///
/// MIGRATED FROM: src/state/networking_state.rs:77-109
/// This replaces the NetworkingState struct with modular P2P state management
#[derive(Debug, Clone)]
pub struct P2PStateManager {
    /// P2P configuration
    config: P2PConfig,
    /// Map of connected peers
    peer_map: PeerMap,
    /// Connection tracker for DDoS protection
    connection_tracker: ConnectionTracker,
    /// Reputation manager for peer standing
    reputation_manager: ReputationManager,
    /// Peer databases for persistent storage
    peer_databases: PeerDatabases,
    /// Sync anchor for archival nodes
    sync_anchor: Option<SyncAnchor>,
    /// Instance ID for this node
    instance_id: u128,
    /// Whether the node is frozen (no P2P operations)
    freeze: bool,
    /// Disconnection times of past peers
    disconnection_times: HashMap<InstanceId, SystemTime>,
}

impl P2PStateManager {
    /// Create new P2P state manager
    ///
    /// MIGRATED FROM: src/state/networking_state.rs:111-121
    pub fn new(config: P2PConfig, instance_id: u128) -> Self {
        Self {
            config,
            peer_map: PeerMap::new(),
            connection_tracker: ConnectionTracker::new(),
            reputation_manager: ReputationManager::new(),
            peer_databases: PeerDatabases {
                peer_standings: HashMap::new(), // TODO: Initialize with proper NeptuneLevelDb
            },
            sync_anchor: None,
            instance_id,
            freeze: false,
            disconnection_times: HashMap::new(),
        }
    }

    /// Create P2P state manager from global state
    ///
    /// This method migrates existing networking state to the new P2P structure
    pub fn from_global_state(global_state: &GlobalState) -> Self {
        let config = P2PConfig::default(); // TODO: Extract from CLI args
        let instance_id = global_state.net.instance_id;

        let mut manager = Self::new(config, instance_id);

        // Migrate peer map
        for (addr, peer_info) in &global_state.net.peer_map {
            manager.peer_map.insert(*addr, peer_info.clone());
        }

        // TODO: Migrate peer databases - type mismatch between p2p::state::manager::PeerDatabases and state::database::PeerDatabases
        // manager.peer_databases = global_state.net.peer_databases.clone();

        // TODO: Migrate sync anchor - type mismatch between p2p::state::manager::SyncAnchor and networking_state::SyncAnchor
        // manager.sync_anchor = global_state.net.sync_anchor.clone();

        // Migrate freeze state
        manager.freeze = global_state.net.freeze;

        // TODO: Migrate disconnection times - private field
        // manager.disconnection_times = global_state.net.disconnection_times.clone();

        manager
    }

    /// Initialize peer databases
    ///
    /// MIGRATED FROM: src/state/networking_state.rs:123-135
    pub async fn initialize_peer_databases(_data_dir: &DataDirectory) -> Result<PeerDatabases> {
        // TODO: Initialize with proper NeptuneLevelDb when type compatibility is resolved
        Ok(PeerDatabases {
            peer_standings: HashMap::new(),
        })
    }

    /// Add a peer to the state
    pub fn add_peer(&mut self, peer_info: PeerInfo) {
        let address = peer_info.connected_address();
        self.peer_map.insert(address, peer_info);

        // Record successful connection
        self.reputation_manager.record_behavior(
            address.ip(),
            crate::p2p::state::reputation::BehaviorEvent::SuccessfulConnection,
        );
        self.connection_tracker
            .record_attempt(address.ip(), true, None);
    }

    /// Remove a peer from the state
    pub fn remove_peer(&mut self, address: SocketAddr) -> Option<PeerInfo> {
        if let Some(peer_info) = self.peer_map.remove(&address) {
            // Record disconnection time
            self.disconnection_times
                .insert(peer_info.instance_id(), SystemTime::now());
            Some(peer_info)
        } else {
            None
        }
    }

    /// Get peer by address
    pub fn get_peer(&self, address: SocketAddr) -> Option<&PeerInfo> {
        self.peer_map.get(&address)
    }

    /// Get all connected peers
    pub fn get_all_peers(&self) -> &PeerMap {
        &self.peer_map
    }

    /// Check if peer is connected
    pub fn is_peer_connected(&self, address: SocketAddr) -> bool {
        self.peer_map.contains_key(&address)
    }

    /// Get number of connected peers
    pub fn peer_count(&self) -> usize {
        self.peer_map.len()
    }

    /// Set freeze state
    pub fn set_freeze(&mut self, freeze: bool) {
        self.freeze = freeze;
    }

    /// Check if frozen
    pub fn is_frozen(&self) -> bool {
        self.freeze
    }

    /// Get sync anchor
    pub fn get_sync_anchor(&self) -> &Option<SyncAnchor> {
        &self.sync_anchor
    }

    /// Set sync anchor
    pub fn set_sync_anchor(&mut self, anchor: Option<SyncAnchor>) {
        self.sync_anchor = anchor;
    }

    /// Register peer disconnection
    ///
    /// MIGRATED FROM: src/state/networking_state.rs:211-213
    pub fn register_peer_disconnection(&mut self, id: InstanceId, time: SystemTime) {
        self.disconnection_times.insert(id, time);
    }

    /// Get last disconnection time for a peer
    ///
    /// MIGRATED FROM: src/state/networking_state.rs:215-217
    pub fn last_disconnection_time_of_peer(&self, id: InstanceId) -> Option<SystemTime> {
        self.disconnection_times.get(&id).copied()
    }

    /// Get peer standing from database
    ///
    /// MIGRATED FROM: src/state/networking_state.rs:151-153
    pub async fn get_peer_standing_from_database(&self, ip: IpAddr) -> Option<PeerStanding> {
        self.peer_databases.peer_standings.get(&ip).copied()
    }

    /// Clear IP standing in database
    ///
    /// MIGRATED FROM: src/state/networking_state.rs:155-163
    pub async fn clear_ip_standing_in_database(&mut self, ip: IpAddr) {
        if let Some(mut standing) = self.peer_databases.peer_standings.get(&ip).copied() {
            standing.clear_standing();
            self.peer_databases.peer_standings.insert(ip, standing);
        }
    }

    /// Clear all standings in database
    ///
    /// MIGRATED FROM: src/state/networking_state.rs:165-182
    pub async fn clear_all_standings_in_database(&mut self) {
        // Clear all standings in HashMap
        for (_, standing) in &mut self.peer_databases.peer_standings {
            standing.clear_standing();
        }
    }

    /// Write peer standing on decrease
    ///
    /// MIGRATED FROM: src/state/networking_state.rs:187-200
    pub async fn write_peer_standing_on_decrease(
        &mut self,
        ip: IpAddr,
        current_standing: PeerStanding,
    ) {
        let old_standing = self.peer_databases.peer_standings.get(&ip).copied();

        if old_standing.is_none() || old_standing.unwrap().standing > current_standing.standing {
            self.peer_databases
                .peer_standings
                .insert(ip, current_standing);
        }
    }

    /// Get all peer sanctions in database
    ///
    /// MIGRATED FROM: src/state/networking_state.rs:137-149
    pub fn all_peer_sanctions_in_database(&self) -> HashMap<IpAddr, PeerStanding> {
        let mut sanctions = HashMap::default();

        let mut dbiterator = self.peer_databases.peer_standings.iter();
        for (ip, standing) in dbiterator.by_ref() {
            if standing.is_negative() {
                sanctions.insert(*ip, *standing);
            }
        }

        sanctions
    }

    /// Check if connection is allowed (enhanced DDoS protection)
    pub fn is_connection_allowed(&mut self, address: SocketAddr) -> bool {
        // Check if frozen
        if self.freeze {
            return false;
        }

        // Check if peer is already connected
        if self.is_peer_connected(address) {
            return false;
        }

        // Check if IP is banned
        if self.reputation_manager.is_banned(address.ip()) {
            return false;
        }

        // Check if IP meets minimum reputation
        if self
            .reputation_manager
            .should_allow_connection(address.ip())
            .is_err()
        {
            return false;
        }

        // Check if rate limited
        if self.connection_tracker.is_rate_limited(address.ip()) {
            return false;
        }

        // Check max peers limit
        if self.peer_count() >= self.config.connection.max_num_peers {
            return false;
        }

        // Check max connections per IP
        if let Some(max_per_ip) = self.config.connection.max_connections_per_ip {
            let connections_to_ip = self
                .peer_map
                .keys()
                .filter(|addr| addr.ip() == address.ip())
                .count();
            if connections_to_ip >= max_per_ip {
                return false;
            }
        }

        true
    }

    /// Record connection attempt
    pub fn record_connection_attempt(
        &mut self,
        address: SocketAddr,
        successful: bool,
        failure_reason: Option<String>,
    ) {
        self.connection_tracker
            .record_attempt(address.ip(), successful, failure_reason);

        // Record behavior in reputation system
        let event = if successful {
            crate::p2p::state::reputation::BehaviorEvent::SuccessfulConnection
        } else {
            crate::p2p::state::reputation::BehaviorEvent::FailedConnection
        };
        self.reputation_manager.record_behavior(address.ip(), event);
    }

    /// Check if IP is rate limited
    pub fn is_rate_limited(&mut self, ip: IpAddr) -> bool {
        self.connection_tracker.is_rate_limited(ip)
    }

    /// Check if message is rate limited
    pub fn is_message_rate_limited(&self, _ip: IpAddr) -> bool {
        // TODO: Implement message rate limiting
        false
    }

    /// Get connection statistics
    pub fn get_total_connections(&self) -> usize {
        self.connection_tracker.get_total_connections()
    }

    /// Get failed connections count
    pub fn get_failed_connections(&self) -> usize {
        self.connection_tracker.get_failed_connections()
    }

    /// Get rate limited connections count
    pub fn get_rate_limited_connections(&self) -> usize {
        self.connection_tracker.get_rate_limited_connections()
    }

    /// Get total messages processed
    pub fn get_total_messages_processed(&self) -> usize {
        // TODO: Implement message tracking
        0
    }

    /// Get rate limited messages count
    pub fn get_rate_limited_messages(&self) -> usize {
        // TODO: Implement message tracking
        0
    }

    /// Get invalid messages count
    pub fn get_invalid_messages(&self) -> usize {
        // TODO: Implement message tracking
        0
    }

    /// Get connection tracker
    pub fn get_connection_tracker(&self) -> &ConnectionTracker {
        &self.connection_tracker
    }

    /// Get mutable connection tracker
    pub fn get_connection_tracker_mut(&mut self) -> &mut ConnectionTracker {
        &mut self.connection_tracker
    }

    /// Get reputation manager
    pub fn get_reputation_manager(&self) -> &ReputationManager {
        &self.reputation_manager
    }

    /// Get mutable reputation manager
    pub fn get_reputation_manager_mut(&mut self) -> &mut ReputationManager {
        &mut self.reputation_manager
    }

    /// Get P2P configuration
    pub fn get_config(&self) -> &P2PConfig {
        &self.config
    }

    /// Get instance ID
    pub fn get_instance_id(&self) -> u128 {
        self.instance_id
    }

    /// Get peer databases
    pub fn get_peer_databases(&self) -> &PeerDatabases {
        &self.peer_databases
    }

    /// Get mutable peer databases
    pub fn get_peer_databases_mut(&mut self) -> &mut PeerDatabases {
        &mut self.peer_databases
    }

    /// Cleanup old data
    pub fn cleanup_old_data(&mut self) {
        self.connection_tracker.cleanup_old_history();
        self.reputation_manager.cleanup_old_data();
    }

    /// Sync with global state
    ///
    /// This method keeps the global state in sync with P2P state changes
    pub fn sync_with_global_state(&self, global_state: &mut GlobalState) {
        // Update peer map - convert PeerMap to HashMap
        global_state.net.peer_map = self.peer_map.to_hashmap();

        // TODO: Update peer databases - type mismatch
        // global_state.net.peer_databases = self.peer_databases.clone();

        // TODO: Update sync anchor - type mismatch
        // global_state.net.sync_anchor = self.sync_anchor.clone();

        // Update freeze state
        global_state.net.freeze = self.freeze;

        // TODO: Update disconnection times - private field
        // global_state.net.disconnection_times = self.disconnection_times.clone();
    }
}
