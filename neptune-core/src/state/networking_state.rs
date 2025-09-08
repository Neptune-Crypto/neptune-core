use std::collections::HashMap;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::time::SystemTime;

use anyhow::Result;
use tasm_lib::prelude::Digest;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;

use crate::application::config::data_directory::DataDirectory;
use crate::application::database::create_db_if_missing;
use crate::application::database::NeptuneLevelDb;
use crate::application::database::WriteBatchAsync;
use crate::protocol::consensus::block::block_height::BlockHeight;
use crate::protocol::consensus::block::difficulty_control::ProofOfWork;
use crate::protocol::peer::peer_info::PeerInfo;
use crate::protocol::peer::InstanceId;
use crate::protocol::peer::PeerStanding;
use crate::state::database::PeerDatabases;

pub const BANNED_IPS_DB_NAME: &str = "banned_ips";

type PeerMap = HashMap<SocketAddr, PeerInfo>;

/// Information about a foreign tip towards which the client is syncing.
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct SyncAnchor {
    /// Cumulative proof-of-work number of the target fork that we are syncing
    /// towards. This number is immutable for each `SyncAnchor`.
    pub(crate) cumulative_proof_of_work: ProofOfWork,

    /// The block MMR accumulator *after* appending the claimed tip digest. This
    /// value is immutable for each `SyncAnchor`.
    pub(crate) block_mmr: MmrAccumulator,

    /// Indicates the block that we have currently synced to under this anchor.
    pub(crate) champion: Option<(BlockHeight, Digest)>,

    /// The last time this anchor was either created or updated.
    pub(crate) updated: SystemTime,
}

impl SyncAnchor {
    pub(crate) fn new(
        claimed_cumulative_pow: ProofOfWork,
        claimed_block_mmra: MmrAccumulator,
    ) -> Self {
        Self {
            cumulative_proof_of_work: claimed_cumulative_pow,
            block_mmr: claimed_block_mmra,
            champion: None,
            updated: SystemTime::now(),
        }
    }

    pub(crate) fn catch_up(&mut self, height: BlockHeight, block_hash: Digest) {
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

/// `NetworkingState` contains in-memory and persisted data for interacting
/// with network peers.
#[derive(Debug, Clone)]
pub struct NetworkingState {
    /// Stores info about the peers that the client is connected to
    /// Peer tasks may update their own entries into this map.
    pub peer_map: PeerMap,

    /// `peer_databases` are used to persist IPs with their standing.
    /// The peer tasks may update their own entries into this map.
    pub peer_databases: PeerDatabases,

    /// This value is only Some if the instance is running an archival node
    /// that is currently in sync mode (downloading blocks in batches).
    /// Only the main task may update this flag
    pub(crate) sync_anchor: Option<SyncAnchor>,

    /// Read-only value set at random during startup
    pub instance_id: u128,

    /// If set to `true`, no blocks, block proposals, or transactions will be
    /// sent from this client, or accepted from peers.
    /// Only the RPC server may update this flag.
    pub freeze: bool,

    /// Disconnection times of past peers. Can be used to determine if a connection
    /// request should be accepted or rejected.
    ///
    /// Only records times of _graceful_ disconnections that were triggered by
    /// _this_ node. That is, times of the following events are _not_ recorded:
    /// - Graceful disconnect initiated by the peer.
    /// - Abrupt disconnections, for example due to network failures.
    ///
    /// Only the peer tasks may update this map.
    disconnection_times: HashMap<InstanceId, SystemTime>,
}

impl NetworkingState {
    pub(crate) fn new(peer_map: PeerMap, peer_databases: PeerDatabases) -> Self {
        Self {
            peer_map,
            peer_databases,
            sync_anchor: None,
            instance_id: rand::random(),
            freeze: false,
            disconnection_times: HashMap::new(),
        }
    }

    /// Create databases for peer standings
    pub async fn initialize_peer_databases(data_dir: &DataDirectory) -> Result<PeerDatabases> {
        let database_dir_path = data_dir.database_dir_path();
        DataDirectory::create_dir_if_not_exists(&database_dir_path).await?;

        let peer_standings = NeptuneLevelDb::<IpAddr, PeerStanding>::new(
            &data_dir.banned_ips_database_dir_path(),
            &create_db_if_missing(),
        )
        .await?;

        Ok(PeerDatabases { peer_standings })
    }

    /// Return a list of peer sanctions stored in the database.
    pub fn all_peer_sanctions_in_database(&self) -> HashMap<IpAddr, PeerStanding> {
        let mut sanctions = HashMap::default();

        let mut dbiterator = self.peer_databases.peer_standings.iter();
        for (ip, standing) in dbiterator.by_ref() {
            if standing.is_negative() {
                sanctions.insert(ip, standing);
            }
        }

        sanctions
    }

    pub async fn get_peer_standing_from_database(&self, ip: IpAddr) -> Option<PeerStanding> {
        self.peer_databases.peer_standings.get(ip).await
    }

    pub async fn clear_ip_standing_in_database(&mut self, ip: IpAddr) {
        let old_standing = self.peer_databases.peer_standings.get(ip).await;

        if let Some(mut standing) = old_standing {
            standing.clear_standing();

            self.peer_databases.peer_standings.put(ip, standing).await;
        }
    }

    pub async fn clear_all_standings_in_database(&mut self) {
        let new_entries: Vec<_> = self
            .peer_databases
            .peer_standings
            .iter()
            .map(|(ip, mut standing)| {
                standing.clear_standing();
                (ip, standing)
            })
            .collect();

        let mut batch = WriteBatchAsync::new();
        for (ip, standing) in new_entries {
            batch.op_write(ip, standing);
        }

        self.peer_databases.peer_standings.batch_write(batch).await
    }

    // Storing IP addresses is, according to this answer, not a violation of GDPR:
    // https://law.stackexchange.com/a/28609/45846
    // Wayback machine: https://web.archive.org/web/20220708143841/https://law.stackexchange.com/questions/28603/how-to-satisfy-gdprs-consent-requirement-for-ip-logging/28609
    pub async fn write_peer_standing_on_decrease(
        &mut self,
        ip: IpAddr,
        current_standing: PeerStanding,
    ) {
        let old_standing = self.peer_databases.peer_standings.get(ip).await;

        if old_standing.is_none() || old_standing.unwrap().standing > current_standing.standing {
            self.peer_databases
                .peer_standings
                .put(ip, current_standing)
                .await
        }
    }

    /// Register the disconnection time of a peer.
    ///
    /// Only use this to register disconnection times of _graceful_
    /// disconnections that were triggered by _this_ node. That is, times of the
    /// following events should _not_ be recorded:
    /// - Graceful disconnect initiated by the peer.
    /// - Abrupt disconnections, for example due to network failures.
    ///
    /// Only the peer tasks may call this method.
    pub(crate) fn register_peer_disconnection(&mut self, id: InstanceId, time: SystemTime) {
        self.disconnection_times.insert(id, time);
    }

    pub(crate) fn last_disconnection_time_of_peer(&self, id: InstanceId) -> Option<SystemTime> {
        self.disconnection_times.get(&id).copied()
    }
}
