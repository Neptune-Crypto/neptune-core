use crate::config_models::data_directory::DataDirectory;
use crate::database::{create_db_if_missing, NeptuneLevelDb, WriteBatchAsync};
use crate::models::database::PeerDatabases;
use crate::models::peer::{self, PeerStanding};
use anyhow::Result;
use std::net::IpAddr;
use std::{collections::HashMap, net::SocketAddr};

pub const BANNED_IPS_DB_NAME: &str = "banned_ips";

type PeerMap = HashMap<SocketAddr, peer::PeerInfo>;

/// `NetworkingState` contains in-memory and persisted data for interacting
/// with network peers.
#[derive(Debug, Clone)]
pub struct NetworkingState {
    // Stores info about the peers that the client is connected to
    // Peer threads may update their own entries into this map.
    pub peer_map: PeerMap,

    // `peer_databases` are used to persist IPs with their standing.
    // The peer threads may update their own entries into this map.
    pub peer_databases: PeerDatabases,

    // This value is only true if instance is running an archival node
    // that is currently downloading blocks to catch up.
    // Only the main thread may update this flag
    pub syncing: bool,

    // Read-only value set during startup
    pub instance_id: u128,
}

impl NetworkingState {
    pub fn new(peer_map: PeerMap, peer_databases: PeerDatabases, syncing: bool) -> Self {
        Self {
            peer_map,
            peer_databases,
            syncing,
            instance_id: rand::random(),
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
    pub async fn all_peer_sanctions_in_database(&self) -> HashMap<IpAddr, PeerStanding> {
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

        if old_standing.is_some() {
            self.peer_databases
                .peer_standings
                .put(ip, PeerStanding::default())
                .await
        }
    }

    pub async fn clear_all_standings_in_database(&mut self) {
        let new_entries: Vec<_> = self
            .peer_databases
            .peer_standings
            .iter()
            .map(|(ip, _old_standing)| (ip, PeerStanding::default()))
            .collect();

        let mut batch = WriteBatchAsync::new();
        for (ip, standing) in new_entries.into_iter() {
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
}
