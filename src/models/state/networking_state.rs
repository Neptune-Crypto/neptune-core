use crate::config_models::data_directory::DataDirectory;
use crate::database::leveldb::LevelDB;
use crate::database::rusty::{create_db_if_missing, RustyLevelDB};
use crate::models::database::PeerDatabases;
use crate::models::peer::{self, PeerStanding};
use anyhow::Result;
use std::net::IpAddr;
use std::sync::Mutex as StdMutex;
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::sync::Mutex as TokioMutex;

pub const BANNED_IPS_DB_NAME: &str = "banned_ips";

type PeerMap = HashMap<SocketAddr, peer::PeerInfo>;

/// `NetworkingState` contains in-memory and persisted data for interacting
/// with network peers.
#[derive(Debug, Clone)]
pub struct NetworkingState {
    // Stores info about the peers that the client is connected to
    // Peer threads may update their own entries into this map.
    pub peer_map: Arc<StdMutex<PeerMap>>,

    // Since this is a database, we use the tokio Mutex here.
    // `peer_databases` are used to persist IPs with their standing.
    // The peer threads may update their own entries into this map.
    pub peer_databases: Arc<TokioMutex<PeerDatabases>>,

    // This value is only true if instance is running an archival node
    // that is currently downloading blocks to catch up.
    // Only the main thread may update this flag
    pub syncing: Arc<std::sync::RwLock<bool>>,

    // Read-only value set during startup
    pub instance_id: u128,
}

impl NetworkingState {
    pub fn new(
        peer_map: Arc<StdMutex<PeerMap>>,
        peer_databases: Arc<TokioMutex<PeerDatabases>>,
        syncing: Arc<std::sync::RwLock<bool>>,
    ) -> Self {
        Self {
            peer_map,
            peer_databases,
            syncing,
            instance_id: rand::random(),
        }
    }

    /// Create databases for peer standings
    pub fn initialize_peer_databases(data_dir: &DataDirectory) -> Result<PeerDatabases> {
        let database_dir_path = data_dir.database_dir_path();
        DataDirectory::create_dir_if_not_exists(&database_dir_path)?;

        let peer_standings = RustyLevelDB::<IpAddr, PeerStanding>::new(
            &data_dir.banned_ips_database_dir_path(),
            &create_db_if_missing(),
        )?;

        Ok(PeerDatabases { peer_standings })
    }

    /// Return a list of peer sanctions stored in the database.
    pub async fn all_peer_sanctions_in_database(&self) -> HashMap<IpAddr, PeerStanding> {
        let mut sanctions = HashMap::default();

        let peer_databases = self.peer_databases.lock().await;
        let mut dbiterator = peer_databases.peer_standings.new_iter();
        for (ip, standing) in dbiterator.by_ref() {
            if standing.is_negative() {
                sanctions.insert(ip, standing);
            }
        }

        sanctions
    }

    pub async fn get_peer_standing_from_database(&self, ip: IpAddr) -> Option<PeerStanding> {
        let mut peer_databases = self.peer_databases.lock().await;
        peer_databases.peer_standings.get(ip)
    }

    pub async fn clear_ip_standing_in_database(&self, ip: IpAddr) {
        let mut peer_databases = self.peer_databases.lock().await;

        let old_standing = peer_databases.peer_standings.get(ip);

        if old_standing.is_some() {
            peer_databases
                .peer_standings
                .put(ip, PeerStanding::default())
        }
    }

    pub async fn clear_all_standings_in_database(&self) {
        let mut peer_databases = self.peer_databases.lock().await;

        let mut dbiterator = peer_databases.peer_standings.new_iter();

        let mut new_entries = vec![];
        for (ip, _old_standing) in dbiterator.by_ref() {
            new_entries.push((ip, PeerStanding::default()));
        }

        peer_databases.peer_standings.batch_write(&new_entries);
    }

    // Storing IP addresses is, according to this answer, not a violation of GDPR:
    // https://law.stackexchange.com/a/28609/45846
    // Wayback machine: https://web.archive.org/web/20220708143841/https://law.stackexchange.com/questions/28603/how-to-satisfy-gdprs-consent-requirement-for-ip-logging/28609
    pub async fn write_peer_standing_on_decrease(
        &self,
        ip: IpAddr,
        current_standing: PeerStanding,
    ) {
        let mut peer_databases = self.peer_databases.lock().await;
        let old_standing = peer_databases.peer_standings.get(ip);

        if old_standing.is_none() || old_standing.unwrap().standing > current_standing.standing {
            peer_databases.peer_standings.put(ip, current_standing)
        }
    }
}
