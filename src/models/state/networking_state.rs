use crate::models::database::PeerDatabases;
use crate::models::peer;
use std::sync::Mutex as StdMutex;
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::sync::Mutex as TokioMutex;

type PeerMap = HashMap<SocketAddr, peer::PeerInfo>;

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
}
