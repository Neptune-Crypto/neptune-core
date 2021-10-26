pub mod big_array;
pub mod blockchain;
pub mod channel;
pub mod database;
pub mod peer;
pub mod shared;

use self::database::Databases;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Debug)]
pub struct State {
    pub peer_map: Arc<std::sync::Mutex<HashMap<SocketAddr, peer::Peer>>>,
    pub databases: Arc<tokio::sync::Mutex<Databases>>,
}

impl Clone for State {
    fn clone(&self) -> Self {
        let peer_map = Arc::clone(&self.peer_map);
        let databases = Arc::clone(&self.databases);
        Self {
            peer_map,
            databases,
        }
    }
}
