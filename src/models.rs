pub mod big_array;
pub mod blockchain;
pub mod channel;
pub mod database;
pub mod peer;
pub mod shared;

use self::blockchain::block::block_header::BlockHeader;
use self::database::Databases;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Debug)]
pub struct State {
    // From the documentation:
    // "If the value behind the mutex is just data, it's usually appropriate to use a blocking mutex such as the one in the standard library or (...)"
    pub latest_block_header: Arc<std::sync::Mutex<BlockHeader>>,
    pub peer_map: Arc<std::sync::Mutex<HashMap<SocketAddr, peer::Peer>>>,

    // Since this is a database, we use the tokio Mutex here.
    pub databases: Arc<tokio::sync::Mutex<Databases>>,
}

impl Clone for State {
    fn clone(&self) -> Self {
        let peer_map = Arc::clone(&self.peer_map);
        let databases = Arc::clone(&self.databases);
        let block_head_header = Arc::clone(&self.latest_block_header);
        Self {
            peer_map,
            databases,
            latest_block_header: block_head_header,
        }
    }
}
