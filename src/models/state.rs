use super::blockchain::block::block_header::BlockHeader;
use super::database::Databases;
use super::peer;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Debug)]
pub struct State {
    // From the documentation of `tokio::sync::Mutex`:
    // "If the value behind the mutex is just data, it's usually appropriate to use a blocking mutex
    // such as the one in the standard library or (...)"
    pub latest_block_header: Arc<std::sync::Mutex<BlockHeader>>,
    pub peer_map: Arc<std::sync::Mutex<HashMap<SocketAddr, peer::Peer>>>,

    // Since this is a database, we use the tokio Mutex here.
    pub databases: Arc<tokio::sync::Mutex<Databases>>,

    // This value is only true if instance is running an archival node
    // that is currently downloading blocks to catch up.
    pub syncing: Arc<std::sync::RwLock<bool>>,
}

impl Clone for State {
    fn clone(&self) -> Self {
        let syncing = Arc::new(std::sync::RwLock::new(false));
        let peer_map = Arc::clone(&self.peer_map);
        let databases = Arc::clone(&self.databases);
        let block_head_header = Arc::clone(&self.latest_block_header);
        Self {
            latest_block_header: block_head_header,
            peer_map,
            databases,
            syncing,
        }
    }
}
