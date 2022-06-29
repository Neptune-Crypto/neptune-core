use leveldb::kv::KV;
use leveldb::options::{ReadOptions, WriteOptions};

use super::blockchain::block::block_header::BlockHeader;
use super::blockchain::block::Block;
use super::blockchain::digest::keyable_digest::KeyableDigest;
use super::blockchain::digest::{Hashable, RESCUE_PRIME_DIGEST_SIZE_IN_BYTES};
use super::database::{DatabaseUnit, Databases};
use super::peer;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

/// State handles all state of the client that is shared across threads.
/// The policy used here is that only the main thread should update the
/// state, all other threads are only allowed to read from the state.
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

impl State {
    fn get_latest_block_header_from_ram(&self) -> BlockHeader {
        self.latest_block_header.lock().unwrap().to_owned()
    }

    /// Method for applying the latest block to the database. Warning: A lock *must* be held on
    /// `block_header` by the caller, over this function call, for this to be a safe operation.
    pub async fn update_latest_block_only_database(&self, new_block: Box<Block>) -> Result<()> {
        let block_hash_raw: [u8; RESCUE_PRIME_DIGEST_SIZE_IN_BYTES] = new_block.hash.into();
        let dbs = self.databases.lock().await;

        // TODO: Mutliple blocks can have the same height: fix!
        dbs.block_height_to_hash.put(
            WriteOptions::new(),
            new_block.header.height,
            &block_hash_raw,
        )?;
        dbs.block_hash_to_block.put::<KeyableDigest>(
            WriteOptions::new(),
            new_block.hash.into(),
            &bincode::serialize(&new_block).expect("Failed to serialize block"),
        )?;

        dbs.latest_block_header.put(
            WriteOptions::new(),
            DatabaseUnit(),
            &bincode::serialize(&new_block.header).expect("Failed to serialize block"),
        )?;

        Ok(())
    }

    pub async fn update_latest_block(&self, new_block: Box<Block>) -> Result<()> {
        let mut block_head_header = self
            .latest_block_header
            .lock()
            .expect("Locking block header must succeed");
        self.update_latest_block_only_database(new_block.clone())
            .await?;
        *block_head_header = new_block.header;

        Ok(())
    }
}
