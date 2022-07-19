use super::blockchain::block::block_header::BlockHeader;
use super::blockchain::block::Block;
use super::blockchain::digest::{Digest, RESCUE_PRIME_DIGEST_SIZE_IN_BYTES};
use super::database::{BlockDatabases, PeerDatabases};
use super::peer::{self, PeerStanding};
use crate::config_models::cli_args;
use crate::database::leveldb::LevelDB;
use anyhow::Result;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
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
    pub peer_map: Arc<std::sync::Mutex<HashMap<SocketAddr, peer::PeerInfo>>>,

    // Since this is a database, we use the tokio Mutex here.
    pub block_databases: Arc<tokio::sync::Mutex<BlockDatabases>>,

    // Since this is a database, we use the tokio Mutex here.
    pub peer_databases: Arc<tokio::sync::Mutex<PeerDatabases>>,

    pub cli_args: Arc<cli_args::Args>,

    // This value is only true if instance is running an archival node
    // that is currently downloading blocks to catch up.
    pub syncing: Arc<std::sync::RwLock<bool>>,
}

impl Clone for State {
    fn clone(&self) -> Self {
        let syncing = Arc::new(std::sync::RwLock::new(false));
        let peer_map = Arc::clone(&self.peer_map);
        let databases = Arc::clone(&self.block_databases);
        let peer_databases = Arc::clone(&self.peer_databases);
        let block_head_header = Arc::clone(&self.latest_block_header);
        let cli_args = Arc::clone(&self.cli_args);
        Self {
            latest_block_header: block_head_header,
            peer_map,
            block_databases: databases,
            peer_databases,
            syncing,
            cli_args,
        }
    }
}

impl State {
    /// Return latest block from database, or genesis block if no other block
    /// is known.
    pub async fn get_latest_block(&mut self) -> Block {
        let mut dbs = self.block_databases.lock().await;
        let lookup_res_info: Option<Block> =
            BlockDatabases::get_latest_block(&mut dbs).expect("Failed to read from DB");

        match lookup_res_info {
            None => Block::genesis_block(),
            Some(block) => block,
        }
    }

    // Return the block with a given block digest, iff it's available in state somewhere
    pub async fn get_block(&self, block_digest: Digest) -> Result<Option<Block>> {
        let block = self
            .block_databases
            .lock()
            .await
            .block_hash_to_block
            .get(block_digest)
            .or_else(move || {
                // If block was not found in database, check if the digest matches the genesis block
                let genesis = Block::genesis_block();
                if genesis.hash == block_digest {
                    Some(genesis)
                } else {
                    None
                }
            });

        Ok(block)
    }

    // Method for updating state's block header and database entry. A lock must be held on bloc
    // header by the caller
    pub fn update_latest_block_with_block_header_mutexguard(
        &self,
        new_block: Box<Block>,
        databases: &mut tokio::sync::MutexGuard<BlockDatabases>,
        block_header: &mut std::sync::MutexGuard<BlockHeader>,
    ) -> Result<()> {
        let block_hash_raw: [u8; RESCUE_PRIME_DIGEST_SIZE_IN_BYTES] = new_block.hash.into();

        // TODO: Mutliple blocks can have the same height: fix!
        databases
            .block_height_to_hash
            .put(new_block.header.height, block_hash_raw.into());
        databases
            .block_hash_to_block
            .put(new_block.hash, *new_block.clone());

        databases
            .latest_block_header
            .put((), new_block.header.clone());

        **block_header = new_block.header;

        Ok(())
    }

    pub async fn update_latest_block(&self, new_block: Box<Block>) -> Result<()> {
        let mut databases = self.block_databases.lock().await;
        let mut block_head_header = self
            .latest_block_header
            .lock()
            .expect("Locking block header must succeed");
        self.update_latest_block_with_block_header_mutexguard(
            new_block.clone(),
            &mut databases,
            &mut block_head_header,
        )?;

        Ok(())
    }

    // Storing IP addresses is, according to this answer, not a violation of GDPR:
    // https://law.stackexchange.com/a/28609/45846
    // Wayback machine: https://web.archive.org/web/20220708143841/https://law.stackexchange.com/questions/28603/how-to-satisfy-gdprs-consent-requirement-for-ip-logging/28609
    pub async fn write_peer_standing_on_increase(&self, ip: IpAddr, standing: PeerStanding) {
        let mut peer_databases = self.peer_databases.lock().await;
        let old_standing = peer_databases.peer_standings.get(ip);

        if old_standing.is_none() || old_standing.unwrap().standing < standing.standing {
            peer_databases.peer_standings.put(ip, standing)
        }
    }

    pub async fn get_peer_standing_from_database(&self, ip: IpAddr) -> Option<PeerStanding> {
        let mut peer_databases = self.peer_databases.lock().await;
        peer_databases.peer_standings.get(ip)
    }
}
