use super::blockchain::block::block_header::BlockHeader;
use super::blockchain::block::Block;
use super::blockchain::digest::keyable_digest::KeyableDigest;
use super::blockchain::digest::{Digest, RESCUE_PRIME_DIGEST_SIZE_IN_BYTES};
use super::database::{BlockDatabases, DatabaseUnit, KeyableIpAddress, PeerDatabases};
use super::peer::{self, PeerStanding};
use crate::config_models::cli_args;
use anyhow::Result;
use leveldb::kv::KV;
use leveldb::options::{ReadOptions, WriteOptions};
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
    pub async fn get_latest_block(&self) -> Block {
        let dbs = self.block_databases.lock().await;
        let lookup_res_info: Option<Block> =
            BlockDatabases::get_latest_block(dbs).expect("Failed to read from DB");

        match lookup_res_info {
            None => Block::genesis_block(),
            Some(block) => block,
        }
    }

    // Return the block with a given block digest, iff it's available in state somewhere
    pub async fn get_block(&self, block_digest: Digest) -> Result<Option<Block>> {
        // First see if we can get block from database
        let block_bytes: Option<Vec<u8>> =
            self.block_databases
                .lock()
                .await
                .block_hash_to_block
                .get::<KeyableDigest>(ReadOptions::new(), block_digest.into())?;
        let mut block: Option<Block> = block_bytes
            .map(|bytes| bincode::deserialize(&bytes).expect("Deserialization of block failed"));

        // If block was not found in database, check if the digest matches the genesis block
        let genesis = Block::genesis_block();
        if genesis.hash == block_digest {
            block = Some(genesis);
        }

        Ok(block)
    }

    // Method for updating state's block header and database entry. A lock must be held on bloc
    // header by the caller
    pub fn update_latest_block_with_block_header_mutexguard(
        &self,
        new_block: Box<Block>,
        databases: &tokio::sync::MutexGuard<BlockDatabases>,
        block_header: &mut std::sync::MutexGuard<BlockHeader>,
    ) -> Result<()> {
        let block_hash_raw: [u8; RESCUE_PRIME_DIGEST_SIZE_IN_BYTES] = new_block.hash.into();

        // TODO: Mutliple blocks can have the same height: fix!
        databases.block_height_to_hash.put(
            WriteOptions::new(),
            new_block.header.height,
            &block_hash_raw,
        )?;
        databases.block_hash_to_block.put::<KeyableDigest>(
            WriteOptions::new(),
            new_block.hash.into(),
            &bincode::serialize(&new_block).expect("Failed to serialize block"),
        )?;

        databases.latest_block_header.put(
            WriteOptions::new(),
            DatabaseUnit(),
            &bincode::serialize(&new_block.header).expect("Failed to serialize block"),
        )?;

        **block_header = new_block.header;

        Ok(())
    }

    pub async fn update_latest_block(&self, new_block: Box<Block>) -> Result<()> {
        let databases = self.block_databases.lock().await;
        let mut block_head_header = self
            .latest_block_header
            .lock()
            .expect("Locking block header must succeed");
        self.update_latest_block_with_block_header_mutexguard(
            new_block.clone(),
            &databases,
            &mut block_head_header,
        )?;

        Ok(())
    }

    // Storing IP addresses is, according to this answer, not a violation of GDPR:
    // https://law.stackexchange.com/a/28609/45846
    // Wayback machine: https://web.archive.org/web/20220708143841/https://law.stackexchange.com/questions/28603/how-to-satisfy-gdprs-consent-requirement-for-ip-logging/28609
    pub async fn write_peer_standing_to_database(&self, ip: IpAddr, standing: PeerStanding) {
        let peer_databases = self.peer_databases.lock().await;
        peer_databases
            .peer_standings
            .put::<KeyableIpAddress>(
                WriteOptions::new(),
                ip.into(),
                &bincode::serialize(&standing).expect("Failed to serialize peer standing"),
            )
            .expect("Failed to write to database");
    }

    pub async fn get_peer_standing_from_database(&self, ip: IpAddr) -> Option<PeerStanding> {
        let peer_databases = self.peer_databases.lock().await;
        let peer_info_bytes = peer_databases
            .peer_standings
            .get::<KeyableIpAddress>(ReadOptions::new(), ip.into())
            .expect("Failed to read from peer info db");
        peer_info_bytes
            .map(|bytes| bincode::deserialize(&bytes).expect("Failed to deserialize peer info"))
    }
}
