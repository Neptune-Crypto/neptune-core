use super::blockchain::block::block_header::BlockHeader;
use super::blockchain::block::Block;
use super::blockchain::digest::Digest;
use super::database::{BlockDatabases, PeerDatabases};
use super::peer::{self, HandshakeData, PeerStanding};
use crate::config_models::cli_args;
use crate::database::leveldb::LevelDB;
use crate::VERSION;
use anyhow::Result;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use tokio::sync::Mutex as TokioMutex;

#[derive(Debug, Clone)]
pub struct LightState {
    // From the documentation of `tokio::sync::Mutex`:
    // "If the value behind the mutex is just data, it's usually appropriate to use a blocking mutex
    // such as the one in the standard library or (...)"
    pub latest_block_header: Arc<StdMutex<BlockHeader>>,
}

impl LightState {
    // TODO: Consider renaming to `new_threadsafe()` to reflect it does not return a `Self`.
    pub fn new(initial_latest_block_header: BlockHeader) -> Self {
        Self {
            latest_block_header: Arc::new(StdMutex::new(initial_latest_block_header)),
        }
    }

    pub fn get_latest_block_header(&self) -> BlockHeader {
        self.latest_block_header.lock().unwrap().clone()
    }
}

#[derive(Clone, Debug)]
pub struct ArchivalState {
    // Since this is a database, we use the tokio Mutex here.
    pub block_databases: Arc<TokioMutex<BlockDatabases>>,
}

impl ArchivalState {
    pub fn new(initial_block_databases: Arc<TokioMutex<BlockDatabases>>) -> Self {
        Self {
            block_databases: initial_block_databases,
        }
    }

    /// Return latest block from database, or genesis block if no other block
    /// is known.
    pub async fn get_latest_block(&self) -> Block {
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
        let maybe_block = self
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

        Ok(maybe_block)
    }
}

#[derive(Debug, Clone)]
pub struct BlockchainState {
    pub light_state: LightState,
    pub archival_state: Option<ArchivalState>,
}

type PeerMap = HashMap<SocketAddr, peer::PeerInfo>;

#[derive(Debug, Clone)]
pub struct NetworkingState {
    // Stores info about the peers that the client is connected to
    pub peer_map: Arc<StdMutex<PeerMap>>,

    // Since this is a database, we use the tokio Mutex here.
    // `peer_databases` are used to persist IPs with their standing.
    pub peer_databases: Arc<TokioMutex<PeerDatabases>>,

    // This value is only true if instance is running an archival node
    // that is currently downloading blocks to catch up.
    pub syncing: Arc<std::sync::RwLock<bool>>,

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

/// State handles all state of the client that is shared across threads.
/// The policy used here is that only the main thread should update the
/// state, all other threads are only allowed to read from the state.
#[derive(Debug, Clone)]
pub struct State {
    pub chain: BlockchainState,
    pub net: NetworkingState,
    pub cli: cli_args::Args,
}

impl State {
    // Storing IP addresses is, according to this answer, not a violation of GDPR:
    // https://law.stackexchange.com/a/28609/45846
    // Wayback machine: https://web.archive.org/web/20220708143841/https://law.stackexchange.com/questions/28603/how-to-satisfy-gdprs-consent-requirement-for-ip-logging/28609
    pub async fn write_peer_standing_on_increase(&self, ip: IpAddr, standing: PeerStanding) {
        let mut peer_databases = self.net.peer_databases.lock().await;
        let old_standing = peer_databases.peer_standings.get(ip);

        if old_standing.is_none() || old_standing.unwrap().standing < standing.standing {
            peer_databases.peer_standings.put(ip, standing)
        }
    }

    pub async fn get_peer_standing_from_database(&self, ip: IpAddr) -> Option<PeerStanding> {
        let mut peer_databases = self.net.peer_databases.lock().await;
        peer_databases.peer_standings.get(ip)
    }

    pub async fn update_latest_block(&self, new_block: Box<Block>) -> Result<()> {
        // Acquire both locks before updating
        let mut databases_locked = self
            .chain
            .archival_state
            .as_ref()
            .unwrap()
            .block_databases
            .lock()
            .await;
        let mut light_state_locked = self.chain.light_state.latest_block_header.lock().unwrap();

        // Perform the updates while holding both locks
        *light_state_locked = new_block.header.clone();

        // TODO: Multiple blocks can have the same height: fix!
        databases_locked
            .block_height_to_hash
            .put(new_block.header.height, new_block.hash);
        databases_locked
            .block_hash_to_block
            .put(new_block.hash, *new_block.clone());
        databases_locked
            .latest_block_header
            .put((), new_block.header.clone());

        // Release both locks

        Ok(())
    }

    pub async fn get_handshakedata(&self) -> HandshakeData {
        let listen_addr_socket = SocketAddr::new(self.cli.listen_addr, self.cli.peer_port);
        // let latest_block = self.chain.archival_state.as_ref().unwrap().get_latest_block().await;
        let latest_block_header = self.chain.light_state.get_latest_block_header();

        HandshakeData {
            tip_header: latest_block_header,
            listen_address: Some(listen_addr_socket),
            network: self.cli.network,
            instance_id: rand::random(),
            version: VERSION.to_string(),
        }
    }
}
