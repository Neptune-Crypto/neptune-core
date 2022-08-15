use anyhow::Result;
use std::net::{IpAddr, SocketAddr};

use self::{blockchain_state::BlockchainState, networking_state::NetworkingState};
use crate::{
    config_models::cli_args,
    database::{leveldb::LevelDB, rusty::RustyLevelDBIterator},
    models::{
        blockchain::block::Block,
        peer::{HandshakeData, PeerStanding},
    },
    VERSION,
};

pub mod archival_state;
pub mod blockchain_state;
pub mod light_state;
pub mod networking_state;

/// State handles all state of the client that is shared across threads.
/// The policy used here is that only the main thread should update the
/// state, all other threads are only allowed to read from the state.
#[derive(Debug, Clone)]
pub struct State {
    // Only the main thread may update these values.
    pub chain: BlockchainState,

    // This contains values that both the peer threads and main thread may update
    pub net: NetworkingState,

    // This field is read-only as it's set at launch
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
        let latest_block_header = self.chain.light_state.get_latest_block_header();

        HandshakeData {
            tip_header: latest_block_header,
            listen_address: Some(listen_addr_socket),
            network: self.cli.network,
            instance_id: self.net.instance_id,
            version: VERSION.to_string(),
        }
    }

    pub async fn clear_ip_standing_in_database(&self, ip: IpAddr) {
        let mut peer_databases = self.net.peer_databases.lock().await;

        let old_standing = peer_databases.peer_standings.get(ip);

        if old_standing.is_some() {
            peer_databases
                .peer_standings
                .put(ip, PeerStanding::default())
        }
    }

    pub async fn clear_all_standings_in_database(&self) {
        let mut peer_databases = self.net.peer_databases.lock().await;

        let mut dbiterator: RustyLevelDBIterator<IpAddr, PeerStanding> =
            peer_databases.peer_standings.new_iter();

        for (ip, _v) in dbiterator.by_ref() {
            let old_standing = peer_databases.peer_standings.get(ip);

            if old_standing.is_some() {
                peer_databases
                    .peer_standings
                    .put(ip, PeerStanding::default())
            }
        }
    }
}
