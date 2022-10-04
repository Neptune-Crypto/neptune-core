use anyhow::Result;
use std::net::{IpAddr, SocketAddr};

use self::{
    blockchain_state::BlockchainState, mempool::Mempool, networking_state::NetworkingState,
};
use super::blockchain::{
    transaction::{utxo::Utxo, Transaction},
    wallet::WalletState,
};
use crate::{
    config_models::cli_args,
    database::{leveldb::LevelDB, rusty::RustyLevelDBIterator},
    models::peer::{HandshakeData, PeerStanding},
    VERSION,
};

pub mod archival_state;
pub mod blockchain_state;
pub mod light_state;
pub mod mempool;
pub mod networking_state;
pub mod shared;

/// `GlobalState` handles all state of a Neptune node that is shared across its threads.
///
/// Some fields are only written to by certain threads.
#[derive(Debug, Clone)]
pub struct GlobalState {
    /// The `WalletState` may be updated by the main thread and the RPC server.
    pub wallet_state: WalletState,

    /// The `BlockchainState` may only be updated by the main thread.
    pub chain: BlockchainState,

    /// The `NetworkingState` may be updated by both the main thread and peer threads.
    pub net: NetworkingState,

    /// The `cli_args::Args` are read-only and accessible by all threads.
    pub cli: cli_args::Args,

    /// The `Mempool` may only be updated by the main thread.
    pub mempool: Mempool,
}

impl GlobalState {
    pub async fn create_transaction(&self, _output_utxo: Utxo) -> Result<Transaction> {
        todo!()
    }

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

    pub fn get_handshakedata(&self) -> HandshakeData {
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
