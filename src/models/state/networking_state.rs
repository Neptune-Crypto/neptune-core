use crate::config_models::data_directory::DataDirectory;
use crate::database::{create_db_if_missing, NeptuneLevelDb};
use crate::models::database::PeerDatabases;
use crate::models::peer::{
    self, ConnectionRefusedReason, ConnectionStatus, HandshakeData, PeerSanctionReason,
    PeerStanding, PeerUnsanctionReason,
};
use anyhow::Result;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use tracing::{debug, info, warn};

pub const BANNED_IPS_DB_NAME: &str = "banned_ips";

// When a potential peer is banned because of PeerSanctionReason::ConnectFailed,
// our node will wait this many seconds until trying to connect to that peer again.
//
// For now we arbitrarily set it to 5 minutes.
pub const CONNECT_FAILED_TIMEOUT_SECS: u16 = 60 * 5;

type PeerMap = HashMap<SocketAddr, peer::PeerInfo>;

/// `NetworkingState` contains in-memory and persisted data for interacting
/// with network peers.
#[derive(Debug, Clone)]
pub struct NetworkingState {
    // Stores info about the peers that the client is connected to
    // Peer threads may update their own entries into this map.
    pub peer_map: PeerMap,

    // `peer_databases` are used to persist SocketAddrs with their standing.
    // The peer threads may update their own entries into this map.
    pub peer_databases: PeerDatabases,

    // This value is only true if instance is running an archival node
    // that is currently downloading blocks to catch up.
    // Only the main thread may update this flag
    pub syncing: bool,

    // Read-only value set during startup
    pub instance_id: u128,

    // Read-only value from cli args. set during startup
    pub peer_tolerance: i32,
}

impl NetworkingState {
    pub fn new(
        peer_map: PeerMap,
        peer_databases: PeerDatabases,
        syncing: bool,
        peer_tolerance: i32,
    ) -> Self {
        Self {
            peer_map,
            peer_databases,
            syncing,
            instance_id: rand::random(),
            peer_tolerance,
        }
    }

    /// Create databases for peer standings
    pub async fn initialize_peer_databases(data_dir: &DataDirectory) -> Result<PeerDatabases> {
        let database_dir_path = data_dir.database_dir_path();
        DataDirectory::create_dir_if_not_exists(&database_dir_path)?;

        let peer_standings = NeptuneLevelDb::<SocketAddr, PeerStanding>::new(
            &data_dir.banned_ips_database_dir_path(),
            &create_db_if_missing(),
        )
        .await?;

        Ok(PeerDatabases { peer_standings })
    }

    /// Return a list of peer sanctions stored in the database.
    ///
    /// Finds all [PeerStanding] with a standing score in the negative.
    ///
    /// note:
    ///   The DB iterator used performs blocking I/O, so we wrap it
    ///   with [tokio::task::block_in_place()] to make this method async-friendly.
    ///
    ///   This requires tokio feature `rt-multi-thread`, and any
    ///   test that calls this method must use:
    ///     `#[tokio::test(flavor = "multi_thread")]`
    pub async fn all_peer_sanctions_in_database(&self) -> HashMap<SocketAddr, PeerStanding> {
        tokio::task::block_in_place(|| {
            self.peer_databases
                .peer_standings
                .iter()
                .filter(|(_addr, standing)| standing.is_negative())
                .collect()
        })
    }

    pub async fn get_peer_standing_from_database(&self, addr: SocketAddr) -> Option<PeerStanding> {
        self.peer_databases.peer_standings.get(addr).await
    }

    pub async fn clear_peer_standing_in_database(&mut self, addr: SocketAddr) {
        let old_standing = self.peer_databases.peer_standings.get(addr).await;

        if old_standing.is_some() {
            self.peer_databases
                .peer_standings
                .put(addr, PeerStanding::default())
                .await
        }
    }

    pub async fn clear_all_standings_in_database(&mut self) {
        let new_entries: Vec<_> = self
            .peer_databases
            .peer_standings
            .iter()
            .map(|(addr, _old_standing)| (addr, PeerStanding::default()))
            .collect();

        self.peer_databases
            .peer_standings
            .batch_write(new_entries)
            .await
    }

    // Storing IP addresses is, according to this answer, not a violation of GDPR:
    // https://law.stackexchange.com/a/28609/45846
    // Wayback machine: https://web.archive.org/web/20220708143841/https://law.stackexchange.com/questions/28603/how-to-satisfy-gdprs-consent-requirement-for-ip-logging/28609
    pub async fn write_peer_standing_on_decrease(
        &mut self,
        addr: SocketAddr,
        current_standing: PeerStanding,
    ) {
        let old_standing = self.peer_databases.peer_standings.get(addr).await;

        if old_standing.is_none() || old_standing.unwrap().score > current_standing.score {
            self.peer_databases
                .peer_standings
                .put(addr, current_standing)
                .await
        }
    }

    pub async fn write_peer_standing(&mut self, addr: SocketAddr, current_standing: PeerStanding) {
        self.peer_databases
            .peer_standings
            .put(addr, current_standing)
            .await
    }

    /// Sanctions a peer by lowering its standing score.
    ///
    /// Each peer is identified by a [SocketAddr].
    ///
    /// The standing score can be lowered to a minimum of
    /// `0 - NetworkingState::peer_tolerance - 1`.
    ///
    /// When the minimum score is reached, this results in a ban.
    /// Further calls do not lower the score, but do record the
    /// [PeerSanctionReason] and a timestamp.
    ///
    /// If a ban occurs, a log warning is issued.
    ///
    /// This method will sanction a peer even if it not currently connected
    /// and thus not in [peer_map](Self::peer_map).
    ///
    /// This method writes to the peer database and will also update the
    /// `peer_map` entry if the peer is presently connected.
    ///
    /// The returned [PeerStanding] represents the new standing after sanctioning.
    pub async fn sanction_peer(
        &mut self,
        peer_address: SocketAddr,
        reason: PeerSanctionReason,
    ) -> Result<PeerStanding> {
        let mut peer_standing = match self.peer_map.get_mut(&peer_address).map(|p| p.standing) {
            Some(ps) => ps,
            None => self
                .get_peer_standing_from_database(peer_address)
                .await
                .unwrap_or_default(),
        };

        warn!(
            "Sanctioning peer {}:{} for {:?}",
            peer_address.ip(),
            peer_address.port(),
            reason
        );

        debug!(
            "Old Standing for Peer {}:{} was {:?}",
            peer_address.ip(),
            peer_address.port(),
            peer_standing,
        );

        let banned_before = self.peer_standing_is_banned(&peer_standing);
        peer_standing.sanction(reason, self.peer_standing_banned_score());
        let banned_now = self.peer_standing_is_banned(&peer_standing);

        debug!(
            "New Standing for Peer {}:{} is {:?}",
            peer_address.ip(),
            peer_address.port(),
            peer_standing,
        );

        self.peer_map
            .entry(peer_address)
            .and_modify(|ps| ps.standing = peer_standing);

        self.write_peer_standing(peer_address, peer_standing).await;

        // warn if peer was in good standing and now is in bad standing
        if !banned_before && banned_now {
            warn!("Banning peer {}:{}", peer_address.ip(), peer_address.port());
        }

        Ok(peer_standing)
    }

    /// Unsanctions (rewards) a peer by increasing its standing score.
    ///
    /// Each peer is identified by a [SocketAddr].
    ///
    /// The standing score can be raised to a maximum of
    /// `NetworkingState::peer_tolerance + 1`.
    ///
    /// When the maximum score is reached, subsequent
    /// calls do not increase the score, but do record the
    /// [PeerUnsanctionReason] and a timestamp.
    ///
    /// If the peer was previously banned via [sanction_peer()](Self::sanction_peer()) then
    /// this call will result in the peer being unbanned provided the
    /// [PeerUnsanctionReason] has a non-zero effect on the score.
    ///
    /// This method will reward a peer even if it not currently connected
    /// and thus not in [peer_map](Self::peer_map).
    ///
    /// This method writes to the peer database and will also update the
    /// `peer_map` entry if the peer is presently connected.
    ///
    /// The returned [PeerStanding] represents the new standing after unsanctioning.
    pub async fn unsanction_peer(
        &mut self,
        peer_address: SocketAddr,
        reason: PeerUnsanctionReason,
    ) -> Result<PeerStanding> {
        info!(
            "rewarding peer {}:{} for {:?}",
            peer_address.ip(),
            peer_address.port(),
            reason
        );

        let mut peer_standing = match self.peer_map.get_mut(&peer_address).map(|p| p.standing) {
            Some(ps) => ps,
            None => self
                .get_peer_standing_from_database(peer_address)
                .await
                .unwrap_or_default(),
        };

        debug!(
            "Old Standing for Peer {}:{} was {:?}",
            peer_address.ip(),
            peer_address.port(),
            peer_standing,
        );

        let banned_before = self.peer_standing_is_banned(&peer_standing);

        peer_standing.unsanction(reason, self.peer_tolerance + 1);
        let banned_now = self.peer_standing_is_banned(&peer_standing);

        debug!(
            "New Standing for Peer {}:{} is {:?}",
            peer_address.ip(),
            peer_address.port(),
            peer_standing,
        );

        self.peer_map
            .entry(peer_address)
            .and_modify(|ps| ps.standing = peer_standing);

        self.write_peer_standing(peer_address, peer_standing).await;

        // if peer was banned and now is not, log the change.
        if banned_before && !banned_now {
            info!(
                "Unbanning peer {}:{}",
                peer_address.ip(),
                peer_address.port()
            );
        }

        Ok(peer_standing)
    }

    /// Looks up peer by [SocketAddr] and returns true if peer is banned, false if not, and None if record not found in DB.
    ///
    /// A peer is considered Banned if the peer's standing score is less than
    /// (0 - peer_tolerance), which is a config option.
    #[inline]
    pub(crate) async fn peer_is_banned(&self, peer_addr: SocketAddr) -> Option<bool> {
        self.get_peer_standing_from_database(peer_addr)
            .await
            .map(|ps| self.peer_standing_is_banned(&ps))
    }

    /// returns false if [PeerStanding] is in a banned state, else true
    ///
    /// A peer is considered Banned if the peer's standing score is less than
    /// (0 - peer_tolerance), which is a config option.
    #[inline]
    fn peer_standing_is_banned(&self, peer_standing: &PeerStanding) -> bool {
        peer_standing.score <= self.peer_standing_banned_score()
    }

    #[inline]
    pub(crate) fn peer_standing_banned_score(&self) -> i32 {
        PeerStanding::default_score() - self.peer_tolerance
    }

    /// Indicates if we can connect to the peer identified by [SocketAddr]
    ///
    /// Connect may proceed if `Ok` is returned.
    ///
    /// We can connect to a peer unless:
    ///   + The peer's IP is banned by config.
    ///   + we have reached max number of peers
    ///   + we are already connected to this peer.
    ///   + not allowed due to peer standing.
    ///     see [standing_permits_connect_to_peer()](Self::standing_permits_connect_to_peer())
    ///
    /// This method emits debug log entries for all conditions to aid with diagnosis.
    pub async fn allow_connect_to_peer(
        &self,
        socket_addr: SocketAddr,
        banned_ip_list: &[IpAddr],
        max_peers: usize,
    ) -> Result<(), AllowConnectToPeerError> {
        // Disallow connection if peer's IP is banned (via CLI/config)
        if banned_ip_list.contains(&socket_addr.ip()) {
            warn!(
                "allow_connect_to_peer: {}. peer's IP is BANNED by config.  allow: false",
                socket_addr
            );
            return Err(AllowConnectToPeerError::IpBannedByConfig);
        }

        // Disallow connection if max number of peers has been attained
        if max_peers <= self.peer_map.len() {
            debug!(
                "allow_connect_to_peer: {:?}. max peers limit of {} reached.  allow: false",
                socket_addr, max_peers
            );
            return Err(AllowConnectToPeerError::MaxPeersExceeded);
        }

        // Disallow connection to already connected peer.
        if self.peer_map.contains_key(&socket_addr) {
            debug!(
                "allow_connect_to_peer: {:?}. already connected to this peer. allow: false",
                socket_addr
            );
            return Err(AllowConnectToPeerError::AlreadyConnected);
        }

        self.standing_permits_connect_to_peer(socket_addr).await
    }

    /// Indicates if peer's [PeerStanding] permits connecting to them.
    ///
    /// With regard to PeerStanding, we can connect to a peer unless:
    ///   1. Peer has been banned.  (bad standing)  *and*
    ///   2. The peer's latest [PeerSanctionReason] was NOT a `ConnectFailed`  *or*
    ///   3. The peer's latest [PeerSanctionReason] was a `ConnectFailed` *and*
    ///      more than [CONNECT_FAILED_TIMEOUT_SECS] seconds have elapsed.
    ///
    /// This method emits debug log entries for all conditions to aid with diagnosis.
    pub async fn standing_permits_connect_to_peer(
        &self,
        socket_addr: SocketAddr,
    ) -> Result<(), AllowConnectToPeerError> {
        let standing_opt = self.get_peer_standing_from_database(socket_addr).await;

        match standing_opt {
            Some(standing) => {
                if !self.peer_standing_is_banned(&standing) {
                    debug!(
                        "standing_permits_connect_to_peer: {:?}.  peer NOT banned. score: {}. allow: true",
                        socket_addr, standing.score
                    );
                    Ok(())
                } else {
                    // we still allow connect if the last_sanction was a ConnectFailed and the
                    // elapsed time since last sanction is greater than sanction_retry_connect timeout
                    match (
                        standing.latest_sanction,
                        standing.timestamp_of_latest_sanction,
                    ) {
                        (Some(latest_sanction), Some(timestamp)) => {
                            let sanction_duration = CONNECT_FAILED_TIMEOUT_SECS as i128;
                            let sanction_remaining_secs =
                                sanction_duration - timestamp.elapsed().unwrap().as_secs() as i128;

                            match latest_sanction {
                                PeerSanctionReason::ConnectFailed => {
                                    let allow = sanction_remaining_secs <= 0;

                                    match allow {
                                        true => {
                                            debug!("standing_permits_connect_to_peer: {:?}. peer is BANNED but timeout expired since ConnectFailed sanction. score: {}. allow: true", socket_addr, standing.score);
                                            Ok(())
                                        }
                                        false => {
                                            debug!("standing_permits_connect_to_peer: {:?}. peer remains BANNED since last ConnectFailed.  Can try again in {} seconds.  score: {}. allow: false", socket_addr, sanction_remaining_secs, standing.score);
                                            Err(AllowConnectToPeerError::BannedForConnectFailed(
                                                sanction_remaining_secs as u64, // must be positive here; cast is safe.
                                            ))
                                        }
                                    }
                                }
                                _ => {
                                    debug!("standing_permits_connect_to_peer: {:?}. Peer remains BANNED. latest sanction: {:?}. score: {}. allow: false", socket_addr, latest_sanction, standing.score);
                                    Err(AllowConnectToPeerError::Banned(standing))
                                }
                            }
                        }
                        _ => {
                            debug!("standing_permits_connect_to_peer: {:?}. latest sanction not found.  allow: true", socket_addr);
                            Ok(())
                        }
                    }
                }
            }
            None => {
                debug!(
                    "standing_permits_connect_to_peer: {:?}.  peer standing not found. allow: true",
                    socket_addr
                );
                Ok(())
            }
        }
    }

    /// Check if an established connection is allowed to proceed.
    ///
    /// Intended for both incoming and outgoing connections.
    ///
    /// checks for:
    ///  + peer's IP is banned by config
    ///  + peer is banned due to past sanctions
    ///  + we reached our max number of peers
    ///  + we already have a connection to this peer
    ///  + we connected to ourself
    ///  + peer version number is incompatible with ours.
    pub async fn check_if_connection_is_allowed(
        &self,
        banned_ip_list: &[IpAddr],
        max_peers: usize,
        own_handshake: &HandshakeData,
        other_handshake: &HandshakeData,
        peer_address: SocketAddr,
    ) -> ConnectionStatus {
        fn versions_are_compatible(own_version: &str, other_version: &str) -> bool {
            let own_version = semver::Version::parse(own_version)
                .expect("Must be able to parse own version string. Got: {own_version}");
            let other_version = match semver::Version::parse(other_version) {
                Ok(version) => version,
                Err(err) => {
                    warn!("Peer version is not a valid semver version. Got error: {err}",);
                    return false;
                }
            };

            // All alphanet versions are incompatible with each other. Alphanet has versions
            // "0.0.n". Alphanet is also incompatible with mainnet or any other versions.
            if own_version.major == 0 && own_version.minor == 0
                || other_version.major == 0 && other_version.minor == 0
            {
                return own_version == other_version;
            }

            true
        }

        // Disallow connection if peer's IP is banned (via CLI arguments)
        if banned_ip_list.contains(&peer_address.ip()) {
            warn!(
                "Banned peer {} attempted to connect. Disallowing.",
                peer_address.ip()
            );
            return ConnectionStatus::Refused(ConnectionRefusedReason::BadStanding);
        }

        // Disallow connection if peer is banned.
        if let Some(banned) = self.peer_is_banned(peer_address).await {
            if banned {
                return ConnectionStatus::Refused(ConnectionRefusedReason::BadStanding);
            }
        }

        if let Some(status) = {
            // Disallow connection if max number of &peers has been attained
            if max_peers <= self.peer_map.len() {
                Some(ConnectionStatus::Refused(
                    ConnectionRefusedReason::MaxPeerNumberExceeded,
                ))
            }
            // Disallow connection to already connected peer.
            else if self.peer_map.values().any(|peer| {
                peer.instance_id == other_handshake.instance_id
                    || peer_address == peer.connected_address
            }) {
                Some(ConnectionStatus::Refused(
                    ConnectionRefusedReason::AlreadyConnected,
                ))
            } else {
                None
            }
        } {
            return status;
        }

        // Disallow connection to self
        if own_handshake.instance_id == other_handshake.instance_id {
            return ConnectionStatus::Refused(ConnectionRefusedReason::SelfConnect);
        }

        // Disallow connection if versions are incompatible
        if !versions_are_compatible(&own_handshake.version, &other_handshake.version) {
            warn!(
                "Attempting to connect to incompatible version. You might have to upgrade, or the other node does. Own version: {}, other version: {}",
                own_handshake.version,
                other_handshake.version);
            return ConnectionStatus::Refused(ConnectionRefusedReason::IncompatibleVersion);
        }

        info!("ConnectionStatus::Accepted");
        ConnectionStatus::Accepted
    }
}

#[derive(thiserror::Error, Debug, Clone, PartialEq)]
pub enum AllowConnectToPeerError {
    #[error("the IP is banned by configuration")]
    IpBannedByConfig,

    #[error("max peers limit exceeded")]
    MaxPeersExceeded,

    #[error("already connected to peer")]
    AlreadyConnected,

    #[error("peer is still banned since last ConnectFailed. Can retry in {0} seconds")]
    BannedForConnectFailed(u64),

    #[error("peer is banned.  standing: {0:?}")]
    Banned(PeerStanding),
}
