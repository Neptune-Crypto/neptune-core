//! Connected peers and their standings.
//!
//! Kept beside the global state lock rather than under it, so that
//! connecting, disconnecting and sanctioning peers never wait for block
//! processing, and never make block processing wait.

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::Mutex;
use std::sync::PoisonError;
use std::sync::RwLock;
use std::time::SystemTime;

use anyhow::Result;
use libp2p::PeerId;
use neptune_database::create_db_if_missing;
use neptune_database::NeptuneLevelDb;
use neptune_database::WriteBatchAsync;
use neptune_p2p::peer::peer_info::PeerInfo;
use neptune_p2p::peer::InstanceId;
use neptune_p2p::peer::PeerSanction;
use neptune_p2p::peer::PeerStanding;
use neptune_p2p::peer::StandingExceedsBanThreshold;
use neptune_primitives::data_directory::DataDirectory;

pub type PeerMap = HashMap<PeerId, PeerInfo>;

/// The connected peers, with their standings, and the stored standings of
/// peers by IP address.
///
/// The connected peers are behind a lock that is only ever held for the
/// duration of a closure. The standings database needs no lock.
pub struct Peers {
    connected: RwLock<PeerMap>,

    /// Times of graceful disconnections that this node initiated, by the
    /// disconnected peer's instance ID. Consulted before reconnecting to a
    /// peer. Disconnections initiated by the peer, or abrupt ones, are not
    /// recorded.
    disconnection_times: Mutex<HashMap<InstanceId, SystemTime>>,

    // Storing IP addresses is, according to this answer, not a violation of
    // GDPR: https://law.stackexchange.com/a/28609/45846
    standings: NeptuneLevelDb<IpAddr, PeerStanding>,
}

impl fmt::Debug for Peers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Peers")
            .field("num_connected", &self.with_connected(PeerMap::len))
            .finish_non_exhaustive()
    }
}

impl Peers {
    pub(crate) fn new(standings: NeptuneLevelDb<IpAddr, PeerStanding>) -> Self {
        Self {
            connected: RwLock::new(PeerMap::new()),
            disconnection_times: Mutex::new(HashMap::new()),
            standings,
        }
    }

    /// Open the standings database in the data directory, creating it if it
    /// is missing. No peers are connected yet.
    pub(crate) async fn initialize(data_dir: &DataDirectory) -> Result<Self> {
        let database_dir_path = data_dir.database_dir_path();
        DataDirectory::create_dir_if_not_exists(&database_dir_path).await?;

        let standings = NeptuneLevelDb::<IpAddr, PeerStanding>::new(
            &data_dir.banned_ips_database_dir_path(),
            &create_db_if_missing(),
        )
        .await?;

        Ok(Self::new(standings))
    }

    /// Read the connected peers. The closure runs under the lock, so it must
    /// be quick and must not touch the connected peers again.
    pub fn with_connected<R>(&self, f: impl FnOnce(&PeerMap) -> R) -> R {
        f(&self
            .connected
            .read()
            .unwrap_or_else(PoisonError::into_inner))
    }

    /// Modify the connected peers. The closure runs under the lock, so it
    /// must be quick and must not touch the connected peers again.
    pub(crate) fn with_connected_mut<R>(&self, f: impl FnOnce(&mut PeerMap) -> R) -> R {
        f(&mut self
            .connected
            .write()
            .unwrap_or_else(PoisonError::into_inner))
    }

    /// A copy of the connected peers, for use outside the lock.
    pub(crate) fn snapshot(&self) -> PeerMap {
        self.with_connected(PeerMap::clone)
    }

    /// The number of connected peers.
    pub fn len(&self) -> usize {
        self.with_connected(PeerMap::len)
    }

    pub fn is_empty(&self) -> bool {
        self.with_connected(PeerMap::is_empty)
    }

    /// A copy of the connected peer's info, if it is connected.
    #[cfg(test)]
    pub(crate) fn get(&self, peer_id: PeerId) -> Option<PeerInfo> {
        self.with_connected(|connected| connected.get(&peer_id).cloned())
    }

    /// Add a connected peer, returning what was recorded for it before.
    #[cfg(test)]
    pub(crate) fn insert(&self, peer_id: PeerId, peer_info: PeerInfo) -> Option<PeerInfo> {
        self.with_connected_mut(|connected| connected.insert(peer_id, peer_info))
    }

    /// Apply a sanction to a connected peer's standing. Returns `None` if the
    /// peer is not connected, and otherwise whether the standing is still
    /// above the ban threshold.
    pub(crate) fn sanction(
        &self,
        peer_id: PeerId,
        sanction: PeerSanction,
    ) -> Option<Result<(), StandingExceedsBanThreshold>> {
        self.with_connected_mut(|connected| {
            let peer_info = connected.get_mut(&peer_id)?;
            Some(peer_info.standing.sanction(sanction))
        })
    }

    /// The stored standing of the IP address, if any.
    pub(crate) async fn stored_standing(&self, ip: IpAddr) -> Option<PeerStanding> {
        self.standings.get(ip).await
    }

    /// Persist the standing of an IP address.
    pub(crate) async fn store_standing(&self, ip: IpAddr, standing: PeerStanding) {
        self.standings.clone().put(ip, standing).await;
    }

    /// The stored standings that are negative.
    pub(crate) fn all_stored_sanctions(&self) -> HashMap<IpAddr, PeerStanding> {
        self.standings
            .iter()
            .filter(|(_, standing)| standing.is_negative())
            .collect()
    }

    /// Clear the stored standing of an IP address, if any.
    pub(crate) async fn clear_stored_standing(&self, ip: IpAddr) {
        if let Some(mut standing) = self.standings.get(ip).await {
            standing.clear_standing();
            self.standings.clone().put(ip, standing).await;
        }
    }

    /// Clear all stored standings.
    pub(crate) async fn clear_all_stored_standings(&self) {
        let mut batch = WriteBatchAsync::new();
        for (ip, mut standing) in self.standings.iter() {
            standing.clear_standing();
            batch.op_write(ip, standing);
        }
        self.standings.clone().batch_write(batch).await;
    }

    /// Flush the standings database to disk.
    pub(crate) async fn flush(&self) {
        self.standings.clone().flush().await;
    }

    /// Register the time of a graceful disconnection from a peer that this
    /// node initiated.
    pub(crate) fn register_disconnection(&self, id: InstanceId, time: SystemTime) {
        self.disconnection_times
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id, time);
    }

    /// When this node last disconnected gracefully from the peer, if ever.
    pub(crate) fn last_disconnection_time(&self, id: InstanceId) -> Option<SystemTime> {
        self.disconnection_times
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&id)
            .copied()
    }
}

#[cfg(test)]
mod tests {
    use neptune_p2p::peer::NegativePeerSanction;
    use neptune_wallet::wallet_entropy::WalletEntropy;

    use super::*;
    use crate::application::config::cli_args;
    use crate::tests::shared::globalstate::mock_genesis_global_state;

    fn standing(value: i32) -> PeerStanding {
        PeerStanding::init(
            value,
            Some((NegativePeerSanction::DifferentGenesis, SystemTime::now())),
            None,
            1000,
        )
    }

    #[tokio::test]
    async fn a_standing_above_the_stored_one_is_still_written() {
        let cli = cli_args::Args::default();
        let state = mock_genesis_global_state(0, WalletEntropy::new_random(), cli).await;
        let ip: IpAddr = "203.0.113.10".parse().unwrap();

        state.peers().store_standing(ip, standing(-1000)).await;
        state.peers().store_standing(ip, standing(-600)).await;

        assert_eq!(
            Some(standing(-600).standing),
            state.peers().stored_standing(ip).await.map(|s| s.standing),
            "the later, less negative standing must have been written"
        );
    }
}
