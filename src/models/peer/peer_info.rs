use std::net::SocketAddr;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use serde::Deserialize;
use serde::Serialize;

use super::InstanceId;
use super::PeerStanding;
use crate::HandshakeData;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub(crate) struct PeerConnectionInfo {
    port_for_incoming_connections: Option<u16>,
    connected_address: SocketAddr,
    inbound: bool,
}

impl PeerConnectionInfo {
    pub(crate) fn new(
        port_for_incoming_connections: Option<u16>,
        connected_address: SocketAddr,
        inbound: bool,
    ) -> Self {
        Self {
            port_for_incoming_connections,
            connected_address,
            inbound,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PeerInfo {
    peer_connection_info: PeerConnectionInfo,
    instance_id: InstanceId,
    pub(crate) own_timestamp_connection_established: SystemTime,
    pub(crate) peer_timestamp_connection_established: SystemTime,
    pub(crate) standing: PeerStanding,
    version: String,
    is_archival_node: bool,
}

impl PeerInfo {
    pub(crate) fn new(
        peer_connection_info: PeerConnectionInfo,
        peer_handshake: &HandshakeData,
        connection_established: SystemTime,
        peer_tolerance: u16,
    ) -> Self {
        assert!(peer_tolerance > 0, "Peer tolerance must be positive");
        let standing = PeerStanding::new(peer_tolerance);
        Self {
            peer_connection_info,
            instance_id: peer_handshake.instance_id,
            own_timestamp_connection_established: connection_established,
            peer_timestamp_connection_established: peer_handshake.timestamp,
            standing,
            version: peer_handshake.version.to_string(),
            is_archival_node: peer_handshake.is_archival_node,
        }
    }

    /// Infallible absolute difference between two timestamps, in seconds.
    fn system_time_diff_seconds(peer: SystemTime, own: SystemTime) -> i128 {
        let peer = peer
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i128)
            .unwrap_or_else(|e| -(e.duration().as_secs() as i128));

        let own = own
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i128)
            .unwrap_or_else(|e| -(e.duration().as_secs() as i128));

        own - peer
    }

    /// Return the difference in time as reported by peer and client in seconds.
    /// The returned value is `peer clock - own clock`. So the amount of time
    /// that the connected peer is ahead of this client's clock. Negative value
    /// if peer clock is behind our clock.
    pub(crate) fn time_difference_in_seconds(&self) -> i128 {
        Self::system_time_diff_seconds(
            self.peer_timestamp_connection_established,
            self.own_timestamp_connection_established,
        )
    }

    pub(crate) fn with_standing(mut self, standing: PeerStanding) -> Self {
        self.standing = standing;
        self
    }

    pub(crate) fn instance_id(&self) -> u128 {
        self.instance_id
    }

    pub fn standing(&self) -> PeerStanding {
        self.standing
    }

    pub fn connected_address(&self) -> SocketAddr {
        self.peer_connection_info.connected_address
    }

    pub fn connection_established(&self) -> SystemTime {
        self.own_timestamp_connection_established
    }

    pub fn is_archival_node(&self) -> bool {
        self.is_archival_node
    }

    pub(crate) fn connection_is_inbound(&self) -> bool {
        self.peer_connection_info.inbound
    }

    /// returns the neptune-core version-string reported by the peer.
    ///
    /// note: the peer might not be honest.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Return the socket address that the peer is expected to listen on. Returns `None` if peer does not accept
    /// incoming connections.
    pub fn listen_address(&self) -> Option<SocketAddr> {
        self.peer_connection_info
            .port_for_incoming_connections
            .map(|port| SocketAddr::new(self.peer_connection_info.connected_address.ip(), port))
    }

    #[cfg(test)]
    pub(crate) fn set_connection_established(&mut self, new_timestamp: SystemTime) {
        self.own_timestamp_connection_established = new_timestamp;
    }
}

#[cfg(test)]
mod tests {
    use test_strategy::proptest;

    use super::*;

    #[test]
    fn time_difference_in_seconds_simple() {
        let now = SystemTime::now();
        let and_now = SystemTime::now();
        assert!(PeerInfo::system_time_diff_seconds(now, and_now) < 10);
    }

    #[proptest]
    fn time_difference_doesnt_crash(now: SystemTime, and_now: SystemTime) {
        PeerInfo::system_time_diff_seconds(now, and_now);
    }
}
