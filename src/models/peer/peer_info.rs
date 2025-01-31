use std::net::SocketAddr;
use std::time::SystemTime;

use serde::Deserialize;
use serde::Serialize;

use super::handshake_data::VersionString;
use super::InstanceId;
use super::PeerStanding;

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
    connection_established: SystemTime,
    pub(crate) standing: PeerStanding,
    version: VersionString,
    is_archival_node: bool,
}

impl PeerInfo {
    pub(crate) fn new(
        peer_connection_info: PeerConnectionInfo,
        instance_id: InstanceId,
        connection_established: SystemTime,
        version: VersionString,
        is_archival_node: bool,
        peer_tolerance: u16,
    ) -> Self {
        assert!(peer_tolerance > 0, "Peer tolerance must be positive");
        let standing = PeerStanding::new(peer_tolerance);
        Self {
            peer_connection_info,
            instance_id,
            connection_established,
            standing,
            version,
            is_archival_node,
        }
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
        self.connection_established
    }

    pub fn is_archival_node(&self) -> bool {
        self.is_archival_node
    }

    pub(crate) fn connection_is_inbound(&self) -> bool {
        self.peer_connection_info.inbound
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
        self.connection_established = new_timestamp;
    }
}
