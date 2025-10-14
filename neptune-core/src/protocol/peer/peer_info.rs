use std::net::IpAddr;
use std::net::SocketAddr;
use std::time::SystemTime;

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

    pub(crate) fn connection_is_outbound(&self) -> bool {
        !self.connection_is_inbound()
    }

    pub(crate) fn ip_is_local(address: IpAddr) -> bool {
        match address {
            IpAddr::V4(ipv4_addr) => {
                ipv4_addr.is_private() || ipv4_addr.is_loopback() || ipv4_addr.is_link_local()
            }
            IpAddr::V6(ipv6_addr) => {
                ipv6_addr.is_unique_local()
                    || ipv6_addr.is_loopback()
                    || ipv6_addr.is_unicast_link_local()
            }
        }
    }

    /// Determine if the connection was established on a local network, i.e.,
    /// if the IP used for the connection is a local IP.
    pub(crate) fn is_local_connection(&self) -> bool {
        Self::ip_is_local(self.peer_connection_info.connected_address.ip())
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

#[cfg(any(feature = "mock-rpc", test))]
impl rand::distr::Distribution<PeerConnectionInfo> for rand::distr::StandardUniform {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> PeerConnectionInfo {
        PeerConnectionInfo {
            port_for_incoming_connections: if rng.random_bool(0.5) {
                Some(rng.random())
            } else {
                None
            },
            connected_address: SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                    rng.random(),
                    rng.random(),
                    rng.random(),
                    rng.random(),
                )),
                rng.random_range(1..=65535),
            ),
            inbound: rng.random(),
        }
    }
}

#[cfg(any(feature = "mock-rpc", test))]
impl rand::distr::Distribution<PeerInfo> for rand::distr::StandardUniform {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> PeerInfo {
        let own_timestamp_connection_established =
            SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(rng.next_u64() >> 20);
        let peer_timestamp_connection_established =
            SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(rng.next_u64() >> 20);
        let local_rng = <rand::rngs::StdRng as rand::SeedableRng>::from_seed(rng.random());
        PeerInfo {
            peer_connection_info: rng.random(),
            instance_id: rng.random(),
            own_timestamp_connection_established,
            peer_timestamp_connection_established,
            standing: rng.random(),
            version: <rand::rngs::StdRng as rand::Rng>::sample_iter(
                local_rng,
                &rand::distr::Alphanumeric,
            )
            .take(10)
            .map(char::from)
            .collect(),
            is_archival_node: rng.random(),
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn can_identify_local_addresses() {
        assert!(PeerInfo::ip_is_local("10.125.55.26".parse().unwrap()));
        assert!(PeerInfo::ip_is_local("192.168.0.23".parse().unwrap()));
        assert!(PeerInfo::ip_is_local("169.254.1.1".parse().unwrap()));
        assert!(PeerInfo::ip_is_local("127.0.0.1".parse().unwrap()));
        assert!(!PeerInfo::ip_is_local("8.8.8.8".parse().unwrap()));
        assert!(PeerInfo::ip_is_local("::1".parse().unwrap()));
        assert!(PeerInfo::ip_is_local("fd00::1".parse().unwrap()));
        assert!(PeerInfo::ip_is_local("fe80::1".parse().unwrap()));
        assert!(!PeerInfo::ip_is_local("2001:db8::1".parse().unwrap()));
    }
}
