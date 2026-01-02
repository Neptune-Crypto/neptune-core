use std::net::IpAddr;
use std::net::SocketAddr;
use std::time::SystemTime;

use libp2p::multiaddr::Protocol;
use libp2p::multihash::Multihash;
use libp2p::Multiaddr;
use libp2p::PeerId;
use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;

use super::InstanceId;
use super::PeerStanding;
use crate::HandshakeData;

/// Derive a pseudorandom [`PeerId`] from a [`SocketAddr`].
///
/// This is a controversial feature, with accordingly complex motivation -- bear
/// with:
///
/// This map is a compatibility layer bridging two architectures. With the
/// introduction of the libp2p network stack, all peer-related dictionaries
/// were modified to use the [`PeerId`] as the key instead of the
/// [`SocketAddr`]. Here is why the [`PeerId`] is a better choice:
///  - In the libp2p stack, the [`PeerId`] is cryptographically bound to the
///    peer's public key -- and the stack will refuse to connect if it fails to
///    verify that the peer really knows the matching secret key.
///  - The same peer (identified by public key) can have multiple
///    [`SocketAddr`]s, and even other internet-route-locators. While malicious
///    attackers can generate many key pairs, the point is that honest peers
///    will reuse the same public key but will be treated as different peers if
///    their [`SocketAddr`] is used as a stand-in for their identity. The
///    [`SocketAddr`] can change under benign circumstances, for instance if the
///    peer switches from WiFi to 4G, or it their ISP switches to a different
///    IP. So for honest peers, using the [`PeerId`] as the identifier leads to
///    less redundant work and greater peer set entropy.
///  - Malicious nodes must still use a variety of [`SocketAddr`]s if the goal
///    is to populate a victim's peer set with sybils and drive out honest
///    peers.Banning still happens at the level of [`SocketAddr`]s. So this
///    transition does not degrade security.
///
/// However, since the legacy peer-to-peer stack has no concept of [`PeerId`],
/// it is difficult to access the dictionaries that now use the [`PeerId`] as
/// key, such as `peer_map` and `peer_standing`. This map deterministically
/// derives an identity ([`PeerId`]) from the peer's [`SocketAddr`]. This is a
/// controversial identification because a) there is no cryptographic
/// authentication or even tie to public keys; and b) leads to duplication of
/// work and weaker peer set entropy. Therefore, this map should only be used in
/// the context of the legacy peer-to-peer stack and, if the legacy peer-to-peer
/// stack is deprecated, this function should be deprecated along with it.
pub(crate) fn pseudorandom_peer_id(addr: &SocketAddr) -> PeerId {
    let mut hasher = Sha256::new();
    hasher.update(b"legacy-mapping");
    hasher.update(addr.to_string().as_bytes());
    let hash_result = hasher.finalize();

    // Use SHA2_256 (Code 0x12) which is the libp2p standard.
    let mhash = Multihash::wrap(0x12, &hash_result)
        .expect("SHA2-256 hash length is 32 bytes, which is valid for multihash");

    PeerId::from_multihash(mhash).expect("SHA2-256 is the standard libp2p PeerId hash algorithm")
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PeerConnectionInfo {
    listen_port: Option<u16>,
    address: Multiaddr,
    inbound: bool,
}

impl PeerConnectionInfo {
    pub fn new(listen_port: Option<u16>, connected_address: Multiaddr, inbound: bool) -> Self {
        Self {
            listen_port,
            address: connected_address,
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

    pub fn with_standing(mut self, standing: PeerStanding) -> Self {
        self.standing = standing;
        self
    }

    pub fn instance_id(&self) -> u128 {
        self.instance_id
    }

    pub fn standing(&self) -> PeerStanding {
        self.standing
    }

    pub fn connection_established(&self) -> SystemTime {
        self.own_timestamp_connection_established
    }

    pub fn is_archival_node(&self) -> bool {
        self.is_archival_node
    }

    pub fn address(&self) -> Multiaddr {
        self.peer_connection_info.address.clone()
    }

    pub fn connection_is_inbound(&self) -> bool {
        self.peer_connection_info.inbound
    }

    pub fn connection_is_outbound(&self) -> bool {
        !self.connection_is_inbound()
    }

    pub fn ip_is_local(address: IpAddr) -> bool {
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
    pub fn is_local_connection(&self) -> bool {
        let ip_addr = self
            .peer_connection_info
            .address
            .iter()
            .find_map(|p| match p {
                Protocol::Ip4(ip) => Some(std::net::IpAddr::V4(ip)),
                Protocol::Ip6(ip) => Some(std::net::IpAddr::V6(ip)),
                _ => None,
            });

        match ip_addr {
            Some(ip) => Self::ip_is_local(ip),
            None => false, // No IP found (e.g., it's a DNS address or relay)
        }
    }

    /// returns the neptune-core version-string reported by the peer.
    ///
    /// note: the peer might not be honest.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Return the [`Multiaddr`] that the peer is expected to listen on. Returns
    /// `None` if peer does not accept incoming connections.
    pub fn listen_address(&self) -> Option<Multiaddr> {
        let listen_port = self.peer_connection_info.listen_port?;
        let mut new_multiaddr = Multiaddr::empty();

        for component in &self.peer_connection_info.address {
            match component {
                // If TCP or UDP, replace the port with listen_port
                Protocol::Tcp(_) => new_multiaddr.push(Protocol::Tcp(listen_port)),
                Protocol::Udp(_) => new_multiaddr.push(Protocol::Udp(listen_port)),

                // Otherwise, keep the component as is (IP, DNS, etc.)
                other => new_multiaddr.push(other),
            }
        }
        Some(new_multiaddr)
    }

    #[cfg(test)]
    pub(crate) fn set_connection_established(&mut self, new_timestamp: SystemTime) {
        self.own_timestamp_connection_established = new_timestamp;
    }
}

#[cfg(any(feature = "mock-rpc", test))]
fn generate_pseudorandom_multiaddr(seed: u64) -> Multiaddr {
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(seed);
    let mut addr = Multiaddr::empty();

    // transport protocol
    match <rand::rngs::StdRng as rand::Rng>::random_range(&mut rng, 0..3) {
        0 => {
            let ip = std::net::Ipv4Addr::from(
                <rand::rngs::StdRng as rand::Rng>::random::<[u8; 4]>(&mut rng),
            );
            addr.push(Protocol::Ip4(ip));
        }
        1 => {
            let ip = std::net::Ipv6Addr::from(
                <rand::rngs::StdRng as rand::Rng>::random::<[u8; 16]>(&mut rng),
            );
            addr.push(Protocol::Ip6(ip));
        }
        _ => {
            addr.push(Protocol::Dns("example.com".into()));
        }
    }

    // port
    addr.push(Protocol::Tcp(
        <rand::rngs::StdRng as rand::Rng>::random_range(&mut rng, 1024..65535),
    ));

    addr
}

#[cfg(any(feature = "mock-rpc", test))]
impl rand::distr::Distribution<PeerConnectionInfo> for rand::distr::StandardUniform {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> PeerConnectionInfo {
        PeerConnectionInfo {
            listen_port: if rng.random_bool(0.5) {
                Some(rng.random())
            } else {
                None
            },
            address: generate_pseudorandom_multiaddr(rng.random()),
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
    use test_strategy::proptest;

    use super::*;
    use std::net::Ipv4Addr;
    use std::net::SocketAddr;
    use std::net::SocketAddrV4;

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

    #[test]
    fn test_pseudorandom_peer_id_determinism() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        // Ensure it doesn't panic
        let id1 = pseudorandom_peer_id(&addr);
        let id2 = pseudorandom_peer_id(&addr);

        // Ensure determinism
        assert_eq!(id1, id2, "Same SocketAddr must produce same PeerId");

        // Ensure different addresses produce different IDs
        let addr_different: SocketAddr = "127.0.0.1:8081".parse().unwrap();
        let id_different = pseudorandom_peer_id(&addr_different);
        assert_ne!(
            id1, id_different,
            "Different ports must produce different PeerIds"
        );
    }

    #[test]
    fn test_peer_id_round_trip_string() {
        let addr: SocketAddr = "192.168.1.1:9000".parse().unwrap();
        let id = pseudorandom_peer_id(&addr);

        // Verify it can be encoded/decoded as a standard libp2p string
        let id_str = id.to_base58();
        let decoded_id: PeerId = id_str.parse().expect("Should be a valid Base58 PeerId");
        assert_eq!(id, decoded_id);
    }

    #[proptest]
    fn pseudorandom_peer_id_does_not_crash(c0: u8, c1: u8, c2: u8, c3: u8, port: u16) {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(c0, c1, c2, c3), port));
        let peer_id = pseudorandom_peer_id(&addr); // no crash
    }
}
