use std::net::IpAddr;
use std::net::SocketAddr;

use libp2p::multiaddr::Protocol;
use libp2p::Multiaddr;

#[derive(Debug, thiserror::Error)]
pub(crate) enum MultiaddrParseError {
    #[error("input is neither a valid Multiaddr nor IP")]
    Invalid,
}

pub(crate) fn parse_to_multiaddr(s: &str) -> Result<Multiaddr, MultiaddrParseError> {
    // 1. Try direct Multiaddr first
    if let Ok(m) = s.parse::<Multiaddr>() {
        return Ok(m);
    }

    // 2. Bare IP
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(match ip {
            IpAddr::V4(v4) => Multiaddr::from(Protocol::Ip4(v4)),
            IpAddr::V6(v6) => Multiaddr::from(Protocol::Ip6(v6)),
        });
    }

    // 3. SocketAddr
    let Ok(socket_addr) = s.parse() else {
        return Err(MultiaddrParseError::Invalid);
    };

    Ok(socketaddr_to_multiaddr(socket_addr))
}

/// Converts a `Multiaddr` to a `SocketAddr` if possible. Useful when libp2p and
/// the legacy P2P stack are used interchangeably.
pub(crate) fn multiaddr_to_socketaddr(addr: &Multiaddr) -> Option<SocketAddr> {
    let mut ip: Option<IpAddr> = None;
    let mut port: Option<u16> = None;

    for p in addr {
        match p {
            Protocol::Ip4(v4) => ip = Some(IpAddr::V4(v4)),
            Protocol::Ip6(v6) => ip = Some(IpAddr::V6(v6)),
            Protocol::Tcp(p) => port = Some(p),
            _ => {}
        }
    }

    match (ip, port) {
        (Some(ip), Some(port)) => Some(SocketAddr::new(ip, port)),
        _ => None,
    }
}

/// Used in tests, but also in genesis_node.rs, which explains why this function
/// and the module in which it is lived is marked `pub`.
pub fn socketaddr_to_multiaddr(addr: SocketAddr) -> Multiaddr {
    let mut maddr = Multiaddr::empty();

    let ip_proto = match addr.ip() {
        IpAddr::V4(ipv4) => Protocol::Ip4(ipv4),
        IpAddr::V6(ipv6) => Protocol::Ip6(ipv6),
    };
    maddr.push(ip_proto);

    let tcp_proto = Protocol::Tcp(addr.port());
    maddr.push(tcp_proto);

    maddr
}

#[cfg(test)]
pub mod tests {

    use std::net::SocketAddrV4;
    use std::net::SocketAddrV6;

    use proptest::prop_assert_eq;
    use test_strategy::proptest;

    use super::*;
    use crate::tests::shared::globalstate::get_dummy_socket_address;

    #[test]
    fn can_convert_socketaddrs_to_multiaddrs() {
        assert!(parse_to_multiaddr("139.162.193.206:9798").is_ok());
        assert!(parse_to_multiaddr("[2001:bc8:17c0:41e:46a8:42ff:fe22:e8e9]:9798").is_ok());
    }

    #[test]
    fn can_convert_ips_to_multiadds() {
        assert!(parse_to_multiaddr("139.162.193.206").is_ok());
        assert!(parse_to_multiaddr("2001:bc8:17c0:41e:46a8:42ff:fe22:e8e9").is_ok());
    }

    #[test]
    fn socketaddr_multiaddr_round_trip_unit() {
        let socket_address = get_dummy_socket_address(0);
        let multiaddr = socketaddr_to_multiaddr(socket_address);
        let socket_address_again = multiaddr_to_socketaddr(&multiaddr).unwrap();
        assert_eq!(socket_address_again, socket_address);
    }

    #[proptest]
    fn ipv4_multiaddr_round_trip_prop(ipv4: SocketAddrV4) {
        let socket_addr = SocketAddr::from(ipv4);
        let multiaddr = socketaddr_to_multiaddr(socket_addr);
        let socket_address_again = multiaddr_to_socketaddr(&multiaddr).unwrap();
        prop_assert_eq!(socket_addr, socket_address_again);
    }

    #[proptest]
    fn ipv6_multiaddr_round_trip_prop(ipv6: SocketAddrV6) {
        let socket_addr = SocketAddr::from(ipv6);
        let multiaddr = socketaddr_to_multiaddr(socket_addr);
        let socket_address_again = multiaddr_to_socketaddr(&multiaddr).unwrap();

        // Only compare ip + port
        prop_assert_eq!(socket_addr.ip(), socket_address_again.ip());
        prop_assert_eq!(socket_addr.port(), socket_address_again.port());

        // (Scope ID is ignored.)
    }
}
