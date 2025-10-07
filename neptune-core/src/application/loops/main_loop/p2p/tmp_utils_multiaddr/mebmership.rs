use libp2p::Multiaddr;
use multiaddr::Protocol;

pub fn is_ipadr_in_madrs(
    ipadr: std::net::IpAddr, 
    // madrs: &[Multiaddr]
    madrs: std::slice::Iter<'_, Multiaddr>
) -> bool {
    !madrs.filter(|madr| !itertools::Itertools::contains(&mut madr.protocol_stack(), &Protocol::P2pCircuit.tag()))
    // .iter()
    .any(|madr| itertools::Itertools::contains(&mut madr.iter(), &ipadr.into()))
}

/// *strips the `PeerId` endings from `madrs`*
/// 
/// Note that this ignores possible `PeerId` in `madrs`. For our needs it seems possible to extend it with those, though it's a very low priority TODO.
pub fn does_madrs_cover_socketadr(
    socketadr: &std::net::SocketAddr, madrs: std::slice::IterMut<'_, Multiaddr>
) -> bool {
    // let socketadr = [
    //     Protocol::from(socketadr.ip().clone()), Protocol::Tcp(socketadr.port())
    // ];
    let socketadr_ip = Multiaddr::from(socketadr.ip());
    let socketadr = socketadr_ip.clone().with(Protocol::Tcp(socketadr.port()));
    // let madrs = 
    madrs.map(|madr| super::peerid_split(madr).1)
    .any(|madr| madr.ends_with(&socketadr_ip) || madr.ends_with(&socketadr))
    // if madrs {true} else {}
    // let socketadr = match socketadr {
    //     SocketAddr::V4(socket_addr_v4) => [
    //         Protocol::from(socket_addr_v4.ip().clone()), Protocol::Tcp(socket_addr_v4.port())
    //     ],
    //     SocketAddr::V6(socket_addr_v6) => [
    //         Protocol::from(socket_addr_v6.ip().clone()), Protocol::Tcp(socket_addr_v6.port())
    //     ],
    // };
}