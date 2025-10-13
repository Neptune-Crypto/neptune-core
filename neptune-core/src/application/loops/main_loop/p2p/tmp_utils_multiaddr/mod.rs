//! To add `libp2p` with less seams unexpectedly often ops turned out to be conversions between `Multiaddr` and `SocketAddr`.

use std::net::SocketAddr;

use libp2p::Multiaddr;
use multiaddr::Protocol;

use crate::application::loops::MSG_CONDIT;

pub mod membership;

/// if ends with `PeerId` that will be popped separately
pub fn peerid_split(couldendwith_peerid: &mut Multiaddr) -> (Option<libp2p::PeerId>, &mut Multiaddr) {if couldendwith_peerid.is_empty() {(None, couldendwith_peerid)} else {
    if let Protocol::P2p(peerid) = couldendwith_peerid.iter().last().expect(MSG_CONDIT) {
        couldendwith_peerid.pop();
        (Some(peerid), couldendwith_peerid)
    } 
    else {
        (None, couldendwith_peerid)
    }
}}

/// *strips the `PeerId` endings from `madrs`, and pops one or two `Protocol`*
pub fn socketaddr_tryfrom(madr: &mut Multiaddr) -> Option<SocketAddr> {if let Some(Protocol::Tcp(port)) = peerid_split(madr).1.pop() {
    Some(SocketAddr::new(match madr.pop() {
        Some(Protocol::Ip4(ip)) => ip.into(),
        Some(Protocol::Ip6(ip)) => ip.into(),
        _ => return None,
    }, port))
} else {None}}

pub fn multiaddr_from(sadr: &SocketAddr) -> Multiaddr {
    Multiaddr::empty().with(sadr.ip().into()).with(multiaddr::Protocol::Tcp(sadr.port()))
}