//! A record of the IP addresses peers were *observed* connecting from.

use std::collections::HashMap;
use std::collections::HashSet;
use std::net::IpAddr;
use std::time::SystemTime;

use itertools::Itertools;
use libp2p::Multiaddr;
use libp2p::PeerId;

/// Cap on the number of peers IPs remembered.
const OBSERVED_IPS_MAX_SIZE: usize = 2_000;

/// Where each peer was actually seen connecting from.
#[derive(Debug, Clone, Default)]
pub(crate) struct ObservedIps {
    by_peer: HashMap<PeerId, (SystemTime, HashSet<IpAddr>)>,
}

impl ObservedIps {
    /// Note the address a peer was observed connecting from.
    ///
    /// Relayed addresses are not recorded, as an IP for the peer is not known
    /// in this case.
    pub(crate) fn record(&mut self, peer_id: PeerId, address: &Multiaddr) {
        let Some(ip) = attributable_ip(address) else {
            return;
        };

        let (last_seen, ips) = self
            .by_peer
            .entry(peer_id)
            .or_insert_with(|| (SystemTime::now(), HashSet::new()));
        *last_seen = SystemTime::now();
        ips.insert(ip);

        self.prune_to_length(OBSERVED_IPS_MAX_SIZE);
    }

    /// The IPs a peer was observed at.
    pub(crate) fn get(&self, peer_id: &PeerId) -> impl Iterator<Item = IpAddr> + '_ {
        self.by_peer
            .get(peer_id)
            .into_iter()
            .flat_map(|(_last_seen, ips)| ips.iter().copied())
    }

    /// Forget the least recently seen peers, down to `target_length`.
    fn prune_to_length(&mut self, target_length: usize) {
        if self.by_peer.len() <= target_length {
            return;
        }

        let num_to_drop = self.by_peer.len() - target_length;
        let stale = self
            .by_peer
            .iter()
            .map(|(peer_id, (last_seen, _))| (*peer_id, *last_seen))
            .sorted_by_key(|(_, last_seen)| *last_seen)
            .take(num_to_drop)
            .map(|(peer_id, _)| peer_id)
            .collect_vec();

        for peer_id in stale {
            self.by_peer.remove(&peer_id);
        }
    }
}

/// The IP that behaviour at this address can be *attributed* to, if any.
///
/// If the connection is a relayed connection, `None` is returned since we don't
/// have an IP address to tie to the peer.
pub(crate) fn attributable_ip(address: &Multiaddr) -> Option<IpAddr> {
    if is_relayed(address) {
        return None;
    }

    ip_of(address)
}

/// Whether the address routes through a relay, and so names the relay rather
/// than the peer.
fn is_relayed(address: &Multiaddr) -> bool {
    address
        .iter()
        .any(|proto| matches!(proto, libp2p::multiaddr::Protocol::P2pCircuit))
}

/// The first IP address named by a multiaddress, if any.
pub(crate) fn ip_of(address: &Multiaddr) -> Option<IpAddr> {
    address.iter().find_map(|protocol| match protocol {
        libp2p::multiaddr::Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
        libp2p::multiaddr::Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
        _ => None,
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::net::Ipv4Addr;
    use std::net::Ipv6Addr;
    use std::time::Duration;

    use super::*;

    fn peer(seed: u8) -> PeerId {
        PeerId::from_multihash(libp2p::multihash::Multihash::wrap(0x00, &[seed; 32]).unwrap())
            .unwrap()
    }

    #[test]
    fn records_the_ip_of_a_direct_connection() {
        let mut observed = ObservedIps::default();
        let peer_id = peer(1);
        observed.record(peer_id, &"/ip4/9.9.9.9/tcp/9798".parse().unwrap());

        assert_eq!(
            vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))],
            observed.get(&peer_id).collect_vec()
        );
    }

    #[test]
    fn records_ipv6_too() {
        let mut observed = ObservedIps::default();
        let peer_id = peer(2);
        observed.record(peer_id, &"/ip6/::1/tcp/9798".parse().unwrap());

        assert_eq!(
            vec![IpAddr::V6(Ipv6Addr::LOCALHOST)],
            observed.get(&peer_id).collect_vec()
        );
    }

    #[test]
    fn ignores_relayed_addresses() {
        let mut observed = ObservedIps::default();
        let peer_id = peer(3);
        let relayed = format!("/ip4/9.9.9.9/tcp/9798/p2p/{}/p2p-circuit", peer(4));
        observed.record(peer_id, &relayed.parse().unwrap());

        assert!(observed.get(&peer_id).next().is_none());
    }

    #[test]
    fn a_direct_address_is_attributable_to_its_ip() {
        assert_eq!(
            Some(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))),
            attributable_ip(&"/ip4/9.9.9.9/tcp/9798".parse().unwrap())
        );
    }

    #[test]
    fn a_relayed_address_is_attributable_to_nobody() {
        let relayed = format!("/ip4/9.9.9.9/tcp/9798/p2p/{}/p2p-circuit", peer(9));
        assert_eq!(None, attributable_ip(&relayed.parse().unwrap()));
    }

    #[test]
    fn an_unknown_peer_has_no_observed_ips() {
        let observed = ObservedIps::default();
        assert!(observed.get(&peer(5)).next().is_none());
    }

    #[test]
    fn several_addresses_for_one_peer_are_all_kept() {
        let mut observed = ObservedIps::default();
        let peer_id = peer(6);
        observed.record(peer_id, &"/ip4/9.9.9.9/tcp/9798".parse().unwrap());
        observed.record(peer_id, &"/ip4/8.8.8.8/tcp/9798".parse().unwrap());

        assert_eq!(2, observed.get(&peer_id).count());
    }

    #[test]
    fn pruning_drops_the_least_recently_seen() {
        let mut observed = ObservedIps::default();
        let old = peer(7);
        let recent = peer(8);

        observed.record(old, &"/ip4/9.9.9.9/tcp/9798".parse().unwrap());
        observed.by_peer.get_mut(&old).unwrap().0 = SystemTime::now() - Duration::from_secs(3600);
        observed.record(recent, &"/ip4/8.8.8.8/tcp/9798".parse().unwrap());

        observed.prune_to_length(1);

        assert!(observed.get(&old).next().is_none());
        assert!(observed.get(&recent).next().is_some());
    }
}
