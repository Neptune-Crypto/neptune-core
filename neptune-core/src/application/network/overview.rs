use std::fmt::Display;

use libp2p::autonat::NatStatus;
use libp2p::Multiaddr;
use libp2p::PeerId;
use serde::Deserialize;
use serde::Serialize;

use crate::application::network::reachability::ReachabilityState;

/// Shadow enum to avoid Serialize / Deserialize problems for [`NatStatus`].
#[derive(Serialize, Deserialize)]
#[serde(remote = "NatStatus")]
enum NatStatusDef {
    #[serde(rename = "unknown")]
    Unknown,
    #[serde(rename = "public")]
    Public(Multiaddr),
    #[serde(rename = "private")]
    Private,
}

/// Overview data for the libp2p network stack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkOverview {
    // Reachability
    #[serde(with = "NatStatusDef")]
    pub nat_status: NatStatus,
    pub reachability_state: ReachabilityState,
    pub external_addresses: Vec<Multiaddr>,

    // Connection Capacity
    pub connection_count: usize,
    pub connection_limit: usize,

    // Relay State
    pub num_active_relays: usize,

    // Persistent State
    pub peer_id: PeerId,
    pub address_book_size: usize,
    pub num_banned_peers: usize,
}

impl Display for NetworkOverview {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "PeerId:             {}", self.peer_id)?;
        writeln!(f, "NAT Status:         {:?}", self.nat_status)?;
        writeln!(
            f,
            "Connections:        {}/{}",
            self.connection_count, self.connection_limit
        )?;
        writeln!(f, "Relay Reservations: {}", self.num_active_relays)?;

        if !self.external_addresses.is_empty() {
            writeln!(f, "External Addresses:")?;
            for addr in &self.external_addresses {
                writeln!(f, "        {}", addr)?;
            }
        }

        writeln!(f, "Address Book Size:  {}", self.address_book_size)?;

        writeln!(f, "Black List Size   : {}", self.num_banned_peers)?;

        Ok(())
    }
}

#[cfg(any(test, feature = "arbitrary-impls"))]
mod arbitrary {
    use ::arbitrary::Arbitrary;
    use ::arbitrary::Result;
    use ::arbitrary::Unstructured;
    use proptest::prelude::Strategy;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;

    use super::*;
    use crate::application::network::arbitrary::arb_multiaddr;
    use crate::application::network::arbitrary::arb_peer_id;

    impl<'a> Arbitrary<'a> for NetworkOverview {
        fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
            let mut runner = TestRunner::deterministic();
            let peer_id = arb_peer_id().new_tree(&mut runner).unwrap().current();
            let reachability_state = ReachabilityState::arbitrary()
                .new_tree(&mut runner)
                .unwrap()
                .current();
            let mut get_multiaddr = || arb_multiaddr().new_tree(&mut runner).unwrap().current();

            let connection_limit = u.int_in_range(10..=1000)?;
            let num_active_relays = u.int_in_range(0..=5)?;

            let address_book_size = u.int_in_range(0..=100)?;
            let num_banned_peers = u.int_in_range(0..=50)?;

            Ok(NetworkOverview {
                peer_id,
                nat_status: match u.int_in_range(0..=2)? {
                    0 => NatStatus::Public(get_multiaddr()),
                    1 => NatStatus::Private,
                    _ => NatStatus::Unknown,
                },
                external_addresses: (0..u.int_in_range(0..=4)?)
                    .map(|_| Ok(get_multiaddr()))
                    .collect::<Result<Vec<_>>>()?,

                connection_count: u.int_in_range(0..=connection_limit)?,
                connection_limit,
                num_active_relays,
                address_book_size,
                num_banned_peers,
                reachability_state,
            })
        }
    }
}

#[cfg(any(test, feature = "mock-rpc"))]
impl rand::distr::Distribution<NetworkOverview> for rand::distr::StandardUniform {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> NetworkOverview {
        const SHA256_CODE: u64 = 0x12;
        let raw_hash = rng.random::<[u8; 32]>();
        let multihash = libp2p::multihash::Multihash::wrap(SHA256_CODE, &raw_hash)
            .expect("32 bytes is valid for SHA2-256");
        let peer_id = PeerId::from_multihash(multihash).expect("Valid multihash");
        let num_public_addresses = rng.random_range(0..5);
        let external_addresses: Vec<_> = (0..num_public_addresses)
            .map(|_| rng.random::<[u8; 4]>())
            .map(std::net::Ipv4Addr::from)
            .map(std::net::IpAddr::V4)
            .map(Multiaddr::from)
            .collect();
        let nat_status = match rng.random_range(0usize..3) {
            0 => NatStatus::Unknown,
            1 => NatStatus::Private,
            2 => {
                if !external_addresses.is_empty() {
                    NatStatus::Public(external_addresses[0].clone())
                } else {
                    NatStatus::Private
                }
            }
            _ => unreachable!(),
        };
        let reachability_state = rng.random::<ReachabilityState>();
        let connection_limit = rng.random_range(0usize..=10);
        let connection_count = rng.random_range(0..=connection_limit);

        let num_active_relays = rng.random_range(0usize..5);

        let address_book_size = rng.random_range(0usize..100);
        let num_banned_peers = rng.random_range(0usize..50);

        NetworkOverview {
            peer_id,
            nat_status,
            external_addresses,
            connection_count,
            connection_limit,
            num_active_relays,
            address_book_size,
            num_banned_peers,
            reachability_state,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::hint::black_box;

    use proptest_arbitrary_interop::arb;
    use rand::rng;
    use rand::Rng;
    use test_strategy::proptest;

    use super::*;

    #[proptest]
    fn can_format_arbitrary_network_overview(
        #[strategy(arb::<NetworkOverview>())] overview: NetworkOverview,
    ) {
        let s = format!("{overview}"); // no crash
        black_box(s);
    }

    #[test]
    fn can_format_random_network_overview() {
        let mut rng = rng();
        let overview = rng.random::<NetworkOverview>();
        let s = format!("{overview}"); // no crash
        black_box(s);
    }
}
