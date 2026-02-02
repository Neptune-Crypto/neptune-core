use std::net::IpAddr;

use libp2p::Multiaddr;
use libp2p::PeerId;
use proptest::collection::vec;
use proptest::prelude::any;
use proptest::prelude::Strategy;
use proptest::prop_oneof;

// Strategy to generate an IpAddr
pub(crate) fn arb_ip_addr() -> impl Strategy<Value = IpAddr> {
    prop_oneof![
        any::<[u8; 4]>().prop_map(|octets| IpAddr::V4(octets.into())),
        any::<[u8; 16]>().prop_map(|octets| IpAddr::V6(octets.into())),
    ]
}

pub(crate) fn arb_multiaddr() -> impl Strategy<Value = Multiaddr> {
    // Generate a standard port range
    let port_strat = 1..65535u16;

    (arb_ip_addr(), port_strat).prop_map(|(ip, port)| {
        match ip {
            IpAddr::V4(ipv4_addr) => format!("/ip4/{ipv4_addr}/tcp/{port}"),
            IpAddr::V6(ipv6_addr) => format!("/ip6/{ipv6_addr}/tcp/{port}"),
        }
        .parse::<Multiaddr>()
        .expect("Generated Multiaddr string should always be valid")
    })
}

pub(crate) fn arb_peer_id() -> impl Strategy<Value = PeerId> {
    vec(0u8..=u8::MAX, 32).prop_map(|seed| {
        let seed = std::convert::TryInto::<[u8; 32]>::try_into(seed).unwrap();
        // Create a deterministic keypair from the generated seed
        let secret_key = libp2p::identity::ed25519::SecretKey::try_from_bytes(seed).unwrap();
        let keypair = libp2p::identity::ed25519::Keypair::from(secret_key);
        PeerId::from_public_key(&libp2p::identity::PublicKey::from(keypair.public()))
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use std::time::Duration;
    use std::time::SystemTime;

    use libp2p::StreamProtocol;
    use proptest::prelude::BoxedStrategy;
    use proptest::prelude::Strategy;

    use super::*;
    use crate::application::network::address_book::Peer;

    /// Generates an arbitrary valid libp2p StreamProtocol.
    ///
    /// This strategy creates strings in the format "/[a-z0-9]/[semver]"
    /// to simulate realistic protocol identifiers.
    pub(crate) fn arb_stream_protocol() -> impl Strategy<Value = StreamProtocol> {
        // Generate a name (e.g., "neptune", "kad", "ping")
        // and a version (e.g., "1.0.0", "2.1.0")
        ("[a-z]{3,10}", "[0-9]\\.[0-9]\\.[0-9]").prop_map(|(name, version)| {
            let proto_string = format!("/{}/{}", name, version);
            // StreamProtocol::new expects a &'static str or similar.
            // For testing, Box::leak is the cleanest way to satisfy the lifetime
            // if your version doesn't support owned conversion.
            StreamProtocol::new(Box::leak(proto_string.into_boxed_str()))
        })
    }
    /// Generates a realistic agent version string (e.g., "neptune-cash/0.1.5")
    pub(crate) fn arb_agent_version() -> impl Strategy<Value = String> {
        // Generate a client name and a semver version
        ("[a-z-]{3,12}", "[0-9]\\.[0-9]{1,2}\\.[0-9]{1,2}")
            .prop_map(|(name, version)| format!("{}/{}", name, version))
    }

    /// Generates a realistic protocol version string (e.g., "/neptune/1.0.0")
    pub(crate) fn arb_protocol_version() -> impl Strategy<Value = String> {
        // Protocols almost always start with a slash and follow a tiered naming
        ("[a-z]{3,10}", "[0-9]\\.[0-9]\\.[0-9]")
            .prop_map(|(proto, version)| format!("/{}/{}", proto, version))
    }

    /// Generates a SystemTime between Jan 1 2025 and Jan 1 2026.
    /// This range ensures the data is realistic for a modern blockchain node.
    pub(crate) fn arb_system_time() -> impl Strategy<Value = SystemTime> {
        // Approx seconds from 1970 to Jan 1 2025: 1_735_689_600
        // We generate an offset from that point.
        (0..31_536_000u64).prop_map(|offset_seconds| {
            use std::time::UNIX_EPOCH;

            UNIX_EPOCH + Duration::from_secs(1_735_689_600 + offset_seconds)
        })
    }

    impl Peer {
        pub(crate) fn arbitrary() -> BoxedStrategy<Self> {
            let range_for_num_listen_addresses = 0..5;
            let range_for_num_protocols = 0..5;

            let strategy_for_listen_addresses =
                proptest::collection::vec(arb_multiaddr(), range_for_num_listen_addresses);
            let strategy_for_protocols =
                proptest::collection::vec(arb_stream_protocol(), range_for_num_protocols);

            (
                strategy_for_listen_addresses,
                arb_agent_version(),
                arb_protocol_version(),
                strategy_for_protocols,
                [arb_system_time(), arb_system_time()],
                0u32..u32::MAX,
            )
                .prop_map(
                    |(
                        listen_addresses,
                        agent_version,
                        protocol_version,
                        supported_protocols,
                        timestamps,
                        fail_count,
                    )| {
                        let first_seen = timestamps[0].min(timestamps[1]);
                        let last_seen = timestamps[0].max(timestamps[1]);
                        Self {
                            listen_addresses,
                            agent_version,
                            protocol_version,
                            supported_protocols,
                            first_seen,
                            last_seen,
                            fail_count,
                        }
                    },
                )
                .boxed()
        }
    }
}
