use serde::Deserialize;
use serde::Serialize;
use std::fmt::Display;

/// Tracks the state of the [`NetworkActor`](super::actor::NetworkActor) with
/// regards to its knowledge about how reachable it is, and to its strategy for
/// becoming reachable.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, strum::EnumCount)]
pub enum ReachabilityState {
    /// Initial state: we don't know our NAT status yet.
    #[default]
    Unknown,

    /// We don't know our NAT status yet, but we have observed our own observed
    /// address.
    UnknownWithExternalAddress(libp2p::Multiaddr),

    /// We are behind a NAT and cannot be reached directly.
    /// We are currently attempting to fix this.
    Private(RelayStrategy),

    /// AutoNAT confirmed public reachability.
    Public(libp2p::Multiaddr),

    /// UPnP successfully opened a port mapping on the router.
    Upnp(libp2p::Multiaddr),
}

impl Display for ReachabilityState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReachabilityState::Unknown => write!(f, "unknown"),
            ReachabilityState::UnknownWithExternalAddress(multiaddr) => {
                write!(f, "unknown ({multiaddr})")
            }
            ReachabilityState::Private(relay_strategy) => write!(f, "natted and {relay_strategy}"),
            ReachabilityState::Public(multiaddr) => write!(f, "public: {multiaddr}"),
            ReachabilityState::Upnp(multiaddr) => write!(f, "upnp: {multiaddr}"),
        }
    }
}

/// Tracks the state of the reachability machine.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(
    any(test, feature = "arbitrary-impls", feature = "mock-rpc"),
    derive(strum::EnumCount)
)]
pub enum RelayStrategy {
    /// We know we are private, but Identify hasn't given us an external IP yet.
    #[default]
    WaitingForExternalAddress,

    /// We have an IP and have requested a Relay reservation.
    Pending(libp2p::Multiaddr),

    /// Relay reservation is active. We are "reachable" via a proxy.
    Relayed(libp2p::Multiaddr),
}

impl Display for RelayStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelayStrategy::WaitingForExternalAddress => write!(f, "waiting for external address"),
            RelayStrategy::Pending(multiaddr) => write!(f, "relay pending ({multiaddr}) ..."),
            RelayStrategy::Relayed(multiaddr) => write!(f, "relayed -- {multiaddr}"),
        }
    }
}

impl ReachabilityState {
    /// Advances the [`ReachabilityState`] in response to a change in AutoNAT
    /// status.
    pub(super) fn handle_new_nat_status(&mut self, status: libp2p::autonat::NatStatus) {
        *self = match (self.clone(), status) {
            // AutoNAT determined that it does not know our NAT status any more.
            // No change until we have definite information.
            (current_state, libp2p::autonat::NatStatus::Unknown) => current_state,

            // AutoNAT determined that we are private, and we do not know much
            // else.
            (ReachabilityState::Unknown, libp2p::autonat::NatStatus::Private) => {
                ReachabilityState::Private(RelayStrategy::WaitingForExternalAddress)
            }

            // AutoNAT determined that we are private -- but we already have an
            // external address we can use. So we can skip one state!
            (
                ReachabilityState::UnknownWithExternalAddress(addr),
                libp2p::autonat::NatStatus::Private,
            ) => ReachabilityState::Private(RelayStrategy::Pending(addr.clone())),

            // AutoNAT determined that we are private, contrary to previous
            // determinations. Drop any previous external address info.
            (_, libp2p::autonat::NatStatus::Private) => {
                ReachabilityState::Private(RelayStrategy::WaitingForExternalAddress)
            }

            // If we find out we're public, we upgrade immediately.
            (_, libp2p::autonat::NatStatus::Public(addr)) => ReachabilityState::Public(addr),
        }
    }

    /// Moves the [`ReachabilityState`] in response to a successful UPnP
    /// request.
    pub(super) fn handle_upnp_success(&mut self, addr: libp2p::Multiaddr) {
        *self = ReachabilityState::Upnp(addr)
    }

    /// Advances the [`ReachabilityState`] in response to discovering an
    /// external address (from Identify or UPnP).
    pub(super) fn handle_external_address(&mut self, addr: libp2p::Multiaddr) {
        let is_circuit = addr
            .iter()
            .any(|proto| matches!(proto, libp2p::multiaddr::Protocol::P2pCircuit));

        *self = match self.clone() {
            // Circuitous external addresses do not help determine reachability.
            ReachabilityState::Unknown if is_circuit => ReachabilityState::Unknown,

            // Address is not circuit but direct. Record it.
            ReachabilityState::Unknown => ReachabilityState::UnknownWithExternalAddress(addr),

            // Prefer newest external address provided it is not a circuit, so
            // overwrite.
            ReachabilityState::UnknownWithExternalAddress(existing_addr) => {
                if !is_circuit {
                    ReachabilityState::UnknownWithExternalAddress(addr)
                } else {
                    ReachabilityState::UnknownWithExternalAddress(existing_addr)
                }
            }

            // Proceed to Pending if possible; otherwise remain. Do not risk
            // overwriting a confirmed address.
            ReachabilityState::Private(strategy) => ReachabilityState::Private(match strategy {
                RelayStrategy::WaitingForExternalAddress => {
                    // Advance to Pending if the address is not circuitous.
                    if !is_circuit {
                        RelayStrategy::Pending(addr)
                    } else {
                        RelayStrategy::WaitingForExternalAddress
                    }
                }
                RelayStrategy::Pending(multiaddr) => RelayStrategy::Pending(multiaddr),
                RelayStrategy::Relayed(multiaddr) => RelayStrategy::Relayed(multiaddr),
            }),

            // Do not risk overwriting a confirmed address.
            ReachabilityState::Public(address) => ReachabilityState::Public(address),

            // Do not risk overwriting a confirmed address.
            ReachabilityState::Upnp(address) => ReachabilityState::Upnp(address),
        };
    }

    /// Advances the [`ReachabilityState`] in response to a confirmed relay
    /// reservation.
    pub(super) fn handle_relay_confirmed(&mut self, circuit_addr: libp2p::Multiaddr) {
        if let ReachabilityState::Private(strategy) = self {
            *strategy = RelayStrategy::Relayed(circuit_addr);
        }
    }

    /// Return the `external_address` the state is currently
    /// `Private(Pending(external_address))`, and `None` otherwise.
    ///
    /// `Pending` is the signal to the
    /// [`NetworkActor`](super::actor::NetworkActor) that it is time to initiate
    /// relay requests.
    pub(super) fn is_pending(&self) -> Option<libp2p::Multiaddr> {
        if let ReachabilityState::Private(RelayStrategy::Pending(ref addr)) = self {
            Some(addr.clone())
        } else {
            None
        }
    }

    /// Return the external [`Multiaddr`](libp2p::Multiaddr), if there is one.
    pub(super) fn external_address(&self) -> Option<libp2p::Multiaddr> {
        match self {
            ReachabilityState::Unknown => None,
            ReachabilityState::UnknownWithExternalAddress(multiaddr) => Some(multiaddr.clone()),
            ReachabilityState::Private(relay_strategy) => match relay_strategy {
                RelayStrategy::WaitingForExternalAddress => None,
                RelayStrategy::Pending(multiaddr) => Some(multiaddr.clone()),
                RelayStrategy::Relayed(multiaddr) => Some(multiaddr.clone()),
            },
            ReachabilityState::Public(multiaddr) => Some(multiaddr.clone()),
            ReachabilityState::Upnp(multiaddr) => Some(multiaddr.clone()),
        }
    }

    /// Go back to the initial state, Unknown.
    ///
    /// Drop all associated data.
    pub(super) fn reset(&mut self) {
        *self = ReachabilityState::Unknown
    }

    pub(super) fn is_private_and_waiting(&self) -> bool {
        matches!(
            self,
            ReachabilityState::Private(RelayStrategy::WaitingForExternalAddress)
        )
    }
}

#[cfg(any(test, feature = "mock-rpc"))]
impl rand::distr::Distribution<ReachabilityState> for rand::distr::StandardUniform {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> ReachabilityState {
        let addr = true
            .then(|| rng.random::<[u8; 4]>())
            .map(std::net::Ipv4Addr::from)
            .map(std::net::IpAddr::V4)
            .map(libp2p::Multiaddr::from)
            .unwrap();
        let relay_strategy = rng.random::<RelayStrategy>();
        match rng.random_range(0..<ReachabilityState as strum::EnumCount>::COUNT) {
            0 => ReachabilityState::Unknown,
            1 => ReachabilityState::UnknownWithExternalAddress(addr),
            2 => ReachabilityState::Private(relay_strategy),
            3 => ReachabilityState::Upnp(addr),
            4 => ReachabilityState::Public(addr),
            _ => unreachable!("check enum count"),
        }
    }
}

#[cfg(any(test, feature = "mock-rpc"))]
impl rand::distr::Distribution<RelayStrategy> for rand::distr::StandardUniform {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> RelayStrategy {
        let addr = true
            .then(|| rng.random::<[u8; 4]>())
            .map(std::net::Ipv4Addr::from)
            .map(std::net::IpAddr::V4)
            .map(libp2p::Multiaddr::from)
            .unwrap();
        match rng.random_range(0..<RelayStrategy as strum::EnumCount>::COUNT) {
            0 => RelayStrategy::WaitingForExternalAddress,
            1 => RelayStrategy::Pending(addr),
            2 => RelayStrategy::Relayed(addr),
            _ => unreachable!("check enum count"),
        }
    }
}

#[cfg(any(test, feature = "arbitrary-impls"))]
pub(crate) mod arbitrary {

    use proptest::prelude::BoxedStrategy;
    use proptest::strategy::Strategy;

    use crate::application::network::arbitrary::arb_multiaddr;

    use super::*;

    impl RelayStrategy {
        pub(crate) fn arbitrary() -> BoxedStrategy<Self> {
            let discriminant = 0..<Self as strum::EnumCount>::COUNT;
            (discriminant, arb_multiaddr())
                .prop_map(|(disc, addr)| match disc {
                    0 => Self::WaitingForExternalAddress,
                    1 => Self::Pending(addr),
                    2 => Self::Relayed(addr),
                    _ => unreachable!("check enum count"),
                })
                .boxed()
        }
    }

    impl ReachabilityState {
        pub(crate) fn arbitrary() -> BoxedStrategy<Self> {
            let discriminant = 0..<Self as strum::EnumCount>::COUNT;
            (discriminant, arb_multiaddr(), RelayStrategy::arbitrary())
                .prop_map(|(disc, addr, relay_strategy)| match disc {
                    0 => Self::Unknown,
                    1 => Self::UnknownWithExternalAddress(addr),
                    2 => Self::Private(relay_strategy),
                    3 => Self::Upnp(addr),
                    4 => Self::Public(addr),
                    _ => unreachable!("check enum count"),
                })
                .boxed()
        }
    }
}
