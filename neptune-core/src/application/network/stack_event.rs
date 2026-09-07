use crate::application::network::gateway::GatewayEvent;

/// Unified event type for all protocols running within the libp2p stack.
///
/// This enum aggregates events from various libp2p sub-protocols. It allows
/// the [`NetworkActor`](super::actor::NetworkActor) to handle diverse network
/// signaling—from high-level Neptune handshakes to low-level NAT traversal
/// updates—through a single event stream.
pub enum NetworkStackEvent {
    /// Signals an update from the Ping protocol.
    Ping(Box<libp2p::ping::Event>),

    /// Signals an update from the libp2p Identify protocol.
    ///
    /// Used to discover the remote peer's public addresses, agent version,
    /// and supported protocols.
    Identify(Box<libp2p::identify::Event>),

    /// Signals an update from the UPnP mechanism.
    ///
    /// If the router is configured right, it will open a port in response to
    /// the UPnP request. As a result, the node will become public and no hole
    /// punching will be necessary.
    Upnp(Box<libp2p::upnp::Event>),

    /// Signals an update from the autoNAT mechanism.
    ///
    /// Used as diagnostics layer to determine whether the node is behind a NAT
    /// or firewall.
    AutoNat(Box<libp2p::autonat::Event>),

    /// Signals an event from the Relay server.
    ///
    /// Enables the node to serve as a proxy for peers behind NATs or firewalls.
    RelayServer(Box<libp2p::relay::Event>),

    /// Signals an event from the Relay client.
    ///
    /// Enables the node to communicate with peers behind firewalls by
    /// using a public relay server.
    RelayClient(Box<libp2p::relay::client::Event>),

    /// Signals an event from the Direct Connection Upgrade through Relay
    /// (DCUtR).
    ///
    /// Facilitates "hole punching" to upgrade a relayed connection to a
    /// direct peer-to-peer connection.
    Dcutr(Box<libp2p::dcutr::Event>),

    /// Events emitted by the Kademlia DHT behavior.
    ///
    /// These include routing table updates, the results of bootstrap
    /// operations, and the progress of iterative queries (finding peers or
    /// records).
    Kademlia(Box<libp2p::kad::Event>),

    /// Signals a successful Neptune-specific handshake.
    ///
    /// This is the primary event used to "hijack" a connection and
    /// transition it into a peer loop.
    StreamGateway(Box<GatewayEvent>),
}

impl From<libp2p::ping::Event> for NetworkStackEvent {
    fn from(event: libp2p::ping::Event) -> Self {
        Self::Ping(Box::new(event))
    }
}

impl From<libp2p::identify::Event> for NetworkStackEvent {
    fn from(event: libp2p::identify::Event) -> Self {
        Self::Identify(Box::new(event))
    }
}

impl From<libp2p::upnp::Event> for NetworkStackEvent {
    fn from(event: libp2p::upnp::Event) -> Self {
        Self::Upnp(Box::new(event))
    }
}
impl From<libp2p::autonat::Event> for NetworkStackEvent {
    fn from(event: libp2p::autonat::Event) -> Self {
        Self::AutoNat(Box::new(event))
    }
}

impl From<libp2p::relay::Event> for NetworkStackEvent {
    fn from(event: libp2p::relay::Event) -> Self {
        Self::RelayServer(Box::new(event))
    }
}

impl From<libp2p::relay::client::Event> for NetworkStackEvent {
    fn from(event: libp2p::relay::client::Event) -> Self {
        Self::RelayClient(Box::new(event))
    }
}

impl From<libp2p::dcutr::Event> for NetworkStackEvent {
    fn from(event: libp2p::dcutr::Event) -> Self {
        Self::Dcutr(Box::new(event))
    }
}

impl From<libp2p::kad::Event> for NetworkStackEvent {
    fn from(event: libp2p::kad::Event) -> Self {
        Self::Kademlia(Box::new(event))
    }
}

// These `From` impls are required by the derive macro `NetworkBehaviour` to map
// child events into the `NetworkStackEvent` enum.
impl From<GatewayEvent> for NetworkStackEvent {
    fn from(event: GatewayEvent) -> Self {
        Self::StreamGateway(Box::new(event))
    }
}
