use libp2p::swarm::NetworkBehaviour;

use crate::application::network::gateway::GatewayEvent;
use crate::application::network::gateway::StreamGateway;

/// The protocol ID string, dynamically generated from the crate version, e.g.,
/// "/neptune/0.6.0"
pub(crate) const NEPTUNE_PROTOCOL_STR: &str = concat!("/neptune/", env!("CARGO_PKG_VERSION"));

/// The internal collection of libp2p protocols that define how this node
/// interacts with the p2p network at the transport and discovery level.
///
/// This struct implements
/// [`NetworkBehaviour`], allowing it to be driven by the libp2p
/// [`Swarm`](libp2p::Swarm). It specifically aggregates behaviors required for
/// successful peer communication in restrictive network environments (NATs).
///
/// ### Component Roles:
///
/// * **[`ping`](libp2p::ping)**: Keep track of which peers are still alive.
///   Pro-actively disengage from peers that are unresponsive. As an important
///   side-effect, the ping traffic will keep NAT ports open.
/// * **[`identify`](libp2p::identify)**: Essential for peer discovery and
///   protocol negotiation. It allows peers to exchange public keys, listen
///   addresses, and supported protocols (like our blockchain protocol).
/// * **[`upnp`](libp2p::upnp)** Asks the router politely to open up ports for
///   communications.
/// * **[`autonat`](libp2p::autonat)**: Automatic NAT detection. This behavior
///   periodically probes other peers to determine the node's reachability
///   status. It identifies whether the node is publicly accessible or "private"
///   (behind a NAT/Firewall). This status info is used to decide when to seek
///   out a relay reservation or attempt a hole punch.
/// * **[`relay`](libp2p::relay)**: Requires nodes to act as a relay server for
///   peers behind NATs, making them reachable via proxy.
/// * **[`relay::client`](libp2p::relay::client)**: Enables nodes behind a NAT
///   to reserve a sub-address with a relay server, thereby becoming reachable.
/// * **[`dcutr`](libp2p::dcutr)**: *Direct Connection Upgrade through Relay*.
///   This behavior monitors relayed connections and attempts to perform a "Hole
///   Punch" to upgrade the connection to a direct, high-performance peer-to-
///   peer link, bypassing the relay once the path is established.
/// * **[`kademlia`](libp2p::kad)**: Implements node lookup through a DHT. By
///   looking up ourselves, we end up crawling the network and populating our
///   internal phone book along the way, not to mention those of peers.
/// * **[`gateway`](Self::gateway)**: A "stream factory" that uses a raw stream
///   and hijacks it. It negotiates the initial handshake via CBOR
///   and provides the raw [`libp2p::Stream`] which is then upgraded into a
///   long-lived bidirectional communication channel by the peer message
///   handler.
///
/// ### Note on Messaging:
///
/// This stack does not contain a messaging behavior. Actual data exchange (the
/// [`PeerMessage`](crate::protocol::peer::PeerMessage) stream) is handled via
/// the [`libp2p stream`](libp2p::Stream) control mechanism, which operates
/// independently of this behavior struct in libp2p version 0.56.0.
#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "NetworkStackEvent")]
pub(crate) struct NetworkStack {
    pub(crate) ping: libp2p::ping::Behaviour,
    pub(crate) identify: libp2p::identify::Behaviour,
    pub(crate) upnp: libp2p::upnp::tokio::Behaviour,
    pub(crate) autonat: libp2p::autonat::Behaviour,
    pub(crate) relay_server: libp2p::relay::Behaviour,
    pub(crate) relay_client: libp2p::relay::client::Behaviour,
    pub(crate) dcutr: libp2p::dcutr::Behaviour,
    pub(crate) kademlia: libp2p::kad::Behaviour<libp2p::kad::store::MemoryStore>,

    /// Custom "Hijacker" that handles the handshake and turns it into a stream.
    pub(crate) gateway: StreamGateway,
}

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
