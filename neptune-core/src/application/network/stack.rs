use libp2p::swarm::NetworkBehaviour;
use libp2p::StreamProtocol;

use crate::application::network::gateway::{GatewayEvent, StreamGateway};

/// The protocol ID string, dynamically generated from the crate version, e.g.,
/// "/neptune/0.6.0"
const NEPTUNE_PROTOCOL_STR: &str = concat!("/neptune/", env!("CARGO_PKG_VERSION"));

/// Defines the libp2p [`StreamProtocol`] identifier for the blockchain network.
pub(crate) const NEPTUNE_PROTOCOL: StreamProtocol = StreamProtocol::new(NEPTUNE_PROTOCOL_STR);

/// The internal collection of libp2p protocols that define how this node
/// interacts with the p2p network at the transport and discovery level.
///
/// This struct implements
/// [`NetworkBehaviour`](libp2p::swarm::NetworkBehaviour), allowing it to be
/// driven by the libp2p [`Swarm`](libp2p::Swarm). It specifically aggregates
/// behaviors required for successful peer communication in restrictive network
/// environments (NATs).
///
/// ### Component Roles:
///
/// * **[`identify`](libp2p::identify)**: Essential for peer discovery and
///   protocol negotiation. It allows peers to exchange public keys, listen
///   addresses, and supported protocols (like our blockchain protocol).
/// * **[`relay::client`](libp2p::relay::client)**: Enables "Circuit Relay"
///   support. This allows the node to use a third-party relay to establish a
///   connection when both peers are behind symmetric NATs and cannot be reached
///   directly.
/// * **[`dcutr`](libp2p::dcutr)**: *Direct Connection Upgrade through Relay*.
///   This behavior monitors relayed connections and attempts to perform a "Hole
///   Punch" to upgrade the connection to a direct, high-performance peer-to-
///   peer link, bypassing the relay once the path is established.
/// * **[`peer_handler_gateway`](Self::peer_handler_gateway)**: A "stream
///   factory" that uses the [`request_response`](libp2p::request_response)
///   protocol in streaming mode. It negotiates the initial handshake via CBOR
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
    pub(crate) identify: libp2p::identify::Behaviour,
    pub(crate) relay: libp2p::relay::client::Behaviour,
    pub(crate) dcutr: libp2p::dcutr::Behaviour,

    /// Custom "Hijacker" that handles the handshake and turns it into a stream.
    pub(crate) gateway: StreamGateway,
}

/// Unified event type for all protocols running within the libp2p stack.
///
/// This enum aggregates events from various libp2p sub-protocols. It allows
/// the [`Actor`] to handle diverse network signaling—from high-level
/// Neptune handshakes to low-level NAT traversal updates—through a
/// single event stream.
pub enum NetworkStackEvent {
    /// Signals a successful Neptune-specific handshake.
    ///
    /// This is the primary event used to "hijack" a connection and
    /// transition it into a peer loop.
    PeerHandlerGateway(Box<GatewayEvent>),

    /// Signals an update from the libp2p Identify protocol.
    ///
    /// Used to discover the remote peer's public addresses, agent version,
    /// and supported protocols.
    Identify(Box<libp2p::identify::Event>),

    /// Signals an event from the Relay client.
    ///
    /// Enables the node to communicate with peers behind firewalls by
    /// using a public relay server.
    Relay(Box<libp2p::relay::client::Event>),

    /// Signals an event from the Direct Connection Upgrade through Relay
    /// (DCUtR).
    ///
    /// Facilitates "hole punching" to upgrade a relayed connection to a
    /// direct peer-to-peer connection.
    Dcutr(Box<libp2p::dcutr::Event>),
}

// These `From` impls are required by the derive macro `NetworkBehaviour` to map
// child events into the `NetworkStackEvent`` enum.
impl From<GatewayEvent> for NetworkStackEvent {
    fn from(event: GatewayEvent) -> Self {
        Self::PeerHandlerGateway(Box::new(event))
    }
}

impl From<libp2p::identify::Event> for NetworkStackEvent {
    fn from(event: libp2p::identify::Event) -> Self {
        Self::Identify(Box::new(event))
    }
}

impl From<libp2p::relay::client::Event> for NetworkStackEvent {
    fn from(event: libp2p::relay::client::Event) -> Self {
        Self::Relay(Box::new(event))
    }
}

impl From<libp2p::dcutr::Event> for NetworkStackEvent {
    fn from(event: libp2p::dcutr::Event) -> Self {
        Self::Dcutr(Box::new(event))
    }
}
