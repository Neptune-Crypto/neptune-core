// The deriving of `NetworkBehaviour` expands to code with an unreachable arm.
// If the dependency is upgraded to a version where this is fixed, this allow
// should be removed.
//
// Deliberately `allow` and not `expect`: as of rustc 1.98 the lint rule is not
// violated here.
#![allow(unreachable_code)]

use libp2p::swarm::NetworkBehaviour;

use crate::application::network::gateway::StreamGateway;
use crate::application::network::source_limits::SourceLimits;
use crate::application::network::stack_event::NetworkStackEvent;

/// The protocol ID string
pub(crate) const NEPTUNE_PROTOCOL_STR: &str = "/neptune/";

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
/// [`PeerMessage`](neptune_p2p::peer::PeerMessage) stream) is handled via
/// the [`libp2p stream`](libp2p::Stream) control mechanism, which operates
/// independently of this behavior struct in libp2p version 0.56.0.
#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "NetworkStackEvent")]
pub(crate) struct NetworkStack {
    /// Global cap on connections being initiated, protects against floods.
    pub(crate) connection_limits: libp2p::connection_limits::Behaviour,

    /// Limits on inbound connections from clustered IPs.
    pub(crate) source_limits: SourceLimits,

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
