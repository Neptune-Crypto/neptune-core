use std::net::IpAddr;

use itertools::Either;
use libp2p::Multiaddr;
use libp2p::PeerId;
use tokio::task::JoinHandle;

use crate::application::network::overview::NetworkOverview;

/// Commands from Application -> Network
pub enum NetworkActorCommand {
    /// Instructs the libp2p swarm to dial a specific [`Multiaddr`].
    Dial(Multiaddr),

    /// Instructs the [`NetworkActor`](super::actor::NetworkActor) to open
    /// dialing endpoint on the given [`Multiaddr`]for incoming connections.
    Listen(Multiaddr),

    /// Instructs the [`NetworkActor`](super::actor::NetworkActor) to ban the
    /// given peer.
    Ban(Either<PeerId, IpAddr>),

    /// Instructs the [`NetworkActor`](super::actor::NetworkActor) to remove the
    /// IP address from the black list, thereby unbanning them.
    Unban(IpAddr),

    /// Instructs the [`NetworkActor`](super::actor::NetworkActor) to remove all
    /// IP addresses from the black list, thereby revoking all bans.
    UnbanAll,

    /// Forces a re-evaluation of the local NAT status.
    ///
    /// This triggers the `libp2p-autonat` behavior to probe current network
    /// observability. It is useful if the node has moved networks or if
    /// port-forwarding rules have changed since startup.
    ProbeNat,

    /// Clears and re-establishes all active relay circuit reservations.
    ///
    /// This command drops all existing `v2::hop` and `v2::stop` reservations
    /// and forces the `Relay` behavior to seek fresh connections with
    /// configured relay nodes. Use this if the node is stuck behind a symmetric
    /// NAT and relay connectivity has degraded.
    ResetRelayReservations,

    /// Asks for a status update.
    ///
    /// In more detail, this variant instructs the
    /// [`NetworkActor`](super::actor::NetworkActor) to assemble a
    /// [`NetworkOverview`] package of overview data and health statistics and
    /// send the assembled package back over the given channel.
    GetNetworkOverview(tokio::sync::oneshot::Sender<NetworkOverview>),

    /// Signals the [`NetworkActor`](super::actor::NetworkActor) to begin a
    /// graceful shutdown of all network tasks.
    Shutdown,
}

/// Events from Network -> Application
pub enum NetworkEvent {
    /// Emitted when a peer has successfully completed the handshake and the
    /// peer loop has been spawned.
    NewPeerLoop { loop_handle: JoinHandle<()> },
}
