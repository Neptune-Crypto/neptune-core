use std::net::IpAddr;

use itertools::Either;
use libp2p::Multiaddr;
use libp2p::PeerId;
use tokio::task::JoinHandle;

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
