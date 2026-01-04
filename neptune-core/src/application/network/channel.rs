use libp2p::Multiaddr;
use tokio::task::JoinHandle;

/// Commands from Application -> Network
pub enum NetworkActorCommand {
    /// Instructs the libp2p swarm to dial a specific [`Multiaddr`].
    Dial(Multiaddr),

    /// Instructs the Actor to open dialing endpoint on the given [`Multiaddr`]
    /// for incoming connections.
    Listen(Multiaddr),

    /// Signals the Actor to begin a graceful shutdown of all network tasks.
    Shutdown,
}

/// Events from Network -> Application
pub enum NetworkEvent {
    /// Emitted when a peer has successfully completed the handshake and the
    /// peer loop has been spawned.
    NewPeerLoop { loop_handle: JoinHandle<()> },
}
