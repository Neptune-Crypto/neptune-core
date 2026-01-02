use crate::protocol::peer::handshake_data::HandshakeData;
use libp2p::Multiaddr;
use libp2p::PeerId;
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
    PeerConnected {
        peer_id: PeerId,
        handshake: Box<HandshakeData>,
        address: Multiaddr,
        loop_handle: JoinHandle<()>,
    },

    /// Emitted when a peer connection is dropped or the peer loop exits.
    PeerDisconnected(PeerId),
}
