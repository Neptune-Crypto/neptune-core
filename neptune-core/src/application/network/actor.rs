use arc_swap::ArcSwap;
use futures::prelude::*;
use libp2p::swarm::SwarmEvent;
use libp2p::Multiaddr;
use libp2p::PeerId;
use rand::Rng;
use tokio::sync::mpsc;
use tracing::error;
use tracing::info;
use tracing::warn;

use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::sync::Arc;
use std::time::Duration;

use crate::application::loops::peer_loop::channel::MainToPeerTask;
use crate::application::loops::peer_loop::channel::PeerTaskToMain;
use crate::application::loops::peer_loop::PeerLoopHandler;
use crate::application::network::bridge::bridge_libp2p_stream;
use crate::application::network::channel::NetworkActorCommand;
use crate::application::network::channel::NetworkEvent;
use crate::application::network::gateway::GatewayEvent;
use crate::application::network::gateway::StreamGateway;
use crate::application::network::stack::NetworkStack;
use crate::application::network::stack::NetworkStackEvent;
use crate::protocol::peer::handshake_data::HandshakeData;
use crate::state::GlobalStateLock;

/// The libp2p adapter for the Neptune network stack.
///
/// The [`Actor`] serves as a specialized interface between the libp2p network
/// stack and the application's main loop. Unlike typical actor models, this
/// struct does not own the primary event loop; instead, it facilitates the
/// transition of libp2p-negotiated connections into the standard Neptune
/// protocol ecosystem. Specifically, it mediates establishment of a libp2p
/// stream which it then hijacks and passes to a freshly spawned peer loop.
///
/// ### Core Responsibilities:
///
/// 1. **Stack Interfacing**: It encapsulates the libp2p
///    [`Swarm`](libp2p::Swarm) and the
///    [`StreamGateway`](super::gateway::StreamGateway) behaviour, shielding the
///    rest of the application from libp2p-specific complexities.
/// 2. **Stream Handoff**: Upon a successful [`GatewayEvent`], it extracts
///    the validated [`Stream`](libp2p::Stream) and passes it into a concrete
///    protocol handler.
/// 3. **Protocol Unified Logic**: It spawns the same peer loop used by the
///    legacy network stack. Consequently Neptune message handling remains
///    unified regardless of the transport layer.
///
/// ### Integration:
///
/// Because the main loop manages the lifecycle of the node, the [`Actor`] can
/// be bypassed or run in parallel with legacy network components. It acts as a
/// "feeder" that produces verified peer connections for the main loop to track
/// or for dedicated tasks to manage.
pub(crate) struct Actor {
    /// The [`Swarm`](libp2p::Swarm) driving the [`NetworkStack`], configured
    /// with the Neptune [`StreamGateway`](super::gateway::StreamGateway).
    swarm: libp2p::Swarm<NetworkStack>,

    global_state_lock: GlobalStateLock,

    // Dependency Injection: The Actor holds these to give to new peer loops
    peer_to_main_loop_tx: mpsc::Sender<PeerTaskToMain>,
    main_to_peer_broadcast: tokio::sync::broadcast::Sender<MainToPeerTask>,

    // Channels for the Actor's own life
    command_rx: mpsc::Receiver<NetworkActorCommand>,
    event_tx: mpsc::Sender<NetworkEvent>,

    /// Smart pointer to the local (*i.e.*, this peer's) handshake. The smart
    /// pointer allows the owner (the main loop) to update its value atomically
    /// while reading happens without locks.
    local_handshake: Arc<ArcSwap<HandshakeData>>,
}

impl Actor {
    /// Initialize a new libp2p Actor.
    ///
    /// This constructor sets up the underlying libp2p Swarm with TCP transport,
    /// Noise encryption, and Yamux multiplexing, alongside the StreamGateway
    /// for handing off control over bidirectional streams to peer loops.
    pub fn new(
        local_key: libp2p::identity::Keypair,
        local_handshake: Arc<ArcSwap<HandshakeData>>,
        peer_to_main_loop_tx: mpsc::Sender<PeerTaskToMain>,
        main_to_peer_broadcast: tokio::sync::broadcast::Sender<MainToPeerTask>,
        command_rx: mpsc::Receiver<NetworkActorCommand>,
        event_tx: mpsc::Sender<NetworkEvent>,
        global_state_lock: GlobalStateLock,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Create the Identify config (required for the NetworkStack)
        let identify_config = libp2p::identify::Config::new(
            "/neptune/identify/1.0".into(), // Protocol version
            local_key.public(),
        );

        let swarm = libp2p::SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_tcp(
                libp2p::tcp::Config::default(),
                libp2p::noise::Config::new,
                libp2p::yamux::Config::default,
            )?
            .with_relay_client(libp2p::noise::Config::new, libp2p::yamux::Config::default)?
            .with_behaviour(|key, relay_behaviour| {
                let local_peer_id = key.public().to_peer_id();

                NetworkStack {
                    gateway: StreamGateway::new(local_handshake.clone()),
                    identify: libp2p::identify::Behaviour::new(identify_config),
                    relay: relay_behaviour,
                    dcutr: libp2p::dcutr::Behaviour::new(local_peer_id),
                }
            })?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(30)))
            .build();

        Ok(Self {
            swarm,
            local_handshake,
            peer_to_main_loop_tx,
            main_to_peer_broadcast,
            command_rx,
            event_tx,
            global_state_lock,
        })
    }

    /// Start listening for incoming libp2p connections.
    ///
    /// This informs the underlying Swarm to bind to the provided [`Multiaddr`].
    /// Incoming connections will automatically undergo the handshake defined in
    /// the [`StreamGateway`].
    fn listen(&mut self, addr: Multiaddr) -> Result<(), libp2p::TransportError<std::io::Error>> {
        let listener_id = self.swarm.listen_on(addr.clone())?;

        // Log or trace the listen event for debugging the bridge
        tracing::info!(%addr, %listener_id, "libp2p stack listening");

        Ok(())
    }

    /// The event loop for the Network Actor.
    ///
    /// Drives the libp2p Swarm and handles incoming connection handshakes.
    pub(crate) async fn run(mut self) {
        loop {
            tokio::select! {
                // Handle libp2p Swarm Events.
                event = self.swarm.select_next_some() => {
                    self.handle_swarm_event(event).await;
                }

                // Handle Commands from the Main Loop destined for the Actor (so
                // not for peer loops), such as dialing a Multiaddress.
                Some(command) = self.command_rx.recv() => {
                    self.handle_command(command);
                }
            }
        }
    }

    /// Handle an event coming from the libp2p Swarm.
    async fn handle_swarm_event(&mut self, event: SwarmEvent<NetworkStackEvent>) {
        match event {
            // StreamGateway successfully hijacked a stream.
            SwarmEvent::Behaviour(NetworkStackEvent::PeerHandlerGateway(gateway_event)) => {
                let GatewayEvent::HandshakeReceived {
                    peer_id,
                    handshake,
                    stream,
                } = *gateway_event;

                info!(peer = %peer_id, "New peer stream hijacked via StreamGateway");

                // Generate a new the receiver channel for this specific peer.
                let from_main_rx = self.main_to_peer_broadcast.subscribe();

                // Notify the rest of the application that a peer is ready.
                let _ = self
                    .event_tx
                    .send(NetworkEvent::PeerConnected {
                        peer_id,
                        handshake: Box::new(handshake),
                    })
                    .await;

                // Spawn the legacy loop with the hijacked stream.
                self.spawn_peer_loop(peer_id, handshake, stream, from_main_rx);
            }

            SwarmEvent::NewListenAddr { address, .. } => {
                info!("Node is listening on {:?}", address);
            }

            SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                warn!(peer = %peer_id, "Connection closed: {:?}", cause);
            }

            // Explicitly handle Dial failures to clean up state
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                warn!(peer = ?peer_id, "Failed to connect: {:?}", error);
            }

            // Handle listener errors to prevent the node from failing silently
            SwarmEvent::ListenerError { listener_id, error } => {
                error!(?listener_id, "Listener failed: {:?}", error);
            }

            _ => {}
        }
    }

    /// Handle messages from the Main Loop.
    fn handle_command(&mut self, command: NetworkActorCommand) {
        match command {
            NetworkActorCommand::Dial(addr) => {
                info!("Manual dial requested for address: {}", addr);
                // We use the swarm's dial method. libp2p handles the underlying
                // TCP/transport logic.
                if let Err(e) = self.swarm.dial(addr.clone()) {
                    warn!("Failed to dial {}: {:?}", addr, e);
                }
            }

            NetworkActorCommand::Listen(addr) => {
                tracing::info!(%addr, "Received command to listen");
                if let Err(e) = self.listen(addr.clone()) {
                    tracing::error!(%addr, error = %e, "Failed to start listening");
                    // Optional: notify main loop of failure via event_tx
                } else {
                    tracing::info!(%addr, "Successfully bound to address");
                }
            }

            NetworkActorCommand::Shutdown => {
                info!("Network Actor shutting down Swarm...");
                // Do not touch the peer loops here, just stop the Actor's own
                // loop.
                // Consequently, we cannot return or set a flag here; that will
                // drop the Swarm, which closes all underlying sockets.
            }
        }
    }

    /// Spawns a long-lived Tokio task to manage the lifecycle of a single peer
    /// connection.
    ///
    /// This function acts as the bridge between the libp2p transport and the
    /// protocol logic. It performs the following steps:
    /// 1. Derives a deterministic `SocketAddr` from the `PeerId` to maintain
    ///    compatibility with legacy state tracking (the "Pseudo-IP").
    /// 2. Subscribes to the global `MainToPeerTask` broadcast channel.
    /// 3. Upgrades the raw [`libp2p::Stream`] into a [`Framed`]
    ///    [`PeerMessage`](crate::protocol::peer::PeerMessage) stream using the
    ///    same codec bridge already in use for the legacy TCP stack.
    /// 4. Calls the legacy [`PeerLoopHandler::run_wrapper`] method verbatim,
    ///    handing over control of the connection to the established protocol
    ///    logic.
    ///
    /// The task terminates automatically if the stream is closed or a shutdown
    /// signal is received from the main loop.
    fn spawn_peer_loop(
        &self,
        peer_id: PeerId,
        handshake: HandshakeData,
        raw_stream: libp2p::Stream,
        from_main_rx: tokio::sync::broadcast::Receiver<MainToPeerTask>,
    ) {
        // Counts the number of hops between the node and peers it is connected
        // to. We probably don't need this for the libp2p wrapper.
        const DISTANCE_TO_CONNECTED_PEER: u8 = 1u8;

        // We need a `SocketAddr` identify the peer with as far as
        // `PeerLoopHandler` goes. The proper way to fix this is to modify that
        // to take `PeerId` or `Multiaddress` instead, but for now we want to
        // write a clean wrapper that isolates all changes to one new module.
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&peer_id.to_bytes()[2..6]);
        let peer_address = SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::from(bytes),
            0, // Port doesn't matter for identification
        ));

        // Create immutable (across the lifetime of the connection) peer state.
        // This variable needs to be mutable because of efficient pointer reuse
        // in the course of punishments. We probably want to change that.
        let mut peer_loop_handler = PeerLoopHandler::new(
            self.peer_to_main_loop_tx.clone(),
            self.global_state_lock.clone(),
            peer_address,
            handshake,
            rand::rng().random_bool(0.5f64),
            DISTANCE_TO_CONNECTED_PEER,
        );

        let peer_stream = bridge_libp2p_stream(raw_stream);

        tokio::spawn(async move {
            // Because 'peer_stream' implements Sink + Stream + Unpin,
            // and we have the broadcast receiver, this just works.
            if let Err(e) = peer_loop_handler
                .run_wrapper(peer_stream, from_main_rx)
                .await
            {
                tracing::warn!(peer = %peer_id, "Peer loop exited with error: {:?}", e);
            }
        });
    }
}
