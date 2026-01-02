use futures::prelude::*;
use libp2p::swarm::SwarmEvent;
use libp2p::Multiaddr;
use libp2p::PeerId;
use rand::Rng;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use std::collections::HashMap;
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
/// The [`NetworkActor`] serves as a specialized interface between the libp2p
/// network stack and the application's main loop. Unlike typical actor models,
/// this struct does not own the primary event loop; instead, it facilitates the
/// transition of libp2p-negotiated connections into the standard Neptune
/// protocol ecosystem. Specifically, it mediates establishment of a libp2p
/// stream which it then hijacks and passes to a freshly spawned peer loop.
///
/// ### Core Responsibilities:
///
/// 1. **Stack Interfacing**: It encapsulates the libp2p
///    [`Swarm`](libp2p::Swarm) and the
///    [`StreamGateway`] behaviour, shielding the rest of the application from
///    libp2p-specific complexities.
/// 2. **Stream Handoff**: Upon a successful [`GatewayEvent`], it extracts
///    the validated [`Stream`](libp2p::Stream) and passes it into a concrete
///    protocol handler.
/// 3. **Protocol Unified Logic**: It spawns the same peer loop used by the
///    legacy network stack. Consequently Neptune message handling remains
///    unified regardless of the transport layer.
///
/// ### Integration:
///
/// Because the main loop manages the lifecycle of the node, the
/// [`NetworkActor`] can be bypassed or run in parallel with legacy network
/// components. It acts as a "feeder" that produces verified peer connections
/// for the main loop to track or for dedicated tasks to manage.
pub(crate) struct NetworkActor {
    /// The [`Swarm`](libp2p::Swarm) driving the [`NetworkStack`], configured
    /// with the Neptune [`StreamGateway`].
    swarm: libp2p::Swarm<NetworkStack>,

    global_state_lock: GlobalStateLock,

    // Dependency Injection: The Actor holds these to give to new peer loops
    peer_to_main_loop_tx: mpsc::Sender<PeerTaskToMain>,
    main_to_peer_broadcast: tokio::sync::broadcast::Sender<MainToPeerTask>,

    // Channels for the Actor's own life
    command_rx: mpsc::Receiver<NetworkActorCommand>,
    event_tx: mpsc::Sender<NetworkEvent>,

    // Lookup table to find the addresses of peers
    address_map: HashMap<PeerId, Multiaddr>,
}

impl NetworkActor {
    /// Whether to keep the Actor's event loop running (true) or to shut it down
    /// gracefully (false).
    const KEEP_ALIVE: bool = true;

    /// Initialize a new libp2p Actor.
    ///
    /// This constructor sets up the underlying libp2p Swarm with TCP transport,
    /// Noise encryption, and Yamux multiplexing, alongside the StreamGateway
    /// for handing off control over bidirectional streams to peer loops.
    pub fn new(
        local_key: libp2p::identity::Keypair,
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
                    gateway: StreamGateway::new(global_state_lock.clone()),
                    identify: libp2p::identify::Behaviour::new(identify_config),
                    relay: relay_behaviour,
                    dcutr: libp2p::dcutr::Behaviour::new(local_peer_id),
                }
            })?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(30)))
            .build();

        Ok(Self {
            swarm,
            peer_to_main_loop_tx,
            main_to_peer_broadcast,
            command_rx,
            event_tx,
            global_state_lock,
            address_map: HashMap::new(),
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
    pub(crate) async fn run(mut self) -> Result<(), ActorError> {
        loop {
            tokio::select! {
                // Handle libp2p Swarm Events.
                event = self.swarm.select_next_some() => {
                    self.handle_swarm_event(event).await?;
                }

                // Handle Commands from the Main Loop destined for the Actor (so
                // not for peer loops), such as dialing a Multiaddress.
                maybe_cmd = self.command_rx.recv() => {
                    match maybe_cmd {
                        Some(cmd) => {
                            if self.handle_command(cmd)? != Self::KEEP_ALIVE {
                                break;
                            }
                        },
                        None => {
                            // The sender was dropped. Shutdown time!
                            tracing::warn!("Sender (controlled by main loop) was dropped; initiating irregular shut down of NetworkActor.");
                            return Err(ActorError::ChannelClosed);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Handle an event coming from the libp2p Swarm.
    async fn handle_swarm_event(
        &mut self,
        event: SwarmEvent<NetworkStackEvent>,
    ) -> Result<(), ActorError> {
        match event {
            // StreamGateway successfully hijacked a stream.
            SwarmEvent::Behaviour(NetworkStackEvent::StreamGateway(gateway_event)) => {
                let GatewayEvent::HandshakeReceived {
                    peer_id,
                    handshake,
                    stream,
                } = *gateway_event;

                tracing::info!(peer = %peer_id, "New peer stream hijacked via StreamGateway");

                // Generate a new the receiver channel for this specific peer.
                let from_main_rx = self.main_to_peer_broadcast.subscribe();

                // Fetch address from carefully maintained address map.
                let Some(address) = self.address_map.get(&peer_id).cloned() else {
                    return Err(ActorError::NoAddressForPeer(peer_id));
                };

                // Spawn the legacy loop with the hijacked stream.
                let loop_handle =
                    self.spawn_peer_loop(peer_id, address.clone(), handshake, stream, from_main_rx);

                // Notify the rest of the application that a peer is ready.
                let _ = self
                    .event_tx
                    .send(NetworkEvent::PeerConnected {
                        peer_id,
                        handshake: Box::new(handshake),
                        address,
                        loop_handle,
                    })
                    .await;
            }

            SwarmEvent::NewListenAddr { address, .. } => {
                tracing::info!("Node is listening on {:?}", address);
            }

            SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                if let Some(address) = self.address_map.remove(&peer_id) {
                    tracing::info!("Connection to peer {peer_id} at {address} closed.");
                } else {
                    tracing::warn!(peer = %peer_id, "Connection closed abruptly: {:?}", cause);
                }
            }

            // Explicitly handle Dial failures to clean up state
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                tracing::warn!(peer = ?peer_id, "Failed to connect: {:?}", error);
            }

            // Handle listener errors to prevent the node from failing silently
            SwarmEvent::ListenerError { listener_id, error } => {
                tracing::error!(?listener_id, "Listener failed: {:?}", error);
            }

            // Handle new connection
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                let address = endpoint.get_remote_address().clone();
                tracing::info!("Established new connection with {peer_id} at {address}.");
                self.address_map.insert(peer_id, address.clone());
            }

            _ => {}
        }

        Ok(())
    }

    /// Handle messages (commands) from the Main Loop.
    ///
    /// # Return Value
    ///
    ///  - Err(_) if something went wrong badly enough to warrant the
    ///    application (or at least the libp2p Actor) to shut down immediately.
    ///  - Ok(Self::KEEP_ALIVE) to keep the event loop running.
    ///  - Ok(!Self::KEEP_ALIVE) to gracefully shut down the event loop.
    #[allow(
        clippy::unnecessary_wraps,
        reason = "function signature anticipates more complex, fallible commands"
    )]
    fn handle_command(&mut self, command: NetworkActorCommand) -> Result<bool, ActorError> {
        match command {
            NetworkActorCommand::Dial(addr) => {
                tracing::info!("Manual dial requested for address: {}", addr);
                // We use the swarm's dial method. libp2p handles the underlying
                // TCP/transport logic.
                if let Err(e) = self.swarm.dial(addr.clone()) {
                    tracing::warn!("Failed to dial {}: {:?}", addr, e);
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
                tracing::info!("Network Actor shutting down Swarm...");
                // Do not touch the peer loops here, just stop the Actor's own
                // loop.
                return Ok(!Self::KEEP_ALIVE);
            }
        }

        Ok(Self::KEEP_ALIVE)
    }

    /// Spawns a long-lived Tokio task to manage the lifecycle of a single peer
    /// connection.
    ///
    /// This function acts as the bridge between the libp2p transport and the
    /// protocol logic. It performs the following steps:
    /// 1. Derives a deterministic `SocketAddr` from the `PeerId` to maintain
    ///    compatibility with legacy state tracking (the "Pseudo-IP").
    /// 2. Subscribes to the global `MainToPeerTask` broadcast channel.
    /// 3. Upgrades the raw [`libp2p::Stream`] into a
    ///    `tokio_util::codec::framed::Framed`
    ///    [`PeerMessage`](crate::protocol::peer::PeerMessage) stream using the
    ///    same codec bridge already in use for the legacy TCP stack.
    /// 4. Calls the legacy [`PeerLoopHandler::run_wrapper`] method, handing
    ///    over control of the connection to the established protocol logic.
    ///
    /// The task terminates automatically if the stream is closed or a shutdown
    /// signal is received from the main loop.
    fn spawn_peer_loop(
        &self,
        peer_id: PeerId,
        peer_address: Multiaddr,
        handshake: HandshakeData,
        raw_stream: libp2p::Stream,
        from_main_rx: tokio::sync::broadcast::Receiver<MainToPeerTask>,
    ) -> JoinHandle<()> {
        // Counts the number of hops between the node and peers it is connected
        // to. We probably don't need this for the libp2p wrapper.
        const DISTANCE_TO_CONNECTED_PEER: u8 = 1u8;

        // Create immutable (across the lifetime of the connection) peer state.
        // This variable needs to be mutable because of efficient pointer reuse
        // in the course of punishments. We probably want to change that.
        let mut peer_loop_handler = PeerLoopHandler::new(
            self.peer_to_main_loop_tx.clone(),
            self.global_state_lock.clone(),
            peer_id,
            peer_address,
            handshake,
            rand::rng().random_bool(0.5f64),
            DISTANCE_TO_CONNECTED_PEER,
        );

        let peer_stream = bridge_libp2p_stream(raw_stream);

        tokio::spawn(async move {
            // Because 'peer_stream' implements Sink + Stream + Unpin,
            // and we have the broadcast receiver, this just works.
            peer_loop_handler
                .run_wrapper(peer_stream, from_main_rx)
                .await
                .unwrap_or_else(|e| {
                    tracing::warn!(peer = %peer_id, "Peer loop exited with error: {:?}", e);
                })
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ActorError {
    #[error("Network channel closed unexpectedly")]
    ChannelClosed,

    #[error("No address found for peer {0} in address map")]
    NoAddressForPeer(PeerId),
}
