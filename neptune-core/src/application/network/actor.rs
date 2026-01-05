use futures::prelude::*;
use libp2p::swarm::SwarmEvent;
use libp2p::Multiaddr;
use libp2p::PeerId;
use rand::Rng;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use crate::application::loops::peer_loop::channel::MainToPeerTask;
use crate::application::loops::peer_loop::channel::PeerTaskToMain;
use crate::application::loops::peer_loop::PeerLoopHandler;
use crate::application::network::address_book::AddressBook;
use crate::application::network::address_book::ADDRESS_BOOK_MAX_SIZE;
use crate::application::network::bridge::bridge_libp2p_stream;
use crate::application::network::channel::NetworkActorCommand;
use crate::application::network::channel::NetworkEvent;
use crate::application::network::gateway::GatewayEvent;
use crate::application::network::gateway::StreamGateway;
use crate::application::network::stack::NetworkStack;
use crate::application::network::stack::NetworkStackEvent;
use crate::application::network::stack::NEPTUNE_PROTOCOL;
use crate::application::network::stack::NEPTUNE_PROTOCOL_STR;
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

    /// Lookup table to find the current addresses of connected peers.
    active_connections: HashMap<PeerId, Multiaddr>,

    /// Dictionary to find peer metadata, connected or not.
    address_book: AddressBook,

    /// File to store the address book, if any.
    address_book_file: Option<PathBuf>,
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
        maybe_address_book_file: Option<PathBuf>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Create the Identify config (required for the NetworkStack)
        let identify_config =
            libp2p::identify::Config::new(NEPTUNE_PROTOCOL_STR.to_owned(), local_key.public())
                .with_agent_version(format!("neptune-cash/{}", env!("CARGO_PKG_VERSION")));

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

                // Use the default autoNAT config for now. For later reference,
                // the fields of autonat::Config are `pub` and so can be
                // changed. Here is a selection of fields we might consider
                // changing to non-default values.
                //  - `retry_interval` (default 1m)
                //  - `refresh_interval` (default: 15m)
                //  - `boot_delay` (default: 1s)
                let autonat_config = libp2p::autonat::Config::default();

                NetworkStack {
                    gateway: StreamGateway::new(global_state_lock.clone()),
                    identify: libp2p::identify::Behaviour::new(identify_config),
                    autonat: libp2p::autonat::Behaviour::new(local_peer_id, autonat_config),
                    relay: relay_behaviour,
                    dcutr: libp2p::dcutr::Behaviour::new(local_peer_id),
                }
            })?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(30)))
            .build();

        let mut address_book = AddressBook::new();
        let mut address_book_file = None;
        if let Some(file_name) = maybe_address_book_file {
            if let Err(e) = address_book.load_from_disk(&file_name) {
                tracing::warn!(
                    "Failed to load address book from '{}': {e}.",
                    file_name.to_string_lossy()
                );
            } else {
                tracing::info!(
                    "Loaded address book from '{}'.",
                    file_name.to_string_lossy()
                );
                address_book_file = Some(file_name);
            }
        }

        Ok(Self {
            swarm,
            peer_to_main_loop_tx,
            main_to_peer_broadcast,
            command_rx,
            event_tx,
            global_state_lock,
            active_connections: HashMap::new(),
            address_book,
            address_book_file,
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

    /// Fetch a list of suitable peers from the address book and dial them.
    pub(crate) fn dial_initial_peers(&mut self) {
        let initial_peers = self.address_book.select_initial_peers(10);
        for peer in initial_peers {
            if let Err(e) = self.swarm.dial(peer.clone()) {
                tracing::warn!("Failed to dial initial peer {}: {e}", peer.to_string());
            } else {
                tracing::info!("Dialed initial peer {}.", peer.to_string());
            }
        }
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
            // An event from our own network stack bubbles up.
            SwarmEvent::Behaviour(network_stack_event) => {
                match network_stack_event {
                    NetworkStackEvent::Identify(identify_event) => {
                        self.handle_identify_event(*identify_event);
                    }
                    NetworkStackEvent::AutoNat(auto_nat_event) => {
                        self.handle_autonat_event(*auto_nat_event);
                    }
                    NetworkStackEvent::Relay(_event) => {}
                    NetworkStackEvent::Dcutr(_event) => {}

                    // StreamGateway successfully hijacked a stream.
                    NetworkStackEvent::StreamGateway(gateway_event) => {
                        self.handle_stream_gateway_event(*gateway_event).await?;
                    }
                }
            }

            SwarmEvent::NewListenAddr { address, .. } => {
                tracing::info!("Node is listening on {:?}", address);
            }

            SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                if let Some(address) = self.active_connections.remove(&peer_id) {
                    tracing::info!("Connection to peer {peer_id} at {address} closed.");
                } else {
                    tracing::warn!(peer = %peer_id, "Connection closed abruptly: {:?}", cause);
                }
            }

            // Dial failure
            SwarmEvent::OutgoingConnectionError {
                peer_id: Some(peer_id),
                error,
                ..
            } => {
                tracing::debug!(peer = %peer_id, %error, "Dial failed, updating address book.");
                self.address_book.bump_fail_count(peer_id);
            }

            // Low-level connection failure
            SwarmEvent::OutgoingConnectionError {
                peer_id: None,
                error,
                ..
            } => {
                tracing::debug!(%error, "Connection failed.");
            }

            // Handle listener errors to prevent the node from failing silently
            SwarmEvent::ListenerError { listener_id, error } => {
                tracing::error!(?listener_id, "Listener failed: {:?}", error);
            }

            // Handle new connection
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                self.address_book.reset_fail_count(peer_id);
                let address = endpoint.get_remote_address().clone();
                let direction = if endpoint.is_dialer() {
                    "Outbound"
                } else {
                    "Inbound"
                };
                tracing::info!("{direction} connection established with {peer_id} at {address}.");
                self.active_connections.insert(peer_id, address.clone());
            }

            _ => {}
        }

        Ok(())
    }

    /// Handles Identify protocol events to synchronize protocol versions and
    /// external address observations.
    fn handle_identify_event(&mut self, event: libp2p::identify::Event) {
        match event {
            // We received Identify info from a remote peer.
            libp2p::identify::Event::Received { peer_id, info, .. } => {
                tracing::debug!(peer = %peer_id, "Received identify info");

                // Check if the peer speaks the same Neptune version as us.
                if !info.protocols.contains(&NEPTUNE_PROTOCOL) {
                    tracing::warn!(
                        peer = %peer_id,
                        version = %info.protocol_version,
                        "Peer is running an incompatible protocol version. Expected: {}",
                        NEPTUNE_PROTOCOL_STR
                    );

                    // Trigger a disconnect; we want Neptune-only.
                    self.swarm.disconnect_peer_id(peer_id).ok();
                    return;
                }

                // The remote peer told us what our IP/port looks like from
                // their perspective. This is useful for AutoNAT and for our own
                // reachability logic.
                tracing::info!(
                    peer = %peer_id,
                    observed_addr = %info.observed_addr,
                    "Remote peer observed us at a specific address."
                );

                // Keep a record of this peer in our address book, or update it.
                self.address_book.insert_or_update(
                    peer_id,
                    info.listen_addrs,
                    info.agent_version,
                    info.protocol_version,
                    info.protocols,
                );

                // Prune if necessary, to avoid state bloat.
                self.address_book.prune_to_length(ADDRESS_BOOK_MAX_SIZE);
            }

            // We successfully sent our Identify info to a peer in response to
            // a request.
            libp2p::identify::Event::Sent { peer_id, .. } => {
                tracing::debug!(peer = %peer_id, "Sent identify info to peer");
            }

            // We successfully sent our Identify info to a peer at our own
            // behest.
            libp2p::identify::Event::Pushed { peer_id, .. } => {
                tracing::debug!(peer = %peer_id, "Pushed identify info to peer");
            }

            // An error occurred during the Identify exchange.
            libp2p::identify::Event::Error { peer_id, error, .. } => {
                tracing::warn!(peer = %peer_id, "Identify error: {:?}", error);
            }
        }
    }

    /// Process events from the `StreamGateway` subprotocol to transform a raw
    /// libp2p stream into bidirectional stream compatible with the legacy
    /// Neptune Cash peer-loop architecture.
    ///
    /// This function acts as the bridge between the asynchronous `libp2p` swarm
    /// and the dedicated actor loops managed by the `NetworkActor`. When a new
    /// stream is successfully "hijacked" and the initial handshake is
    /// negotiated:
    ///
    ///  1. **Context Recovery**: It retrieves the peer's network address from
    ///     the internal `address_map` to maintain consistency with legacy
    ///     expectations.
    ///  2. **Loop Spawning**: It initializes a new peer-specific message
    ///     handler (the legacy event loop) by providing it with the hijacked
    ///     stream and a subscription to the global main-to-peer broadcast
    ///     channel.
    ///  3. **Application Notification**: It signals to the main loop that a
    ///     new, authenticated peer is fully operational and ready for
    ///     synchronization.
    ///
    /// # Errors
    ///
    /// Returns [`ActorError::NoAddressForPeer`] if a stream is established for
    /// a peer whose connection metadata was not correctly tracked in the
    /// address map.
    async fn handle_stream_gateway_event(&mut self, event: GatewayEvent) -> Result<(), ActorError> {
        let GatewayEvent::HandshakeReceived {
            peer_id,
            handshake,
            stream,
        } = event;

        tracing::info!(peer = %peer_id, "New peer stream hijacked via StreamGateway");

        // Generate a new the receiver channel for this specific peer.
        let from_main_rx = self.main_to_peer_broadcast.subscribe();

        // Fetch address from carefully maintained address map.
        let Some(address) = self.active_connections.get(&peer_id).cloned() else {
            return Err(ActorError::NoAddressForPeer(peer_id));
        };

        // Spawn the legacy loop with the hijacked stream.
        let loop_handle =
            self.spawn_peer_loop(peer_id, address.clone(), handshake, stream, from_main_rx);

        // Notify the rest of the application that a peer is ready.
        let _ = self
            .event_tx
            .send(NetworkEvent::NewPeerLoop { loop_handle })
            .await;

        Ok(())
    }

    /// Handles events emitted by the AutoNAT behavior to determine the node's
    /// network reachability.
    ///
    /// AutoNAT works by asking remote peers to attempt a "dial back" to our
    /// observed addresses. This function processes the results of those probes:
    ///
    /// * **Inbound/Outbound Probes**: Logged at the debug level. These
    ///   represent the active probing mechanism where we either assist others
    ///   or request assistance to determine our own reachability. No manual
    ///   intervention is required as the behavior handles the underlying
    ///   protocol exchange.
    ///
    /// * **Status Changes**: Logged at the info level. This is the critical
    ///   output of the behavior.
    ///   - `Public`: Confirms the node is directly accessible from the
    ///     internet.
    ///   - `Private`: Indicates the node is behind a NAT or firewall and
    ///     requires **Relay** and **DCUtR** to be reachable by others.
    ///   - `Unknown`: The initial state before enough probes have been
    ///     completed to form a consensus on reachability.
    fn handle_autonat_event(&mut self, event: libp2p::autonat::Event) {
        match event {
            // Someone asked us "can you see me?" and we respond(ed).
            libp2p::autonat::Event::InboundProbe(_inbound_probe_event) => {
                tracing::debug!("Peer query for NAT reachability; delegating event for automatic handling by libp2p::auto_nat.");
            }

            // We asked someone "can you see me?" and they respond(ed).
            libp2p::autonat::Event::OutboundProbe(_outbound_probe_event) => {
                tracing::debug!("Queried peer for NAT reachability; delegating event for automatic handling by libp2p::auto_nat.");
            }

            // New NAT status
            libp2p::autonat::Event::StatusChanged { old: _, new } => {
                let status = match new {
                    libp2p::autonat::NatStatus::Public(multiaddr) => {
                        format!("Public({})", multiaddr)
                    }
                    libp2p::autonat::NatStatus::Private => {
                        // TODO: Reachability-based Triggering.
                        // When identified as Private, the node should initiate
                        // a Relay reservation to ensure inbound connectivity.
                        // Scan Kademlia/Identify for peers supporting the
                        // '/libp2p/relay/2.0.0/stop' protocol and call
                        // `relay.reserve(peer_id)`.
                        "Private".to_string()
                    }
                    libp2p::autonat::NatStatus::Unknown => "Unknown".to_string(),
                };
                tracing::info!("New NAT status: {status}");
            }
        }
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

                if let Some(file_name) = self.address_book_file.as_ref() {
                    if let Err(e) = self.address_book.save_to_disk(file_name) {
                        tracing::warn!(
                            "Failed to persist address book at '{}': {e}.",
                            file_name.to_string_lossy()
                        );
                    }
                }

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
                });
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
