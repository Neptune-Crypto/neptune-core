use const_format::concatcp;
use futures::prelude::*;
use itertools::Itertools;
use libp2p::swarm::SwarmEvent;
use libp2p::Multiaddr;
use libp2p::PeerId;
use rand::seq::SliceRandom;
use rand::Rng;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use std::collections::HashMap;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::SystemTime;

use crate::application::loops::peer_loop::channel::MainToPeerTask;
use crate::application::loops::peer_loop::channel::PeerTaskToMain;
use crate::application::loops::peer_loop::PeerLoopHandler;
use crate::application::network::address_book::AddressBook;
use crate::application::network::address_book::ADDRESS_BOOK_MAX_SIZE;
use crate::application::network::ban::BlackList;
use crate::application::network::bridge::bridge_libp2p_stream;
use crate::application::network::channel::NetworkActorCommand;
use crate::application::network::channel::NetworkEvent;
use crate::application::network::config::NetworkConfig;
use crate::application::network::gateway::GatewayEvent;
use crate::application::network::gateway::StreamGateway;
use crate::application::network::overview::NetworkOverview;
use crate::application::network::stack::NetworkStack;
use crate::application::network::stack::NetworkStackEvent;
use crate::application::network::stack::NEPTUNE_PROTOCOL_STR;
use crate::protocol::peer::handshake_data::HandshakeData;
use crate::state::GlobalStateLock;

/// Tracks the status of a relay reservation.
#[derive(Debug, Copy, Clone)]
enum RelayStatus {
    Waiting(libp2p::core::transport::ListenerId),
    Active(SystemTime, libp2p::core::transport::ListenerId),
    Closed(SystemTime),
}

impl RelayStatus {
    /// Set the status to `Active(now, listener_id)`.
    ///
    /// Works regardless of whether previous status was
    ///  - `Waiting(listener_id)`, or
    ///  - `Active(previous_timestamp, listener_id)`.
    ///
    /// # Panics
    ///
    ///  - If status was `Closed(_)`
    fn activate(&mut self) {
        let listener_id = self.listener_id().expect("Cannot activate `Closed` relay.");
        *self = RelayStatus::Active(SystemTime::now(), listener_id);
    }

    /// Fetch the listener ID, if any; otherwise `None`.
    fn listener_id(&self) -> Option<libp2p::core::transport::ListenerId> {
        match self {
            RelayStatus::Waiting(listener_id) => Some(*listener_id),
            RelayStatus::Active(_system_time, listener_id) => Some(*listener_id),
            RelayStatus::Closed(_system_time) => None,
        }
    }
}

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

    /// Lookup table to find the current address of connected peers or how long
    /// they have been connected for.
    active_connections: HashMap<PeerId, (SystemTime, Multiaddr)>,

    /// Peers with whom the connection was upgraded to the consensus peer loop.
    upgraded_peers: Arc<Mutex<HashSet<PeerId>>>,

    /// Dictionary to find peer metadata, connected or not.
    address_book: AddressBook,

    /// Tracks which peers are going to hold a reservation for us, currently
    /// holding one for us, or closed the reservation for us abruptly, along
    /// with timestamps and the listener id (which we need to stop listening).
    relays: HashMap<PeerId, RelayStatus>,

    /// Tracks active local listeners (open ports). These IDs represent local
    /// sockets bound to the NIC.
    active_listeners: Vec<libp2p::core::transport::ListenerId>,

    /// Curated list of banned IPs.
    black_list: BlackList,

    /// Peer addresses passed through CLI.
    ///
    /// This dictionary maps addresses (specified in CLI arguments) to
    ///  - `StickyPeer::None` by default;
    ///  - `StickyPeer::Dialing(since_simestamp)` when a connection attempt is
    ///    on-going and has been since `since_timestamp`;
    ///  - `StickyPeer::Connected(peer_id)` when a connection was established.
    sticky_peers: HashMap<Multiaddr, StickyPeer>,

    /// Limits the total number of connections.
    max_num_peers: usize,
}

/// Helper struct encapsulating all channels for the [`NetworkActor`].
///
/// Avoids triggering #[warn(clippy::too_many_arguments)]. Also reduces
/// boilerplate.
pub(crate) struct NetworkActorChannels {
    peer_to_main_loop_tx: mpsc::Sender<PeerTaskToMain>,
    main_to_peer_broadcast: tokio::sync::broadcast::Sender<MainToPeerTask>,
    command_rx: mpsc::Receiver<NetworkActorCommand>,
    event_tx: mpsc::Sender<NetworkEvent>,
}

impl NetworkActorChannels {
    /// Set up the channels for the [`NetworkActor`].
    ///
    /// Takes two channels that already exist: these are the channels between
    /// the main loop and the peer loop (either direction). The [`NetworkActor`]
    /// feeds a clone and a subscription to these to the peer loop whenever it
    /// spawns one.
    ///
    /// This function also generates two more channels; these are for the main
    /// loop and the [`NetworkActor`] to communicate between each other.
    ///
    /// # Parameters
    ///
    ///  - `mpsc::Sender<PeerTaskToMain>` -- the sender channel for the peer
    ///    loop to send messages to the main loop.
    ///  - `broadcast::Sender<MainToPeerTask>` -- the receiver channel for the
    ///    peer loop to receive messages from the main loop.
    ///
    /// # Return Value
    ///
    /// A tuple consisting of:
    ///
    ///  - `Self` -- the [`NetworkActorChannels`] object to be passed on to the
    ///    constructor for [`NetworkActor`].
    ///  - `mpsc::Sender<NetworkActorCommand>` -- the sender channel for the
    ///    main loop to send messages (commands) to the [`NetworkActor`].
    ///  - `mpsc::Receiver<NetworkEvent>` -- the receiver channel for the
    ///    main loop to receive notifications from the [`NetworkActor`]
    ///    (notifications of events).
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use tokio::sync::broadcast;
    /// use tokio::sync::mpsc;
    ///
    /// use crate::application::loops::peer_loop::channel::PeerTaskToMain;
    /// use crate::application::loops::peer_loop::channel::MainToPeerTask;
    /// use crate::application::network::actor::NetworkActorChannels;
    ///
    /// // Construct the broadcast channel to communicate from the main task to
    /// // peer tasks
    /// let (main_to_peer_broadcast_tx, _main_to_peer_broadcast_rx) =
    ///     broadcast::channel::<MainToPeerTask>(1000);
    ///
    /// // Add the MPSC (multi-producer, single consumer) channel for
    /// // peer-task-to-main communication
    /// let (peer_task_to_main_tx, peer_task_to_main_rx) =
    ///     mpsc::channel::<PeerTaskToMain>(1000);
    ///
    /// // Construct the channels for the `NetworkActor`
    /// let (channels, network_command_tx, network_event_rx) = NetworkActorChannels::setup(
    ///     peer_task_to_main_tx.clone(),
    ///     main_to_peer_broadcast_tx.clone(),
    /// );
    /// ```
    ///
    /// (Note that the doctest cannor run because message types `PeerTaskToMain`
    /// and `MainToPeerTask`, not to mention this constructor, are private.)
    pub(crate) fn setup(
        peer_to_main_loop_tx: mpsc::Sender<PeerTaskToMain>,
        main_to_peer_broadcast: tokio::sync::broadcast::Sender<MainToPeerTask>,
    ) -> (
        Self,
        mpsc::Sender<NetworkActorCommand>,
        mpsc::Receiver<NetworkEvent>,
    ) {
        let (network_command_tx, network_command_rx) = mpsc::channel(100);
        let (network_event_tx, network_event_rx) = mpsc::channel(100);

        let channels = Self {
            peer_to_main_loop_tx,
            main_to_peer_broadcast,
            command_rx: network_command_rx,
            event_tx: network_event_tx,
        };

        (channels, network_command_tx, network_event_rx)
    }
}

#[derive(Debug, Clone)]
enum StickyPeer {
    None,
    Dialing(SystemTime),
    Connected(PeerId),
}

impl NetworkActor {
    /// Whether to keep the Actor's event loop running (true) or to shut it down
    /// gracefully (false).
    const KEEP_ALIVE: bool = true;

    /// How long relay reservations (proxy addresses) last.
    const RELAY_RESERVATION_DURATION: Duration = Duration::from_secs(120);

    /// How long before we are allowed to re-initiate a relay to replace the
    /// failed one.
    const RELAY_COOLDOWN_PERIOD: Duration = Duration::from_secs(10);

    /// Hardcoded version strings for Kademlia.
    const KADEMLIA_FOR_NEPTUNE_STRING: &str = concatcp!(NEPTUNE_PROTOCOL_STR, "/kad/");
    const KADEMLIA_FOR_NEPTUNE_PROTOCOL: libp2p::StreamProtocol =
        libp2p::StreamProtocol::new(Self::KADEMLIA_FOR_NEPTUNE_STRING);

    /// Initialize a new libp2p Actor.
    ///
    /// This constructor sets up the underlying libp2p Swarm with TCP transport,
    /// Noise encryption, and Yamux multiplexing, alongside the StreamGateway
    /// for handing off control over bidirectional streams to peer loops.
    pub fn new(
        local_key: libp2p::identity::Keypair,
        channels: NetworkActorChannels,
        global_state_lock: GlobalStateLock,
        config: NetworkConfig,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let NetworkActorChannels {
            peer_to_main_loop_tx,
            main_to_peer_broadcast,
            command_rx,
            event_tx,
        } = channels;

        // Create the Identify config (required for the NetworkStack)
        let network = global_state_lock.cli().network;
        let protocol_version = format!("{NEPTUNE_PROTOCOL_STR}-{network}");
        let identify_config = libp2p::identify::Config::new(protocol_version, local_key.public())
            .with_agent_version(format!("neptune-cash/{}", env!("CARGO_PKG_VERSION")))
            // pro-actively tell peers about new (sub-)addresses
            .with_push_listen_addr_updates(true)
            .with_interval(std::time::Duration::from_secs(300));

        // Configure Ping.
        let ping_config = libp2p::ping::Config::new()
            .with_interval(std::time::Duration::from_secs(9)) // Ping every 9s
            .with_timeout(std::time::Duration::from_secs(32)); // 32s until we give up

        // Configure connection limits
        let max_num_peers = config.max_num_peers;

        // Configure autoNAT
        let autonat_config = if config.network.is_reg_test() {
            // Flag `only_global_ips` determines whether to ignore
            // addresses reported by peers when those addresses are
            // local, e.g., 192.168.0.15. On main net we cannot use
            // these addresses for anything so we might as well ignore
            // them.
            // On regtest however, the entire network is local and we
            // want to pretend that it's not. In other words, we still
            // want to trigger all usual actions and sequences for the
            // purpose of testing them. Therefore, on regtest we do not
            // ignore local IPs.
            libp2p::autonat::Config {
                only_global_ips: false,
                ..Default::default()
            }
        } else {
            libp2p::autonat::Config::default()
        };

        // Configure yamux (stream multiplexer)
        let yamux_tuner = || {
            let mut cfg = libp2p::yamux::Config::default();
            cfg.set_max_num_streams(256); // reduced from 8192; still plenty
            cfg
        };

        // Configure relay server
        let relay_server_config = libp2p::relay::Config {
            // # sub-addresses
            max_reservations: 128,
            // # active connections
            max_circuits: 16,
            // time for hole punch only
            reservation_duration: Self::RELAY_RESERVATION_DURATION,
            ..Default::default()
        };

        // Configure Kademlia
        let kad_config = libp2p::kad::Config::new(Self::KADEMLIA_FOR_NEPTUNE_PROTOCOL);

        // Build Swarm
        let swarm = libp2p::SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_tcp(
                libp2p::tcp::Config::default(),
                libp2p::noise::Config::new,
                yamux_tuner,
            )?
            .with_quic()
            .with_relay_client(libp2p::noise::Config::new, yamux_tuner)?
            .with_behaviour(|key, relay_client| {
                let local_peer_id = key.public().to_peer_id();

                let relay_server =
                    libp2p::relay::Behaviour::new(local_peer_id, relay_server_config);

                let store = libp2p::kad::store::MemoryStore::new(local_peer_id);
                let mut kademlia =
                    libp2p::kad::Behaviour::with_config(local_peer_id, store, kad_config);
                kademlia.set_mode(Some(libp2p::kad::Mode::Server));

                let upnp = libp2p::upnp::tokio::Behaviour::default();

                NetworkStack {
                    ping: libp2p::ping::Behaviour::new(ping_config),
                    identify: libp2p::identify::Behaviour::new(identify_config),
                    upnp,
                    autonat: libp2p::autonat::Behaviour::new(local_peer_id, autonat_config),
                    relay_server,
                    relay_client,
                    dcutr: libp2p::dcutr::Behaviour::new(local_peer_id),
                    kademlia,
                    gateway: StreamGateway::new(global_state_lock.clone()),
                }
            })?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(30)))
            .build();

        // Load or build address book
        let address_book_file = config.address_book_file();
        let address_book = AddressBook::load_or_new(&address_book_file).unwrap_or_else(|e| {
            tracing::warn!(
                "Failed to load address book from '{}': {e}.",
                address_book_file.to_string_lossy()
            );
            AddressBook::new_empty(address_book_file)
        });

        // Load or build black list
        let black_list_file = config.blacklist_file();
        let black_list = BlackList::load_or_new(&black_list_file)
            .unwrap_or_else(|e| {
                tracing::warn!(
                    "Failed to load blacklist from '{}': {e}.",
                    black_list_file.to_string_lossy()
                );
                BlackList::new(black_list_file)
            })
            .with_ephemeral_bans(config.banned_ips());

        let sticky_peers = config
            .sticky_peers
            .iter()
            .map(|ma| (ma.clone(), StickyPeer::None))
            .collect();

        Ok(Self {
            swarm,
            peer_to_main_loop_tx,
            main_to_peer_broadcast,
            command_rx,
            event_tx,
            global_state_lock,
            active_connections: HashMap::new(),
            address_book,
            relays: HashMap::new(),
            active_listeners: vec![],
            black_list,
            sticky_peers,
            max_num_peers,
            upgraded_peers: Arc::new(Mutex::new(HashSet::new())),
        })
    }

    /// Start listening for incoming libp2p connections.
    ///
    /// This informs the underlying Swarm to bind to the provided [`Multiaddr`].
    /// Incoming connections will automatically undergo the handshake defined in
    /// the [`StreamGateway`].
    fn listen(&mut self, addr: Multiaddr) -> Result<(), libp2p::TransportError<std::io::Error>> {
        match self.swarm.listen_on(addr.clone()) {
            Ok(listener_id) => {
                tracing::info!(%addr, %listener_id, "libp2p stack listening.");
                // Keeping track of listeners allows for a graceful shutdown: by
                // explicitly removing them at shutdown time, we trigger the
                // UPnP behavior to send 'DeletePortMapping' requests to
                // politely ask for those port mappings to be closed.
                self.active_listeners.push(listener_id);
                Ok(())
            }
            Err(e) => {
                tracing::error!("Failed to listen on {}: {}", addr, e);
                Err(e)
            }
        }
    }
    /// Fetch a list of suitable peers from the address book and dial them.
    pub(crate) fn dial_initial_peers(&mut self) {
        let initial_peers = self.address_book.select_initial_peers(10);
        tracing::debug!("Dialing {} initial peers.", initial_peers.len());
        for address in initial_peers {
            if let Err(e) = self.swarm.dial(address.clone()) {
                tracing::warn!("Failed to dial initial peer {}: {e}", address.to_string());
                continue;
            }
            tracing::info!("Dialed initial peer {}.", address.to_string());
        }
    }

    /// The event loop for the Network Actor.
    ///
    /// Drives the libp2p Swarm and handles incoming connection handshakes.
    ///
    /// Includes a 10-second 'Check Relay Reservations' heartbeat. NATted nodes
    /// continuously ask their peers to reserve a relay slot in order to be
    /// reachable. (After establishing the relayed connection, that connection
    /// will automatically upgrade through DCUtR or "hole punching"; the relay
    /// reservation merely serves to enable this coordination.) These slots are
    /// short-lived. To remain reachable, NATted nodes must pro-actively reserve
    /// new slots before the old ones expire.
    ///
    /// Includes a 10-minute 'Crawl Refresh' heartbeat. This heartbeat ensures
    /// that even if we become isolated, we proactively reach out to re-verify
    /// our  'one-hop' neighbors and discover new nodes that have joined the
    /// network since our last update.
    pub(crate) async fn run(mut self) -> Result<(), ActorError> {
        // Timer for renewing relays.
        let mut check_relay_reservations = tokio::time::interval(Duration::from_secs(10));

        // Timer for refreshing the Kademlia crawl.
        let mut refresh_kademlia_crawl = tokio::time::interval(Duration::from_mins(10));

        // Timer for checking that we are still connected to sticky peers.
        let mut check_sticky_peers = tokio::time::interval(Duration::from_secs(30));

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
                            if self.handle_command(cmd).await? != Self::KEEP_ALIVE {
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

                // Renew about-to-expire relay reservations (if any).
                _ = check_relay_reservations.tick() => {
                    self.check_relays_reservations();
                }

                // Re-launch a crawl with Kademlia
                _ = refresh_kademlia_crawl.tick() => {
                    // Trigger the "One-Hop" crawl we documented earlier.
                    // Asks our current neighbors: "Who is new in the network?"
                    if let Err(e) = self.swarm.behaviour_mut().kademlia.bootstrap() {
                        tracing::warn!("Crawl refresh skipped: No known peers to ask. {:?}", e);
                        self.dial_initial_peers();
                    } else {
                        tracing::info!("Starting periodic network crawl to maintain connectivity ...");
                    }
                }

                // Check sticky peers.
                _ = check_sticky_peers.tick() => {

                    // Determine which sticky peers to re-dial.
                    let mut dials = vec![];
                    for (multiaddr, sticky_peer) in &mut self.sticky_peers {
                        let now = SystemTime::now();
                        match sticky_peer.clone() {
                            StickyPeer::None => {
                                *sticky_peer = StickyPeer::Dialing(now);
                                dials.push(multiaddr.clone());
                                if let Err(e) = self.swarm.dial(multiaddr.clone()) {
                                    tracing::warn!(%multiaddr, "Could not dial sticky peer: {e}.");
                                }
                            }
                            StickyPeer::Dialing(since_timestamp) => {
                                // If time since dialing started is too big,
                                // try again.
                                if now.duration_since(since_timestamp).ok().is_some_and(|duration| duration > Duration::from_mins(2)) {
                                    tracing::warn!(%multiaddr, "Sticky peer seems stuck in dialing phase; trying again.");
                                    *sticky_peer = StickyPeer::Dialing(now);
                                dials.push(multiaddr.clone());
                                    if let Err(e) = self.swarm.dial(multiaddr.clone()) {
                                        tracing::warn!(%multiaddr, "Could not dial sticky peer: {e}.");
                                    }
                                }
                            }
                            StickyPeer::Connected(peer_id) => {
                                // Verify that the peer id is connected, and if
                                // not, re-dial.
                                if !self.active_connections.contains_key(&peer_id) {
                                    tracing::warn!(%peer_id, %multiaddr, "Sticky peer disconnected; attempting to re-establish connection..");
                                    *sticky_peer = StickyPeer::Dialing(now);
                                dials.push(multiaddr.clone());
                                    if let Err(e) = self.swarm.dial(multiaddr.clone()) {
                                        tracing::warn!(%multiaddr, "Could not dial sticky peer: {e}.");
                                    }
                                }
                            }
                        }
                    }

                    // If we are not connected to anyone, and if there are not
                    // sticky peers, then dial initial peers from address book.
                    if self.sticky_peers.is_empty() && self.active_connections.is_empty() {
                        dials.append(&mut self.address_book.select_initial_peers(3));
                    }

                    // Disconnect if necessary to free up enough slots.
                    let num_free_slots = self.max_num_peers.saturating_sub(self.active_connections.len());
                    if num_free_slots < dials.len() {
                        for _ in num_free_slots..dials.len() {
                            self.disconnect_from_longest_lived_peer();
                        }
                    }

                    // Issue dial commands.
                    for dial in dials {
                        if let Err(e) = self.swarm.dial(dial.clone()) {
                            tracing::warn!(%dial, "Could not dial peer: {e}.");
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
                    NetworkStackEvent::Ping(ping_event) => {
                        self.handle_ping_event(*ping_event);
                    }
                    NetworkStackEvent::Identify(identify_event) => {
                        self.handle_identify_event(*identify_event);
                    }
                    NetworkStackEvent::Upnp(upnp_event) => {
                        self.handle_upnp_event(*upnp_event);
                    }
                    NetworkStackEvent::AutoNat(auto_nat_event) => {
                        self.handle_autonat_event(*auto_nat_event);
                    }
                    NetworkStackEvent::RelayServer(relay_server_event) => {
                        self.handle_relay_server_event(*relay_server_event);
                    }
                    NetworkStackEvent::RelayClient(relay_client_event) => {
                        self.handle_relay_client_event(*relay_client_event);
                    }
                    NetworkStackEvent::Dcutr(dcutr_event) => {
                        self.handle_dcutr_event(*dcutr_event);
                    }
                    NetworkStackEvent::Kademlia(kademlia_event) => {
                        self.handle_kademlia_event(*kademlia_event);
                    }

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
                if let Some((_timestamp, address)) = self.active_connections.remove(&peer_id) {
                    tracing::info!("Connection to peer {peer_id} at {address} closed.");
                } else {
                    tracing::warn!(peer = %peer_id, "Connection closed abruptly: {:?}", cause);
                }
            }

            // Handle failed outgoing dials.
            //
            // 1. If the dial was `Denied`, it's just our Diversity Policy
            //    preventing redundant connections.
            // 2. If it's a real error, we mark the peer as unreliable, ensuring
            //    that future 'one-hop' searches are only using high-quality
            //    leads, keeping the Neptune Cash network healthy and fast.
            SwarmEvent::OutgoingConnectionError {
                peer_id: Some(peer_id),
                error,
                ..
            } => {
                match error {
                    // Bouncer says, "We're already talking to this PeerID!"
                    libp2p::swarm::DialError::Denied { .. } => {
                        tracing::info!(peer = %peer_id, "Dial vetoed: Already have a diverse connection to this peer.");
                    }
                    // Actual network/transport failures
                    _ => {
                        tracing::debug!(peer = %peer_id, %error, "Dial failed, updating address book.");
                        self.address_book.bump_fail_count(peer_id);

                        // Help Kademlia realize this peer is unreliable
                        self.swarm.behaviour_mut().kademlia.remove_peer(&peer_id);
                    }
                }
            }

            // Failed incoming connections.
            //
            // We specifically watch for `ListenError::Denied`. This isn't a
            // failure in the traditional sense; it's our ConnectionLimits
            // behavior enforcing the bouncer's (`limits`'s) rules.
            //
            // Seeing this log confirms that our 'Diversity Policy' is active,
            // protecting our 50 slots for unique one-hop neighbors.
            SwarmEvent::IncomingConnectionError { peer_id, error, .. } => {
                match error {
                    // This is the bouncer (Connection Limits) doing its job.
                    libp2p::swarm::ListenError::Denied { cause } => {
                        tracing::info!(
                            peer = ?peer_id.map(|p| p.to_string()).unwrap_or_else(|| "Unknown".to_string()),
                            %cause,
                            "Incoming connection bounced: Diversity or Capacity limit reached."
                        );
                    }
                    // Other errors (Transport noise, TLS fails, timeouts)
                    _ => {
                        tracing::trace!(peer = ?peer_id, "Incoming connection failed during handshake: {:?}", error);
                    }
                }
            }

            // Low-level connection failure
            SwarmEvent::OutgoingConnectionError {
                peer_id: None,
                error,
                ..
            } => {
                tracing::debug!(%error, "Connection failed.");
            }

            // Non-fatal error.
            SwarmEvent::ListenerError { listener_id, error } => {
                tracing::debug!(?listener_id, "Listener failed: {:?}", error);
            }

            // Graceful closure.
            SwarmEvent::ListenerClosed {
                listener_id,
                reason,
                ..
            } => {
                // Find the matching entry in the local dictionary `relays`.
                let failing_relay = self
                    .relays
                    .iter()
                    .find_map(|(peer_id, status)| match status {
                        RelayStatus::Waiting(id) | RelayStatus::Active(_, id)
                            if *id == listener_id =>
                        {
                            Some(*peer_id)
                        }
                        _ => None,
                    });

                // A match necessarily means an *accidental* closure, because
                // intentional closures come after removing the entry from the
                // map.
                if let Some(peer_id) = failing_relay {
                    match reason {
                        Ok(_) => {
                            tracing::warn!(
                                %peer_id,
                                "Relay listener closed gracefully, but a match \
                                was still found! Reason: unexpected race \
                                condition."
                            )
                        }
                        Err(e) => {
                            tracing::warn!(%peer_id, "Relay reservation failed or closed with error: {:?}", e)
                        }
                    }

                    // Remove it from our tracking map.
                    self.relays
                        .entry(peer_id)
                        .and_modify(|status| *status = RelayStatus::Closed(SystemTime::now()));

                    // Finding a replacement happens automatically in the
                    // regular maintenance task `check_relays`.
                }
            }

            SwarmEvent::IncomingConnection {
                connection_id,
                local_addr: _,
                send_back_addr,
            } => {
                if self.bounce(&send_back_addr) {
                    tracing::warn!(%send_back_addr, %connection_id, "Bouncing incoming connection.");

                    // Signal the swarm to drop this connection
                    // immediately to prevent Identify/Kademlia from
                    // ever seeing this peer.
                    self.swarm.close_connection(connection_id);
                }
            }

            // Handle successful connections.
            SwarmEvent::ConnectionEstablished {
                peer_id,
                endpoint,
                connection_id,
                ..
            } => {
                let address = endpoint.get_remote_address().clone();

                // Check for banned IPs again. The catch above in
                // `IncomingConnection` is a good first filter but because of
                // race conditions, masked addresses, and automatic outgoing
                // dials (as happens in Kademlia), it is possible for banned
                // connections to get to this stage.
                if self.bounce(&address) {
                    tracing::warn!(%address, %connection_id, "Bouncing established connection.");
                    self.swarm.close_connection(connection_id);
                }

                // Connection was successfully established, so erase information
                // about prior failures.
                self.address_book.reset_fail_count(peer_id);
                let direction = if endpoint.is_dialer() {
                    "Outbound"
                } else {
                    "Inbound"
                };
                tracing::info!("{direction} connection established with {peer_id} at {address}.");

                // If this address belongs to one of our sticky peers (`--peer`
                // CLI arguments) then make sure we record the `PeerId`.
                if self.sticky_peers.contains_key(&address) {
                    self.sticky_peers.entry(address.clone()).and_modify(|p| {
                        match p {
                            StickyPeer::None | StickyPeer::Dialing(_) => {
                                tracing::info!(%peer_id, "Found peer id of sticky peer {address}.");
                                *p = StickyPeer::Connected(peer_id);
                            },
                            StickyPeer::Connected(pid) => {
                                if *pid != peer_id {
                                    tracing::info!(%peer_id, "Found *new* peer id of sticky peer {address}.");
                                    *pid = peer_id;
                                }
                            },
                        }
                    });
                }

                // Store the new connection. If the new connection is a direct
                // one and the old connection was relayed, then the relayed
                // address will be overwritten in favor of the direct one.
                self.active_connections
                    .entry(peer_id)
                    .and_modify(|(_timestamp, addr)| {
                        tracing::debug!("Overwriting old address {} in favor of new address {} in active connections map.", *addr, address.clone());
                        if !Self::is_direct(addr) && Self::is_direct(&address) {
                            tracing::info!("New address is direct whereas old address was not. Good!");
                        }
                        *addr = address.clone();
                    })
                    .or_insert_with(|| (SystemTime::now(), address.clone()));

                // Note: Identify and Kademlia will now automatically start
                // their handshakes over this new "open line."
            }

            _ => {}
        }

        Ok(())
    }

    /// Check if the address is on the black list.
    ///
    /// This function enforces three things:
    ///  1. The `max_num_peers` limit on the number of connections.
    ///  2. Bans.
    ///  3. The IP requirement.
    ///
    /// In the future, we can accept alternative, non-IP addresses, but *as long
    /// as they can be soundly banned* -- because otherwise they expose the node
    /// to DoS attacks. Since we have no mechanism to ban generic `Multiaddr`s,
    /// the default behavior should be to treat such peers as banned from the
    /// start.
    fn bounce(&self, address: &Multiaddr) -> bool {
        if self.active_connections.len() >= self.max_num_peers {
            return true;
        }
        if let Some(ip) = address.iter().find_map(|protocol| match protocol {
            libp2p::multiaddr::Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
            libp2p::multiaddr::Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
            _ => None,
        }) {
            if self.black_list.is_banned(&ip) {
                return true;
            }
        }
        // In this `else` case, we have a peer `Multiaddr` but no IP.
        else {
            return true;
        }

        false
    }

    /// Handles Identify protocol events to synchronize protocol versions and
    /// external address observations.
    fn handle_identify_event(&mut self, event: libp2p::identify::Event) {
        match event {
            // We received Identify info from a remote peer.
            libp2p::identify::Event::Received { peer_id, info, .. } => {
                if peer_id == *self.swarm.local_peer_id() {
                    tracing::error!("Received Identify event from ourselves.");
                    return;
                }

                tracing::debug!(peer = %peer_id, "Received identify info");
                tracing::debug!("--- Identify Diagnostic for {} ---", peer_id);
                tracing::debug!("Protocols supported by remote: {:?}", info.protocols);
                tracing::debug!("Observed Address: {:?}", info.observed_addr);
                tracing::debug!("Agent Version: {:?}", info.agent_version);

                // Check if the peer speaks the same Neptune version as us.
                if info.protocol_version != NEPTUNE_PROTOCOL_STR {
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
                    info.listen_addrs.clone(),
                    info.agent_version,
                    info.protocol_version,
                    info.protocols,
                );

                // Prune if necessary, to avoid state bloat.
                self.address_book.prune_to_length(ADDRESS_BOOK_MAX_SIZE);

                // Activate the Kademlia "Bridge": feed the addresses to
                // Kademlia. Filter out local addresses.
                for addr in info.listen_addrs {
                    // Filter out local addresses.
                    let addr_str = addr.to_string();
                    let is_local = addr_str.contains("127.0.0.1")
                        || addr_str.contains("::1")
                        || addr_str.contains("/lan/");
                    if is_local {
                        continue;
                    }

                    self.swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer_id, addr);
                }
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

    /// Handles events generated by the Relay Server `Behaviour`.
    ///
    /// The Relay Server acts as a "matchmaker" or "hop" node, allowing two
    /// peers to communicate when both are behind restrictive NATs. This handler
    /// primarily provides telemetry for monitoring the load and health of the
    /// relay service. In other words, its main function is logging.
    ///
    /// Under a "Direct Connection Utility for Traversal" (DCUtR) strategy, this
    /// relay should only be used briefly to coordinate a hole-punch. Long-lived
    /// circuits or high volumes of denied requests may indicate either a surge
    /// in private nodes or peers failing to establish direct connections.
    fn handle_relay_server_event(&mut self, event: libp2p::relay::Event) {
        match event {
            // A peer successfully reserved a sub-address.
            libp2p::relay::Event::ReservationReqAccepted { src_peer_id, .. } => {
                tracing::info!(peer = %src_peer_id, "Accepted relay reservation.");
            }

            // A peer tried to reserve, but hit the `max_reservations` limit.
            libp2p::relay::Event::ReservationReqDenied { src_peer_id, .. } => {
                tracing::warn!(peer = %src_peer_id, "Denied relay reservation (limit reached).");
            }

            // A circuit (data pipe) was actually opened between two peers.
            libp2p::relay::Event::CircuitReqAccepted {
                src_peer_id,
                dst_peer_id,
            } => {
                tracing::info!(
                    from = %src_peer_id,
                    to = %dst_peer_id,
                    "Relay circuit established."
                );
            }

            // The data pipe was closed.
            libp2p::relay::Event::CircuitClosed {
                src_peer_id,
                dst_peer_id,
                error,
            } => {
                if let Some(e) = error {
                    tracing::debug!(from = %src_peer_id, to = %dst_peer_id, "Relay circuit closed with error: {:?}.", e);
                } else {
                    tracing::debug!(from = %src_peer_id, to = %dst_peer_id, "Relay circuit closed gracefully.");
                }
            }

            // Denied a circuit request (e.g., too many active pipes).
            libp2p::relay::Event::CircuitReqDenied {
                src_peer_id,
                dst_peer_id,
                ..
            } => {
                tracing::warn!(from = %src_peer_id, to = %dst_peer_id, "Denied relay circuit request.");
            }

            // Other events are not important enough to log.
            _ => {}
        }
    }

    /// Handles events emitted by the Relay Client behavior.
    ///
    /// This handler tracks the status of our reservations (proxy addresses) on
    /// remote relay nodes. Successful reservations allow this node to be
    /// reachable via a `/p2p-circuit` address, which is essential for inbound
    /// connectivity when behind a NAT.
    ///
    /// Note: Failures to initiate or maintain a reservation are often reported
    /// as `SwarmEvent::ListenerClosed` or `SwarmEvent::ListenerError` rather
    /// than through this behavior-specific handler, as relay reservations are
    /// managed as swarm listeners.
    fn handle_relay_client_event(&mut self, event: libp2p::relay::client::Event) {
        match event {
            libp2p::relay::client::Event::ReservationReqAccepted { relay_peer_id, .. } => {
                let eighty_percent = Self::RELAY_RESERVATION_DURATION * 8 / 10;
                let eighty_percent_in = SystemTime::now() + eighty_percent;
                self.relays.entry(relay_peer_id).and_modify(|status| {
                    status.activate();
                });

                tracing::info!(
                    peer = %relay_peer_id,
                    "Relay reservation accepted; renewal scheduled in {:?}",
                    eighty_percent_in
                );
            }
            libp2p::relay::client::Event::OutboundCircuitEstablished { relay_peer_id, .. } => {
                tracing::debug!(relay = %relay_peer_id, "Outbound relayed connection established.");
            }
            libp2p::relay::client::Event::InboundCircuitEstablished { src_peer_id, .. } => {
                tracing::debug!(relay = %src_peer_id, "Inbound relayed connection established.");
            }
        }
    }

    /// Handles events from the DCUtR (Direct Connection Upgrade through Relay)
    /// behavior.
    ///
    /// DCUtR coordinates with remote peers to "upgrade" an existing relayed
    /// connection into a direct one. It works by using the relay connection as
    /// a signaling channel to synchronize a simultaneous outbound dial (TCP
    /// hole punch) from both ends.
    ///
    /// When the result is [Ok], a new direct connection has been established.
    /// The swarm automatically prioritizes this direct connection for future
    /// traffic, though the relayed connection may remain open as a fallback.
    fn handle_dcutr_event(&mut self, event: libp2p::dcutr::Event) {
        let libp2p::dcutr::Event {
            remote_peer_id,
            result,
        } = event;

        match result {
            Ok(_connection_id) => {
                tracing::info!(
                    peer_id = %remote_peer_id,
                    "Hole punch succeeded \\o/ - Connection is now direct."
                );
            }
            Err(e) => {
                // Failure is logged at 'warn' or 'debug' level. In many
                // environments, hole punching is expected to fail (e.g.,
                // Symmetric NATs), in which case the node simply continues
                // using the relay.
                tracing::warn!(
                    peer_id = %remote_peer_id,
                    "Hole punch failed: {e}. Remaining on relayed connection."
                );
            }
        }
    }

    /// Handles events from the Kademlia Distributed Hash Table (DHT).
    ///
    /// Kademlia is the "proactive" discovery engine that allows the network to
    /// scale. It operates on a "one-hop-removed" logic: instead of knowing
    /// every peer, our node knows a few neighbors who act as leads to find
    /// others.
    ///
    /// ## Mechanics
    ///
    /// ### 1. The Pulse (Network Visibility)
    ///
    /// Instead of looking for a specific node, we monitor these events to
    /// ensure we are successfully "plugged in" to the global network map.
    ///
    /// * **The Pulse**: Every `RoutingUpdated` event is a sign that our node is
    ///   becoming a "well-connected hub." The more peers we have in our
    ///   k-buckets, the better we can help *other* nodes find what they are
    ///   looking for.
    ///
    /// ### 2. The Bridge (Contributing to Health)
    ///
    /// We contribute to network health by sharing what we know.
    ///
    /// By adding peers from `Identify` into Kademlia, we aren't just helping
    /// ourselves; we are making those peers discoverable to the rest of the
    /// Neptune Cash network through our own routing table.
    ///
    /// ### 3. The One-Hop Crawl (Proactive Discovery)
    ///
    /// Since we aren't looking for a specific node, the "Bootstrap" query acts
    /// as a **Network Crawl**.
    ///
    /// As the crawl progresses, our node "bubbles up" in the routing tables of
    /// others, increasing our own connectivity.
    fn handle_kademlia_event(&mut self, event: libp2p::kad::Event) {
        match event {
            // The pulse: routing table grows.
            libp2p::kad::Event::RoutingUpdated {
                peer, is_new_peer, ..
            } => {
                if is_new_peer {
                    tracing::info!(peer_id = %peer, "DHT: New peer discovered and added to buckets. Running Kademlia bootstrap.");
                    // We perform the debug crawl in a separate block
                    {
                        let kad = &mut self.swarm.behaviour_mut().kademlia;
                        let mut peer_count = 0;
                        for bucket in kad.kbuckets() {
                            for _entry in bucket.iter() {
                                peer_count += 1;
                            }
                        }
                        tracing::info!("DEBUG: Kademlia Routing Table size: {}", peer_count);
                    }
                    let random_peer = PeerId::random();
                    self.swarm
                        .behaviour_mut()
                        .kademlia
                        .get_closest_peers(random_peer);
                } else {
                    tracing::info!(peer_id = %peer, "DHT: new addresses found for existing peer.");
                }
            }

            // The crawl: this event fires as the "one-hop" recursive search
            // progresses. Each triggered event corresponds to one hop.
            libp2p::kad::Event::OutboundQueryProgressed {
                result: libp2p::kad::QueryResult::Bootstrap(Ok(status)),
                ..
            } => {
                tracing::info!(
                    remaining = status.num_remaining,
                    "Hop! DHT bootstrap in progress..."
                );
            }
            libp2p::kad::Event::OutboundQueryProgressed {
                result: libp2p::kad::QueryResult::Bootstrap(Err(e)),
                ..
            } => {
                tracing::info!("Boink! DHT bootstrap ran into error: {e}.");
            }
            _ => {}
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
        let Some((_timestamp, address)) = self.active_connections.get(&peer_id).cloned() else {
            return Err(ActorError::NoAddressForPeer(peer_id));
        };

        // Spawn the consensus peer loop with the hijacked stream.
        if let Some(loop_handle) =
            self.spawn_peer_loop(peer_id, address.clone(), handshake, stream, from_main_rx)
        {
            // Notify the rest of the application that a peer is ready.
            let _ = self
                .event_tx
                .send(NetworkEvent::NewPeerLoop { loop_handle })
                .await;
        }

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
                let status = match new.clone() {
                    libp2p::autonat::NatStatus::Public(multiaddr) => {
                        format!("Public({})", multiaddr)
                    }

                    // Lost public status.
                    libp2p::autonat::NatStatus::Private => {
                        // Be a responsible node and clear external addresses so
                        // we don't lead peers into a "dial timeout" trap.
                        // Since we can't call 'clear_all' on an iterator, we
                        // iterate over current external addresses.
                        let mut to_remove = Vec::new();
                        for addr in self.swarm.external_addresses() {
                            to_remove.push(addr.clone());
                        }
                        for addr in to_remove {
                            self.swarm.remove_external_address(&addr);
                        }

                        "Private".to_string()
                    }
                    libp2p::autonat::NatStatus::Unknown => "Unknown".to_string(),
                };
                tracing::info!("New NAT status: {status}");

                // Do something (besides logging messages).
                // (And no we cannot integrate this match statement into the
                // match statement above because then the order of the log
                // messages will make no sense.)
                match new {
                    libp2p::autonat::NatStatus::Public(multiaddr) => {
                        // Tell the Swarm to announce this address in future
                        // Identify handshakes.
                        self.swarm.add_external_address(multiaddr.clone());

                        // If we were using proxy addresses, clean them up.
                        self.cleanup_relays();

                        // Set Kademlia mode to server.
                        self.swarm
                            .behaviour_mut()
                            .kademlia
                            .set_mode(Some(libp2p::kad::Mode::Server));
                    }
                    libp2p::autonat::NatStatus::Private => {
                        // If we have external addresses, request for relays.
                        if self.swarm.external_addresses().count() > 0 {
                            self.request_peer_relays(3);
                        } else {
                            tracing::debug!("AutoNAT says Private, but waiting for Identify/UPnP to confirm an external address before requesting relay.");
                        }

                        // Set Kademlia mode to client.
                        self.swarm
                            .behaviour_mut()
                            .kademlia
                            .set_mode(Some(libp2p::kad::Mode::Client));
                    }
                    libp2p::autonat::NatStatus::Unknown => {}
                }
            }
        }
    }

    /// Handle events from the UPnP (Universal Plug and Play) behavior.
    ///
    /// UPnP proactively attempts to map local ports to external ones on the
    /// gateway (router). This is a "best-effort" protocol; success allows the
    /// node to become publicly reachable, while failure simply leaves the node
    /// in a 'Private' state, in which case it falls back to DCUtR (Hole
    /// Punching).
    ///
    /// # Protocol Interactions
    ///
    /// - **Identify**: New external addresses are automatically added to the
    ///   Swarm's address list and shared with peers via Identify.
    /// - **AutoNAT**: Will eventually dial these external addresses to verify
    ///   if the mapping actually allows inbound traffic.
    fn handle_upnp_event(&mut self, event: libp2p::upnp::Event) {
        match event {
            libp2p::upnp::Event::NewExternalAddr(addr) => {
                tracing::info!("UPnP: Successfully mapped a new external address: {addr}");
            }

            libp2p::upnp::Event::ExpiredExternalAddr(addr) => {
                tracing::debug!("UPnP: External mapping for {addr} has expired or was removed.");
            }

            libp2p::upnp::Event::GatewayNotFound => {
                tracing::debug!("UPnP: No UPnP-enabled gateway found on the local network.");
            }

            libp2p::upnp::Event::NonRoutableGateway => {
                tracing::warn!("UPnP: The gateway is not exposed to the public network.");
            }
        }
    }

    /// Handle events from the Ping behavior.
    ///
    /// Log round-trip time at debug level and failures at warn level.
    fn handle_ping_event(&mut self, event: libp2p::ping::Event) {
        match event.result {
            Ok(duration) => {
                tracing::debug!("Ping: RTT to {} is {:?}", event.peer, duration);
            }
            Err(e) => {
                tracing::warn!("Ping: Failure with peer {}: {:?}", event.peer, e);
                // libp2p-ping automatically handles connection closure if
                // 'max_failures' is reached.
            }
        }
    }

    /// Handle messages (commands) from the Main Loop.
    ///
    /// # Return Value
    ///
    ///  - `Err(_)`` if something went wrong badly enough to warrant the
    ///    application (or at least the libp2p NetworkActor) to shut down
    ///    immediately.
    ///  - `Ok(Self::KEEP_ALIVE)` to keep the event loop running.
    ///  - `Ok(!Self::KEEP_ALIVE)` to gracefully shut down the event loop.
    #[allow(
        clippy::unnecessary_wraps,
        reason = "function signature anticipates more complex, fallible commands"
    )]
    async fn handle_command(&mut self, command: NetworkActorCommand) -> Result<bool, ActorError> {
        match command {
            NetworkActorCommand::Dial(addr) => {
                tracing::info!("Manual dial requested for address: {}", addr);

                // If the peer was banned as a result of poor standing, then the
                // Dial overturns that ban. If the peer is banned as a result of
                // a `--ban <IP>` CLI argument, that ban stands.
                if let Some(ip_addr) = addr.iter().find_map(|protocol| match protocol {
                    libp2p::multiaddr::Protocol::Ip4(ipv4_addr) => Some(IpAddr::V4(ipv4_addr)),
                    libp2p::multiaddr::Protocol::Ip6(ipv6_addr) => Some(IpAddr::V6(ipv6_addr)),
                    _ => None,
                }) {
                    if let Some(timestamp) = self.black_list.list.remove(&ip_addr) {
                        tracing::info!(%ip_addr, "Dialed peer was banned until {:?}; now unbanned.", timestamp);

                        // The main loop must not forget to boost the peer's
                        // standing, or they will not be able to set up a
                        // Gateway / peer loop connection. However, this boost
                        // is the main loop's responsibility and should be done
                        // in conjunction with issuing the `Dial` command.
                    }
                }

                // If we are already at max capacity in terms of number of
                // peers, then we disconnect from the peer whose connection is
                // oldest.
                if self.active_connections.len() >= self.max_num_peers {
                    tracing::info!(
                        "At connection capacity ({}). Evicting a peer for manual dial.",
                        self.max_num_peers
                    );

                    self.disconnect_from_longest_lived_peer();
                }

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

            NetworkActorCommand::Ban(malicious_peer) => {
                let mut bannable_ips = HashSet::new();

                match malicious_peer {
                    itertools::Either::Left(malicious_peer_id) => {
                        // Extract IPs
                        let active_connection_address = self
                            .active_connections
                            .get(&malicious_peer_id)
                            .cloned()
                            .into_iter()
                            .map(|(_ts, ad)| ad);
                        let address_book_addresses = self
                            .address_book
                            .get(&malicious_peer_id)
                            .into_iter()
                            .flat_map(|peer| peer.listen_addresses.clone());
                        for address in active_connection_address.chain(address_book_addresses) {
                            if let Some(ip) = address.iter().find_map(|protocol| match protocol {
                                libp2p::multiaddr::Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
                                libp2p::multiaddr::Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
                                _ => None,
                            }) {
                                bannable_ips.insert(ip);
                            }
                        }

                        // Disconnect
                        let _ = self.swarm.disconnect_peer_id(malicious_peer_id);
                    }
                    itertools::Either::Right(ip_addr) => {
                        bannable_ips.insert(ip_addr);
                    }
                }

                // Hammer
                if bannable_ips.is_empty() {
                    tracing::warn!("Could not ban peer because no IP addresses for it are known.");
                } else {
                    tracing::info!("Banning IP addresses [{}].", bannable_ips.iter().join(", "));
                    for ip in bannable_ips {
                        self.black_list.ban(ip);
                    }
                }
            }

            NetworkActorCommand::Unban(ip_addr) => {
                if !self.black_list.unban(&ip_addr) {
                    tracing::warn!("Unbanned IP address {ip_addr} was not in black list.");
                }
            }

            NetworkActorCommand::UnbanAll => {
                let keys = self.black_list.list.keys().copied().collect_vec();
                for entry in keys {
                    self.black_list.unban(&entry);
                }
            }

            NetworkActorCommand::Shutdown => {
                tracing::info!("Network Actor shutting down Swarm...");

                // Trigger UPnP DeletePortMapping
                // By explicitly removing these listeners, we trigger the UPnP
                // behavior to send 'DeletePortMapping' requests to
                // gateways/routers, ensuring ports don't remain "ghosted" after
                // exit.
                for id in &self.active_listeners {
                    let _ = self.swarm.remove_listener(*id);
                }

                // Give the UPnP behavior one 'tick' to process the removal
                // and send the network packets.
                tokio::task::yield_now().await;

                // Disable peer discovery: put Kademlia into client mode.
                self.swarm
                    .behaviour_mut()
                    .kademlia
                    .set_mode(Some(libp2p::kad::Mode::Client));

                // Set max num peers to zero. Any incoming connection attempts
                // will now be 'Denied'.
                self.max_num_peers = 0;

                // Save the address book.
                if let Err(e) = self.address_book.save_to_disk() {
                    tracing::warn!("Failed to persist address book: {e}.");
                }

                // Save the black list.
                if let Err(e) = self.black_list.save_to_disk() {
                    tracing::warn!("Failed to persist black list: {e}.")
                }

                // Break connections.
                let peers = self.swarm.connected_peers().copied().collect_vec();
                for peer_id in peers {
                    // Send 'FIN' or 'CLOSE_FRAME': "I'm leaving, don't try to
                    // dial me back."
                    let _ = self.swarm.disconnect_peer_id(peer_id);
                }

                // Wait 2 seconds to flush frames, clear buffers, update
                // counters, etc.
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

                // Do not touch the peer loops here, just stop the Actor's own
                // loop.
                return Ok(!Self::KEEP_ALIVE);
            }
            NetworkActorCommand::ProbeNat => {
                tracing::info!("Triggering NAT probe...");
                // Call `autonat.probe_address` with a good guess at our own
                // public address. Where to get that good guess from?
                //  1. external addresses confirmed by the swarm;
                //  2. listen addresses,
                //  3. localhost. (This last one is obviously not publicly
                //     reachable but the point is to trigger the `prove_address`
                //     logic.)
                let mut addresses: Vec<Multiaddr> =
                    self.swarm.external_addresses().cloned().collect();
                if addresses.is_empty() {
                    addresses = self.swarm.listeners().cloned().collect();
                }
                if addresses.is_empty() {
                    tracing::warn!(
                        "No listeners or external addresses found. Using fallback loopback."
                    );
                    if let Ok(fallback) = "/ip4/127.0.0.1/tcp/0".parse::<Multiaddr>() {
                        addresses.push(fallback);
                    }
                }

                // If we do have more than one good guess at our own public
                // address, then probe all of them.
                for addr in addresses {
                    // This tells AutoNAT: "I think these are my public
                    // addresses. Please ask a random server to try and dial me
                    // here."
                    self.swarm.behaviour_mut().autonat.probe_address(addr);
                }
            }
            NetworkActorCommand::ResetRelayReservations => {
                tracing::info!("Resetting relay reservations ...");

                for (peer_id, status) in self.relays.drain() {
                    tracing::debug!(%peer_id, "Evicting relay to force re-reservation.");
                    if let Some(listener_id) = status.listener_id() {
                        self.swarm.remove_listener(listener_id);
                    }
                    let _ = self.swarm.disconnect_peer_id(peer_id);
                    self.active_connections.remove(&peer_id);
                }
            }
            NetworkActorCommand::GetNetworkOverview(channel) => {
                tracing::debug!("Assembling network overview ...");
                let overview = self.assemble_overview();
                if channel.send(overview).is_err() {
                    tracing::error!("Cannot send NetworkOverview from NetworkActor over one-shot.");
                }
            }
        }

        Ok(Self::KEEP_ALIVE)
    }

    /// Closes all active relay listeners and clears the relay tracking state.
    ///
    /// This should be called when the node's NAT status transitions to
    /// `Public`, as maintaining relay reservations is unnecessary and consumes
    /// resources on both this node and the remote relay servers.
    fn cleanup_relays(&mut self) {
        tracing::info!("Cleaning up relay reservations.");

        for (_peer_id, status) in self.relays.drain() {
            if let Some(listener_id) = status.listener_id() {
                if self.swarm.remove_listener(listener_id) {
                    tracing::debug!(?listener_id, "Closed relay listener.");
                }
            }
        }
    }

    /// Monitors active relay reservations.
    ///
    /// Triggers renewals for those relays nearing expiration, and re-launches
    /// relays to replace those that were closed abruptly.
    ///
    /// This function compares the timestamp calculated at the time the
    /// reservation is accepted against the current system time. If a
    /// reservation has passed the 80% mark, it is removed from the relay
    /// set.
    ///
    /// The closed relays, whose closure timestamps exceed now by more than the
    /// cooldown period, are counted and removed from the relay set.
    ///
    /// Finally [Self::request_peer_relays] is called to secure replacement
    /// reservation for all duly and abruptly closed reservations.
    ///
    /// By refreshing slightly before the actual expiration, the node remains
    /// reachable throughout (under normal conditions).
    fn check_relays_reservations(&mut self) {
        if self.relays.is_empty() {
            return;
        }

        // Collect and remove about-to-expire relays.
        let now = SystemTime::now();
        let expired_relays = self
            .relays
            .iter()
            .filter_map(|(peer_id, status)| match status {
                RelayStatus::Active(timestamp, _listener_id) => {
                    let eighty_percent = Self::RELAY_RESERVATION_DURATION * 8 / 10;
                    let eighty_percent_mark = *timestamp + eighty_percent;
                    if now.duration_since(eighty_percent_mark).is_ok() {
                        Some(*peer_id)
                    } else {
                        None
                    }
                }
                _ => None,
            })
            .collect_vec();
        let num_expired_relays = expired_relays.len();
        for expiry in expired_relays {
            // If the relay is about to expire, we remove it from the map
            // pro-actively. As a result, when it does expire, no match is
            // found, and no substitute is produced.
            self.relays.remove(&expiry);
        }

        // Collect and remove (abruptly) closed relays.
        let closed_relays = self
            .relays
            .iter()
            .filter_map(|(peer_id, status)| match status {
                RelayStatus::Closed(timestamp) => {
                    let cooldown_end = *timestamp + Self::RELAY_COOLDOWN_PERIOD;
                    if now.duration_since(cooldown_end).is_ok() {
                        Some(*peer_id)
                    } else {
                        None
                    }
                }
                _ => None,
            })
            .collect_vec();
        let num_closed_relays = closed_relays.len();
        for closure in closed_relays {
            self.relays.remove(&closure);
        }

        // Request new relays to replace about-to-expire and closed relays.
        tracing::info!("Requesting relays to replace {num_expired_relays} expired relays and {num_closed_relays} abruptly closed ones.");
        self.request_peer_relays(num_expired_relays + num_closed_relays);
    }

    /// Make a random selection of k peers from the set of active connections
    /// that are not already serving as relays, and ask them to relay for us.
    ///
    /// This function may ask fewer peers than the supplied argument, for
    /// instance if there are not enough active connections without on-going
    /// relay commitments.
    fn request_peer_relays(&mut self, num_relays: usize) {
        // Delay requesting relay reservations until we have at least one
        // confirmed external address.
        if self.swarm.external_addresses().next().is_none() {
            tracing::debug!("Skipping relay reservation: No confirmed external addresses yet.");
            return;
        }

        let current_relays = self.relays.keys().collect::<HashSet<_>>();
        let mut available_peers = self
            .active_connections
            .keys()
            .filter(|p| !current_relays.contains(p))
            .collect_vec();
        let mut rng = rand::rng().clone();
        available_peers.shuffle(&mut rng);

        let mut counter = 0;
        for &peer_id in available_peers {
            let Some((_timestamp, addr)) = self.active_connections.get(&peer_id).cloned() else {
                continue;
            };

            // Skip addresses that already contain a p2p-circuit.
            if addr
                .iter()
                .any(|p| matches!(p, libp2p::multiaddr::Protocol::P2pCircuit))
            {
                continue;
            }

            tracing::info!(%peer_id, "Attempting relay reservation at {}", addr);

            // Construct the circuit address.
            // Format: /ip4/RELAY_IP/tcp/PORT/p2p/RELAY_ID/p2p-circuit
            let circuit_addr = addr
                .clone()
                .with(libp2p::multiaddr::Protocol::P2p(peer_id))
                .with(libp2p::multiaddr::Protocol::P2pCircuit);

            tracing::info!(%peer_id, "Attempting relay reservation by listening on {}.", circuit_addr);

            // Listen on the circuit address. This activity triggers the
            // reservation, so catch and record the listener id. We will catch
            // the matching success event (`ReservationReqAccepted`) to activate
            // the relay with an accurate timestamp at that time.
            match self.swarm.listen_on(circuit_addr) {
                Ok(listener_id) => {
                    self.relays
                        .insert(peer_id, RelayStatus::Waiting(listener_id));

                    counter += 1;
                    if counter >= num_relays {
                        break;
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to initiate relay reservation: {:?}", e);
                }
            };
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
    ) -> Option<JoinHandle<()>> {
        // Counts the number of hops between the node and peers it is connected
        // to. We probably don't need this for the libp2p wrapper.
        const DISTANCE_TO_CONNECTED_PEER: u8 = 1u8;

        // Keep track of which peers get upgraded connections. Prevent same
        // peer from getting upgraded multiple times.
        {
            let mut upgraded_peers = self.upgraded_peers.lock().unwrap();
            if upgraded_peers.contains(&peer_id) {
                tracing::info!(
                    "Aborting connection upgrade because this peer was already upgraded."
                );
                return None;
            }
            upgraded_peers.insert(peer_id);
        }

        tracing::info!("Spawning peer loop from libp2p network actor");

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

        let upgraded = self.upgraded_peers.clone();
        Some(tokio::spawn(async move {
            // Because 'peer_stream' implements Sink + Stream + Unpin,
            // and we have the broadcast receiver, this just works.
            peer_loop_handler
                .run_wrapper(peer_stream, from_main_rx)
                .await
                .unwrap_or_else(|e| {
                    tracing::warn!(peer = %peer_id, "Peer loop exited with error: {e}");
                });

            // Remove the PeerId from the set of upgraded peers.
            {
                let mut upgraded_peers = upgraded
                    .lock()
                    .expect("We do not hold the lock ever over something that can panic.");
                let was_present = upgraded_peers.remove(&peer_id);
                assert!(was_present, "Peer ID must be present in upgraded set.");
            }
        }))
    }

    /// Determines if a connection is direct or proxied via a relay.
    ///
    /// Neptune Cash disallows application-level protocol negotiation (the
    /// `StreamGateway`) over relayed connections for three reasons:
    ///  1. to prevent resource exhaustion on relay nodes;
    ///  2. to ensure optimal synchronization latency;
    ///  3. to ban malicious peers directly rather than banning their proxies.
    ///
    /// # Arguments
    ///
    ///  * `address` - The [`Multiaddr`](libp2p::swarm) of the peer.
    ///
    /// # Return Value
    ///
    ///  * `true` if the connection is direct (e.g., `/ip4/.../tcp/...` or `/udp/.../quic-v1`).
    ///  * `false` if the connection is relayed (contains `/p2p-circuit`).
    ///
    /// ### Why this is used instead of raw `!is_relayed()`:
    ///
    /// Neptune-Cash has a strict policy of disallowing application-level protocol
    /// negotiation (the `StreamGateway`) over relayed connections. This prevents
    /// high-bandwidth consensus and synchronization traffic from burdening public
    /// relay nodes and ensures optimal peer latency.
    ///
    /// By using this named helper, we make the intent of the "Direct-Only"
    /// policy explicit in the call site logic.
    pub(crate) fn is_direct(address: &libp2p::Multiaddr) -> bool {
        // A connection is relayed if any part of its address path
        // includes the 'p2p-circuit' protocol.
        !address
            .iter()
            .any(|p| matches!(p, libp2p::multiaddr::Protocol::P2pCircuit))
    }

    /// Disconnect from the longest-lived peer in the network.
    ///
    /// This method identifies the peer that has been connected for the greatest
    /// amount of time based on its entry in `active_connections`. It then
    /// requests the [`Swarm`](libp2p::Swarm) to terminate that connection and
    /// immediately removes the peer from the internal tracking map.
    ///
    /// # Behavior
    ///
    /// - If multiple peers have the exact same connection time, one is chosen
    ///   arbitrarily.
    /// - If no peers are currently connected, this method does nothing.
    /// - The peer is removed from `active_connections` even if the
    ///   [Swarm](libp2p::Swarm) fails to perform the physical disconnect (e.g.,
    ///   if the peer just disconnected).
    fn disconnect_from_longest_lived_peer(&mut self) {
        let oldest_peer = self
            .active_connections
            .iter()
            .min_by_key(|(_peer_id, (connected_at, _addr))| *connected_at)
            .map(|(peer_id, _)| *peer_id);

        if let Some(peer_id) = oldest_peer {
            tracing::info!(%peer_id, "Disconnecting from longest-lived peer.");

            // Signal the swarm to drop the connection
            if self.swarm.disconnect_peer_id(peer_id).is_err() {
                tracing::warn!(%peer_id, "Attempted to disconnect peer, but it was already gone.");
            }

            // We remove it from our map immediately so the count is
            // accurate for any dial logic happening in the same tick.
            self.active_connections.remove(&peer_id);
        } else {
            tracing::debug!("No peers available to disconnect from.");
        }
    }

    /// Collects a point-in-time snapshot of the node's network stack.
    ///
    /// This method aggregates data from the internal Swarm behaviors (AutoNAT,
    /// Relay), the standard libp2p address observation, and the
    /// [`NetworkActor`]'s manual connection tracking to provide a comprehensive
    /// view of current connectivity.
    ///
    /// This is intended for use by dashboard UIs, CLI status commands, or
    /// health-check diagnostics.
    pub(crate) fn assemble_overview(&self) -> NetworkOverview {
        let nat_status = self.swarm.behaviour().autonat.nat_status();
        let external_addresses = self.swarm.external_addresses().cloned().collect();
        let num_active_relays = self.relays.len();
        let address_book_size = self.address_book.len();
        let num_banned_peers = self.black_list.list.len();

        NetworkOverview {
            peer_id: *self.swarm.local_peer_id(),
            nat_status,
            external_addresses,

            connection_count: self.active_connections.len(),
            connection_limit: self.max_num_peers,

            num_active_relays,

            address_book_size,
            num_banned_peers,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ActorError {
    #[error("Network channel closed unexpectedly")]
    ChannelClosed,

    #[error("No address found for peer {0} in address map")]
    NoAddressForPeer(PeerId),
}
