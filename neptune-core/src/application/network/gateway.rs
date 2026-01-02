use std::collections::VecDeque;
use std::task::Context;
use std::task::Poll;

use libp2p::core::transport::PortUse;
use libp2p::swarm::handler::ConnectionEvent;
use libp2p::swarm::handler::ConnectionHandlerEvent;
use libp2p::swarm::handler::FullyNegotiatedInbound;
use libp2p::swarm::ConnectionHandler;
use libp2p::swarm::ConnectionId;
use libp2p::swarm::NetworkBehaviour;
use libp2p::swarm::SubstreamProtocol;
use libp2p::swarm::THandler;
use libp2p::swarm::THandlerInEvent;
use libp2p::swarm::THandlerOutEvent;
use libp2p::swarm::ToSwarm;
use libp2p::Multiaddr;
use libp2p::PeerId;

use crate::application::network::handshake::HandshakeResult;
use crate::application::network::handshake::HandshakeUpgrade;
use crate::protocol::peer::handshake_data::HandshakeData;
use crate::state::GlobalStateLock;

/// Manages the lifecycle of one specific connection.
///
/// The [`GatewayHandler`]'s primary job is to:
///
///  1. **Enforce the Handshake.**
///     It tells libp2p, "Before this peer can do anything else, they must pass
///     the HandshakeUpgrade test."
///  2. **Buffer Results.**
///     It catches the HandshakeData and the Stream once the upgrade finishes
///     and holds them until the "Brain" (the Behaviour) is ready to see them.
///
/// The [`GatewayHandler`] facilitates separation between the Behaviour (fast
/// logic) and network (slow IO) layers. By running in its own background task,
/// a slow or lagging handshake only affects this specific connection,
/// rather than the entire node's network throughput.
///
/// Lifecycle:
/// The [`Swarm`](libp2p::Swarm) manages it automatically through a series of
/// trigger points:
///
///  1. **Instantiation**: When a connection is established, the
///     [`StreamGateway`] (Behaviour) creates a new [`GatewayHandler`].
///  2. **Negotiation**: The [`Swarm`](libp2p::Swarm) uses
///     [`listen_protocol()`](Self::listen_protocol()) to determine the
///     protocol "Rulebook" ([`HandshakeUpgrade`]).
///  3. **Completion**: Once the handshake is finished, the
///     [`Swarm`](libp2p::Swarm) hands the result back to the handler via
///     [`on_connection_event()`](Self::on_connection_event()).
///  4. **Reporting**: The handler's [`poll()`](Self::poll()) method is
///     continuously invoked to push the result up to the Behaviour.
pub(crate) struct GatewayHandler {
    /// Our node's side of the handshake-exchange.
    pub(crate) local_handshake: HandshakeData,

    /// Queue of events to send up to the Behaviour.
    pending_events: VecDeque<ConnectionHandlerEvent<HandshakeUpgrade, (), HandshakeResult>>,
}

impl ConnectionHandler for GatewayHandler {
    // Not relevant for a 'one-shot' handshake that requires no external
    // commands, no state tracking for multiple streams, and no extra metadata.
    type FromBehaviour = ();
    type InboundOpenInfo = ();
    type OutboundOpenInfo = ();

    /// The "Package" we send up the stack (Handshake + Stream).
    type ToBehaviour = HandshakeResult;

    /// The "Rulebook" for when someone calls us.
    type InboundProtocol = HandshakeUpgrade;

    /// The "Rulebook" for when we call someone else.
    type OutboundProtocol = HandshakeUpgrade;

    /// Return the protocol negotiation logic for inbound substreams.
    ///
    /// This is the "Entry Gate":
    ///  - Someone else is calling us (Inbound).
    ///  - We agree on a language (Negotiation).
    ///  - we hand over the "Rulebook" (The HandshakeUpgrade).
    ///
    /// By returning `HandshakeUpgrade` here, we force the remote peer to
    /// complete the handshake before the stream is handed to the Actor.
    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol, Self::InboundOpenInfo> {
        SubstreamProtocol::new(
            HandshakeUpgrade {
                local_handshake: self.local_handshake,
            },
            (),
        )
    }

    /// Handle commands sent from the NetworkBehaviour to this connection
    /// handler.
    ///
    /// This method is currently a no-op because the StreamGateway does not
    /// send control signals to established connections. Once a stream is
    /// hijacked, all communication happens within the inner event loop,
    /// bypassing the libp2p handler entirely. Phrased succinctly: the event
    /// loop does not take orders from libp2p.
    fn on_behaviour_event(&mut self, _event: Self::FromBehaviour) {
        // No action required.
    }

    /// Handle successful protocol negotiations or connection failures.
    ///
    /// This method is the "Catcher" for the results produced by the Upgrade.
    /// When a handshake completes successfully, we extract the peer's handshake
    /// and the raw stream, then queue them to be sent up to the
    /// NetworkBehaviour.
    fn on_connection_event(
        &mut self,
        event: ConnectionEvent<
            Self::InboundProtocol,
            Self::OutboundProtocol,
            Self::InboundOpenInfo,
            Self::OutboundOpenInfo,
        >,
    ) {
        match event {
            // Inbound success
            ConnectionEvent::FullyNegotiatedInbound(FullyNegotiatedInbound {
                protocol, ..
            }) => {
                let (handshake, stream) = protocol;

                // We move the result into the queue so 'poll' can find it.
                self.pending_events
                    .push_back(ConnectionHandlerEvent::NotifyBehaviour(
                        HandshakeResult::Success { handshake, stream },
                    ));
            }

            // Outbound success
            ConnectionEvent::FullyNegotiatedOutbound(
                libp2p::swarm::handler::FullyNegotiatedOutbound { protocol, .. },
            ) => {
                let (handshake, stream) = protocol;

                // We move the result into the queue so 'poll' can find it.
                self.pending_events
                    .push_back(ConnectionHandlerEvent::NotifyBehaviour(
                        HandshakeResult::Success { handshake, stream },
                    ));
            }

            // Log if the handshake failed during negotiation.
            ConnectionEvent::DialUpgradeError(error) => {
                tracing::error!("Outbound handshake failed: {:?}", error.error);
            }

            _ => {}
        }
    }

    /// Check if the protocol upgrade has finished and return the result.
    ///
    /// This method is called repeatedly by the Swarm. It doesn't perform the
    /// handshake itself; instead, it checks the `pending_events` queue to see
    /// if the background "Worker" (the HandshakeUpgrade) has finished.
    /// If a result is ready, it passes it up to the NetworkBehaviour.
    fn poll(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<
        ConnectionHandlerEvent<Self::OutboundProtocol, Self::OutboundOpenInfo, Self::ToBehaviour>,
    > {
        // We check our queue of events related to handshakes
        if let Some(event) = self.pending_events.pop_front() {
            // Poll::Ready(event) tells libp2p to deliver this
            // result to the Behaviour's 'on_connection_handler_event'.
            return Poll::Ready(event);
        }
        Poll::Pending
    }
}

/// Events emitted by the [`StreamGateway`] to the external Actor.
///
/// This enum acts as the final hand-off point between the libp2p network stack
/// and the application logic. When an event is emitted, it signifies that the
/// low-level networking and protocol handshakes are complete.
pub(crate) enum GatewayEvent {
    /// A connection has been fully established and the handshake verified.
    ///
    /// This variant is the "Green Light" for the Actor to take ownership of
    /// the stream and move it into a dedicated event loop.
    HandshakeReceived {
        /// The unique identity of the remote peer.
        peer_id: PeerId,
        /// The verified handshake sent by the peer.
        handshake: HandshakeData,
        /// The live, bidirectional stream ready for inner protocol messages.
        stream: libp2p::Stream,
    },
}

/// Coordinates the inner protocol's event loops across all active connections.
///
/// The [`StreamGateway`] is the central "Brain" of the portal between the
/// network stack and the inner protocol. Its primary responsibilities are:
///
/// 1. **Factory Service**: It creates a new [`GatewayHandler`] for every
///    inbound or outbound connection.
/// 2. **Event Routing**: It collects handshake results from individual handlers
///    and packages them into [`GatewayEvent`]s for the Actor.
/// 3. **Global State**: It maintains the handshake that must be shared with
///    every peer that connects.
///
/// This struct implements
/// [`NetworkBehaviour`](libp2p::swarm::NetworkBehaviour), allowing it to be
/// plugged directly into a libp2p [`Swarm`](libp2p::Swarm).
pub(crate) struct StreamGateway {
    // Used for getting the handshake data
    global_state: GlobalStateLock,

    events: VecDeque<ToSwarm<GatewayEvent, ()>>,
}

impl StreamGateway {
    pub fn new(global_state: GlobalStateLock) -> Self {
        Self {
            global_state,
            events: VecDeque::new(),
        }
    }

    /// Get the handshake data for authentication a peer connection.
    ///
    /// Fetch the handshake data from the global state, and wrap async logic
    /// in `spawn_blocking` so that this function can be called form synchronous
    /// code (such as the implementation of NetworkBehaviour below).
    fn handshake_data(&self) -> HandshakeData {
        self.global_state.get_own_handshakedata_sync()
    }
}

impl NetworkBehaviour for StreamGateway {
    type ConnectionHandler = GatewayHandler;
    type ToSwarm = GatewayEvent;

    /// Create a handler for a new inbound connection established by a remote
    /// peer.
    ///
    /// This is called automatically by the [`Swarm`](libp2p::Swarm) after the
    /// low-level transport (e.g., TCP/Noise) is secured. This function returns
    /// a [`GatewayHandler`] to initiate the Neptune-specific handshake.
    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, libp2p::swarm::ConnectionDenied> {
        Ok(GatewayHandler {
            local_handshake: self.handshake_data(),
            pending_events: VecDeque::new(),
        })
    }

    /// Create a handler for a new outbound connection dialed by our node.
    ///
    /// Like the inbound version, this method prepares a [`GatewayHandler`]
    /// to manage the handshake. Because handshakes are symmetric, we can use
    /// the same handler logic for both directions.
    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: PeerId,
        _addr: &Multiaddr,
        _endpoint: libp2p::core::Endpoint,
        _port_use: PortUse,
    ) -> Result<THandler<Self>, libp2p::swarm::ConnectionDenied> {
        Ok(GatewayHandler {
            local_handshake: self.handshake_data(),
            pending_events: VecDeque::new(),
        })
    }

    /// React to network events emitted by the [`Swarm`](libp2p::Swarm).
    ///
    /// In the case of the gateway, after handing over control to event loops,
    /// it would be moot to communicate the event to the event loop because the
    /// event loop is for high-level protocol events and makes abstraction of
    /// low-level network events.
    fn on_swarm_event(&mut self, _event: libp2p::swarm::FromSwarm) {}

    /// Receive and process results from a connection handler.
    ///
    /// This is the primary bridge between the background connection tasks
    /// and the main behaviour logic. When a [`GatewayHandler`] successfully
    /// completes a handshake, it sends the result here to be converted
    /// into a [`GatewayEvent`].
    fn on_connection_handler_event(
        &mut self,
        peer_id: PeerId,
        _connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        // Use match statement for future-proofing. Right now the enum has one
        // variant so we might as well use if-let; but when someone adds new
        // variants we want to force them to add a case here.
        match event {
            HandshakeResult::Success { handshake, stream } => {
                // This is the "Hijack" point.
                self.events
                    .push_back(ToSwarm::GenerateEvent(GatewayEvent::HandshakeReceived {
                        peer_id,
                        handshake,
                        stream,
                    }));
            } // If we later add a HandshakeResult::Failure, we handle it here
        }
    }

    /// Push pending gateway events up to the Swarm.
    ///
    /// This method is polled by the Swarm to check if any handshakes have
    /// finished. By returning `Poll::Ready`, we pass the verified stream
    /// and handshake data up to the Actor's main event loop.
    fn poll(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(event);
        }
        Poll::Pending
    }
}
