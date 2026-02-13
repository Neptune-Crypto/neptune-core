use std::net::IpAddr;

use clap::Parser;
use libp2p::Multiaddr;

/// Network Command -- a command related to the peer-to-peer or networking
/// layers.
#[derive(Debug, Clone, Parser)]
pub(crate) enum NetworkCommand {
    /// retrieve address for peers to contact this neptune-core node
    OwnListenAddressForPeers,

    /// retrieve instance-id of this neptune-core node
    OwnInstanceId,

    /// Clear all peer standings.
    ///
    /// This is a legacy command that applies to the peer loop logic only. So in
    /// particular, any peers banned at the modern libp2p-level will remain
    /// banned. For the modern equivalent, use the command `unban --all` (which
    /// also clears all standings at the peer loop logic level).
    ClearAllStandings,

    /// Clear standing for peer with a given IP.
    ///
    /// This is a legacy command that applies to the peer loop logic only. So in
    /// particular, if the peer is banned at the modern libp2p-level, that ban
    /// will remain in effect. For the modern equivalent, use the command
    /// `unban` (which also clears the peer's standing at the peer loop logic
    /// level).
    ClearStandingByIp { ip: IpAddr },

    /// Ban one or more peers by address.
    Ban {
        /// The Multiaddrs to ban (e.g., /ip4/1.2.3.4/tcp/8080)
        #[arg(required = true, num_args = 1..)]
        addresses: Vec<Multiaddr>,
    },

    /// Unban one or more peers.
    Unban {
        /// The Multiaddrs to unban
        #[arg(num_args = 0..)]
        addresses: Vec<Multiaddr>,

        /// Clear the entire blacklist
        #[arg(short, long, conflicts_with = "addresses")]
        all: bool,
    },

    /// Dial the given address.
    ///
    /// In other words, attempt to initiate a connection to it.
    Dial {
        #[arg(required = true)]
        address: Multiaddr,
    },

    /// Manually trigger a NAT status probe.
    ///
    /// Neptune nodes use AutoNAT to determine if they are publicly reachable.
    /// Run this if you have recently changed your router settings or
    /// port-forwarding and want the node to update its reachability status
    /// immediately.
    ProbeNat,

    /// Reset all active relay reservations.
    ///
    /// If your node is not publicly reachable and relies on libp2p relays,
    /// this command will drop current relay connections and attempt to
    /// re-reserve slots. This can help resolve "No Relay Circuit" errors
    /// without restarting the entire node.
    ResetRelayReservations,

    /// Show a brief overview of network vitals.
    NetworkOverview,

    /// retrieve info about peers
    PeerInfo,

    /// retrieve list of punished peers
    AllPunishedPeers,
}
