## Network Stack

### 1. Unified Peer Management: The Bridge Pattern

The integration of [`libp2p`](https://libp2p.io/) into Neptune-Cash was designed as a "bridge" rather than a total rewrite. This allowed the node to leverage modern transport protocols while retaining the battle-tested consensus logic found in the core peer loops.

#### The Peer Loop Abstraction

At the heart of Neptune Cash's communication is the **Peer Loop** (`PeerLoopHandler::run`), located in `neptune-core/src/application/loops/peer_loop.rs`. This loop is entirely protocol-agnostic; it manages the high-level application state, including block synchronization, mempool updates, and consensus messages. The peer loop has two lines of communication: one to the main loop within the same process and back, and one to and from its counterpart on the other side of an internet connection.

* **Logic Reuse:** The loop is wrapped in `run_wrapper`, which handles task initialization and graceful shutdown. This wrapper expects a generic asynchronous stream that has already been "primed" with a successful handshake.
* **The Seamless Handoff:** Because `run_wrapper` is generic, it does not know—nor does it need to know—whether it was spawned by the legacy TCP stack or the modern `libp2p` stack. Once a connection is established and the handshake is validated, the underlying stream is handed off to this loop to begin application-level processing.

#### Gateway to libp2p: The `StreamGateway` Subprotocol

To allow `libp2p` to interface with this existing loop, we implemented a custom subprotocol called **`StreamGateway`**.

1. **Handshake Validation:** When two `libp2p` peers connect, the `StreamGateway` subprotocol is negotiated. It exchanges and validates the standard Neptune `HandshakeData` (the same data structure used by the legacy stack).
2. **Stream Hijacking:** Once the handshake is verified, `libp2p` "hijacks" the substream. Instead of using standard `libp2p` message framing, the raw substream is fed directly into a spawned `run_wrapper` task.
3. **Protocol Evolution:** This architecture allows the `PeerMessage` enum—which defines our consensus and state replication protocol—to remain unchanged. While some messages (specifically those for legacy peer discovery) are redundant in the `libp2p` stack, the core consensus logic remains untouched.

#### Modern Identity and Addressing

Despite the reuse of the legacy loops, the influence of the `libp2p` stack is visible throughout the system's types:

* **Identification:** Peers are no longer identified by transient IP/Port combinations. Every peer is identified by a unique, cryptographic **`PeerId`**.
* **Addressing:** The system has moved away from `SocketAddr` in favor of **`Multiaddr`**. This allows the network stack to seamlessly handle TCP, QUIC, and Relay addresses using a single, future-proof format (e.g., `/ip4/1.2.3.4/udp/4001/quic-v1`).

| Component | Legacy Stack | libp2p Stack |
| --- | --- | --- |
| **Connection Logic** | `call_peer` / `answer_peer` | `StreamGateway` Subprotocol |
| **Addressing** | `SocketAddr` | `Multiaddr` |
| **Identity** | IP-based / Transient | `PeerId` (Cryptographic) |
| **Application Logic** | `PeerLoopHandler` | `PeerLoopHandler` (Reused) |

### 2. Transition and Deprecation Roadmap

The Neptune-Cash network is currently in a **Dual-Stack Phase**. We support both the legacy TCP stack and the `libp2p` stack simultaneously to ensure maximum reach and stability during the transition. However, the legacy stack is officially on a path toward deprecation and eventual removal.

#### Motivations for the [`libp2p`](https://libp2p.io/) Standard

Moving away from the custom TCP stack to `libp2p` provides several critical advantages for the Neptune-Cash ecosystem:

* **Transport Flexibility:** While the legacy stack is tethered to TCP, `libp2p` grants us native support for **UDP and QUIC**. QUIC, in particular, offers 1-RTT handshakes and eliminates head-of-line blocking, which is a massive performance boon for block propagation.
* **Native Encryption:** The legacy stack offers no transport-level encryption. `libp2p` provides transport-level encryption (via Noise or TLS) natively.
* **Advanced Networking Features:** `libp2p` comes with "off-the-shelf" modules for **Multiplexing** (Yamux), **Relaying** (Circuit Relay v2), and **Hole Punching** (DCUtR). Rebuilding these features in a custom TCP stack would be an enormous, error-prone undertaking.
* **Ecosystem Compatibility:** `libp2p` is the industry standard for decentralized networks, used by Ethereum, IPFS, Polkadot, and Filecoin. Adopting it ensures that Neptune-Cash benefits from the collective security audits and performance optimizations of the wider blockchain community.
* **Future-Proofing:** The modular nature of `libp2p` allows us to plug in new discovery mechanisms or transports as they emerge without needing to refactor our core consensus loops.

| Feature | Legacy TCP Stack | libp2p Stack |
| --- | --- | --- |
| **Status** | Deprecation Candidate | **Current Standard** |
| **Primary Transport** | TCP Only | **QUIC (UDP) / TCP** |
| **Encryption** | None | **Native (Transport-level)** |
| **NAT Traversal** | None | **AutoNAT / UPnP / Relay+DCUtR** |
| **Development** | Maintenance only | **Active Extension** |

### 3. Node Identity and Cryptographic Keys

In the `libp2p` ecosystem, a node’s identity is not defined by its IP address, but by a stable, unique identifier called a **`PeerId`**. This allows the Neptune-Cash network to track peer performance and reputation across different sessions, even if the peer's physical location or network address changes. It also allows advanced features like whitelisting or peer pairing.

#### The Origin of a `PeerId`

A `PeerId` is a verifiable link to a node's cryptographic credentials. It is a `Multihash` of the node's **public key**.

* **Keypairs:** Every node generates a cryptographic key pair (by default, Ed25519).
* **Encryption & Signing:** These keys serve a dual purpose: they are used to sign peer-to-peer messages (ensuring they haven't been tampered with) and to establish secure, encrypted "Noise" or TLS channels between peers.
* **Separation of Concerns:** It is important to note that these networking keys are **entirely separate** from the cryptographic keys used to manage Neptune-Cash funds. The networking identity is used strictly for routing, confidentiality, authenticity, and reputation within the peer-to-peer stack.

#### Persistence and Management

To ensure a stable presence in the network, `neptune-core` persists its networking identity to a file. This prevents the node from appearing as a brand-new entity (a "churn" event) every time it restarts.

* **Default Behavior:** At startup, the node looks for an `identity.key` file in its data directory. If the file exists, the node loads its long-term identity; if not, it generates a new one and saves it.
* **CLI Configurations:**
* `--identity-file <file>`: Overrides the default location, allowing users to manage multiple identities.
* `--new-identity`: Backs up the current identity file and generates a fresh one. This is useful if a user wants to "reset" their network reputation.
* `--incognito`: Instructs the node to use an **ephemeral identity**. The node will generate a fresh key pair in memory and discard it upon shutdown, leaving no trace in the data directory. This is ideal for privacy-conscious users or short-lived diagnostic nodes.

#### Why Identity Persistence Matters

1. **Network Reputation:** By maintaining a stable `PeerId`, a node can build good standing with its neighbors. While there is presently no mechanism for persisting peer standing across connection outages, a stable `PeerId` is necessary for it.
2. **Kademlia DHT Efficiency:** The Distributed Hash Table (DHT), which powers peer discovery, relies on nodes staying at a fixed "distance" from one another in the network's keyspace. If `PeerId`s changed constantly, the DHT would be in a perpetual state of reorganization, making peer discovery slow and unreliable.
3. **Reconnect Speed:** Peers who have previously connected to you store your `PeerId` and `Multiaddr` in their local address books, resulting in faster re-connections without needing to query the DHT again.
4. **IPs Change:** IPs are rarely static but vary because they are assigned from a limited address space or resampled upon system reboot. As a result, whitelisting peers based on IP is fragile and unsound in the face of IP spoofing, but whitelisting based on their `PeerId` provides a robust countermeasure against this range of attacks. However, persistent `PeerId`s offer little security against misbehaving nodes which is why the ban list contains IP addresses and not `PeerId`s.

You are right to pull me back to the actual implementation details—let’s sharpen this. You're correct about Kademlia: in `rust-libp2p`, unless you've manually implemented a persistence layer for the `MemoryStore` or switched to a different storage backend, the routing table is transient and clears on restart. We rely on the **Address Book** to provide the "seeds" for Kademlia to rebuild itself.

## 4. The NetworkActor

The `NetworkActor` is the central struct that manages the network's lifecycle. It defines helper functions and contains the state for an event loop.

### The `NetworkStack` (NetworkBehaviour)

The main composite protocol is named `NetworkStack`. This struct defines the protocols our node supports. By deriving `NetworkBehaviour`, libp2p handles routing events between these internal modules.

```rust
#[derive(libp2p::swarm::NetworkBehaviour)]
pub struct NetworkStack {
    pub kademlia: kad::Behaviour<MemoryStore>,
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
    pub connection_limits: connection_limits::Behaviour,
    pub autonat: autonat::Behaviour,
    pub relay_client: relay::client::Behaviour,
    pub relay_server: relay::Behaviour,
    pub dcutr: dcutr::Behaviour,
    pub upnp: upnp::tokio::Behaviour,
    pub gateway: StreamGateway, // The custom bridge to the PeerLoop
}

```

### Actor State and PeerLoop Spawning

The `NetworkActor` possesses all the context required to instantiate a StreamGateway protocol, which hijacks a raw libp2p substream and passes it to a newly spawned peer loop. To do this, the actor holds:

* **Main Channel Handles:** The mpsc sender and receiver used to communicate with the **Main Loop**.
* **Global State Access:** Necessary to generate handshakes as well as an input to the Peer Loop.
* **Peer Loop Channel Handles:** The broadcast receiver and mpsc sender channels that are also inputs to the Peer Loop.

When the `StreamGateway` successfully negotiates a new connection, the `NetworkActor` reacts to that event by spawning a new `tokio` task. This task runs `run_wrapper`, effectively handing over the hijacked stream and the necessary channel handles to the `PeerLoopHandler`.

### The Event Loop: Communication and Coordination

The `NetworkActor` runs a `select!` loop that serves as the coordination point for the node's P2P activity. It balances three specific streams of information:

1. **Swarm Events:** Bottom-up events from libp2p (e.g., "Peer  has a new address"). If an event indicates a successful `StreamGateway` negotiation, the Actor triggers the Peer Loop spawning logic.
2. **Main Loop Commands:** The Actor listens to a command channel from the **Main Loop**. This is how the rest of the application tells the network to dial a specific peer, initiate a NAT probe, or shutdown.
3. **Peer Persistence & Health:** While the **Kademlia routing table** is kept in memory (and thus lost on restart), the Actor is responsible for persisting the **Address Book**. By saving known `Multiaddr`s to disk, the Actor ensures that upon restart, it has a list of "seed" peers to dial, which in turn allows Kademlia to repopulate its routing table.

### Graceful Shutdown

Because the `NetworkActor` owns the Peer Loop spawning context and the Swarm, it is the sole authority on shutting down the network.

* It closes all active listeners (TCP/QUIC/UPnP).
* It ensures the **Address Book** is flushed to the data directory.
* It terminates all connections with peers at the libp2p level.

Note that the main loop is responsible for broadcasting a `Disconnect` message to all running Peer Loops.

In the `NetworkStack` (the libp2p `NetworkBehaviour`), each subprotocol serves a specialized role. Together, they handle everything from finding peers in a decentralized DHT to "punching" through firewalls.

Here is a summary of the protocols integrated into Neptune-Cash.

## 5. Component Protocols

### [Identify](https://github.com/libp2p/specs/tree/master/identify)

The "handshake" of the `libp2p` world. It allows peers to exchange their public keys, communicate which protocols they support (like Kademlia or StreamGateway), and their observed external addresses.

* **Neptune Use:** Essential for version checking and for the node to learn its own "observed" public IP address from others.

### [Ping](https://github.com/libp2p/specs/tree/master/ping)

A simple liveness check that periodically sends a bit of data and measures the response time.

* **Neptune Use:** Used to prune "zombie" connections that have timed out and keep NAT ports open.

### [Kademlia (K-DHT)](https://github.com/libp2p/specs/tree/master/kad-dht)

The Distributed Hash Table used for peer discovery. It allows nodes to find the network addresses of other peers by querying the network for a specific `PeerId`.

* **Neptune Use:** The primary mechanism for finding new Neptune-Cash nodes without relying on a central server.

***Cold Start Workflow:*** Upon startup, the NetworkActor loads the persisted Address Book. It dials these known "seed" addresses; once connected, the Kademlia behavior uses these peers to re-discover the rest of the network and rebuild its in-memory routing table.

### [AutoNAT](https://github.com/libp2p/specs/tree/master/autonat)

Acts as a [STUN](https://en.wikipedia.org/wiki/STUN) client/server. A node asks its peers: "Can you see me at this address?"

* **Neptune Use:** Determines if the node is **Public** or **Private**. This status dictates whether the node should attempt to reserve a slot on a Relay or act as a Relay itself.

### [UPnP (Universal Plug and Play)](https://en.wikipedia.org/wiki/Universal_Plug_and_Play)

A protocol for automatic port mapping on local routers.

* **Neptune Use:** Asks to open a port on the user's home router so that the node can be reached directly via TCP/QUIC without needing a Relay.

### [Circuit Relay v2](https://github.com/libp2p/specs/tree/master/relay)

Allows a node to stay reachable even if it is behind a restrictive firewall by using a third-party "Relay" node as a proxy.

* **Neptune Use:** Neptune nodes can act as both **Clients** (to be reachable) and **Servers** (to help others).

### [DCUtR (Direct Connection Upgrade through Relay)](https://github.com/libp2p/specs/tree/master/dcutr)

Coordinates a "synchronized" connection attempt between two private nodes already connected via a Relay.

* **Neptune Use:** "Hole punching." It upgrades a slow, proxied Relay connection to a fast, direct P2P connection.

### [Connection Limits](https://docs.rs/libp2p-connection-limits/latest/libp2p_connection_limits/)

Enforces hard caps on the number of concurrent connections.

* **Neptune Use:** Prevents Sybil attacks and resource exhaustion by limiting the total number of established and pending connections.

***Resource Safety Note:*** To prevent memory-based DoS attacks without impacting the Mempool's growth, Neptune-Cash avoids process-wide memory limits. Instead, it uses Yamux Auto-Tuning and a strict cap on sub-streams (`set_max_num_streams(256)`) to ensure that a single malicious peer cannot exhaust the node's resources by opening thousands of idle streams.

### StreamGateway (Custom)

A custom protocol that acts as the handoff point between libp2p and the legacy consensus logic.

* **Function:** It negotiates a stream, validates the `HandshakeData`, and then "hijacks" the underlying stream to feed it into the `PeerLoopHandler`.
* **Neptune Use:** The "glue" that allows modern libp2p transports to power our existing consensus and synchronization loops.

***Serialization:*** Uses Bincode with a length-prefixed framing. Bincode was selected over CBOR to ensure robust handling of fixed-capacity `ArrayString` types and to minimize serialization overhead in the high-frequency handshake phase.
