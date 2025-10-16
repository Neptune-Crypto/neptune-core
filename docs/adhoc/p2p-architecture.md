# Neptune Core P2P Architecture

**Last Updated**: 2025-10-16
**Status**: Production Ready

---

## Table of Contents

1. [Overview](#overview)
2. [Module Structure](#module-structure)
3. [DDoS Protection System](#ddos-protection-system)
4. [Ban System](#ban-system)
5. [Connection Flow](#connection-flow)
6. [Message Handling](#message-handling)
7. [Configuration](#configuration)

---

## Overview

Neptune Core implements a modularized P2P networking layer with comprehensive DDoS protection. All connections share a unified state manager (`Arc<RwLock<P2PStateManager>>`), ensuring consistent rate limiting, reputation tracking, and ban enforcement across the entire network.

**Key Features:**

- ✅ Shared state management (Arc<RwLock<>>)
- ✅ Multi-layer DDoS protection (99% attack mitigation)
- ✅ Automatic IP reputation tracking
- ✅ Progressive ban system (temporary → permanent)
- ✅ Rate limiting (per-IP and global)
- ✅ Token bucket burst protection
- ✅ Handshake timeout protection

---

## Module Structure

```
neptune-core/src/p2p/
├── config/              # P2P configuration
│   ├── connection.rs    # Connection settings
│   ├── protocol.rs      # Protocol settings
│   └── peer.rs          # Peer settings
│
├── connection/          # Connection management
│   ├── acceptor.rs      # Incoming connection handler
│   ├── initiator.rs     # Outgoing connection handler
│   ├── handshake.rs     # Handshake protocol with timeout
│   └── validator.rs     # Connection validation (8-phase)
│
├── peer/                # Peer management
│   ├── info.rs          # Peer information
│   └── manager.rs       # Peer lifecycle
│
├── protocol/            # Protocol implementation
│   ├── handler.rs       # Message handler
│   └── messages.rs      # Protocol messages
│
├── state/               # State management (SHARED)
│   ├── manager.rs       # P2PStateManager (Arc<RwLock<>>)
│   ├── connection_tracker.rs  # Rate limiting
│   ├── reputation.rs    # IP reputation & bans
│   └── peer_map.rs      # Connected peers
│
├── transport/           # Network transport
│   └── codec.rs         # Message encoding/decoding
│
├── service/             # P2P service
│   ├── p2p_service.rs   # Main service
│   └── event_loop.rs    # Event processing
│
└── integration/         # Integration layer
    ├── service_factory.rs      # Service creation
    └── main_loop_integration.rs # Main loop bridge
```

---

## DDoS Protection System

### Protection Layers

The system implements **5 layers** of DDoS protection, applied in sequence:

#### 1. Rate Limiting (Sliding Window)

**Per-IP Limits:**

- 30 attempts/minute
- 60 attempts/hour

**Global Limits:**

- 100 attempts/minute
- 200 attempts/hour

**Implementation:** `connection_tracker.rs`

```rust
// Check rate limiting (requires mutable access to shared state)
let mut state = self.state_manager.write().await;
if !state.is_connection_allowed(peer_address) {
    // Connection blocked by rate limiting
    return Err("Rate limit exceeded");
}
```

#### 2. Token Bucket (Burst Protection)

**Configuration:**

- Capacity: 50 tokens
- Refill rate: 1 token/second
- Shared across all connections

**Purpose:** Allows legitimate burst traffic while preventing sustained attacks.

#### 3. IP Reputation System

**Reputation Score:** 0.0 (worst) to 1.0 (best)

- New IPs start at 0.5 (neutral)
- Violations decrease score
- Successful connections increase score
- Minimum required: 0.3

**Behavior Events:**

- `SuccessfulConnection`: +0.05
- `FailedConnection`: -0.02
- `MalformedHandshake`: -0.10
- `RateLimitViolation`: -0.15
- `ProtocolViolation`: -0.20

**Implementation:** `reputation.rs`

#### 4. Cooldown Periods

After rate limit violations:

- **Duration:** 60 seconds
- **Scope:** Per-IP, enforced globally
- **Purpose:** Prevent rapid reconnection attempts

#### 5. Connection Validation (8-Phase)

**Phase 1:** Rate Limiting Check
**Phase 2:** Reputation Check
**Phase 3:** Static Ban Check (CLI configured)
**Phase 4:** Max Peers Limit
**Phase 5:** Max Connections Per IP
**Phase 6:** Self-Connection Prevention
**Phase 7:** Network Compatibility
**Phase 8:** Version Compatibility

**Implementation:** `validator.rs`

### Test Results

**Attack:** 2000 connections @ 100/sec for 20 seconds

| Metric              | Result  |
| ------------------- | ------- |
| TCP Established     | 2,000   |
| Protocol Allowed    | ~20     |
| Protocol Blocked    | 1,980   |
| **Mitigation Rate** | **99%** |

---

## Ban System

### How Attacking Nodes Are Handled

When a node is identified as attacking, it goes through a **progressive ban system**:

#### Step 1: Violation Tracking

Every attack attempt is recorded:

```rust
pub enum BehaviorEvent {
    MalformedHandshake,      // -0.10 reputation
    RateLimitViolation,      // -0.15 reputation
    ProtocolViolation,       // -0.20 reputation
    // ...
}
```

#### Step 2: Automatic Temporary Ban

**Triggers:**

- Reputation drops below 0.2, OR
- 10 violations within 1 hour

**Effect:**

- IP blocked for 1 hour
- All connection attempts rejected
- Log message: `"🛡️ REPUTATION: IP X blocked - TEMPORARILY BANNED"`

**Code:**

```rust
if recent_violations >= 10 || reputation <= 0.2 {
    apply_temporary_ban(ip, Duration::from_secs(3600));
    warn!("Applied temporary ban to IP {} for 1 hour", ip);
}
```

#### Step 3: Automatic Permanent Ban

**Triggers:**

- Reputation drops below 0.1, OR
- 50 violations within 1 hour
- Must be enabled in config (`enable_auto_perm_ban: true`)

**Effect:**

- IP blocked permanently (until manual unban)
- Survives node restarts (if persisted)
- Log message: `"🛡️ REPUTATION: IP X blocked - PERMANENTLY BANNED"`

**Code:**

```rust
if recent_violations >= 50 || reputation <= 0.1 {
    apply_permanent_ban(ip);
    warn!("Applied permanent ban to IP {}", ip);
}
```

**Default Configuration:**

- Temporary bans: **ENABLED**
- Permanent bans: **DISABLED** (requires manual review)

#### Step 4: Reputation Decay

Over time, reputation scores decay toward neutral (0.5):

- **Decay rate:** 0.01 per hour
- **Purpose:** Allow reformed IPs to reconnect
- **Does not affect bans:** Bans must be manually lifted

### Ban Persistence

**Current State:**

- Bans are in-memory only
- Reset on node restart

**Future Enhancement:**

- Persist bans to database
- Shared banlist across network
- Manual ban management commands

---

## Connection Flow

### Incoming Connection

```
1. TCP Accept (OS level)
   ↓
2. P2P Integration Layer
   p2p_integration.handle_incoming_connection(stream, addr)
   ↓
3. Connection Acceptor (with DDoS protection)
   - Phase 1: Static precheck (CLI bans)
   - Phase 2: DDoS protection checks
     • Rate limiting (shared state)
     • Reputation check (shared state)
     • Cooldown enforcement
   ↓
4. Record Connection Attempt
   state_manager.write().await.record_connection_attempt(addr, ...)
   ↓
5. Spawn Peer Task
   tokio::spawn(answer_peer(...))
   ↓
6. Handshake (with 30s timeout)
   - Send magic bytes
   - Exchange HandshakeData
   - Validate compatibility
   ↓
7. Connection Established
   - Add to peer map
   - Start message loop
```

### Outgoing Connection

```
1. User/Discovery Initiates
   p2p_service.connect_to_peer(addr)
   ↓
2. Connection Initiator
   - Check DDoS rules (shared state)
   - Record attempt
   ↓
3. TCP Connect
   TcpStream::connect(addr).await
   ↓
4. Handshake (with 30s timeout)
   ↓
5. Connection Established
```

---

## Message Handling

### Message Flow

```
Peer → TcpStream → Codec → MessageHandler → Main Loop
                              ↓
                    DDoS Check (rate limiting)
                              ↓
                    Validation
                              ↓
                    Process & Route
```

### Message Rate Limiting

Per-IP message rate limits (enforced in `MessageHandler`):

```rust
let is_rate_limited = {
    let mut state = self.state_manager.write().await;
    state.is_message_rate_limited(peer_addr.ip())
};

if is_rate_limited {
    warn!("Message from {} rate limited by DDoS protection", peer_addr);
    return Ok(true); // Close connection
}
```

### Message Types

**Peer Discovery:**

- `PeerListRequest`
- `PeerListResponse`

**Block Propagation:**

- `BlockNotification` → Request full block
- `Block` → Validate and add to chain

**Transaction Propagation:**

- `TransactionNotification` → Request full tx
- `Transaction` → Validate and add to mempool

**Sync:**

- `BlockRequestBatch` → Send batch of blocks
- `BlockProposalNotification` → Notify of new block proposal

**Control:**

- `Disconnect` → Graceful shutdown

---

## Configuration

### Default Configuration

```rust
// Rate Limiting
max_attempts_per_ip_per_minute: 30,
max_attempts_per_ip_per_hour: 60,
global_max_attempts_per_minute: 100,
global_max_attempts_per_hour: 200,
cooldown_period: Duration::from_secs(60),

// Token Bucket
enable_token_bucket: true,
token_refill_rate: 1.0,  // tokens per second
token_bucket_capacity: 50,

// Reputation
min_reputation_score: 0.3,
reputation_decay_rate: 0.01,  // per hour
enable_auto_temp_ban: true,
enable_auto_perm_ban: false,  // Manual review required
temp_ban_threshold: 0.2,
perm_ban_threshold: 0.1,
temp_ban_duration: Duration::from_secs(3600),  // 1 hour
temp_ban_violation_threshold: 10,  // in 1 hour
perm_ban_violation_threshold: 50,  // in 1 hour

// Connection
max_num_peers: 100,
max_connections_per_ip: 3,
handshake_timeout: Duration::from_secs(30),
```

### Strict Configuration (High Security)

```rust
let config = RateLimitConfig::strict();
let reputation = ReputationConfig::strict();

// Stricter limits:
// - max_attempts_per_ip_per_minute: 10 (vs 30)
// - temp_ban_violation_threshold: 5 (vs 10)
// - min_reputation_score: 0.5 (vs 0.3)
```

### Permissive Configuration (Development)

```rust
let config = RateLimitConfig::permissive();
let reputation = ReputationConfig::permissive();

// More lenient:
// - max_attempts_per_ip_per_minute: 100 (vs 30)
// - temp_ban_violation_threshold: 50 (vs 10)
// - min_reputation_score: 0.1 (vs 0.3)
```

---

## Monitoring

### Log Messages

**DDoS Protection Active:**

```
WARN 🛡️ DDOS PROTECTION: Connection from 1.2.3.4 blocked by DDoS protection
WARN 🛡️ DDOS PROTECTION: IP 1.2.3.4 blocked - exceeded 30/min limit
WARN 🛡️ DDOS PROTECTION: Global rate limit exceeded - blocking new connections
```

**Reputation System:**

```
WARN 🛡️ REPUTATION: IP 1.2.3.4 blocked - TEMPORARILY BANNED (until: ...)
WARN 🛡️ REPUTATION: IP 1.2.3.4 blocked - PERMANENTLY BANNED (violations: 52)
INFO Applied temporary ban to IP 1.2.3.4 for 1 hour
WARN Applied permanent ban to IP 1.2.3.4
```

**Successful Connections:**

```
INFO 🔗 Incoming connection from 1.2.3.4
DEBUG ✅ Connection allowed from 1.2.3.4
INFO ✅ Connection from 1.2.3.4 passed DDoS validation, proceeding with handshake
```

### Statistics (TODO: Dashboard)

Available via P2P service methods:

- `get_total_connections()`
- `get_failed_connections()`
- `get_rate_limited_connections()`
- `get_banned_ips()`
- `get_reputation_score(ip)`

---

## Testing

### DDoS Attack Script

Location: `scripts/python/ddos.py`

**Available Attacks:**

- `connection-flood` - Rapid connection attempts
- `slowloris` - Slow connection holds
- `malformed-handshake` - Invalid protocol data
- `rpc-flood` - RPC endpoint spam
- `multi-vector` - Combined attack types

**Usage:**

```bash
python3 scripts/python/ddos.py \
    --target 127.0.0.1 \
    --port 9798 \
    --attack connection-flood \
    --rate 100 \
    --duration 20 \
    --force
```

**Expected Results:**

- TCP connections: 100% success (OS level)
- Protocol handshakes: ~99% blocked (application level)
- Node logs: Extensive `🛡️ DDOS PROTECTION` warnings

---

## Future Enhancements

1. **Metrics Dashboard**

   - Real-time connection statistics
   - Attack visualization
   - Reputation scores per IP
   - Ban list management

2. **Persistent Bans**

   - Store bans in database
   - Survive node restarts
   - Export/import ban lists

3. **Shared Reputation Network**

   - Gossip reputation data between nodes
   - Distributed banlist
   - Reputation vouching system

4. **Firewall Integration**

   - Auto-configure iptables/nftables
   - TCP-level blocking for banned IPs
   - DDoS attack notifications

5. **Admin Commands**
   - Manual ban/unban
   - Reputation override
   - Whitelist management
   - Statistics queries

---

## Summary

**Current State: PRODUCTION READY**

- ✅ 99% DDoS attack mitigation rate
- ✅ Automatic temporary bans for attackers
- ✅ Optional automatic permanent bans
- ✅ Shared state across all connections
- ✅ Comprehensive logging and observability
- ✅ Zero-configuration protection

**Attack Response:**

1. Initial violations → Rate limiting (immediate blocking)
2. Continued attacks → Reputation drop + cooldown (60s)
3. Persistent attacks → Temporary ban (1 hour)
4. Severe attacks → Permanent ban (manual review)

The P2P layer now provides enterprise-grade DDoS protection while maintaining full compatibility with legitimate peers.
