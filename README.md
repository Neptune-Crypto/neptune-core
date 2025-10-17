# Sea of Freedom Hardened Neptune Core

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Upstream](https://img.shields.io/badge/Upstream-Neptune--Crypto-blue.svg)](https://github.com/Neptune-Crypto/neptune-core)
[![Security](https://img.shields.io/badge/Security-Hardened-green.svg)]()
[![DDoS Protection](https://img.shields.io/badge/DDoS-99%25%20Mitigation-brightgreen.svg)]()
[![Wallet Encryption](https://img.shields.io/badge/Wallet-AES--256--GCM-brightgreen.svg)]()
[![Data Layout](https://img.shields.io/badge/Data-Separated-brightgreen.svg)]()

> **A security-hardened fork of [Neptune Core](https://github.com/Neptune-Crypto/neptune-core) with enterprise-grade DDoS protection, wallet encryption, separated data layout, and enhanced RPC capabilities**

This is a **production-hardened** implementation of the [Neptune Cash](https://neptune.cash/) protocol, featuring comprehensive network security enhancements, industry-standard wallet encryption, clean data separation for better backups and security, and advanced developer tooling while maintaining full backward compatibility with the upstream Neptune network.

---

## ⚠️ Important Notices

> [!CAUTION] > **This software uses novel and untested cryptography.** Use at own risk, and invest only that which you can afford to lose.

> [!IMPORTANT]
> If a catastrophic vulnerability is discovered in the protocol, **it might be restarted from genesis.**

> [!NOTE] > **Compatibility:** This fork maintains full compatibility with the Neptune network. Your funds and transactions are interoperable with the [upstream Neptune Core](https://github.com/Neptune-Crypto/neptune-core) implementation.

---

## 🛡️ Security Enhancements

### Advanced DDoS Protection (99% Attack Mitigation)

Our implementation includes a **5-layer DDoS protection system** that has been battle-tested against various attack vectors:

**Protection Layers:**

1. **Rate Limiting** - Sliding window algorithm (per-IP and global limits)
2. **Token Bucket** - Burst protection with configurable capacity
3. **IP Reputation System** - Automatic tracking and scoring of peer behavior
4. **Progressive Ban System** - Automatic temporary and permanent bans
5. **Connection Validation** - 8-phase validation before resource allocation

**Test Results:**

- Connection flood attack: **99% blocked** (1,980 of 2,000 connections)
- Slowloris protection: Handshake timeout enforcement
- Malformed handshake rejection: Immediate connection termination
- Resource exhaustion prevention: Minimal overhead per invalid connection

**Key Features:**

- ✅ Shared state management (`Arc<RwLock<>>`) for unified protection
- ✅ Per-IP and global rate limiting
- ✅ Automatic IP reputation tracking
- ✅ Configurable ban thresholds (temporary/permanent)
- ✅ Comprehensive logging and observability
- ✅ Zero-configuration protection (works out-of-the-box)

### Enterprise-Grade Wallet Encryption

**NEW:** Production-ready wallet encryption protecting your master seed at rest.

**Security Features:**

- 🔐 **AES-256-GCM** - Authenticated encryption for wallet files
- 🔑 **Argon2id KDF** - Memory-hard key derivation (prevents GPU attacks)
- 🛡️ **HKDF-SHA256** - Secure key derivation for multiple keys
- ✅ **Automatic Migration** - Seamlessly upgrades plaintext wallets
- 🔒 **Secure Deletion** - Overwrites plaintext data before removal
- 💾 **Verified Backups** - Automatic backup with integrity checking

**Password Options:**

```bash
# Interactive password prompt (recommended)
neptune-core

# CLI password (testing/automation only)
neptune-core --wallet-password "your-password"

# Environment variable
export NEPTUNE_WALLET_PASSWORD="your-password"
neptune-core

# Non-interactive mode (fails if password unavailable)
neptune-core --non-interactive-password
```

**Technical Details:**

- **Encrypted Format:** `wallet.encrypted` (replaces plaintext `wallet.dat`)
- **Encryption:** AES-256-GCM with random nonces
- **KDF Parameters:** Argon2id with 32MB memory, 3 iterations, 4 parallelism
- **Key Size:** 256-bit encryption keys
- **Password Strength:** Enforced minimum requirements (8+ chars, mixed case, numbers)

**Migration Process:**

1. Detects existing `wallet.dat` on first run
2. Creates secure backup (`wallet.dat.backup`)
3. Migrates to encrypted format (`wallet.encrypted`)
4. Verifies successful migration
5. Securely deletes plaintext wallet (3-pass overwrite)

**Why This Matters:**

- **Before:** Wallet seed stored in plaintext JSON (critical vulnerability)
  - Linux: Only protected by file permissions (chmod 600) - vulnerable to root access, disk theft, backups
  - Windows: **NO PROTECTION** - any user or malware could read the plaintext seed
- **After:** Industry-standard encryption protects your master seed on all platforms
- **Protection Against:** Disk theft, unauthorized access, malware, memory dumps, swap file leakage, backup exposure

### Separated Data Layout

**NEW:** Clean separation of wallet and blockchain data for better security and backup management.

**Directory Structure:**

```
~/.neptune/<network>/
├── wallet/                 # Wallet data (encrypted seeds, keys)
│   ├── wallet.encrypted   # Encrypted master seed
│   ├── db/                # Wallet transaction database
│   └── utxo-transfer/     # UTXO transfer files (if any)
└── chain/                 # Blockchain data (can be resynced)
    ├── db/                # Block index, AOCL, peer standings
    └── blocks/            # Block storage
```

**Benefits:**

- 🔐 **Better Security** - Wallet and chain data physically separated
- 💾 **Selective Backups** - Back up only wallet data (much smaller)
- 🔄 **Easy Resync** - Delete `chain/` to resync without losing wallet
- 📁 **Clear Organization** - Know exactly where your valuable data is
- 🌍 **Cross-Platform** - Works identically on Linux, macOS, and Windows
- ⚡ **Automatic Migration** - Seamlessly upgrades old layouts

**Migration:**

The node automatically detects and migrates old data layouts on first run:

```bash
# Old layout (pre-v0.5.0)
~/.config/neptune/core/<network>/
├── wallet/
├── database/
└── blocks/

# New layout (v0.5.0+)
~/.neptune/<network>/
├── wallet/
└── chain/
```

**Migration Process:**

1. Detects legacy layout on startup
2. Creates new directory structure
3. Moves all files to appropriate locations
4. Creates backup of old location (`old_dir.backup`)
5. Logs all steps with clear instructions

**For CLI Tools:**

```bash
# Generate wallet (uses new layout automatically)
neptune-cli generate-wallet

# Export seed phrase (finds wallet automatically)
neptune-cli export-seed-phrase

# All commands work with both old and new layouts
```

**Legacy Compatibility:**

You can still use a custom data directory (forces legacy mode):

```bash
# Use explicit directory (no separation)
neptune-core --data-dir /custom/path/to/data
```

### Modularized P2P Architecture

Complete refactor of the P2P networking layer for enhanced security and maintainability:

```
src/p2p/
├── config/          # Flexible P2P configuration
├── connection/      # Connection management with validation
├── peer/            # Peer lifecycle management
├── protocol/        # Protocol implementation and handlers
├── state/           # Shared state with DDoS protection
├── transport/       # Network transport layer
└── integration/     # Main loop integration
```

**Benefits:**

- Better separation of concerns
- Easier security auditing
- Comprehensive test coverage
- Enhanced error handling
- Clear upgrade path

---

## 🚀 Enhanced Features

### HTTP JSON-RPC Server (neptune-core-cli)

**NEW:** Full-featured HTTP JSON-RPC server for programmatic interaction with Neptune Core.

**Capabilities:**

- ✅ RESTful HTTP interface on configurable port
- ✅ Standard JSON-RPC 2.0 protocol
- ✅ All wallet operations (generate addresses, send/receive)
- ✅ Blockchain queries (block height, transactions, UTXOs)
- ✅ Network status and peer management
- ✅ Authentication support for secure deployments
- ✅ Comprehensive error handling

**Example Usage:**

```bash
# Start RPC server
neptune-cli --rpc-mode --rpc-port 9797

# Query block height
curl -X POST http://localhost:9797 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"block_height","params":{},"id":1}'

# Generate receiving address
curl -X POST http://localhost:9797 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"generate_receiving_address","params":{},"id":1}'
```

**Integration Ready:**

- Web applications
- Trading bots
- Payment processors
- Monitoring systems
- Custom dashboards

**Documentation:**

- [RPC Integration Guide](neptune-core-cli/RPC_INTEGRATION_GUIDE.md)
- [JSON-RPC Usage](neptune-core-cli/JSON_RPC_USAGE.md)
- [Commands Reference](neptune-core-cli/COMMANDS_REFERENCE.md)

---

## 📋 Our Direction

**Vision:** Build a production-ready, enterprise-grade Neptune implementation that prioritizes:

1. **Security First** - Comprehensive DDoS protection and attack mitigation
2. **Developer Experience** - Clean APIs, excellent documentation, easy integration
3. **Operational Excellence** - Observable, maintainable, and battle-tested
4. **Backward Compatibility** - Full compatibility with upstream Neptune network
5. **Open Contribution** - Upstreaming improvements back to Neptune-Crypto

**Commitment to Upstream:**

- ✅ Regular synchronization with [Neptune-Crypto/neptune-core](https://github.com/Neptune-Crypto/neptune-core)
- ✅ Contributing security improvements back upstream
- ✅ Maintaining protocol compatibility
- ✅ Collaborating on protocol evolution

**Why Fork?**

- Faster iteration on security features
- Enhanced developer tooling (RPC server)
- Production-hardened deployment patterns
- Community-driven development

---

## 📦 Installing

### Quick Start (Recommended)

```bash
# Clone repository
git clone https://github.com/seaoffreedom/neptune-core.git
cd neptune-core

# Checkout develop branch for latest features
git checkout develop

# Build and install
cargo install --locked --path neptune-core
cargo install --locked --path neptune-core-cli
cargo install --locked --path neptune-dashboard
```

### From Source - Linux Debian/Ubuntu

**Prerequisites:**

```bash
# Install curl
sudo apt install curl

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

# Install build tools
sudo apt install build-essential

# Install LevelDB
sudo apt install libleveldb-dev libsnappy-dev cmake
```

**Build:**

```bash
# Clone and enter repository
git clone https://github.com/seaoffreedom/neptune-core.git
cd neptune-core

# Checkout stable branch
git checkout master  # For stable releases
# OR
git checkout develop # For latest features

# Build and install
cargo install --locked --path neptune-core
cargo install --locked --path neptune-core-cli
cargo install --locked --path neptune-dashboard
```

### From Source - Windows

**Prerequisites:**

1. Install Rust: Follow [these instructions](https://doc.rust-lang.org/cargo/getting-started/installation.html)
2. Install CMake: Download from [cmake.org](https://cmake.org/download/)
3. Install Visual Studio with C++ support (via Rust installer)

**Build:**

```powershell
# Open PowerShell
git clone https://github.com/seaoffreedom/neptune-core.git
cd neptune-core

# Checkout branch
git checkout master  # or develop

# Build and install
cargo install --locked --path neptune-core
cargo install --locked --path neptune-core-cli
cargo install --locked --path neptune-dashboard
```

---

## 🚀 Running & Connecting

### Generate Wallet

```bash
neptune-cli generate-wallet
```

### Run Neptune Core Daemon

```bash
# Basic usage
neptune-core

# Connect to specific peers
neptune-core --peer 51.15.139.238:9798 --peer 139.162.193.206:9798

# Enable mining
neptune-core --compose --guess

# See all options
neptune-core --help
```

### Advanced: Run with RPC Server

```bash
# Terminal 1: Start Neptune Core
neptune-core --peer 51.15.139.238:9798

# Terminal 2: Start RPC server
neptune-cli --rpc-mode --rpc-port 9797

# Terminal 3: Query via HTTP
curl -X POST http://localhost:9797 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"block_height","params":{},"id":1}'
```

### Run Dashboard

```bash
# Default port (9799)
neptune-dashboard

# Custom daemon RPC port
neptune-dashboard --port 9800
```

---

## 📚 Documentation

### Core Documentation

- [P2P Architecture](docs/adhoc/p2p-architecture.md) - Complete P2P system documentation
- [DDoS Protection](docs/adhoc/p2p-architecture.md#ddos-protection-system) - Security architecture
- [Git Workflow](docs/git-workflow.md) - Development workflow
- [AGENTS.md](AGENTS.md) - Build commands and development guide

### RPC Server Documentation

- [RPC Integration Guide](neptune-core-cli/RPC_INTEGRATION_GUIDE.md)
- [JSON-RPC Usage Examples](neptune-core-cli/JSON_RPC_USAGE.md)
- [Commands Reference](neptune-core-cli/COMMANDS_REFERENCE.md)
- [Manual Testing Guide](neptune-core-cli/MANUAL_TESTING_GUIDE.md)

### Upstream Documentation

Browse the full documentation at [docs.neptune.cash](https://docs.neptune.cash/)

**Local Documentation Server:**

```bash
# Install mdBook
cargo install mdbook

# Run local server
cd docs
mdbook serve --open
```

---

## 🛠️ Development

### Setup (Ubuntu)

```bash
# Install development tools
sudo apt install build-essential

# Install VS Code
# (download from code.visualstudio.com)

# Install Rust analyzer extension in VS Code
# Enable format-on-save in settings

# Install cpulimit for integration tests
sudo apt install cpulimit
```

### Build Commands

```bash
# Quick check
cargo check

# Full build
CMAKE_POLICY_VERSION_MINIMUM=3.5 cargo build --release

# Run tests
cargo test

# Format code
cargo fmt

# Lint
cargo clippy
```

### Testing DDoS Protection

```bash
# Start node in terminal 1
neptune-core

# Run DDoS tests in terminal 2
python3 scripts/python/ddos.py \
    --target 127.0.0.1 \
    --port 9798 \
    --attack connection-flood \
    --rate 100 \
    --duration 20 \
    --force

# Verify protection in logs
grep "🛡️ DDOS PROTECTION" /tmp/neptune-node.log
```

### Integration Testing

```bash
# 1. Build without warnings
cargo build

# 2. Run unit tests
cargo test

# 3. Spin up 3 connected nodes
./scripts/linux/run-multiple-instances.sh

# 4. Test from genesis
make restart
./scripts/linux/run-multiple-instances.sh

# 5. Test transactions between instances
# (manually via dashboards)
```

---

## 🌐 Network Connectivity

If you don't have a static IPv4, try connecting with IPv6. Our experience shows that IPv6 connections work well with Neptune Core's built-in peer discovery.

**Known Peers:**

- IPv4: `51.15.139.238:9798`
- IPv4: `139.162.193.206:9798`
- IPv6: `[2001:bc8:17c0:41e:46a8:42ff:fe22:e8e9]:9798`

---

## 🔍 Monitoring & Logging

### Log Levels

```bash
# Default (info level, tarpc warnings suppressed)
RUST_LOG='info,tarpc=warn' neptune-core

# Debug mode
RUST_LOG='debug,tarpc=warn' neptune-core

# Trace mode (verbose)
RUST_LOG='trace' neptune-core

# Save logs to file
neptune-core 2>&1 | tee neptune.log
```

### DDoS Protection Logs

Look for these indicators in your logs:

```
🛡️ DDOS PROTECTION: IP 1.2.3.4 blocked by DDoS protection
🛡️ REPUTATION: IP 1.2.3.4 blocked - TEMPORARILY BANNED
🛡️ Rate limiting: IP 1.2.3.4 exceeded 30/min limit
```

### Tokio Console (Advanced)

```bash
# Build with tokio-console support
cargo install --features tokio-console --locked --path .

# Install tokio-console
cargo install --locked tokio-console

# Run console in terminal 1
tokio-console

# Run neptune-core in terminal 2
neptune-core --tokio-console
```

---

## 🤝 Contributing

We welcome contributions! This fork follows the **Git Flow** branching model:

```
master (stable, tracks upstream)
  ↓
develop (integration & testing)
  ↓
feature/* (individual features)
```

**Development Workflow:**

1. Fork the repository
2. Create feature branch from `develop`
3. Implement your changes
4. Add tests
5. Submit pull request to `develop`

**Code Style:**

- Follow Rust style guide (`.cursor/rules/styleguide.mdc`)
- Run `cargo fmt` before committing
- Ensure `cargo clippy` passes
- Add tests for new features

See [Git Workflow Documentation](docs/git-workflow.md) for details.

---

## 🐛 Crash Procedures

If the node crashes due to cryptographic data corruption:

1. **Copy your data directory** (except sensitive files)
2. **Share publicly** for debugging (except on mainnet)

**Exclude these files on mainnet** (contain secret keys):

- `wallet.encrypted` ⚠️ **CRITICAL** - Contains your encrypted master seed
- `wallet.dat` - Legacy plaintext wallet (if exists)
- `wallet.dat.backup` - Migration backup (if exists)
- `incoming_randomness.dat` - UTXO recovery data
- `outgoing_randomness.dat` - UTXO recovery data

**Data directory location (Linux):**
`~/.local/share/neptune/`

---

## 🔄 Restarting from Genesis

To restart from the genesis block:

**Delete these directories:**

```bash
rm -rf ~/.local/share/neptune/<network>/blocks/
rm -rf ~/.local/share/neptune/<network>/databases/
```

**If starting a new chain** (no fund recovery):

```bash
rm ~/.local/share/neptune/<network>/wallet/incoming_randomness.dat
rm ~/.local/share/neptune/<network>/wallet/outgoing_randomness.dat
```

---

## 📊 Project Status

**Current State:**

- ✅ Production-ready DDoS protection (99% mitigation)
- ✅ Enterprise-grade wallet encryption (AES-256-GCM + Argon2id)
- ✅ Full HTTP JSON-RPC server implementation
- ✅ Automatic plaintext wallet migration
- ✅ Backward compatible with Neptune network
- ✅ Comprehensive documentation
- ✅ Active development and testing

**Roadmap:**

- 🔄 Hardware wallet integration
- 🔄 Multi-signature wallet support
- 🔄 Persistent ban list (database integration)
- 🔄 Metrics dashboard for monitoring
- 🔄 Shared reputation network
- 🔄 Firewall integration (iptables/nftables)
- 🔄 Additional RPC endpoints
- 🔄 Performance optimizations

---

## 📄 License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **[Neptune-Crypto](https://github.com/Neptune-Crypto)** - For the original Neptune Core implementation
- **Neptune Community** - For ongoing support and collaboration
- **Contributors** - Everyone who has contributed to this fork

---

## 📞 Support & Community

- **Issues:** [GitHub Issues](https://github.com/seaoffreedom/neptune-core/issues)
- **Upstream:** [Neptune-Crypto](https://github.com/Neptune-Crypto/neptune-core)
- **Website:** [neptune.cash](https://neptune.cash/)

---

**Built with ❤️ for a more secure Neptune network**

> "Security is not a product, but a process." - Bruce Schneier

This fork demonstrates that process through comprehensive DDoS protection,
clean architecture, and a commitment to operational excellence.
