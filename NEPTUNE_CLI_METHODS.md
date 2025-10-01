# Neptune CLI Methods Documentation

This document provides a comprehensive overview of all available methods in the Neptune Core CLI (`neptune-cli`), organized by category and functionality.

## Table of Contents

- [Global Options](#global-options)
- [Standalone Commands (No Server Required)](#standalone-commands-no-server-required)
- [RPC Commands (Requires neptune-core Server)](#rpc-commands-requires-neptune-core-server)
  - [Authentication & Network Info](#authentication--network-info)
  - [Blockchain Data](#blockchain-data)
  - [Wallet & Balance Management](#wallet--balance-management)
  - [Mempool Operations](#mempool-operations)
  - [Peer Management](#peer-management)
  - [Blockchain Statistics](#blockchain-statistics)
  - [Transaction Operations](#transaction-operations)
  - [Node Control](#node-control)
  - [Broadcasting](#broadcasting)
  - [Development & Testing](#development--testing)
- [Unused RPC Methods](#unused-rpc-methods)

---

## Global Options

The following options are available for all commands:

### `--port, -p <port>`

**Description**: Sets the neptune-core RPC server localhost port to connect to.  
**Default**: `9799`  
**Usage**: `neptune-cli --port 9799 <command>`

### `--data-dir <DATA_DIR>`

**Description**: Specifies the neptune-core data directory containing wallet and blockchain state.  
**Usage**: `neptune-cli --data-dir /path/to/data <command>`

### `--help, -h`

**Description**: Prints help information for the command or subcommand.  
**Usage**: `neptune-cli --help` or `neptune-cli <command> --help`

---

## Standalone Commands (No Server Required)

These commands can be executed without a running neptune-core server. They operate entirely offline and handle wallet management, address generation, and shell completions.

### `completions`

**Description**: Generates shell completion scripts for the CLI.  
**CLI Command**: `neptune-cli completions`  
**Output**: Shell completion script for the current shell  
**Usage**: `neptune-cli completions | source` (for fish shell)

### `help`

**Description**: Prints help information for commands and subcommands.  
**CLI Command**: `neptune-cli help [<command>]`  
**Parameters**:

- `command`: Optional subcommand to get help for  
  **Output**: Help text for the specified command or general help

### `which_wallet`

**Description**: Displays path to wallet secrets file (offline operation).  
**CLI Command**: `neptune-cli which-wallet [--network <network>]`  
**Parameters**:

- `--network`: Network (default: main)  
  **Output**: Wallet file path

### `generate_wallet`

**Description**: Generates a new wallet (offline operation).  
**CLI Command**: `neptune-cli generate-wallet [--network <network>]`  
**Parameters**:

- `--network`: Network (default: main)  
  **Output**: Wallet location and seed phrase instructions

### `export_seed_phrase`

**Description**: Exports mnemonic seed phrase (offline operation).  
**CLI Command**: `neptune-cli export-seed-phrase [--network <network>]`  
**Parameters**:

- `--network`: Network (default: main)  
  **Output**: 18-word seed phrase

### `import_seed_phrase`

**Description**: Imports mnemonic seed phrase (offline operation).  
**CLI Command**: `neptune-cli import-seed-phrase [--network <network>]`  
**Parameters**:

- `--network`: Network (default: main)  
  **Output**: Interactive seed phrase entry

### `nth_receiving_address`

**Description**: Returns the nth generation receiving address (offline operation).  
**CLI Command**: `neptune-cli nth-receiving-address <index> [--network <network>]`  
**Parameters**:

- `index`: Address index
- `--network`: Network (default: main)  
  **Output**: Bech32m encoded address

### `premine_receiving_address`

**Description**: Returns a static generation receiving address for premine recipients (offline operation).  
**CLI Command**: `neptune-cli premine-receiving-address [--network <network>]`  
**Parameters**:

- `--network`: Network (default: main)  
  **Output**: Bech32m encoded address

### `shamir_share`

**Description**: Shares wallet secret using Shamir secret sharing (offline operation).  
**CLI Command**: `neptune-cli shamir-share <t> <n> [--network <network>]`  
**Parameters**:

- `t`: Threshold (minimum shares needed)
- `n`: Total number of shares  
  **Output**: Interactive share generation

### `shamir_combine`

**Description**: Combines Shamir secret shares to reproduce wallet (offline operation).  
**CLI Command**: `neptune-cli shamir-combine <t> [--network <network>]`  
**Parameters**:

- `t`: Number of shares to combine  
  **Output**: Interactive share combination

---

## RPC Commands (Requires neptune-core Server)

These commands require a running neptune-core server and make RPC calls to interact with the blockchain, wallet, and network.

## Authentication & Network Info

### `cookie_hint`

**RPC Method**: `cookie_hint()`  
**Description**: Returns authentication cookie location and network information for zero-conf authentication.  
**Usage**: Used internally for authentication setup.  
**Authentication**: Not required (bootstrap method).

### `network`

**RPC Method**: `network()`  
**Description**: Returns the network this neptune-core instance is running on.  
**CLI Command**: `neptune-cli network`  
**Output**: Network name (e.g., "main", "test", "regtest")

### `own_listen_address_for_peers`

**RPC Method**: `own_listen_address_for_peers()`  
**Description**: Returns the address for peers to contact this neptune-core node.  
**CLI Command**: `neptune-cli own-listen-address-for-peers`  
**Output**: Socket address or "No listen address configured"

### `own_instance_id`

**RPC Method**: `own_instance_id()`  
**Description**: Returns the instance ID of this neptune-core node.  
**CLI Command**: `neptune-cli own-instance-id`  
**Output**: Unique instance identifier

---

## Blockchain Data

### `block_height`

**RPC Method**: `block_height()`  
**Description**: Returns the current block height.  
**CLI Command**: `neptune-cli block-height`  
**Output**: Current block height number

### `block_info`

**RPC Method**: `block_info()`  
**Description**: Returns information about a specific block.  
**CLI Command**: `neptune-cli block-info <block_selector>`  
**Parameters**:

- `block_selector`: One of `genesis`, `tip`, `height/<n>`, `digest/<hex>`  
  **Output**: Block information or "Not found"

### `block_digest`

**RPC Method**: `block_digest()`  
**Description**: Returns the digest/hash of a specific block.  
**CLI Command**: `neptune-cli tip-digest` (uses `tip` selector)  
**Output**: Block digest in hexadecimal format

### `block_digests_by_height`

**RPC Method**: `block_digests_by_height()`  
**Description**: Returns block digests for a given block height.  
**CLI Command**: `neptune-cli block-digests-by-height <height>`  
**Parameters**:

- `height`: Block height number  
  **Output**: List of block digests (one per line)

### `header`

**RPC Method**: `header()`  
**Description**: Returns the block header of any block.  
**CLI Command**: `neptune-cli header <block_selector>`  
**Parameters**:

- `block_selector`: One of `genesis`, `tip`, `height/<n>`, `digest/<hex>`  
  **Output**: Block header information or "Block did not exist in database"

### `best_proposal`

**RPC Method**: `best_proposal()`  
**Description**: Returns information about the current best block proposal.  
**CLI Command**: `neptune-cli best-block-proposal`  
**Output**: Best block proposal info or "Not found"

### `confirmations`

**RPC Method**: `confirmations()`  
**Description**: Returns the number of confirmations for the wallet.  
**CLI Command**: `neptune-cli confirmations`  
**Output**: Confirmation count or "Wallet has not received any ingoing transactions yet"

---

## Wallet & Balance Management

### `confirmed_available_balance`

**RPC Method**: `confirmed_available_balance()`  
**Description**: Returns confirmed balance (excludes time-locked UTXOs).  
**CLI Command**: `neptune-cli confirmed-available-balance`  
**Output**: Balance amount

### `unconfirmed_available_balance`

**RPC Method**: `unconfirmed_available_balance()`  
**Description**: Returns unconfirmed balance (includes unconfirmed transactions, excludes time-locked UTXOs).  
**CLI Command**: `neptune-cli unconfirmed-available-balance`  
**Output**: Balance amount

### `wallet_status`

**RPC Method**: `wallet_status()`  
**Description**: Returns comprehensive wallet status information.  
**CLI Command**: `neptune-cli wallet-status [--json] [--table]`  
**Options**:

- `--json`: Raw JSON format (default)
- `--table`: Table format  
  **Output**: Wallet status in specified format

### `num_expected_utxos`

**RPC Method**: `num_expected_utxos()`  
**Description**: Returns the number of UTXOs the wallet expects to receive.  
**CLI Command**: `neptune-cli num-expected-utxos`  
**Output**: Expected UTXO count

### `next_receiving_address`

**RPC Method**: `next_receiving_address()`  
**Description**: Returns the next unused generation receiving address.  
**CLI Command**: `neptune-cli next-receiving-address`  
**Output**: Bech32m encoded address

### `list_own_coins`

**RPC Method**: `list_own_coins()`  
**Description**: Lists known coins owned by the wallet.  
**CLI Command**: `neptune-cli list-coins`  
**Output**: Formatted list of owned coins

---

## Mempool Operations

### `mempool_tx_count`

**RPC Method**: `mempool_tx_count()`  
**Description**: Returns the count of transactions in the mempool.  
**CLI Command**: `neptune-cli mempool-tx-count`  
**Output**: Transaction count

### `mempool_size`

**RPC Method**: `mempool_size()`  
**Description**: Returns the size of mempool in bytes (RAM usage).  
**CLI Command**: `neptune-cli mempool-size`  
**Output**: Size in bytes

### `mempool_tx_ids`

**RPC Method**: `mempool_tx_ids()`  
**Description**: Returns list of mempool transaction IDs.  
**CLI Command**: `neptune-cli list-mempool-transaction-ids`  
**Output**: Transaction IDs (one per line)

### `clear_mempool`

**RPC Method**: `clear_mempool()`  
**Description**: Deletes all transactions from the mempool.  
**CLI Command**: `neptune-cli clear-mempool`  
**Output**: Confirmation message

---

## Peer Management

### `peer_info`

**RPC Method**: `peer_info()`  
**Description**: Returns information about connected peers.  
**CLI Command**: `neptune-cli peer-info`  
**Output**: JSON array of peer information

### `all_punished_peers`

**RPC Method**: `all_punished_peers()`  
**Description**: Returns list of punished peers with their standings.  
**CLI Command**: `neptune-cli all-punished-peers`  
**Output**: IP addresses with standing and latest sanction info

### `clear_all_standings`

**RPC Method**: `clear_all_standings()`  
**Description**: Clears all peer standings.  
**CLI Command**: `neptune-cli clear-all-standings`  
**Output**: Confirmation message

### `clear_standing_by_ip`

**RPC Method**: `clear_standing_by_ip()`  
**Description**: Clears standings for a specific peer IP.  
**CLI Command**: `neptune-cli clear-standing-by-ip <ip>`  
**Parameters**:

- `ip`: IP address of the peer  
  **Output**: Confirmation message

---

## Blockchain Statistics

### `block_intervals`

**RPC Method**: `block_intervals()`  
**Description**: Shows block intervals in milliseconds, in reverse chronological order.  
**CLI Command**: `neptune-cli block-intervals <last_block> [--max-num-blocks <n>]`  
**Parameters**:

- `last_block`: Block selector (genesis, tip, height/n, digest/hex)
- `--max-num-blocks`: Maximum number of blocks to analyze  
  **Output**: Block height and interval pairs

### `mean_block_interval`

**Description**: Shows mean block interval in milliseconds within the specified range.  
**CLI Command**: `neptune-cli mean-block-interval <last_block> [--max-num-blocks <n>]`  
**Output**: Average block interval and standard deviation

### `max_block_interval`

**Description**: Shows biggest block interval in the specified range.  
**CLI Command**: `neptune-cli max-block-interval <last_block> [--max-num-blocks <n>]`  
**Output**: Maximum interval and block height

### `min_block_interval`

**Description**: Shows smallest block interval in the specified range.  
**CLI Command**: `neptune-cli min-block-interval <last_block> [--max-num-blocks <n>]`  
**Output**: Minimum interval and block height

### `block_difficulties`

**RPC Method**: `block_difficulties()`  
**Description**: Shows difficulties for a list of blocks.  
**CLI Command**: `neptune-cli block-difficulties <last_block> [--max-num-blocks <n>]`  
**Output**: Block height and difficulty pairs

### `max_block_difficulty`

**Description**: Shows largest difficulty in the specified range.  
**CLI Command**: `neptune-cli max-block-difficulty <last_block> [--max-num-blocks <n>]`  
**Output**: Maximum difficulty and block height

### `latest_tip_digests`

**RPC Method**: `latest_tip_digests()`  
**Description**: Returns digests of the newest n blocks.  
**CLI Command**: `neptune-cli latest-tip-digests <n>`  
**Parameters**:

- `n`: Number of latest blocks  
  **Output**: Block digests (one per line)

### `tip_header`

**RPC Method**: `header()` (with tip selector)  
**Description**: Returns the block header of the tip block.  
**CLI Command**: `neptune-cli tip-header`  
**Output**: Block header information

---

## Transaction Operations

### `send`

**RPC Method**: `send()`  
**Description**: Sends a payment to a single recipient.  
**CLI Command**: `neptune-cli send <address> <amount> <fee> <receiver_tag> <notify_self> <notify_other>`  
**Parameters**:

- `address`: Recipient's address
- `amount`: Amount to send
- `fee`: Transaction fee
- `receiver_tag`: Local tag for identifying receiver
- `notify_self`: Notification medium for self
- `notify_other`: Notification medium for other  
  **Output**: Transaction ID and UTXO transfer files

### `send_to_many`

**Description**: Sends payments to one or more recipients.  
**CLI Command**: `neptune-cli send-to-many [--file <file>] <outputs>... --fee <fee>`  
**Options**:

- `--file`: File containing outputs (format: address:amount)
- `outputs`: Space-separated outputs (address:amount)
- `--fee`: Transaction fee  
  **Output**: Transaction ID and UTXO transfer files

### `send_transparent`

**RPC Method**: `send_transparent()`  
**Description**: Like `send_to_many` but creates transparent transactions (no privacy).  
**CLI Command**: `neptune-cli send-transparent [--file <file>] <outputs>... --fee <fee>`  
**Output**: Transaction ID (no UTXO transfer files needed)

### `claim_utxo`

**RPC Method**: `claim_utxo()`  
**Description**: Claims an off-chain UTXO transfer.  
**CLI Command**: `neptune-cli claim-utxo <format> [--max-search-depth <depth>]`  
**Subcommands**:

- `file <path>`: Read from UTXO transfer JSON file
- `raw <ciphertext>`: Use raw encrypted payload  
  **Options**:
- `--max-search-depth`: Blocks to look back for already mined UTXO  
  **Output**: Success/failure message

### `upgrade`

**RPC Method**: `upgrade()`  
**Description**: Upgrades a transaction proof.  
**CLI Command**: `neptune-cli upgrade <tx_kernel_id>`  
**Parameters**:

- `tx_kernel_id`: Transaction kernel ID to upgrade  
  **Output**: Success/failure message

---

## Node Control

### `shutdown`

**RPC Method**: `shutdown()`  
**Description**: Shuts down the neptune-core node.  
**CLI Command**: `neptune-cli shutdown`  
**Output**: Confirmation message

### `freeze`

**RPC Method**: `freeze()`  
**Description**: Pauses processing of new transaction data.  
**CLI Command**: `neptune-cli freeze`  
**Output**: Confirmation message

### `unfreeze`

**RPC Method**: `unfreeze()`  
**Description**: Resumes state updates if paused.  
**CLI Command**: `neptune-cli unfreeze`  
**Output**: Confirmation message

### `pause_miner`

**RPC Method**: `pause_miner()`  
**Description**: Pauses mining.  
**CLI Command**: `neptune-cli pause-miner`  
**Output**: Confirmation message

### `restart_miner`

**RPC Method**: `restart_miner()`  
**Description**: Resumes mining.  
**CLI Command**: `neptune-cli restart-miner`  
**Output**: Confirmation message

### `set_tip`

**RPC Method**: `set_tip()`  
**Description**: Sets the blockchain tip to a stored block.  
**CLI Command**: `neptune-cli set-tip <digest>`  
**Parameters**:

- `digest`: Block digest (40-byte hex string)  
  **Output**: Success/failure message

### `prune_abandoned_monitored_utxos`

**RPC Method**: `prune_abandoned_monitored_utxos()`  
**Description**: Prunes monitored UTXOs from abandoned chains.  
**CLI Command**: `neptune-cli prune-abandoned-monitored-utxos`  
**Output**: Number of UTXOs marked as abandoned

---

## Broadcasting

### `broadcast_all_mempool_txs`

**RPC Method**: `broadcast_all_mempool_txs()`  
**Description**: Broadcasts transaction notifications for all mempool transactions.  
**CLI Command**: `neptune-cli broadcast-mempool-transactions`  
**Output**: Confirmation message

### `broadcast_block_proposal`

**RPC Method**: `broadcast_block_proposal()`  
**Description**: Broadcasts a block proposal notification.  
**CLI Command**: `neptune-cli broadcast-block-proposal`  
**Output**: Confirmation message

---

## Development & Testing

### `mine_blocks_to_wallet`

**RPC Method**: `mine_blocks_to_wallet()`  
**Description**: Mines blocks to the node's wallet (RegTest only).  
**CLI Command**: `neptune-cli mine-blocks-to-wallet [<num_blocks>]`  
**Parameters**:

- `num_blocks`: Number of blocks to mine (default: 1)  
  **Output**: Confirmation message

### `set_coinbase_distribution`

**RPC Method**: `set_coinbase_distribution()`  
**Description**: Sets coinbase distribution for the next locally produced block.  
**CLI Command**: `neptune-cli set-coinbase-distribution --file <file>`  
**Parameters**:

- `--file`: JSON file containing coinbase distribution  
  **Output**: Confirmation message

### `unset_coinbase_distribution`

**RPC Method**: `unset_coinbase_distribution()`  
**Description**: Resets coinbase distribution to reward own wallet.  
**CLI Command**: `neptune-cli unset-coinbase-distribution`  
**Output**: Confirmation message

---

## Unused RPC Methods

The following RPC methods are available in the server but not exposed through CLI commands:

### Advanced Blockchain Data

- `block_kernel()` - Get block kernel
- `addition_record_indices_for_block()` - Get addition record indices
- `restore_membership_proof_privacy_preserving()` - Restore membership proofs
- `announcements_in_block()` - Get block announcements
- `utxo_digest()` - Get UTXO digest
- `utxo_origin_block()` - Get UTXO origin block

### Advanced Wallet Operations

- `history()` - Get transaction history
- `known_keys()` - Get known spending keys
- `known_keys_by_keytype()` - Get keys by type
- `list_utxos()` - List UTXOs with UI data
- `spendable_inputs()` - Get spendable inputs
- `select_spendable_inputs()` - Select spendable inputs

### Transaction Building

- `generate_tx_outputs()` - Generate transaction outputs
- `generate_tx_details()` - Generate transaction details
- `generate_witness_proof()` - Generate witness proofs
- `assemble_transaction()` - Assemble transaction
- `assemble_transaction_artifacts()` - Assemble transaction artifacts
- `proof_type()` - Get proof type

### Advanced Mempool

- `mempool_overview()` - Get mempool overview
- `mempool_tx_kernel()` - Get mempool transaction kernel

### System & Validation

- `dashboard_overview_data()` - Get dashboard overview
- `validate_address()` - Validate address
- `validate_amount()` - Validate amount
- `amount_leq_confirmed_available_balance()` - Check balance sufficiency
- `cpu_temp()` - Get CPU temperature
- `pow_puzzle_internal_key()` - Get internal PoW puzzle
- `pow_puzzle_external_key()` - Get external PoW puzzle
- `full_pow_puzzle_external_key()` - Get full external PoW puzzle

### Advanced Operations

- `record_and_broadcast_transaction()` - Record and broadcast transaction
- `provide_pow_solution()` - Provide PoW solution
- `provide_new_tip()` - Provide new tip

---

## Usage Examples

### Standalone Operations (No Server Required)

```bash
# Generate new wallet
neptune-cli generate-wallet

# Export seed phrase
neptune-cli export-seed-phrase

# Generate addresses offline
neptune-cli nth-receiving-address 0
neptune-cli premine-receiving-address

# Shamir secret sharing
neptune-cli shamir-share 3 5
neptune-cli shamir-combine 3

# Get shell completions
neptune-cli completions | source
```

### RPC Operations (Requires neptune-core Server)

```bash
# Check network and block height
neptune-cli network
neptune-cli block-height

# Get wallet status
neptune-cli wallet-status --table
neptune-cli confirmed-available-balance

# Generate new address (requires server)
neptune-cli next-receiving-address
```

### Transaction Operations

```bash
# Send payment
neptune-cli send "address_here" "100" "1" "tag" "onchain" "onchain"

# Send to multiple recipients
neptune-cli send-to-many "addr1:50" "addr2:30" --fee "2"

# Claim UTXO
neptune-cli claim-utxo file /path/to/utxo.json
```

### Node Management

```bash
# Control mining
neptune-cli pause-miner
neptune-cli restart-miner

# Manage peers
neptune-cli peer-info
neptune-cli clear-all-standings

# Shutdown node
neptune-cli shutdown
```

### Development/Testing

```bash
# Mine blocks (RegTest only)
neptune-cli mine-blocks-to-wallet 10

# Set custom coinbase distribution
neptune-cli set-coinbase-distribution --file distribution.json
```

---

## Notes

### Standalone Commands

- **No server required**: These commands work entirely offline
- **Wallet operations**: Generate, import, export, and manage wallets
- **Address generation**: Create addresses without blockchain access
- **Shamir secret sharing**: Split and combine wallet secrets securely

### RPC Commands

- **Server required**: All RPC commands need a running neptune-core server
- **Authentication**: Most RPC methods require authentication except `cookie_hint()` and `network()`
- **Network-specific**: Some commands only work on specific networks (e.g., `mine-blocks-to-wallet` only works on RegTest)
- **Transaction privacy**: Transaction commands generate UTXO transfer files for off-chain privacy

### General Usage

- Use `--help` with any command for detailed parameter information
- The `--port` and `--data-dir` options apply to all commands
- Standalone commands are useful for wallet setup and offline operations
- RPC commands provide full blockchain interaction capabilities

---

## Implementation Plan: neptune-cli RPC Mode

### Overview

Add RPC server capability to neptune-cli to expose standalone methods via JSON-RPC, following the same patterns used in neptune-core. This will enable remote access to wallet management and utility functions.

### Dual Approach Support

The implementation will support both approaches:

1. **Shared Cookie Approach**: Use the same cookie file as neptune-core (if available)
2. **Independent Cookie Approach**: Generate a separate cookie for neptune-cli RPC server

### Implementation Steps

#### 1. Add RPC Server Dependencies

**File**: `neptune-core-cli/Cargo.toml`

```toml
[dependencies]
# ... existing dependencies ...
tarpc = { version = "0.32", features = ["serde-transport"] }
tokio = { version = "1.0", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
anyhow = "1.0"
```

#### 2. Create RPC Service Trait

**File**: `neptune-core-cli/src/rpc/mod.rs`

```rust
use tarpc::context;
use neptune_cash::types::*;

#[tarpc::service]
pub trait NeptuneCliRPC {
    // Standalone Commands (No Server Required)
    async fn generate_wallet(network: Option<String>) -> RpcResult<String>;
    async fn which_wallet(network: Option<String>) -> RpcResult<String>;
    async fn export_seed_phrase(network: Option<String>) -> RpcResult<String>;
    async fn import_seed_phrase(seed_phrase: String, network: Option<String>) -> RpcResult<()>;
    async fn nth_receiving_address(n: u32, network: Option<String>) -> RpcResult<String>;
    async fn premine_receiving_address(network: Option<String>) -> RpcResult<String>;
    async fn shamir_share(t: u32, n: u32, network: Option<String>) -> RpcResult<Vec<String>>;
    async fn shamir_combine(t: u32, network: Option<String>) -> RpcResult<()>;
    async fn completions(shell: String) -> RpcResult<String>;
    async fn help(command: Option<String>) -> RpcResult<String>;

    // Authentication & Network Info
    async fn network() -> RpcResult<String>;
    async fn own_listen_address_for_peers() -> RpcResult<String>;
    async fn own_instance_id() -> RpcResult<String>;

    // Blockchain Data
    async fn block_height() -> RpcResult<BlockHeight>;
    async fn block_info(block_selector: String) -> RpcResult<String>;
    async fn block_digests_by_height(height: BlockHeight) -> RpcResult<Vec<Digest>>;
    async fn best_block_proposal() -> RpcResult<String>;
    async fn confirmations() -> RpcResult<String>;
    async fn tip_digest() -> RpcResult<Digest>;
    async fn latest_tip_digests(n: u32) -> RpcResult<Vec<Digest>>;
    async fn tip_header(n: u32) -> RpcResult<String>;
    async fn header(block_selector: String) -> RpcResult<String>;

    // Wallet & Balance Management
    async fn confirmed_available_balance() -> RpcResult<NativeCurrencyAmount>;
    async fn unconfirmed_available_balance() -> RpcResult<NativeCurrencyAmount>;
    async fn wallet_status(json: bool, table: bool) -> RpcResult<String>;
    async fn num_expected_utxos() -> RpcResult<u32>;
    async fn next_receiving_address() -> RpcResult<ReceivingAddress>;
    async fn list_coins() -> RpcResult<String>;

    // Mempool Operations
    async fn mempool_tx_count() -> RpcResult<u32>;
    async fn mempool_size() -> RpcResult<u64>;
    async fn list_mempool_transaction_ids() -> RpcResult<Vec<String>>;
    async fn clear_mempool() -> RpcResult<()>;

    // Peer Management
    async fn peer_info() -> RpcResult<String>;
    async fn all_punished_peers() -> RpcResult<String>;
    async fn clear_all_standings() -> RpcResult<()>;
    async fn clear_standing_by_ip(ip: String) -> RpcResult<()>;

    // Blockchain Statistics
    async fn block_intervals(last_block: String, max_num_blocks: Option<u32>) -> RpcResult<String>;
    async fn mean_block_interval(last_block: String, max_num_blocks: Option<u32>) -> RpcResult<String>;
    async fn max_block_interval(last_block: String, max_num_blocks: Option<u32>) -> RpcResult<String>;
    async fn min_block_interval(last_block: String, max_num_blocks: Option<u32>) -> RpcResult<String>;
    async fn block_difficulties(last_block: String, max_num_blocks: Option<u32>) -> RpcResult<String>;
    async fn max_block_difficulty(last_block: String, max_num_blocks: Option<u32>) -> RpcResult<String>;

    // Transaction Operations
    async fn send(address: String, amount: String, fee: String, receiver_tag: String, notify_self: String, notify_other: String) -> RpcResult<String>;
    async fn send_to_many(outputs: Vec<String>, fee: String, file: Option<String>) -> RpcResult<String>;
    async fn send_transparent(outputs: Vec<String>, fee: String, file: Option<String>) -> RpcResult<String>;
    async fn claim_utxo(format: String, data: String, max_search_depth: Option<u32>) -> RpcResult<String>;
    async fn upgrade(tx_kernel_id: String) -> RpcResult<()>;

    // Node Control
    async fn shutdown() -> RpcResult<()>;
    async fn freeze() -> RpcResult<()>;
    async fn unfreeze() -> RpcResult<()>;
    async fn pause_miner() -> RpcResult<()>;
    async fn restart_miner() -> RpcResult<()>;
    async fn set_tip(digest: Digest) -> RpcResult<()>;
    async fn prune_abandoned_monitored_utxos() -> RpcResult<u32>;

    // Broadcasting
    async fn broadcast_mempool_transactions() -> RpcResult<()>;
    async fn broadcast_block_proposal() -> RpcResult<()>;

    // Development & Testing
    async fn mine_blocks_to_wallet(num_blocks: Option<u32>) -> RpcResult<()>;
}
```

#### 3. Implement Authentication System

**File**: `neptune-core-cli/src/rpc/auth.rs`

```rust
use std::path::PathBuf;
use rand::Rng;
use tokio::fs;

#[derive(Debug, Clone)]
pub struct Cookie([u8; 32]);

impl Cookie {
    pub async fn try_new(data_dir: &PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        // Check if neptune-core cookie exists first
        let neptune_cookie_path = data_dir.join(".cookie");
        if neptune_cookie_path.exists() {
            // Use existing neptune-core cookie
            let cookie_data = fs::read(&neptune_cookie_path).await?;
            if cookie_data.len() == 32 {
                let mut secret = [0u8; 32];
                secret.copy_from_slice(&cookie_data);
                return Ok(Cookie(secret));
            }
        }

        // Generate new cookie for neptune-cli
        Self::try_new_with_secret(data_dir, Self::gen_secret()).await
    }

    fn gen_secret() -> [u8; 32] {
        let mut secret = [0u8; 32];
        rand::thread_rng().fill(&mut secret);
        secret
    }

    async fn try_new_with_secret(
        data_dir: &PathBuf,
        secret: [u8; 32],
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let cookie_path = data_dir.join(".neptune-cli-cookie");
        let mut path_tmp = cookie_path.clone();
        let extension = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(16)
            .collect::<String>();
        path_tmp.set_extension(extension);

        if let Some(parent_dir) = cookie_path.parent() {
            fs::create_dir_all(parent_dir).await?;
        }

        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path_tmp)
            .await?;

        file.write_all(&secret).await?;
        file.sync_all().await?;
        drop(file);
        fs::rename(&path_tmp, &cookie_path).await?;

        Ok(Cookie(secret))
    }

    pub fn auth(&self, valid_tokens: &[Cookie]) -> Result<(), String> {
        if valid_tokens.contains(self) {
            Ok(())
        } else {
            Err("Invalid authentication token".to_string())
        }
    }
}

impl PartialEq for Cookie {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
```

#### 4. Create RPC Server Implementation

**File**: `neptune-core-cli/src/rpc/server.rs`

```rust
use crate::rpc::{NeptuneCliRPC, NeptuneCliRPCServer};
use crate::rpc::auth::Cookie;
use std::path::PathBuf;
use tarpc::context;
use neptune_cash::types::*;
use neptune_cash::api::*;
use neptune_cash::application::rpc::client::NeptuneRPCClient;
use tarpc::serde_transport::tcp;

pub struct NeptuneCliRPCServerImpl {
    data_directory: PathBuf,
    valid_tokens: Vec<Cookie>,
    neptune_rpc_client: Option<NeptuneRPCClient>,
}

impl NeptuneCliRPCServerImpl {
    pub fn new(data_directory: PathBuf, valid_tokens: Vec<Cookie>) -> Self {
        Self {
            data_directory,
            valid_tokens,
            neptune_rpc_client: None,
        }
    }

    // Helper method to get neptune-core RPC client
    async fn get_neptune_client(&self) -> Result<NeptuneRPCClient, String> {
        if let Some(ref client) = self.neptune_rpc_client {
            Ok(client.clone())
        } else {
            // Connect to neptune-core RPC server
            let transport = tcp::connect("127.0.0.1", 9799, tarpc::serde_transport::tcp::Json::default)
                .await
                .map_err(|e| format!("Failed to connect to neptune-core: {}", e))?;
            let client = NeptuneRPCClient::new(tarpc::client::Config::default(), transport).spawn()
                .map_err(|e| format!("Failed to create neptune-core client: {}", e))?;
            Ok(client)
        }
    }
}

#[tarpc::server]
impl NeptuneCliRPC for NeptuneCliRPCServerImpl {
    // Standalone Commands (No Server Required)
    async fn generate_wallet(self, _: context::Context, network: Option<String>) -> RpcResult<String> {
        // Implement standalone wallet generation logic
        // ... existing generate_wallet logic from main.rs ...
    }

    async fn which_wallet(self, _: context::Context, network: Option<String>) -> RpcResult<String> {
        // Implement standalone which_wallet logic
        // ... existing which_wallet logic from main.rs ...
    }

    async fn export_seed_phrase(self, _: context::Context, network: Option<String>) -> RpcResult<String> {
        // Implement standalone export_seed_phrase logic
        // ... existing export_seed_phrase logic from main.rs ...
    }

    async fn import_seed_phrase(self, _: context::Context, seed_phrase: String, network: Option<String>) -> RpcResult<()> {
        // Implement standalone import_seed_phrase logic
        // ... existing import_seed_phrase logic from main.rs ...
    }

    async fn nth_receiving_address(self, _: context::Context, n: u32, network: Option<String>) -> RpcResult<String> {
        // Implement standalone nth_receiving_address logic
        // ... existing nth_receiving_address logic from main.rs ...
    }

    async fn premine_receiving_address(self, _: context::Context, network: Option<String>) -> RpcResult<String> {
        // Implement standalone premine_receiving_address logic
        // ... existing premine_receiving_address logic from main.rs ...
    }

    async fn shamir_share(self, _: context::Context, t: u32, n: u32, network: Option<String>) -> RpcResult<Vec<String>> {
        // Implement standalone shamir_share logic
        // ... existing shamir_share logic from main.rs ...
    }

    async fn shamir_combine(self, _: context::Context, t: u32, network: Option<String>) -> RpcResult<()> {
        // Implement standalone shamir_combine logic
        // ... existing shamir_combine logic from main.rs ...
    }

    async fn completions(self, _: context::Context, shell: String) -> RpcResult<String> {
        // Implement standalone completions logic
        // ... existing completions logic from main.rs ...
    }

    async fn help(self, _: context::Context, command: Option<String>) -> RpcResult<String> {
        // Implement standalone help logic
        // ... existing help logic from main.rs ...
    }

    // RPC Commands (Requires neptune-core Server)
    async fn network(self, _: context::Context) -> RpcResult<String> {
        let client = self.get_neptune_client().await?;
        let result = client.network(context::current()).await?;
        Ok(result)
    }

    async fn own_listen_address_for_peers(self, _: context::Context) -> RpcResult<String> {
        let client = self.get_neptune_client().await?;
        let result = client.own_listen_address_for_peers(context::current()).await?;
        Ok(result)
    }

    async fn own_instance_id(self, _: context::Context) -> RpcResult<String> {
        let client = self.get_neptune_client().await?;
        let result = client.own_instance_id(context::current()).await?;
        Ok(result)
    }

    async fn block_height(self, _: context::Context) -> RpcResult<BlockHeight> {
        let client = self.get_neptune_client().await?;
        let result = client.block_height(context::current()).await?;
        Ok(result)
    }

    async fn block_info(self, _: context::Context, block_selector: String) -> RpcResult<String> {
        let client = self.get_neptune_client().await?;
        let result = client.block_info(context::current(), block_selector).await?;
        Ok(result)
    }

    async fn block_digests_by_height(self, _: context::Context, height: BlockHeight) -> RpcResult<Vec<Digest>> {
        let client = self.get_neptune_client().await?;
        let result = client.block_digests_by_height(context::current(), height).await?;
        Ok(result)
    }

    async fn best_block_proposal(self, _: context::Context) -> RpcResult<String> {
        let client = self.get_neptune_client().await?;
        let result = client.best_block_proposal(context::current()).await?;
        Ok(result)
    }

    async fn confirmations(self, _: context::Context) -> RpcResult<String> {
        let client = self.get_neptune_client().await?;
        let result = client.confirmations(context::current()).await?;
        Ok(result)
    }

    async fn tip_digest(self, _: context::Context) -> RpcResult<Digest> {
        let client = self.get_neptune_client().await?;
        let result = client.tip_digest(context::current()).await?;
        Ok(result)
    }

    async fn latest_tip_digests(self, _: context::Context, n: u32) -> RpcResult<Vec<Digest>> {
        let client = self.get_neptune_client().await?;
        let result = client.latest_tip_digests(context::current(), n).await?;
        Ok(result)
    }

    async fn tip_header(self, _: context::Context, n: u32) -> RpcResult<String> {
        let client = self.get_neptune_client().await?;
        let result = client.tip_header(context::current(), n).await?;
        Ok(result)
    }

    async fn header(self, _: context::Context, block_selector: String) -> RpcResult<String> {
        let client = self.get_neptune_client().await?;
        let result = client.header(context::current(), block_selector).await?;
        Ok(result)
    }

    async fn confirmed_available_balance(self, _: context::Context) -> RpcResult<NativeCurrencyAmount> {
        let client = self.get_neptune_client().await?;
        let result = client.confirmed_available_balance(context::current()).await?;
        Ok(result)
    }

    async fn unconfirmed_available_balance(self, _: context::Context) -> RpcResult<NativeCurrencyAmount> {
        let client = self.get_neptune_client().await?;
        let result = client.unconfirmed_available_balance(context::current()).await?;
        Ok(result)
    }

    async fn wallet_status(self, _: context::Context, json: bool, table: bool) -> RpcResult<String> {
        let client = self.get_neptune_client().await?;
        let result = client.wallet_status(context::current(), json, table).await?;
        Ok(result)
    }

    async fn num_expected_utxos(self, _: context::Context) -> RpcResult<u32> {
        let client = self.get_neptune_client().await?;
        let result = client.num_expected_utxos(context::current()).await?;
        Ok(result)
    }

    async fn next_receiving_address(self, _: context::Context) -> RpcResult<ReceivingAddress> {
        let client = self.get_neptune_client().await?;
        let result = client.next_receiving_address(context::current()).await?;
        Ok(result)
    }

    async fn list_coins(self, _: context::Context) -> RpcResult<String> {
        let client = self.get_neptune_client().await?;
        let result = client.list_coins(context::current()).await?;
        Ok(result)
    }

    // ... implement all other RPC methods by delegating to neptune-core client ...

    // Mempool Operations
    async fn mempool_tx_count(self, _: context::Context) -> RpcResult<u32> {
        let client = self.get_neptune_client().await?;
        let result = client.mempool_tx_count(context::current()).await?;
        Ok(result)
    }

    async fn mempool_size(self, _: context::Context) -> RpcResult<u64> {
        let client = self.get_neptune_client().await?;
        let result = client.mempool_size(context::current()).await?;
        Ok(result)
    }

    async fn list_mempool_transaction_ids(self, _: context::Context) -> RpcResult<Vec<String>> {
        let client = self.get_neptune_client().await?;
        let result = client.list_mempool_transaction_ids(context::current()).await?;
        Ok(result)
    }

    async fn clear_mempool(self, _: context::Context) -> RpcResult<()> {
        let client = self.get_neptune_client().await?;
        let result = client.clear_mempool(context::current()).await?;
        Ok(result)
    }

    // ... continue with all other methods ...
}
```

#### 5. Add RPC Server Startup

**File**: `neptune-core-cli/src/main.rs`

```rust
use crate::rpc::{NeptuneCliRPCServer, NeptuneCliRPCServerImpl};
use crate::rpc::auth::Cookie;
use tarpc::serde_transport::tcp;
use tarpc::server::BaseChannel;

// Add RPC server startup logic
async fn start_rpc_server(data_directory: PathBuf, rpc_port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let mut rpc_listener = tcp::listen(
        format!("127.0.0.1:{}", rpc_port),
        tarpc::serde_transport::tcp::Json::default,
    ).await?;

    rpc_listener.config_mut().max_frame_length(usize::MAX);

    // Generate or load authentication cookie
    let valid_tokens: Vec<Cookie> = vec![
        Cookie::try_new(&data_directory).await?.into(),
    ];

    let rpc_join_handle = tokio::spawn(
        rpc_listener
            .filter_map(|r| future::ready(r.ok()))
            .map(BaseChannel::with_defaults)
            .max_channels_per_key(5, |t| t.transport().peer_addr().unwrap().ip())
            .map(move |channel| {
                let server = NeptuneCliRPCServerImpl::new(
                    data_directory.clone(),
                    valid_tokens.clone(),
                );
                channel.execute(server.serve()).for_each(spawn)
            })
            .buffer_unordered(10)
            .for_each(|_| async {})
            .await;
    );

    info!("Started neptune-cli RPC server on port {}", rpc_port);
    Ok(())
}
```

#### 6. Add RPC Mode Command Line Option

**File**: `neptune-core-cli/src/main.rs`

```rust
#[derive(Parser)]
#[command(name = "neptune-cli")]
#[command(about = "An RPC client")]
pub struct Args {
    #[arg(short, long, default_value = "9799")]
    pub port: u16,

    #[arg(long)]
    pub data_dir: Option<PathBuf>,

    #[arg(long)]
    pub rpc_mode: bool,

    #[arg(long, default_value = "9798")]
    pub rpc_port: u16,

    #[command(subcommand)]
    pub command: Option<Command>,
}

// In main function
if args.rpc_mode {
    let data_directory = args.data_dir
        .unwrap_or_else(|| DataDirectory::get().unwrap());

    start_rpc_server(data_directory, args.rpc_port).await?;

    // Keep the server running
    tokio::signal::ctrl_c().await?;
    return Ok(());
}
```

#### 7. Create RPC Client for Testing

**File**: `neptune-core-cli/src/rpc/client.rs`

```rust
use crate::rpc::{NeptuneCliRPC, NeptuneCliRPCClient};
use tarpc::serde_transport::tcp;
use tarpc::client::Rpc;

pub async fn create_rpc_client(port: u16) -> Result<NeptuneCliRPCClient, Box<dyn std::error::Error>> {
    let transport = tcp::connect("127.0.0.1", port, tarpc::serde_transport::tcp::Json::default).await?;
    let client = NeptuneCliRPCClient::new(tarpc::client::Config::default(), transport).spawn()?;
    Ok(client)
}
```

### Usage Examples

#### Start RPC Server

```bash
neptune-cli --rpc-mode --rpc-port 9798
```

#### Use RPC Client

```bash
# Standalone Commands (No Server Required)
# Generate wallet via RPC
curl -X POST http://localhost:9798/rpc \
  -H "Content-Type: application/json" \
  -d '{"method": "generate_wallet", "params": [null], "id": 1}'

# Export seed phrase via RPC
curl -X POST http://localhost:9798/rpc \
  -H "Content-Type: application/json" \
  -d '{"method": "export_seed_phrase", "params": [null], "id": 1}'

# Get nth receiving address via RPC
curl -X POST http://localhost:9798/rpc \
  -H "Content-Type: application/json" \
  -d '{"method": "nth_receiving_address", "params": [0, null], "id": 1}'

# Shamir share via RPC
curl -X POST http://localhost:9798/rpc \
  -H "Content-Type: application/json" \
  -d '{"method": "shamir_share", "params": [3, 5, null], "id": 1}'

# RPC Commands (Requires neptune-core Server)
# Get network info via RPC
curl -X POST http://localhost:9798/rpc \
  -H "Content-Type: application/json" \
  -d '{"method": "network", "params": [], "id": 1}'

# Get block height via RPC
curl -X POST http://localhost:9798/rpc \
  -H "Content-Type: application/json" \
  -d '{"method": "block_height", "params": [], "id": 1}'

# Get wallet status via RPC
curl -X POST http://localhost:9798/rpc \
  -H "Content-Type: application/json" \
  -d '{"method": "wallet_status", "params": [false, true], "id": 1}'

# Get confirmed balance via RPC
curl -X POST http://localhost:9798/rpc \
  -H "Content-Type: application/json" \
  -d '{"method": "confirmed_available_balance", "params": [], "id": 1}'

# Send transaction via RPC
curl -X POST http://localhost:9798/rpc \
  -H "Content-Type: application/json" \
  -d '{"method": "send", "params": ["address_here", "100", "1", "tag", "onchain", "onchain"], "id": 1}'

# Send to many via RPC
curl -X POST http://localhost:9798/rpc \
  -H "Content-Type: application/json" \
  -d '{"method": "send_to_many", "params": [["addr1:50", "addr2:30"], "2", null], "id": 1}'

# Get peer info via RPC
curl -X POST http://localhost:9798/rpc \
  -H "Content-Type: application/json" \
  -d '{"method": "peer_info", "params": [], "id": 1}'

# Get mempool info via RPC
curl -X POST http://localhost:9798/rpc \
  -H "Content-Type: application/json" \
  -d '{"method": "mempool_tx_count", "params": [], "id": 1}'

# Control mining via RPC
curl -X POST http://localhost:9798/rpc \
  -H "Content-Type: application/json" \
  -d '{"method": "pause_miner", "params": [], "id": 1}'

# Mine blocks via RPC (RegTest only)
curl -X POST http://localhost:9798/rpc \
  -H "Content-Type: application/json" \
  -d '{"method": "mine_blocks_to_wallet", "params": [10], "id": 1}'
```

### Architecture Overview

The neptune-cli RPC mode provides a unified interface that exposes ALL neptune-cli methods via JSON-RPC:

#### Method Categories

1. **Standalone Methods**: Executed directly by neptune-cli without requiring neptune-core server

   - Wallet management (generate, import, export, Shamir sharing)
   - Address generation (nth, premine)
   - Utility functions (completions, help)

2. **RPC Methods**: Delegated to neptune-core server via tarpc client
   - Blockchain data (block height, block info, confirmations)
   - Wallet operations (balances, status, UTXOs)
   - Mempool operations (count, size, transactions)
   - Peer management (info, standings)
   - Transaction operations (send, claim, upgrade)
   - Node control (shutdown, freeze, mining)
   - Broadcasting (mempool, block proposals)
   - Development/testing (mine blocks, coinbase distribution)

#### Implementation Strategy

- **Standalone Methods**: Implemented directly in neptune-cli RPC server using existing logic from `main.rs`
- **RPC Methods**: Implemented as proxy methods that forward requests to neptune-core RPC server
- **Authentication**: Uses same cookie-based system as neptune-core
- **Error Handling**: Consistent error responses across all methods
- **Type Safety**: Proper Rust types for all parameters and return values

### Benefits

1. **Complete API Coverage**: All neptune-cli methods available via JSON-RPC
2. **Remote Access**: Access both standalone and server-dependent functions remotely
3. **Consistent Authentication**: Uses same cookie system as neptune-core
4. **Dual Approach**: Supports both shared and independent cookie modes
5. **Extensible**: Easy to add more RPC methods in the future
6. **Compatible**: Follows existing neptune-core patterns
7. **Unified Interface**: Single RPC endpoint for all neptune-cli functionality

### Security Considerations

1. **Cookie-based Authentication**: Same security model as neptune-core
2. **Localhost Only**: RPC server binds to 127.0.0.1 by default
3. **Token Validation**: All RPC methods require valid authentication
4. **File Permissions**: Cookie files have restricted permissions

### Testing Strategy

1. **Unit Tests**: Test individual RPC methods
2. **Integration Tests**: Test RPC server startup and client connections
3. **Authentication Tests**: Test cookie generation and validation
4. **End-to-End Tests**: Test complete RPC workflows

### Future Enhancements

1. **TLS Support**: Add TLS encryption for RPC connections
2. **Rate Limiting**: Implement rate limiting for RPC calls
3. **Logging**: Add comprehensive RPC request/response logging
4. **Metrics**: Add RPC performance metrics
5. **WebSocket Support**: Add WebSocket transport for real-time updates
