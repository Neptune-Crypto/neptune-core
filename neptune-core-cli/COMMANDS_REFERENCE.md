# Neptune CLI Commands Reference

## Available Commands

### **READ STATE Commands**

- `network` - Retrieve network that neptune-core is running on
- `own-listen-address-for-peers` - Retrieve address for peers to contact this node
- `own-instance-id` - Retrieve instance-id of this neptune-core node
- `block-height` - Retrieve current block height
- `block-info <block_selector>` - Retrieve information about a block
- `block-digests-by-height <height>` - Retrieve block digests for a given block height
- `best-block-proposal` - Get information about the current best block proposal
- `confirmations` - Retrieve confirmations
- `peer-info` - Retrieve info about peers
- `all-punished-peers` - Retrieve list of punished peers
- `tip-digest` - Retrieve digest/hash of newest block
- `latest-tip-digests <n>` - Retrieve digests of newest n blocks
- `tip-header` - Retrieve block-header of any block
- `header <block_selector>` - Retrieve block-header of any block
- `confirmed-available-balance` - Retrieve confirmed balance (excludes time-locked utxos)
- `unconfirmed-available-balance` - Retrieve unconfirmed balance
- `wallet-status` - Export wallet status information (--json or --table)
- `num-expected-utxos` - Retrieves number of utxos the wallet expects to receive
- `next-receiving-address` - Get next unused generation receiving address
- `nth-receiving-address <index>` - Get the nth generation receiving address
- `premine-receiving-address` - Get a static generation receiving address
- `list-coins` - List known coins
- `mempool-tx-count` - Retrieve count of transactions in the mempool
- `mempool-size` - Retrieve size of mempool in bytes
- `list-mempool-transaction-ids` - List mempool transaction IDs

### **BLOCKCHAIN STATISTICS Commands**

- `block-intervals <last_block> [max_num_blocks]` - Show block intervals in milliseconds
- `mean-block-interval <last_block> [max_num_blocks]` - Show mean block interval
- `max-block-interval <last_block> [max_num_blocks]` - Show biggest block interval
- `min-block-interval <last_block> [max_num_blocks]` - Show smallest block interval
- `block-difficulties <last_block> [max_num_blocks]` - Show difficulties for blocks
- `max-block-difficulty <last_block> [max_num_blocks]` - Show largest difficulty

### **PEER INTERACTIONS Commands**

- `broadcast-mempool-transactions` - Broadcast transaction notifications for all transactions in mempool
- `broadcast-block-proposal` - Broadcast a block proposal notification

### **CHANGE STATE Commands**

- `shutdown` - Shutdown neptune-core
- `clear-all-standings` - Clear all peer standings
- `clear-standing-by-ip <ip>` - Clear standings for peer with a given IP
- `claim-utxo <format>` - Claim an off-chain utxo-transfer
- `send <address> <amount> <fee> <receiver_tag> <notify_self> <notify_other>` - Send payment to single recipient
- `send-to-many [--file <file>] <outputs...> --fee <fee>` - Send payment to multiple recipients
- `send-transparent [--file <file>] <outputs...> --fee <fee>` - Send transparent payment (no privacy)
- `upgrade <tx_kernel_id>` - Upgrade the specified transaction
- `clear-mempool` - Delete all transactions from the mempool
- `freeze` - Pause processing of new transaction data
- `unfreeze` - Resume processing if paused
- `pause-miner` - Pause mining
- `restart-miner` - Resume mining
- `set-coinbase-distribution --file <file>` - Set coinbase distribution
- `unset-coinbase-distribution` - Reset coinbase distribution to reward own wallet
- `set-tip <digest>` - Set the tip of the blockchain state
- `prune-abandoned-monitored-utxos` - Prune monitored utxos from abandoned chains

### **RegTest Mode Commands**

- `mine-blocks-to-wallet [num_blocks]` - Mine blocks to the node's wallet (regtest only)

### **WALLET Commands (offline actions)**

- `generate-wallet [--network <network>]` - Generate a new wallet
- `which-wallet [--network <network>]` - Display path to wallet secrets file
- `export-seed-phrase [--network <network>]` - Export mnemonic seed phrase
- `import-seed-phrase [--network <network>]` - Import mnemonic seed phrase
- `shamir-combine <t> [--network <network>]` - Combine shares from Shamir secret sharing
- `shamir-share <t> <n> [--network <network>]` - Share wallet secret using Shamir scheme

### **RPC Server Mode**

- `--rpc-mode` - Start HTTP JSON-RPC server
- `--rpc-port <port>` - RPC server port (default: 9798)
- `--get-cookie` - Get authentication cookie

## Usage Examples

### Basic CLI Usage

```bash
# Get help
./neptune-cli --help

# Get network info
./neptune-cli network

# Get wallet balance
./neptune-cli confirmed-available-balance
./neptune-cli unconfirmed-available-balance

# Get peer info
./neptune-cli peer-info

# Get block height
./neptune-cli block-height
```

### RPC Server Mode

```bash
# Start RPC server on port 9800
./neptune-cli --rpc-mode --rpc-port 9800

# Get authentication cookie
./neptune-cli --get-cookie
```

### Block Selectors

Block selectors can be:

- `genesis` - Genesis block
- `tip` - Latest block
- `height/<n>` - Block at height n
- `digest/<hex>` - Block with specific digest

### Network Options

- `main` - Main network (default)
- `testnet` - Test network
- `regtest` - Regression test network

## HTTP JSON-RPC Endpoints (Implemented)

### **Standalone Methods (No neptune-core required)**

- `completions` - Generate shell completions
- `help` - Generate help text
- `which_wallet` - Display wallet file path
- `generate_wallet` - Generate new wallet
- `export_seed_phrase` - Export mnemonic seed phrase
- `nth_receiving_address` - Get nth receiving address
- `premine_receiving_address` - Get premine receiving address
- `import_seed_phrase` - Import mnemonic seed phrase
- `shamir_share` - Share wallet secret using Shamir scheme
- `shamir_combine` - Combine Shamir shares

### **Server-Dependent Methods (Require neptune-core running)**

- `block_height` - Get current block height
- `network` - Get network information
- `confirmed_available_balance` - Get confirmed balance
- `unconfirmed_available_balance` - Get unconfirmed balance
- `dashboard_overview_data` - **Comprehensive wallet overview data** ⭐
- `next_receiving_address` - Get next receiving address
- `wallet_status` - Get wallet status
- `confirmations` - Get confirmations
- `send` - Send transaction
- `claim_utxo` - Claim UTXO
- `list_own_coins` - List own coins
- `history` - Get transaction history
- `validate_address` - Validate address
- `validate_amount` - Validate amount
- `peer_info` - Get peer information
- `mempool_tx_count` - Get mempool transaction count
- `send_transparent` - Send transparent transaction
- `upgrade` - Upgrade transaction
- `pause_miner` - Pause mining
- `restart_miner` - Restart mining
- `shutdown` - Shutdown neptune-core

### **Key Endpoint: `dashboard_overview_data`**

This endpoint provides comprehensive wallet overview data including:

- `tip_digest` - Latest block digest
- `tip_header` - Latest block header (height, timestamp)
- `syncing` - Sync status
- `confirmed_available_balance` - Confirmed balance
- `confirmed_total_balance` - Total confirmed balance
- `unconfirmed_available_balance` - Unconfirmed balance
- `unconfirmed_total_balance` - Total unconfirmed balance
- `mempool_size` - Mempool size in bytes
- `mempool_total_tx_count` - Total mempool transactions
- `mempool_own_tx_count` - Own mempool transactions
- `peer_count` - Connected peer count
- `max_num_peers` - Maximum peer limit
- `mining_status` - Mining status
- `proving_capability` - Proving capability
- `confirmations` - Confirmations
- `cpu_temp` - CPU temperature

## Notes

- Most commands require neptune-core to be running
- Wallet commands can be run offline
- RPC server mode provides HTTP JSON-RPC endpoints for wallet integration
- Authentication is required for most operations via cookie-based auth
- **`dashboard_overview_data` is the key endpoint for wallet overview functionality**
