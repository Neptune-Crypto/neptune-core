# Neptune CLI RPC Integration Guide

## Overview

This guide focuses exclusively on using neptune-cli in RPC mode to serve HTTP JSON-RPC endpoints for the Trident Wallet.

## Quick Start

### 1. Build the RPC Server

```bash
cd external/neptune-core/neptune-core-cli
env cargo build --release
```

### 2. Start the RPC Server

```bash
# Start RPC server on port 9800
./target/release/neptune-cli --rpc-mode --rpc-port 9800

# Get authentication cookie
./target/release/neptune-cli --get-cookie
```

### 3. Test the RPC Server

```bash
# Test with curl (replace <cookie> with actual cookie)
curl -X POST http://localhost:9800 \
  -H "Content-Type: application/json" \
  -H "Cookie: neptune-cli=<cookie>" \
  -d '{"jsonrpc": "2.0", "method": "dashboard_overview_data", "id": 1}'
```

## Key RPC Endpoints for Wallet Integration

### **Primary Endpoint: `dashboard_overview_data`**

This is the **main endpoint** your wallet should use. It provides comprehensive wallet state in a single call:

```json
{
  "jsonrpc": "2.0",
  "method": "dashboard_overview_data",
  "id": 1
}
```

**Response includes:**

- `tip_digest` - Latest block digest
- `tip_header.height` - Current block height
- `tip_header.timestamp` - Block timestamp
- `syncing` - Sync status (boolean)
- `confirmed_available_balance` - Confirmed balance
- `unconfirmed_available_balance` - Unconfirmed balance
- `peer_count` - Connected peer count
- `mempool_total_tx_count` - Mempool transaction count
- `mining_status` - Mining status
- `cpu_temp` - CPU temperature

### **Supporting Endpoints**

#### Network Information

```json
{
  "jsonrpc": "2.0",
  "method": "network",
  "id": 2
}
```

#### Peer Information

```json
{
  "jsonrpc": "2.0",
  "method": "peer_info",
  "id": 3
}
```

#### Transaction History

```json
{
  "jsonrpc": "2.0",
  "method": "history",
  "id": 4
}
```

#### Send Transaction

```json
{
  "jsonrpc": "2.0",
  "method": "send",
  "params": {
    "outputs": [{ "address": "nolgam1...", "amount": "1000" }],
    "change_policy": "default",
    "fee": "10"
  },
  "id": 5
}
```

## Wallet Integration Strategy

### **Recommended Approach: Single Dashboard Call**

Instead of making multiple API calls, use `dashboard_overview_data` as your primary endpoint:

```typescript
// In your blockchain-service.ts
async getWalletOverview(): Promise<WalletOverviewData> {
  const response = await this.makeRpcRequest('dashboard_overview_data');

  return {
    balance: {
      confirmed: response.confirmed_available_balance,
      unconfirmed: response.unconfirmed_available_balance
    },
    network: {
      blockHeight: response.tip_header.height,
      tipDigest: response.tip_digest,
      syncing: response.syncing
    },
    peers: {
      connected: response.peer_count,
      max: response.max_num_peers
    },
    mempool: {
      size: response.mempool_size,
      txCount: response.mempool_total_tx_count
    },
    mining: {
      status: response.mining_status,
      capability: response.proving_capability
    }
  };
}
```

### **Authentication**

All RPC calls require a cookie header:

```typescript
const headers = {
  "Content-Type": "application/json",
  Cookie: `neptune-cli=${cookie}`,
};
```

## Available RPC Methods

### **Wallet Operations**

- `dashboard_overview_data` - **Primary endpoint for wallet state**
- `confirmed_available_balance` - Confirmed balance only
- `unconfirmed_available_balance` - Unconfirmed balance only
- `wallet_status` - Detailed wallet status
- `next_receiving_address` - Get next receiving address
- `history` - Transaction history
- `list_own_coins` - List owned coins

### **Network Operations**

- `network` - Network information
- `block_height` - Current block height
- `peer_info` - Peer information
- `confirmations` - Confirmation status

### **Transaction Operations**

- `send` - Send transaction
- `send_transparent` - Send transparent transaction
- `claim_utxo` - Claim UTXO
- `validate_address` - Validate address
- `validate_amount` - Validate amount

### **Mining Operations**

- `pause_miner` - Pause mining
- `restart_miner` - Restart mining

### **System Operations**

- `shutdown` - Shutdown neptune-core

## Error Handling

### **Common Error Codes**

- `-32600` - Invalid Request
- `-32601` - Method not found
- `-32602` - Invalid params
- `-32603` - Internal error
- `-32000` - Server error

### **Authentication Errors**

- Missing or invalid cookie
- neptune-core not running
- Connection refused

## Development Workflow

1. **Start neptune-core** (if not already running)
2. **Start RPC server**: `./neptune-cli --rpc-mode --rpc-port 9800`
3. **Get cookie**: `./neptune-cli --get-cookie`
4. **Test endpoints** with curl or your wallet
5. **Integrate with wallet** using the RPC endpoints

## Performance Considerations

- **Use `dashboard_overview_data`** for comprehensive data in one call
- **Cache responses** to reduce API calls
- **Implement retry logic** for network failures
- **Handle authentication** gracefully

## Security Notes

- **Never expose the RPC server** to the internet
- **Use localhost only** for development
- **Keep cookies secure** in your wallet
- **Validate all responses** before using data
