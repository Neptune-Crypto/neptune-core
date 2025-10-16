# Wallet Integration Testing Guide

## Overview

This guide tests the neptune-cli RPC server with your Trident Wallet app running, which spawns neptune-core. This provides the most realistic testing scenario.

## Prerequisites

- ✅ neptune-cli binary built (`cargo build --release` completed)
- ✅ Trident Wallet app ready to run
- ✅ Wallet configured to spawn neptune-core

## Testing Workflow

### Step 1: Start Your Wallet App

```bash
# From your wallet directory
cd /home/anon/Documents/GitHub_alt/trident-wallet
pnpm start
```

**What to expect:**

- Wallet app starts
- Neptune Core gets spawned by your wallet
- Neptune Core should be running on port 9799 (default)

### Step 2: Verify Neptune Core is Running

```bash
# Check if neptune-core is running
ps aux | grep neptune-core | grep -v grep

# Check if it's listening on port 9799
netstat -tlnp | grep 9799 || ss -tlnp | grep 9799
```

### Step 3: Get Authentication Cookie

```bash
# From the neptune-cli directory
cd external/neptune-core/neptune-core-cli

# Get the authentication cookie
./target/release/neptune-cli --get-cookie
```

**Expected output:**

```
Cookie: <long_hex_string>
```

**Copy this cookie** - you'll need it for all RPC calls.

### Step 4: Start RPC Server

```bash
# Start the HTTP JSON-RPC server on port 9800
./target/release/neptune-cli --rpc-mode --rpc-port 9800
```

**Expected output:**

```
RPC server started on port 9800
```

### Step 5: Test Key Endpoints

#### Test 1: Basic Connectivity

```bash
# Test server is responding
curl -s http://localhost:9800
```

#### Test 2: Network Information

```bash
curl -X POST http://localhost:9800 \
  -H "Content-Type: application/json" \
  -H "Cookie: neptune-cli=YOUR_COOKIE_HERE" \
  -d '{"jsonrpc": "2.0", "method": "network", "id": 1}'
```

#### Test 3: Block Height

```bash
curl -X POST http://localhost:9800 \
  -H "Content-Type: application/json" \
  -H "Cookie: neptune-cli=YOUR_COOKIE_HERE" \
  -d '{"jsonrpc": "2.0", "method": "block_height", "id": 2}'
```

#### Test 4: Dashboard Overview (Main Endpoint) ⭐

```bash
curl -X POST http://localhost:9800 \
  -H "Content-Type: application/json" \
  -H "Cookie: neptune-cli=YOUR_COOKIE_HERE" \
  -d '{"jsonrpc": "2.0", "method": "dashboard_overview_data", "id": 3}'
```

**This is the most important test** - this endpoint provides everything your wallet needs.

#### Test 5: Balance Information

```bash
# Confirmed balance
curl -X POST http://localhost:9800 \
  -H "Content-Type: application/json" \
  -H "Cookie: neptune-cli=YOUR_COOKIE_HERE" \
  -d '{"jsonrpc": "2.0", "method": "confirmed_available_balance", "id": 4}'

# Unconfirmed balance
curl -X POST http://localhost:9800 \
  -H "Content-Type: application/json" \
  -H "Cookie: neptune-cli=YOUR_COOKIE_HERE" \
  -d '{"jsonrpc": "2.0", "method": "unconfirmed_available_balance", "id": 5}'
```

#### Test 6: Peer Information

```bash
curl -X POST http://localhost:9800 \
  -H "Content-Type: application/json" \
  -H "Cookie: neptune-cli=YOUR_COOKIE_HERE" \
  -d '{"jsonrpc": "2.0", "method": "peer_info", "id": 6}'
```

### Step 6: Test Wallet-Specific Endpoints

#### Get Wallet Status

```bash
curl -X POST http://localhost:9800 \
  -H "Content-Type: application/json" \
  -H "Cookie: neptune-cli=YOUR_COOKIE_HERE" \
  -d '{"jsonrpc": "2.0", "method": "wallet_status", "id": 7}'
```

#### Get Next Receiving Address

```bash
curl -X POST http://localhost:9800 \
  -H "Content-Type: application/json" \
  -H "Cookie: neptune-cli=YOUR_COOKIE_HERE" \
  -d '{"jsonrpc": "2.0", "method": "next_receiving_address", "id": 8}'
```

#### Get Transaction History

```bash
curl -X POST http://localhost:9800 \
  -H "Content-Type: application/json" \
  -H "Cookie: neptune-cli=YOUR_COOKIE_HERE" \
  -d '{"jsonrpc": "2.0", "method": "history", "id": 9}'
```

## Expected Results

### Successful Response Format

```json
{
  "jsonrpc": "2.0",
  "result": <actual_data>,
  "id": <request_id>
}
```

### Dashboard Overview Data Structure

```json
{
  "jsonrpc": "2.0",
  "result": {
    "tip_digest": "abc123...",
    "tip_header": {
      "height": 12345,
      "timestamp": "2024-01-01T00:00:00Z"
    },
    "syncing": false,
    "confirmed_available_balance": "1000000",
    "confirmed_total_balance": "1000000",
    "unconfirmed_available_balance": "0",
    "unconfirmed_total_balance": "0",
    "mempool_size": 1024,
    "mempool_total_tx_count": 5,
    "mempool_own_tx_count": 0,
    "peer_count": 3,
    "max_num_peers": 50,
    "mining_status": "active",
    "proving_capability": "enabled",
    "confirmations": "100",
    "cpu_temp": 45.5
  },
  "id": 3
}
```

## Troubleshooting

### Common Issues

1. **"Connection refused" to neptune-core**
   - Make sure your wallet app is running
   - Check if neptune-core spawned successfully
   - Verify neptune-core is listening on port 9799

2. **"Invalid cookie"**
   - Get a fresh cookie after neptune-core is running
   - Make sure neptune-core is fully started before getting cookie

3. **"Method not found"**
   - Check method name spelling
   - Verify JSON-RPC format is correct

4. **"Internal error"**
   - Check neptune-core logs in your wallet app
   - Make sure neptune-core is synced

### Debug Commands

```bash
# Check neptune-core process
ps aux | grep neptune-core

# Check port usage
netstat -tlnp | grep 9799

# Check RPC server logs
tail -f /tmp/neptune-rpc.log  # if using our test script

# Test neptune-core directly
./target/release/neptune-cli network
```

## Integration Validation

### What to Verify

1. **✅ neptune-core is running** (spawned by wallet)
2. **✅ RPC server connects to neptune-core** (cookie works)
3. **✅ All endpoints return valid data** (no errors)
4. **✅ Dashboard overview provides comprehensive data** (main endpoint)
5. **✅ Response formats match expected structure** (JSON-RPC 2.0)

### Performance Notes

- **Dashboard overview** provides everything in one call (most efficient)
- **Individual endpoints** work but require multiple calls
- **Cookie authentication** is working properly
- **Response times** should be reasonable (< 1 second)

## Next Steps

Once testing is successful:

1. **Update your wallet's blockchain-service.ts** to use RPC endpoints
2. **Replace mock data calls** with real RPC calls
3. **Implement cookie management** in your wallet
4. **Test wallet UI integration** with real data
5. **Optimize for single dashboard call** instead of multiple endpoints

## Quick Test Script

Save this as `quick-test.sh` and run it:

```bash
#!/bin/bash
COOKIE=$(./target/release/neptune-cli --get-cookie 2>/dev/null | tail -1)
echo "Testing dashboard_overview_data..."
curl -X POST http://localhost:9800 \
  -H "Content-Type: application/json" \
  -H "Cookie: neptune-cli=$COOKIE" \
  -d '{"jsonrpc": "2.0", "method": "dashboard_overview_data", "id": 1}' | jq '.'
```

This will quickly test the main endpoint your wallet needs.
