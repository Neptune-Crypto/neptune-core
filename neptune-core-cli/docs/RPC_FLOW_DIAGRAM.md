# Neptune-CLI RPC Server Flow Diagram

## Complete RPC Flow Architecture

```mermaid
graph TD
    A[HTTP JSON-RPC Request] --> B[RPC Server<br/>neptune-cli --rpc-mode]
    B --> C{Method Type?}

    C -->|Standalone| D[Standalone Handler<br/>handlers.rs]
    C -->|Server-Dependent| E[Server Handler<br/>handlers.rs]

    D --> D1[generate_wallet]
    D --> D2[export_seed_phrase]
    D --> D3[import_seed_phrase]
    D --> D4[shamir_share]
    D --> D5[shamir_combine]
    D --> D6[which_wallet]
    D --> D7[nth_receiving_address]
    D --> D8[premine_receiving_address]
    D --> D9[completions]
    D --> D10[help]

    D1 --> D11[Direct Wallet Operations<br/>No Server Required]
    D2 --> D11
    D3 --> D11
    D4 --> D11
    D5 --> D11
    D6 --> D11
    D7 --> D11
    D8 --> D11
    D9 --> D11
    D10 --> D11

    E --> F[Reuse Existing Connection Logic<br/>from main.rs lines 755-785]
    F --> F1[Connect to neptune-core<br/>Port 9799 via tarpc]
    F1 --> F2[Get Cookie Hint<br/>data_directory & network]
    F2 --> F3[Load neptune-core Cookie<br/>auth::Cookie::try_load]
    F3 --> F4[Convert to Token<br/>auth::Token::from]
    F4 --> J[neptune-core RPC Methods<br/>Same pattern as CLI commands]

    J --> J1[block_height]
    J --> J2[network]
    J --> J3[list_coins]
    J --> J4[confirmed_available_balance]
    J --> J5[unconfirmed_available_balance]
    J --> J6[wallet_status]
    J --> J7[peer_info]
    J --> J8[tip_digest]
    J --> J9[header]
    J --> J10[block_info]
    J --> J11[send]
    J --> J12[claim_utxo]
    J --> J13[freeze_utxo]
    J --> J14[unfreeze_utxo]
    J --> J15[pause_miner]
    J --> J16[restart_miner]
    J --> J17[mine_blocks_to_wallet]

    D11 --> K[Response to Client]
    J --> K

    style A fill:#e1f5fe
    style B fill:#f3e5f5
    style C fill:#fff3e0
    style D fill:#e8f5e8
    style E fill:#fff8e1
    style G fill:#fce4ec
    style J fill:#e0f2f1
    style K fill:#e1f5fe
    style L fill:#e1f5fe
```

## Flow Description

### 1. **HTTP JSON-RPC Request**

- Client sends HTTP POST request to neptune-cli RPC server
- Request includes method name, parameters, and authentication cookie

### 2. **RPC Server Routing**

- neptune-cli RPC server receives request
- Routes to appropriate handler based on method type

### 3. **Standalone Methods** (No neptune-core required)

- **Wallet Operations**: generate_wallet, export_seed_phrase, import_seed_phrase
- **Address Generation**: nth_receiving_address, premine_receiving_address
- **Shamir Secret Sharing**: shamir_share, shamir_combine
- **Utility**: which_wallet, completions, help
- These methods work directly with wallet files and don't need neptune-core

### 4. **Server-Dependent Methods** (Require neptune-core)

- **Connection**: Reuse existing connection logic from `main.rs` (lines 755-785)
- **Authentication**: Use neptune-core's existing cookie system
  - Load neptune-core's `.cookie` file via `auth::Cookie::try_load()`
  - Convert to `auth::Token` for RPC calls
- **RPC Calls**: Use exact same tarpc pattern as CLI commands

### 5. **neptune-core RPC Methods**

- **Read State**: block_height, network, list_coins, balances, wallet_status
- **Blockchain**: tip_digest, header, block_info, peer_info
- **Transactions**: send, claim_utxo, freeze_utxo, unfreeze_utxo
- **Mining**: pause_miner, restart_miner, mine_blocks_to_wallet

### 6. **Response**

- All methods return JSON-RPC response
- Sent back to client via HTTP

## Key Features

- **Reused Connection Logic**: Server-dependent methods copy the exact connection pattern from `main.rs`
- **Method Separation**: Clear distinction between standalone and server-dependent methods
- **Proven Authentication**: Uses neptune-core's existing cookie system (`auth::Cookie::try_load()`)
- **Consistent Interface**: All methods use the same JSON-RPC interface
- **No New Code**: Simply copy existing, working tarpc connection logic
