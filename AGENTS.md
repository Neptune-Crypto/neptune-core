# AGENTS.md

## Project Overview

Neptune Core is an anonymous peer-to-peer cash system implemented in Rust. This is a fork of the original [Neptune-Crypto/neptune-core](https://github.com/Neptune-Crypto/neptune-core) repository.

## Build Commands

### Prerequisites

- Rust toolchain (latest stable)
- CMake (for compatibility)
- Build essentials (for `make`)

### Build Instructions

- **Release build**: `CMAKE_POLICY_VERSION_MINIMUM=3.5 cargo build --release`
- **Debug build**: `CMAKE_POLICY_VERSION_MINIMUM=3.5 cargo build`
- **Install binaries**: `cargo install --locked --path neptune-core`
- **Install CLI**: `cargo install --locked --path neptune-core-cli`
- **Install dashboard**: `cargo install --locked --path neptune-dashboard`

### Development Setup

- **Quick build check**: `cargo check`
- **Run tests**: `cargo test`
- **Format code**: `cargo fmt`
- **Lint code**: `cargo clippy`

## Code Style

- Follow the Rust style guide in `.cursor/rules/styleguide.mdc`
- Use 4 spaces for indentation (never tabs)
- Maximum line width: 100 characters
- Prefer block indent over visual indent
- Use trailing commas in multi-line structures
- Complete sentences in comments with proper capitalization and periods

## Testing Instructions

### Unit Tests

- Run all tests: `cargo test`
- Run specific test: `cargo test test_name`
- Run with output: `cargo test -- --nocapture`

### Integration Tests

- **Multi-instance test**: `./scripts/linux/run-multiple-instances.sh`
- **Restart test**: `make restart` then `./scripts/linux/run-multiple-instances.sh`
- **Transaction test**: Create transactions between instances and verify mining/balances

### Test Strategy

1. `cargo build` - verify builds without warnings
2. `cargo test` - verify all unit tests pass
3. `run-multiple-instances.sh` - spin up 3 connected nodes
4. `make restart` + `run-multiple-instances.sh` - test from genesis block
5. Manual transaction testing between instances

## Running the Application

### Generate Wallet

```bash
neptune-cli generate-wallet
```

### Start Daemon

```bash
neptune-core --peer [ip_address:port] --compose --guess
```

### Start Dashboard

```bash
neptune-dashboard
```

### CLI Commands

```bash
neptune-cli --help
neptune-cli block-height
```

## Development Environment

### VS Code Setup

- Install `rust-analyzer` extension
- Enable format-on-save
- Install `cpulimit` for integration tests: `apt install cpulimit`

### Logging

- Set log level: `RUST_LOG=trace cargo run`
- Default: `RUST_LOG='info,tarpc=warn'`
- Development: `RUST_LOG='debug,tarpc=warn'`
- Filtered output: `cargo run 2>&1 | sed 's/.*neptune_core:\+\(.*\)/\1/g'`

### Tokio Console (Optional)

- Build with feature: `cargo install --features tokio-console --locked --path .`
- Install console: `cargo install --locked tokio-console`
- Run: `neptune-core --tokio-console`

## Project Structure

- `neptune-core/` - Main daemon application
- `neptune-core-cli/` - Command-line interface
- `neptune-dashboard/` - Console dashboard
- `docs/` - Documentation (mdBook)
- `scripts/` - Build and test scripts

## Git Workflow

### Remotes

- `origin` - Your fork
- `upstream` - Original Neptune-Crypto repository

### Sync with Upstream

```bash
git fetch upstream
git checkout master
git merge upstream/master
git push origin master
```

## Security Considerations

- Never share `wallet.dat`, `incoming_randomness.dat`, or `outgoing_randomness.dat` on mainnet
- For testing/development, these files can be shared if not on mainnet
- If cryptographic data becomes invalid, share data directory (excluding wallet files) for debugging

## Documentation

- Local docs: `cd docs && mdbook serve --open`
- Install mdBook: `cargo install mdbook`

## Common Issues

### Database Corruption

- Delete `<data_directory>/<network>/blocks/` and `<data_directory>/<network>/databases/`
- Restart from genesis block

### Build Issues

- Ensure CMake is installed and up to date
- Use the specific build command with `CMAKE_POLICY_VERSION_MINIMUM=3.5`
- Check Rust toolchain version

### Network Issues

- Try IPv6 connections if no static IPv4
- Use known peer addresses: `51.15.139.238:9798`, `139.162.193.206:9798`

## Adding New RPC Methods

### Pattern for Standalone Methods (No Server Required)

1. **Add method to `handlers.rs`**:

   ```rust
   /// Method description
   async fn method_name(param1: &str, param2: &str) -> Result<String> {
       // Implementation using neptune_cash types directly
       // No tarpc connection needed
   }
   ```

2. **Add to `handle_request` function**:

   ```rust
   "method_name" => {
       let param1 = extract_string_param(&params, "param1")?;
       let param2 = extract_string_param(&params, "param2")?;
       method_name(&param1, &param2).await
   }
   ```

3. **Add to `requires_auth` function** (usually `false` for standalone methods):
   ```rust
   let public_methods = [
       // ... existing methods ...
       "method_name",
   ];
   ```

### Pattern for Server-Dependent Methods (Requires neptune-core)

1. **Extract connection logic** from `main.rs` into reusable module
2. **Add method to `handlers.rs`**:

   ```rust
   /// Method description
   async fn method_name(param1: &str, param2: &str) -> Result<String> {
       // Connect to neptune-core using extracted connection logic
       // Call tarpc method
       // Return formatted response
   }
   ```

3. **Add to `handle_request` function** (same as standalone)
4. **Add to `requires_auth` function** (usually `true` for server methods)

### Helper Functions Available

- `extract_string_param(params, "key")` - Extract string parameter
- `extract_u32_param(params, "key")` - Extract u32 parameter
- `get_wallet_path(network)` - Get wallet file path
- `generate_completions()` - Generate shell completions
- `generate_help()` - Generate help text

### Testing New Methods

```bash
# Start RPC server
neptune-cli --rpc-mode --rpc-port 9797

# Test with curl
curl -X POST http://localhost:9797 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"method_name","params":{"param1":"value1"},"id":1}'
```

## Contributing

- Follow the existing code style and patterns
- Add tests for new functionality
- Update documentation as needed
- Run full test suite before submitting changes
- Use descriptive commit messages
