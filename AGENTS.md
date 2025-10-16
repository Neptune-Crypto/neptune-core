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
