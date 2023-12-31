#!/usr/bin/env bash
#
# Ask three nodes about their latest block

set -e # Exit on first error.

export RUST_LOG=info;

cargo run --bin rpc -- --server-addr 127.0.0.1:19790 head
cargo run --bin rpc -- --server-addr 127.0.0.1:19791 head
cargo run --bin rpc -- --server-addr 127.0.0.1:19792 head
