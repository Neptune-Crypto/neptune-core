#!/usr/bin/env bash
#
# Ask three nodes about connected peers

set -e # Exit on first error.

export RUST_LOG=info;

echo -n "I0: "
cargo run --bin rpc -- --port 19790 get-peer-info
echo -n "I1: "
cargo run --bin rpc -- --port 19791 get-peer-info
echo -n "I2: "
cargo run --bin rpc -- --port 19792 get-peer-info
