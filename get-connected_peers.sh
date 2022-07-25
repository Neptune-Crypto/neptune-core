#!/usr/bin/env bash
#
# Ask three nodes about their latest block

set -e # Exit on first error.

export RUST_LOG=info;

echo -n "I0: "
cargo run --bin rpc -- --server-addr 127.0.0.1:19790 get-peer-info
echo -n "I1: "
cargo run --bin rpc -- --server-addr 127.0.0.1:19791 get-peer-info
echo -n "I2: "
cargo run --bin rpc -- --server-addr 127.0.0.1:19792 get-peer-info
