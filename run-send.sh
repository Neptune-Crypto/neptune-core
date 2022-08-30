#!/usr/bin/env bash

# Run one node with an RPC-server and a mining thread.
# Run one RPC-client and issue `send` command.

set -e # Exit on first error.
set -x # Debug

export RUST_LOG=debug;

(sleep 4s; RUST_LOG=debug cargo run --bin rpc_client -- --server-addr 127.0.0.1:9799 send '[{"recipient_address": "0399bb06fa556962201e1647a7c5b231af6ff6dd6d1c1a8599309caa126526422e", "amount": 11}]') &
# Inspired by https://stackoverflow.com/a/52033580/2574407
(trap 'kill 0' EXIT SIGTERM;
 (RUST_LOG=debug cargo run -- --network regtest --peer-port 29790 --rpc-port 9799 --mine )
)

