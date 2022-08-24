#!/usr/bin/env bash
#
# Run three instances where instance 0 and instance 2 are mining but instance 1 is not. The nodes are connected like this:
# (0) <-> (1) <-> (2)
# So whenever a block is found by 0 or by 2, it is propagated through 1.

set -e # Exit on first error.
#set -x

export RUST_LOG=debug;

(sleep 4s; RUST_LOG=debug cargo run --bin rpc_client -- --server-addr 127.0.0.1:9799 send '[{"recipient_address": "0399bb06fa556962201e1647a7c5b231af6ff6dd6d1c1a8599309caa126526422e", "amount": 11}]') &
# Inspired by https://stackoverflow.com/a/52033580/2574407
(trap 'kill 0' EXIT SIGTERM;
 (RUST_LOG=debug cargo run -- --network regtest --peer-port 29790 --rpc-port 9799 --mine )
)

