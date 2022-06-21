#!/usr/bin/env bash
#
# Run three instances where instance 0 and instance 2 are mining but instance 1 is not. The nodes are connected like this:
# (0) <-> (1) <-> (2)
# So whenever a block is found by 0 or by 2, it is propagated through 1.

set -e # Exit on first error.

export RUST_LOG=debug;

# Inspired by https://stackoverflow.com/a/52033580/2574407
(trap 'kill 0' SIGINT;
 (RUST_BACKTRACE=1 XDG_DATA_HOME=~/.local/share/neptune-integration-test/0/ cargo run -- --network regtest --peer-port 29790 --rpc-port 19790 --mine | sed 's/.*neptune_core:\+\(.*\)/I0:  \1/g') &
 (sleep 2s; RUST_BACKTRACE=1 XDG_DATA_HOME=~/.local/share/neptune-integration-test/1/ cargo run -- --network regtest --peer-port 29791 --rpc-port 19791 --peers 127.0.0.1:29790 | sed 's/.*neptune_core:\+\(.*\)/I1:  \1/g') &
 (sleep 4s; RUST_BACKTRACE=1 XDG_DATA_HOME=~/.local/share/neptune-integration-test/2/ cargo run -- --network regtest --peer-port 29792 --rpc-port 19792 --peers 127.0.0.1:29791 --mine | sed 's/.*neptune_core:\+\(.*\)/I2:  \1/g')
)
