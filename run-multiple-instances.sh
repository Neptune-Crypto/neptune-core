#!/usr/bin/env bash

set -e # Exit on first error.

export RUST_LOG=trace;

# Inspired by https://stackoverflow.com/a/52033580/2574407
(trap 'kill 0' SIGINT; (XDG_DATA_HOME=~/.local/share/neptune-integration-test/0/ cargo run -- --network regtest --mine --port 29790 | sed 's/.*neptune_core:\+\(.*\)/I0:  \1/g') & (sleep 1s; XDG_DATA_HOME=~/.local/share/neptune-integration-test/1/ cargo run -- --network regtest --port 29791 --peers 127.0.0.1:29790 | sed 's/.*neptune_core:\+\(.*\)/I1:  \1/g') & (sleep 2s; XDG_DATA_HOME=~/.local/share/neptune-integration-test/2/ cargo run -- --network regtest --mine --port 29792 --peers 127.0.0.1:29791 | sed 's/.*neptune_core:\+\(.*\)/I2:  \1/g'))
