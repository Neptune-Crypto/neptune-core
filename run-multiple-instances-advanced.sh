#!/usr/bin/env bash

set -e # Exit on first error.

export RUST_LOG=trace;

# Inspired by https://stackoverflow.com/a/52033580/2574407
(
    trap 'kill 0' SIGINT;
    (XDG_DATA_HOME=~/.local/share/neptune-integration-test/0/ cargo run -- --network regtest --mine --port 29790 | sed 's/.*neptune_core:\+\(.*\)/I0:  \1/g') &
    (sleep 1s; XDG_DATA_HOME=~/.local/share/neptune-integration-test/1/ cargo run -- --network regtest --port 29791 --peers 127.0.0.1:29790 | sed 's/.*neptune_core:\+\(.*\)/I1:  \1/g') &
    (sleep 2s; XDG_DATA_HOME=~/.local/share/neptune-integration-test/2/ cargo run -- --network regtest --mine --port 29792 --peers 127.0.0.1:29791 | sed 's/.*neptune_core:\+\(.*\)/I2:  \1/g') &
    (sleep 3s; XDG_DATA_HOME=~/.local/share/neptune-integration-test/3/ cargo run -- --network regtest --port 29793 --peers 127.0.0.1:29792 | sed 's/.*neptune_core:\+\(.*\)/I3:  \1/g') &
    (sleep 4s; XDG_DATA_HOME=~/.local/share/neptune-integration-test/4/ cargo run -- --network regtest --port 29794 --peers 127.0.0.1:29790  --peers 127.0.0.1:29791  --peers 127.0.0.1:29792  --peers 127.0.0.1:29793 | sed 's/.*neptune_core:\+\(.*\)/I4:  \1/g') &
    (sleep 5s; XDG_DATA_HOME=~/.local/share/neptune-integration-test/5/ cargo run -- --network regtest --port 29795 --peers 127.0.0.1:29794 | sed 's/.*neptune_core:\+\(.*\)/I5:  \1/g') &
    (sleep 6s; XDG_DATA_HOME=~/.local/share/neptune-integration-test/6/ cargo run -- --network regtest --port 29796 --peers 127.0.0.1:29795 | sed 's/.*neptune_core:\+\(.*\)/I6:  \1/g') &
    (sleep 7s; XDG_DATA_HOME=~/.local/share/neptune-integration-test/7/ cargo run -- --network regtest --port 29797 --peers 127.0.0.1:29796 | sed 's/.*neptune_core:\+\(.*\)/I7:  \1/g')
)
