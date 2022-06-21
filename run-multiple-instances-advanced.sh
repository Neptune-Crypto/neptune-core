#!/usr/bin/env bash
#
# Run eight instances where instance 0 and instance 2 are mining but the rest are not. The nodes are connected like this:
# (0)--(1)-- (2)--(3)
#   \    |   /    |
#    \   |  /     |
#     \  | /      |
#      \ |/       |
#        4--------/
#        |
#        5
#        |
#        6
#        |
#        7
#
# So whenever a block is found by 0 or by 2, it should be propagated to all participants.

set -e # Exit on first error.

export RUST_LOG=debug;

# Inspired by https://stackoverflow.com/a/52033580/2574407
(
    trap 'kill 0' SIGINT;
    (sleep 0s; XDG_DATA_HOME=~/.local/share/neptune-integration-test/0/ cargo run -- --network regtest --peer-port 29790 --rpc-port 39790 --mine | sed 's/.*neptune_core:\+\(.*\)/I0:  \1/g') &
    (sleep 2s; XDG_DATA_HOME=~/.local/share/neptune-integration-test/1/ cargo run -- --network regtest --peer-port 29791 --rpc-port 39791 --peers 127.0.0.1:29790 | sed 's/.*neptune_core:\+\(.*\)/I1:  \1/g') &
    (sleep 4s; XDG_DATA_HOME=~/.local/share/neptune-integration-test/2/ cargo run -- --network regtest --peer-port 29792 --rpc-port 39792 --mine --peers 127.0.0.1:29791 | sed 's/.*neptune_core:\+\(.*\)/I2:  \1/g') &
    (sleep 6s; XDG_DATA_HOME=~/.local/share/neptune-integration-test/3/ cargo run -- --network regtest --peer-port 29793 --rpc-port 39793 --peers 127.0.0.1:29792 | sed 's/.*neptune_core:\+\(.*\)/I3:  \1/g') &
    (sleep 8s; XDG_DATA_HOME=~/.local/share/neptune-integration-test/4/ cargo run -- --network regtest --peer-port 29794 --rpc-port 39794 --peers 127.0.0.1:29790  --peers 127.0.0.1:29791  --peers 127.0.0.1:29792  --peers 127.0.0.1:29793 | sed 's/.*neptune_core:\+\(.*\)/I4:  \1/g') &
    (sleep 10s; XDG_DATA_HOME=~/.local/share/neptune-integration-test/5/ cargo run -- --network regtest --peer-port 29795 --rpc-port 39795 --peers 127.0.0.1:29794 | sed 's/.*neptune_core:\+\(.*\)/I5:  \1/g') &
    (sleep 12s; XDG_DATA_HOME=~/.local/share/neptune-integration-test/6/ cargo run -- --network regtest --peer-port 29796 --rpc-port 39796 --peers 127.0.0.1:29795 | sed 's/.*neptune_core:\+\(.*\)/I6:  \1/g') &
    (sleep 14s; XDG_DATA_HOME=~/.local/share/neptune-integration-test/7/ cargo run -- --network regtest --peer-port 29797 --rpc-port 39797 --peers 127.0.0.1:29796 | sed 's/.*neptune_core:\+\(.*\)/I7:  \1/g')
)
