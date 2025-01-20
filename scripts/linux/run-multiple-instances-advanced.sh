#!/usr/bin/env bash
#
# Run eight instances where instance 2 is mining but the rest are not. The nodes are connected like this:
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
# So whenever a block is found by 2, it should be propagated to all participants.

if ! command -v cpulimit &> /dev/null
then
    echo "cpulimit could not be found. Please install it."
    echo "For example, on unbuntu: sudo apt-get install cpulimit"
    # Add installation instructions for other Linux distributions here.
    exit
fi

set -e # Exit on first error.

export RUST_LOG=debug;

# Build before spinning up multiple instances, as you'll otherwise get multiple processes trying
# to build at the same time.
cargo build

RUST_BACKTRACE=1 XDG_DATA_HOME=~/.local/share/neptune-integration-test/0/ nice -n 18 --  cargo run -- --network regtest --peer-port 29790 --rpc-port 19790  2>&1 | tee -a advanced_integration_test.log | sed 's/(.*)/\0 \[I0\]/g'  &
pid[0]=$!
sleep 5s;
RUST_BACKTRACE=1 XDG_DATA_HOME=~/.local/share/neptune-integration-test/1/ nice -n 18 --  cargo run -- --network regtest --peer-port 29791 --rpc-port 19791 --peers 127.0.0.1:29790 2>&1 | tee -a advanced_integration_test.log | sed 's/(.*)/\0 \[I1\]/g'  &
pid[1]=$!
sleep 2s;
RUST_BACKTRACE=1 XDG_DATA_HOME=~/.local/share/neptune-integration-test/2/ nice -n 18 --  cargo run -- --network regtest --peer-port 29792 --rpc-port 19792 --compose --guess --peers 127.0.0.1:29791 2>&1 | tee -a advanced_integration_test.log | sed 's/(.*)/\0 \[I2\]/g'  &
pid[2]=$!
sleep 2s;
RUST_BACKTRACE=1 XDG_DATA_HOME=~/.local/share/neptune-integration-test/3/ nice -n 18 --  cargo run -- --network regtest --peer-port 29793 --rpc-port 19793 --peers 127.0.0.1:29792 2>&1 | tee -a advanced_integration_test.log | sed 's/(.*)/\0 \[I3\]/g'  &
pid[3]=$!
sleep 2s;
RUST_BACKTRACE=1 XDG_DATA_HOME=~/.local/share/neptune-integration-test/4/ nice -n 18 --  cargo run -- --network regtest --peer-port 29794 --rpc-port 19794 --peers 127.0.0.1:29790 --peers 127.0.0.1:29791 --peers 127.0.0.1:29792 --peers 127.0.0.1:29793 2>&1 | tee -a advanced_integration_test.log | sed 's/(.*)/\0 \[I4\]/g'  &
pid[4]=$!
sleep 2s;
RUST_BACKTRACE=1 XDG_DATA_HOME=~/.local/share/neptune-integration-test/5/ nice -n 18 --  cargo run -- --network regtest --peer-port 29795 --rpc-port 19795 --peers 127.0.0.1:29794  2>&1 | tee -a advanced_integration_test.log | sed 's/(.*)/\0 \[I5\]/g'  &
pid[5]=$!
sleep 2s;
RUST_BACKTRACE=1 XDG_DATA_HOME=~/.local/share/neptune-integration-test/6/ nice -n 18 --  cargo run -- --network regtest --peer-port 29796 --rpc-port 19796 --peers 127.0.0.1:29795 --sync-mode-threshold 10 2>&1 | tee -a advanced_integration_test.log | sed 's/(.*)/\0 \[I6\]/g'  &
pid[6]=$!
sleep 2s;
RUST_BACKTRACE=1 XDG_DATA_HOME=~/.local/share/neptune-integration-test/7/ nice -n 18 --  cargo run -- --network regtest --peer-port 29797 --rpc-port 19797 --peers 127.0.0.1:29796 --sync-mode-threshold 10 2>&1 | tee -a advanced_integration_test.log | sed 's/(.*)/\0 \[I7\]/g'  &
pid[7]=$!

# Inspired by https://stackoverflow.com/a/52033580/2574407
trap 'kill -0 ${pid[0]} ${pid[1]} ${pid[2]} ${pid[3]} ${pid[4]} ${pid[5]} ${pid[6]} ${pid[7]}; exit 0' SIGINT
wait
