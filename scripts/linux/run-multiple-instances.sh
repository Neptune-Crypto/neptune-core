#!/usr/bin/env bash
#
# Run three instances where only instance 0 is composing.
# Only one node is composing, since it's expensive to produce the transaction
# and block proofs. Node 0 is composing, 0 and 2 are guessing.

# The nodes are connected like this:
# (0) <-> (1) <-> (2)
# So whenever a block is found by 0, it is propagated through 1 to 2.

if ! command -v cpulimit &> /dev/null
then
    echo "cpulimit could not be found. Please install it."
    echo "For example, on unbuntu: sudo apt-get install cpulimit"
    # Add installation instructions for other Linux distributions here.
    exit
fi

set -e # Exit on first error.

export RUST_LOG='debug,tarpc=warn'

NEPTUNE_ARGS="--network regtest"
BUILD_ARGS="--release"
CARGO_ARGS=""

# Build before spinning up multiple instances, as you'll otherwise get multiple processes trying
# to build at the same time.
cargo $CARGO_ARGS build $BUILD_ARGS

RUST_BACKTRACE=1 XDG_DATA_HOME=~/.local/share/neptune-integration-test/0/ nice -n 18 --  cargo $CARGO_ARGS run $BUILD_ARGS -- $NEPTUNE_ARGS --peer-port 29790 --rpc-port 19790 --compose --guess 2>&1 | tee -a integration_test.log | sed 's/(.*)/\0 \[I0\]/g'  &
pid[0]=$!
sleep 5s;
RUST_BACKTRACE=1 XDG_DATA_HOME=~/.local/share/neptune-integration-test/1/ nice -n 18 --  cargo $CARGO_ARGS run $BUILD_ARGS -- $NEPTUNE_ARGS --peer-port 29791 --rpc-port 19791 --peers 127.0.0.1:29790 2>&1 | tee -a integration_test.log | sed 's/(.*)/\0 \[I1\]/g'  &
pid[1]=$!
sleep 5s;
RUST_BACKTRACE=1 XDG_DATA_HOME=~/.local/share/neptune-integration-test/2/ nice -n 18 --  cargo $CARGO_ARGS run $BUILD_ARGS -- $NEPTUNE_ARGS --peer-port 29792 --rpc-port 19792 --guess --peers 127.0.0.1:29791 --sync-mode-threshold 1000 2>&1 | tee -a integration_test.log | sed 's/(.*)/\0 \[I2\]/g'  &
pid[2]=$!

# Inspired by https://stackoverflow.com/a/52033580/2574407
trap 'kill -0 ${pid[0]} ${pid[1]} ${pid[2]}; exit 0' SIGINT
wait
