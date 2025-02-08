#!/usr/bin/env bash
#
# Run three instances where instance 0 and instance 2 are mining but instance 1 is not. The nodes are connected like this:
# (0) <-> (1) <-> (2)
# So whenever a block is found by 0 or by 2, it is propagated through 1.

if ! command -v cpulimit &> /dev/null
then
    echo "cpulimit could not be found. Please install it."
    echo "For example, on unbuntu: sudo apt-get install cpulimit"
    # Add installation instructions for other Linux distributions here.
    exit
fi

set -e # Exit on first error.

export RUST_LOG=debug;

# these features require building with nightly
# the purpose is to log location/duration of locks that are held too long.
export FEATURES="--release --features log-slow-write-lock,log-slow-read-lock"
export NIGHTLY=+nightly

LOCAL_STATE_DIR=~/.local/share/neptune-integration-test-from-genesis

EXTRA_ARGS=""

# delete all local state first.
rm -rf $LOCAL_STATE_DIR

# Build before spinning up multiple instances, as you'll otherwise get multiple processes trying
# to build at the same time.
cargo $NIGHTLY build $FEATURES

RUST_BACKTRACE=1 XDG_DATA_HOME=$LOCAL_STATE_DIR/0/ nice -n 1 --  cargo $NIGHTLY run $FEATURES -- --network regtest --peer-port 29790 --rpc-port 19790 --compose --guess $EXTRA_ARGS 2>&1 | tee /tmp/integration_test_from_genesis-0.log | sed 's/(.*)/\0 \[I0\]/g'  &
pid[0]=$!
sleep 5s;
RUST_BACKTRACE=1 XDG_DATA_HOME=$LOCAL_STATE_DIR/1/ nice -n 1 --  cargo $NIGHTLY run $FEATURES -- --network regtest --peer-port 29791 --rpc-port 19791 --peers 127.0.0.1:29790 $EXTRA_ARGS 2>&1 | tee /tmp/integration_test_from_genesis-1.log | sed 's/(.*)/\0 \[I1\]/g'  &
pid[1]=$!
sleep 5s;
RUST_BACKTRACE=1 XDG_DATA_HOME=$LOCAL_STATE_DIR/2/ nice -n 1 --  cargo $NIGHTLY run $FEATURES  -- --network regtest --peer-port 29792 --rpc-port 19792 --peers 127.0.0.1:29791 --sync-mode-threshold 1000 $EXTRA_ARGS 2>&1 | tee /tmp/integration_test_from_genesis-2.log | sed 's/(.*)/\0 \[I2\]/g'  &
pid[2]=$!

# Inspired by https://stackoverflow.com/a/52033580/2574407
trap 'kill -0 ${pid[0]} ${pid[1]} ${pid[2]}; exit 0' SIGINT
wait
