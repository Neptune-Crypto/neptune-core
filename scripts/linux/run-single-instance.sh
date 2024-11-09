#!/usr/bin/env bash
#
# Run one instance where instance 0 is mining. The nodes are connected like this:
# (0)
# So whenever a block is found by 0, it is not propagated because there is no-one to propagate it to.

if ! command -v cpulimit &> /dev/null
then
    echo "cpulimit could not be found. Please install it."
    echo "For example, on unbuntu: sudo apt-get install cpulimit"
    # Add installation instructions for other Linux distributions here.
    exit
fi

set -e # Exit on first error.

export RUST_LOG=debug;

# Build before proceeding
cargo build

RUST_BACKTRACE=1 XDG_DATA_HOME=~/.local/share/neptune-integration-test/0/ nice -n 1 --  cargo run -- --network regtest --peer-port 29790 --rpc-port 19790 --compose --guess 2>&1 | tee integration_test.log | sed 's/.*neptune_core:\+\(.*\)/I0:  \1/g'  &
pid[0]=$!
sleep 5s;

# Inspired by https://stackoverflow.com/a/52033580/2574407
trap 'kill -0 ${pid[0]}; exit 0' SIGINT
wait
