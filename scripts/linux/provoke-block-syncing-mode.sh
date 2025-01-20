#!/usr/bin/env bash
#
# Run two instances where instance 0 mines, and instance 1 connects after 30 seconds, which should provoke a block syncing event in instance 1.
# If a syncing event is not provoked or compilation shows a problem, you can run the script `run-single-instance.sh` before running this, and
# then wait until instance 0 finds block 3.
# Connection graph:
# (0) <-> (1)

if ! command -v cpulimit &> /dev/null
then
    echo "cpulimit could not be found. Please install it."
    echo "For example, on unbuntu: sudo apt-get install cpulimit"
    # Add installation instructions for other Linux distributions here.
    exit
fi

set -e # Exit on first error.

export RUST_LOG=debug;
if [ "$#" -ne 1 ] || ! [[ "$1" =~ ^[0-9]+$ ]]; then
    echo "Please provide number of seconds that instance 1 should wait before starting"
    exit 1
fi

SLEEP_TIME="$1"
echo "Sleeping for $SLEEP_TIME seconds before starting 2nd instance"

RUST_BACKTRACE=1 XDG_DATA_HOME=~/.local/share/neptune-integration-test/0/ nice -n 0 --  cargo run -- --network regtest --peer-port 29790 --rpc-port 19790 --compose --guess 2>&1 | tee -a integration_test.log | sed 's/(.*)/\0 \[I1\]/g'  &
pid[0]=$!
sleep "$SLEEP_TIME"s;
RUST_BACKTRACE=1 XDG_DATA_HOME=~/.local/share/neptune-integration-test/1/ nice -n 0 --  cargo run -- --network regtest --peer-port 29791 --rpc-port 19791 --peers 127.0.0.1:29790 --sync-mode-threshold 2 2>&1 | tee -a integration_test.log | sed 's/(.*)/\0 \[I1\]/g'  &
pid[1]=$!

# Inspired by https://stackoverflow.com/a/52033580/2574407
trap 'kill -0 ${pid[0]} ${pid[1]}; exit 0' SIGINT
wait
