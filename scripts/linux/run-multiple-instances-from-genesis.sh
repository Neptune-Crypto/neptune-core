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


NETWORK="testnet-mock"
NIGHTLY=""
RELEASE=""
FEATURES=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --network)
      if [ -n "$2" ]; then
        NETWORK="$2"
        shift
      else
        echo "Error: --network option requires a value." >&2
        exit 1
      fi
      shift
      ;;
    --nightly)
      NIGHTLY="+nightly"
      FEATURES="log-slow-write-lock,log-slow-read-lock"
      ;;
    --release)
      RELEASE="--release"
      ;;
    *)
      echo "Error: Unknown option: $1" >&2
      exit 1
      ;;
  esac
  shift
done

echo "NETWORK is set to: $NETWORK"
echo "NIGHTLY is set to: $NIGHTLY"
echo "RELEASE is set to: $RELEASE"
echo "FEATURES is set to: $FEATURES"

#set -e # Exit on first error.

export RUST_LOG="debug,tarpc=warn";

LOCAL_STATE_DIR=~/.local/share/neptune-integration-test-from-genesis

EXTRA_ARGS=""

NODE1_ARGS="--compose --guess"
NODE2_ARGS=""
NODE3_ARGS=""

# delete all local state first.
rm -rf $LOCAL_STATE_DIR

# Build before spinning up multiple instances, as you'll otherwise get multiple processes trying
# to build at the same time.
cargo $NIGHTLY build $RELEASE $FEATURES

RUST_BACKTRACE=1 XDG_DATA_HOME=$LOCAL_STATE_DIR/0/ nice -n 1 --  cargo $NIGHTLY run $RELEASE $FEATURES -- --network $NETWORK --peer-port 29790 --rpc-port 19790 $EXTRA_ARGS $NODE1_ARGS 2>&1 | tee /tmp/integration_test_from_genesis-0.log | sed 's/(.*)/\0 \[I0\]/g'  &
pid[0]=$!
sleep 5s;
RUST_BACKTRACE=1 XDG_DATA_HOME=$LOCAL_STATE_DIR/1/ nice -n 1 --  cargo $NIGHTLY run $RELEASE $FEATURES -- --network $NETWORK --peer-port 29791 --rpc-port 19791 --peers 127.0.0.1:29790 $EXTRA_ARGS $NODE2_ARGS 2>&1 | tee /tmp/integration_test_from_genesis-1.log | sed 's/(.*)/\0 \[I1\]/g'  &
pid[1]=$!
sleep 5s;
RUST_BACKTRACE=1 XDG_DATA_HOME=$LOCAL_STATE_DIR/2/ nice -n 1 --  cargo $NIGHTLY run $RELEASE $FEATURES  -- --network $NETWORK --peer-port 29792 --rpc-port 19792 --peers 127.0.0.1:29791 --sync-mode-threshold 1000 $EXTRA_ARGS $NODE3_ARGS 2>&1 | tee /tmp/integration_test_from_genesis-2.log | sed 's/(.*)/\0 \[I2\]/g'  &
pid[2]=$!

# Inspired by https://stackoverflow.com/a/52033580/2574407
trap 'kill -0 ${pid[0]} ${pid[1]} ${pid[2]}; exit 0' SIGINT
wait
