#!/usr/bin/env bash
#
# Run one instance without mining, with a faked time such that the premine UTXO
# can be spent immediately.

set -e # Exit on first error.

export RUST_LOG=debug;

# Build before proceeding
cargo build

NC_LOCAL_STATE_DIR="$HOME/.local/share/neptune-integration-test-from-genesis"
rm -rf $NC_LOCAL_STATE_DIR

NC_DATA_DIRECTORY="$NC_LOCAL_STATE_DIR/0"
NC_WALLET_DIRECTORY="$NC_DATA_DIRECTORY/neptune/testnet/wallet"
mkdir -p "$NC_WALLET_DIRECTORY"
echo '{"name":"standard_wallet","secret_seed":{"coefficients":[12063201067205522823,1529663126377206632,2090171368883726200]},"version":0}' > $NC_WALLET_DIRECTORY/wallet.dat

# Fake that time locked UTXOs from premine are no longer timelocked
export LD_PRELOAD=/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1
export FAKETIME="+200d"

# LD_PRELOAD=/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1 FAKETIME="+200d" RUST_BACKTRACE=1 XDG_DATA_HOME="$NC_DATA_DIRECTORY" nice -n 1 --  cargo run -- --network testnet --tx-proving-capability=proofcollection --peer-port 29790 --rpc-port 19790  2>&1 | tee integration_test.log | sed 's/(.*)/\0 \[I0\]/g'  &
XDG_DATA_HOME="$NC_LOCAL_STATE_DIR/0/" cargo run -- --network testnet --tx-proving-capability=proofcollection --peer-port 29790 --rpc-port 19790 --max-peers=1 2>&1 | tee integration_test0.log | sed 's/(.*)/\0 \[I0\]/g'  &
pid[0]=$!
sleep 2s;

XDG_DATA_HOME="$NC_LOCAL_STATE_DIR/1/" cargo run -- --network testnet --tx-proving-capability=proofcollection --peer-port 29791 --rpc-port 19791 --max-peers=1 --peers 127.0.0.1:29790 2>&1 | tee integration_test1.log | sed 's/(.*)/\0 \[I1\]/g'  &
pid[0]=$!
sleep 2s;

# Inspired by https://stackoverflow.com/a/52033580/2574407
trap 'kill -0 ${pid[0]}; exit 0' SIGINT
wait
