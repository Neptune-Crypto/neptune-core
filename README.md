# Neptune Core

Neptune-core is the reference implementation for the [Neptune](https://neptune.cash/) protocol. The implementation is not complete yet, but already supports many integral components. In particular, alpha-net is live.

## Compiling from Source

### Linux Debian/Ubuntu

 - Install curl: `apt install curl`
 - Install the rust compiler and accessories: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
 - Source the rust environment: `source $HOME/.cargo/env`
 - Install LebelDB: `apt install libleveldb-dev libsnappy-dev cmake`
 - Download the repository: `git clone git@github.com/Neptune-Crypto/neptune-core`
 - Enter the repository: `cd neptune-core`
 - Build for release and put the binaries in your local path (`~/.cargo/bin/`): `cargo install --path .` (needs at least 3 GB of RAM)

## Running & Connecting

 - Generate a wallet file: `wallet_gen`
 - Run neptune-core daemon: `neptune-core` with flags
   - `--peers [ip_address:port]` to connect to a given peer, for instance `--peers 51.15.139.238:9798` or `--peers 139.162.193.206:9798` or both
   - `--mine` to mine, and with `--throttled-mining` to avoid assigning too much CPU power to mining
   - `--help` to get a list of available command-line arguments

## Dashboard

This software comes with a dashboard that communicates with the daemon. The dashboard is a console-based user interface to generate addresses, receive and send money, and monitor the behavior of the client. The daemon must be running before the dashboard is started. To start the dashboard, run: `neptune-dashboard`. (If you set daemon's RPC port to a custom value specify that value with the flag `--port [port]`.)

## RPC

In addition to a dashboard, the software comes with a CLI client to invoke procedures in the daemon. This can be invoked from another terminal window when the daemon is running. To get all available RPC commands, execute 
```
rpc_cli -- --help
```

To get e.g. the block height of a running daemon, execute
```
rpc_cli -- --server-addr 127.0.0.1:<rpc_port> block-height
```

## Setup for Development (Ubuntu)

 - build-essential (for `make`) -- `apt install build-essential`
 - install `vscode`
 - in `vscode` install the plugin `rust-analyzer`
 - in `vscode` activate format-on-save via `File` > `Preferences` > `Settings` then check the box for "Format on Save"
 - install `cpulimit` for nicer, and more quiet integration tests: `apt install cpulimit`

## Logging

All logging is output to standard out.

The log level can be set through the environment variable `RUST_LOG`. Valid values are: `trace`, `debug`, `info`, `warn`, and `error`. The default value is `info`. E.g.: `RUST_LOG=trace cargo run`.

For development purposes it can sometimes be nice to get a more succint logging output by piping stdout through `sed` with the below command. This will only print the namespace of the logging event and the log text. The log output can also be stored to file by piping it to `tee`, like this: `cargo run 2>&1 | tee -a integration_test.log`.
```
sed 's/.*neptune_core:\+\(.*\)/\1/g'
```

If the RPC server is spamming your log too much, set the logging-level environment to `RUST_LOG='info,tarpc=warn'`.

## Local Integration Test Strategy

This repository contains unit tests, but multi-threaded programs are notoriously hard to test. And the unit tests usually only cover narrow parts of the code within a single thread. When you are making changes to the code, you can run through the following checks
1. `cargo b` to verify that it builds without warnings
2. `cargo t` to verify that all unit tests work
3. `run-multiple-instances.sh` to spin up three nodes that are connected through `localhost`. Instance `I0` and `I2` should be mining and all three clients should be converging on the same blocks. You can read the hashes of the blocks in the log output and verify that they all store the same blocks.
4. Run `make restart` followed by `run-multiple-instances.sh` to verify that the nodes can start from the genesis block, create a database and store subsequent blocks in this database. This test is important to verify that the client software doesn't need an existing database to function.
5. If you encounter an error in some of the stages later then (2), i.e. an error that wasn't caught by the compiler or the tests, consider if you could add a unit test that **would** have caught this error. If that's not possible consider if you can add a manual test (for example a shell script) where the tests would have been visible. Also consider if you can add anything to this list that would have caught this error (assuming you didn't write a unit test that caught it).
