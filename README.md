# Neptune Core

Neptune-core is the reference implementation for the [Neptune](https://neptune.cash/) protocol. The implementation is not complete yet, but already supports many integral components. In particular, alpha-net is live.

## Installing

### Compile from Source -- Linux Debian/Ubuntu

 - Open a terminal to run the following commands.
 - Install curl: `sudo apt install curl`
 - Install the rust compiler and accessories: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y`
 - Source the rust environment: `source "$HOME/.cargo/env"`
 - Install LebelDB: `sudo apt install libleveldb-dev libsnappy-dev cmake`
 - Download the repository: `git clone https://github.com/Neptune-Crypto/neptune-core.git`
 - Enter the repository: `cd neptune-core`
 - Checkout the release branch `git checkout release`. (Alternatively, for the *unstable development* branch, skip this step.)

 - Build for release and put the binaries in your local path (`~/.cargo/bin/`): `cargo install --path .` (needs at least 3 GB of RAM and a few minutes)

### Windows

To install Rust and cargo on Windows, you can follow [these instructions](https://doc.rust-lang.org/cargo/getting-started/installation.html).
Installing cargo might require you to install Visual Studio with some C++ support but the cargo installer for Windows should handle that.
With a functioning version of cargo, compilation on Windows should just work out-of-the-box with cargo build etc.
- Download and run the CMake installer from the [website](https://cmake.org/download/).
- Open PowerShell to run the following commands.
- Download the repository: `git clone https://github.com/Neptune-Crypto/neptune-core.git`
- Enter the repository: `cd neptune-core`
- Checkout the release branch `git checkout release`. (Alternatively, for the *unstable development* branch, skip this step.)

- Run `cargo install --path .`


## Running & Connecting

 - Generate a wallet file: `neptune-cli generate-wallet`
 - Run neptune-core daemon: `neptune-core` with flags
   - `--peers [ip_address:port]` to connect to a given peer, for instance `--peers [2001:bc8:611:1c72::1]:9798` or `--peers 139.162.193.206:9798` or both
   - `--mine` to mine — if you want to generate testnet coins to test sending and receiving
   - `--help` to get a list of available command-line arguments

If you don't have a static IPv4, then try connecting to other nodes with IPv6. It's our experience that you will then be able to open and receive connections to other nodes through Nepture Core's built-in peer-discovery process.

## Dashboard

This software comes with a dashboard that communicates with the daemon. The dashboard is a console-based user interface to generate addresses, receive and send money, and monitor the behavior of the client. The daemon must be running before the dashboard is started. To start the dashboard, run: `neptune-dashboard`. (If you set daemon's RPC port to a custom value specify that value with the flag `--port [port]`.)

## Command-Line Interface

In addition to a dashboard, the software comes with a CLI client to invoke procedures in the daemon. This can be invoked from another terminal window when the daemon is running. To get all available commands, execute
```
neptune-cli --help
```

To get e.g. the block height of a running daemon, execute
```
neptune-cli --server-addr block-height
```

If you set up `neptune-core` on a different address or port from the default (127.0.0.1:9799), then the flag `--server-addr [ip_address:port]` is your friend.

## Setup for Development (Ubuntu)

 - build-essential (for `make`) -- `apt install build-essential`
 - install `vscode`
 - in `vscode` install the plugin `rust-analyzer`
 - in `vscode` activate format-on-save via `File` > `Preferences` > `Settings` then check the box for "Format on Save"
 - install `cpulimit` for nicer, and more quiet integration tests: `apt install cpulimit`

## Branches and Pull Requests

Please see this [this document](./developer_docs/git_branches.md) for documentation of our branching methodology and how to submit a pull request.

## Logging

All logging is output to standard out.

The log level can be set through the environment variable `RUST_LOG`. Valid values are: `trace`, `debug`, `info`, `warn`, and `error`. The default value is `info`. E.g.: `RUST_LOG=trace cargo run`.

For development purposes it can sometimes be nice to get a more succint logging output by piping stdout through `sed` with the below command. This will only print the namespace of the logging event and the log text. The log output can also be stored to file by piping it to `tee`, like this: `cargo run 2>&1 | tee -a integration_test.log`.
```
sed 's/.*neptune_core:\+\(.*\)/\1/g'
```

If the RPC server is spamming your log too much, set the logging-level environment to `RUST_LOG='info,tarpc=warn'`.

## Running tokio-console

[tokio-console](https://github.com/tokio-rs/console) is a tool for monitoring tokio tasks and resources/locks in real-time.  Kind of like unix `top`, but for a single application.

To use tokio-console with neptune-core:

1. `cargo install --locked tokio-console`   see: [tokio-console installation](https://github.com/tokio-rs/console#running-the-console)
2. run tokio-console in a terminal
3. run neptune-core in a separate terminal, passing the --tokio-console flag.


## Local Integration Test Strategy

This repository contains unit tests, but multi-threaded programs are notoriously hard to test. And the unit tests usually only cover narrow parts of the code within a single thread. When you are making changes to the code, you can run through the following checks
1. `cargo b` to verify that it builds without warnings
2. `cargo t` to verify that all unit tests work
3. `run-multiple-instances.sh` to spin up three nodes that are connected through `localhost`. Instance `I0` and `I2` should be mining and all three clients should be converging on the same blocks. You can read the hashes of the blocks in the log output and verify that they all store the same blocks.
4. Run `make restart` followed by `run-multiple-instances.sh` to verify that the nodes can start from the genesis block, create a database and store subsequent blocks in this database. This test is important to verify that the client software doesn't need an existing database to function.
5. If you encounter an error in some of the stages later then (2), i.e. an error that wasn't caught by the compiler or the tests, consider if you could add a unit test that **would** have caught this error. If that's not possible consider if you can add a manual test (for example a shell script) where the tests would have been visible. Also consider if you can add anything to this list that would have caught this error (assuming you didn't write a unit test that caught it).
6. Make a transaction from e.g. `I0` to `I2` and verify that the transaction can successfully be mined and that the balances are updated correctly in each dashboard.

## Crash Procedures

If any cryptographic data ends up in an invalid state, and the note crashes as a result, please copy your entire data directory (except `wallet.dat`, `incoming_randomness.dat`, and `outgoing_randomness.dat`) and share it publicly. If you're not on `main` net, which hasn't been released yet, it should be OK to share `wallet.dat`, which contains your secret key, as well.

## Restarting Node from the Genesis Block

In order to restart your node from the genesis block, you should delete these folders:
- `<data_directory>/<network>/blocks/`
- `<data_directory>/<network>/databases/`

If you're restarting on a new chain and have no hope of recovering any funds, you should also delete these files:
- `<data_directory>/<network>/wallet/incoming_randomness.dat`
- `<data_directory>/<network>/wallet/outgoing_randomness.dat`.

On Linux, with the standard settings, the `data_directory` is
`~/.local/share/neptune/`.
