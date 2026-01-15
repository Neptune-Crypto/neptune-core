# Neptune Core

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![GitHub CI](https://github.com/Neptune-Crypto/neptune-core/actions/workflows/main.yml/badge.svg)](https://github.com/Neptune-Crypto/neptune-core/actions/workflows/main.yml)
[![crates.io](https://img.shields.io/crates/v/neptune-cash.svg)](https://crates.io/crates/neptune-cash)
[![Coverage Status](https://coveralls.io/repos/github/Neptune-Crypto/neptune-core/badge.svg?branch=master)](https://coveralls.io/github/Neptune-Crypto/neptune-core?branch=master)

Neptune-core is the reference implementation for the [Neptune Cash](https://neptune.cash/) protocol.

## Disclaimer

> [!CAUTION]
> This software uses novel and untested cryptography. Use at own risk, and invest only that which
> you can afford to lose.

> [!IMPORTANT]
> If a catastrophic vulnerability is discovered in the protocol, it might be restarted from genesis.

## Installing

### Build with [Nix](https://nixos.org/)

 -  Make sure you have `nix` installed or install it with:
    ```shell
    sh <(curl --proto '=https' --tlsv1.2 -L https://nixos.org/nix/install) --daemon`
    ```
 -  Now simply run it with:
    - `nix run github:Neptune-Crypto/neptune-core` will run the `neptune-core` binary, fetching the git repo automatically.
    - Or run a specific package with `nix run github:Neptune-Crypto/neptune-core#neptune-cli`.
    - Or locally in the repo with `nix run` or `nix run .#neptune-cli`
    - To globally install use `nix profile install` or a specific package with `nix profile install .#neptune-cli`

All required build dependencies are packaged reproducibly and defined in `flake.nix`.
A development shell is included and can be accessed by running `nix develop` or use `direnv allow` if available.

### Compile from Source -- Linux Debian/Ubuntu

- Open a terminal to run the following commands.
- Install curl: `sudo apt install curl`
- Install the rust compiler and accessories:
  `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y`
- Source the rust environment: `source "$HOME/.cargo/env"`
- Install build tools: `sudo apt install build-essential`
- Install LevelDB: `sudo apt install libleveldb-dev libsnappy-dev cmake`
- Download the repository: `git clone https://github.com/Neptune-Crypto/neptune-core.git`
- Enter the repository: `cd neptune-core`
- Checkout the release branch `git checkout release`. (Alternatively, for the *unstable development*
  branch, skip this step.)
- Build for release and put the binaries in your local path (`~/.cargo/bin/`): `make install-linux`

> [!IMPORTANT]
> Any commit except the one tagged `release` is considered an _unstable development_ commit and thus carries a
> higher risk of database corruption and/or loss of funds. However, known bug fixes make their way into `master`
> before being part of a release.

### Windows

To install Rust and cargo on Windows, you can
follow [these instructions](https://doc.rust-lang.org/cargo/getting-started/installation.html).
Installing cargo might require you to install Visual Studio with some C++ support but the cargo
installer for Windows should handle that. With a functioning version of cargo, compilation on
Windows should just work out-of-the-box with cargo build etc.

- Download and run the CMake installer from the [website](https://cmake.org/download/).
- Open PowerShell to run the following commands.
- Download the repository: `git clone https://github.com/Neptune-Crypto/neptune-core.git`
- Enter the repository: `cd neptune-core`
- Checkout the release branch `git checkout release`. (Alternatively, for an *unstable development*
  branch, skip this step.)
- Build for release and put the binaries in your local path (`~/.cargo/bin/`):
  ```
  cargo install --locked --path neptune-core
  cargo install --locked --path neptune-core-cli
  cargo install --locked --path neptune-dashboard
  ```

### MacOS

 - Open a terminal to run the following commands.
 - Make sure you have `Homebrew` installed. If not, install it from [here](https://brew.sh/).
 - Install curl: `brew install curl`
 - Install the rust compiler and accessories: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
 - Source the rust environment: `source "$HOME/.cargo/env"`
 - Install Xcode command line tools: `xcode-select --install`
 - Install LevelDB: `brew install leveldb`
 - Install cmake: `brew install cmake`
 - Install git: `brew install git`
 - Download the repository: `git clone https://github.com/Neptune-Crypto/neptune-core.git`
 - Enter the repository: `cd neptune-core`
 - Build for release and put the binaries in your local path: `make install`

## Running & Connecting

- Generate a wallet file: `neptune-cli generate-wallet`
- Run neptune-core daemon: `neptune-core` with flags
    - `--peer [ip_address:port]` to connect to a given peer, for instance
      `--peer 51.15.139.238:9798` or `--peer 139.162.193.206:9798` or
      `--peer [2001:bc8:17c0:41e:46a8:42ff:fe22:e8e9]:9798`.
    - `--compose --guess` to mine — if you want to generate coins
    - `--help` to get a list of available command-line arguments

If you don't have a static IPv4, then try connecting to other nodes with IPv6. It's our experience
that you will then be able to open and receive connections to other nodes through Nepture Core's
built-in peer-discovery process.

## Documentation

Documentation uses [https://rust-lang.github.io/mdBook/](mdBook). To run a local copy:

- install mdBook: `cargo install mdbook`
- enter into the `docs/` directory: `cd docs`
- run server: `mdbook serve --open`

## Dashboard

This software comes with a dashboard that communicates with the daemon. The dashboard is a
console-based user interface to generate addresses, receive and send money, and monitor the behavior
of the client. The daemon must be running before the dashboard is started. To start the dashboard,
run: `neptune-dashboard`. (If you set daemon's RPC port to a custom value specify that value with
the flag `--port [port]`.)

## Command-Line Interface

In addition to a dashboard, the software comes with a CLI client to invoke procedures in the daemon.
This can be invoked from another terminal window when the daemon is running. To get all available
commands, execute

```
neptune-cli --help
```

To get e.g. the block height of a running daemon, execute

```
neptune-cli block-height
```

If you set up `neptune-core` to listen for RPC requests on a different port from the default (9799),
then the flag `--port <port>` is your friend.

## Setup for Development (Ubuntu)

- build-essential (for `make`) -- `apt install build-essential`
- install `vscode`
- in `vscode` install the plugin `rust-analyzer`
- in `vscode` activate format-on-save via `File` > `Preferences` > `Settings` then check the box
  for "Format on Save"
- install `cpulimit` for nicer, and more quiet integration tests: `apt install cpulimit`

## Branches and Pull Requests

Please see [documentation](https://docs.neptune.cash/contributing/git-workflow.html) of our
branching methodology and how to submit a pull request.

## Logging

All logging is output to standard out.

The log level can be set through the environment variable `RUST_LOG`. Valid values are: `trace`,
`debug`, `info`, `warn`, and `error`. The default value is `info`. E.g.: `RUST_LOG=trace cargo run`.
More complex settings
are [possible](https://docs.rs/env_logger/latest/env_logger/#enabling-logging).

The default log level is: `RUST_LOG='info,tarpc=warn'`. This prevents logging `info` level from the
tarpc (RPC) module, which can spam the log. If you wish to see those, just use `RUST_LOG='info'`

To see even more detail, but without tarpc spam: `RUST_LOG='debug,tarpc=warn'`

For development purposes it can sometimes be nice to get a more succinct logging output by piping
stdout through `sed` with the below command. This will only print the namespace of the logging event
and the log text. The log output can also be stored to file by piping it to `tee`, like this:
`cargo run 2>&1 | tee -a integration_test.log`.

```
sed 's/.*neptune_core:\+\(.*\)/\1/g'
```

## Running tokio-console

[tokio-console](https://github.com/tokio-rs/console) is a tool for monitoring tokio tasks and
resources/locks in real-time. Kind of like unix `top`, but for a single application.

tokio-console support is not built into neptune-core by default. It requires building with
`--features tokio-console`.

To use tokio-console with neptune-core:

1. build and install neptune-core with tokio-console support.

   `cargo install --features tokio-console --locked --path .`

2. install tokio-console executable.

   `cargo install --locked tokio-console`
   see: [tokio-console installation](https://github.com/tokio-rs/console#running-the-console)

3. run tokio-console in a terminal

4. run neptune-core in a separate terminal, passing the --tokio-console flag.

   `neptune-core --tokio-console [other-arguments]`

## Local Integration Test Strategy

This repository contains unit tests, but async programs are notoriously hard to test. And the unit
tests usually only cover narrow parts of the code within a single async task. When you are making
changes to the code, you can run through the following checks

1. `cargo b` to verify that it builds without warnings
2. `cargo t` to verify that all unit tests work
3. `run-multiple-instances.sh` to spin up three nodes that are connected through `localhost`.
   Instance `I0` and `I2` should be mining and all three clients should be converging on the same
   blocks. You can read the hashes of the blocks in the log output and verify that they all store
   the same blocks.
4. Run `make restart` followed by `run-multiple-instances.sh` to verify that the nodes can start
   from the genesis block, create a database and store subsequent blocks in this database. This test
   is important to verify that the client software doesn't need an existing database to function.
5. If you encounter an error in some of the stages later then (2), i.e. an error that wasn't caught
   by the compiler or the tests, consider if you could add a unit test that **would** have caught
   this error. If that's not possible consider if you can add a manual test (for example a shell
   script) where the tests would have been visible. Also consider if you can add anything to this
   list that would have caught this error (assuming you didn't write a unit test that caught it).
6. Make a transaction from e.g. `I0` to `I2` and verify that the transaction can successfully be
   mined and that the balances are updated correctly in each dashboard.

## Crash Procedures

If any cryptographic data ends up in an invalid state, and the note crashes as a result, please copy
your entire data directory (except `wallet.dat`, `incoming_randomness.dat`, and
`outgoing_randomness.dat`) and share it publicly. If you're not on `main` net it should be OK to
share `wallet.dat`, which contains your secret key, as well. If you are on mainnet, don't share any
of these files with anyone because doing so will put your funds at risk.

## Restarting Node from the Genesis Block

In order to restart your node from the genesis block, you should delete these folders:

- `<data_directory>/<network>/blocks/`
- `<data_directory>/<network>/databases/`

If you're restarting on a new chain and have no hope of recovering any funds, you should also delete
these files:

- `<data_directory>/<network>/wallet/incoming_randomness.dat`
- `<data_directory>/<network>/wallet/outgoing_randomness.dat`.

On Linux, with the standard settings, the `data_directory` is
`~/.local/share/neptune/`.
