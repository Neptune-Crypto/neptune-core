# Neptune Core

Reference implementation for the Neptune protocol.

## Setup for Development (Ubuntu)

 - curl -- `apt install curl`
 - rustup -- `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh` (installs rustup, cargo, rustc etc.)
 - source the rust environment `source $HOME/.cargo/env`
 - build-essential (for `make`) -- `apt install build-essential`
 - levelDB (the database used for this program) -- `apt-get install libleveldb-dev libsnappy-dev cmake`
 - install `vscode`
 - in `vscode` install the plugin `rust-analyzer`
 - in `vscode` activate format-on-save via `File` > `Preferences` > `Settings` then check the box for "Format on Save"
 - install `cpulimit` for nicer, and more quiet integration tests: `apt install cpulimit`

## Cheatsheet

 - To test, use `cargo test [start_of_test_name]`. Or, for a complete and much slower build, run `make test`.
 - To generate and view API documentation, use `make doc`.
 - To run, use `make run`.
 - To lint, use `make lint`.
 - To format, use `make format`.
 - To check your code for errors, but skip code generation, use `make check`.  This should be faster than `make build`.
 - To build, use `make build`.
 - To install, use `make install`.
 - To run lint, compile, and run tests use `make all`. Note that this does *not* run install.

During development you can use `cargo` instead of `make` for the above commands. Using `make` makes the compiler treat all warnings as errors, which we want for higher code quality. To send arguments to the Neptune Core program in a development setting use `cargo run -- [<flag> [<value>] [<flag> [<value>]]...]`, e.g: `cargo run -- --peers 8.8.101.69:9798 --peers 8.8.2.123:9798 --mine --listen-addr 10.64.111.55`.

## RPC
This software includes an RPC CLI client to invoke procedures in the daemon. This can be invoked from another terminal window when the daemon is running. To get all available RPC commands, execute 
```
cargo run --bin rpc_cli -- --help
```

To get e.g. the block height of a running daemon, execute
```
cargo run --bin rpc_cli -- --server-addr 127.0.0.1:<rpc_port> block-height
```

## Logging
All logging is output to standard out.

The log level can be set through the environment variable `RUST_LOG`. Valid values are: `trace`, `debug`, `info`, `warn`, and `error`. The default value is `info`. E.g.: `RUST_LOG=trace cargo run`.

For development purposes it can sometimes be nice to get a more succint logging output by piping stdout through `sed` with the below command. This will only print the namespace of the logging event and the log text. The log output can also be stored to file by piping it to `tee`, like this: `cargo run 2>&1 | tee -a integration_test.log`.
```
sed 's/.*neptune_core:\+\(.*\)/\1/g'
```

## Push and branch policy
During initial development, anyone can push to any branches, but if the branch is prepended with a person's initials, only that person should force push to their branch. Please don't force-push to master without asking the other developers. When force-pushing to *any* branch please use `--force-with-lease` as this only overwrites the branch if the `HEAD` of the remote branch is the same as the `HEAD` of the local version of this branch. Major code additions should as a rule of thumb be made through pull requests.

This policy will be restricted as more developers get onboard or at the latest after main net launch.

## Test Strategy
This repository contains unit tests, but multi-threaded programs are notoriously hard to test. And the unit tests usually only cover narrow parts of the code within a single thread. When you are making changes to the code, you can run through the following checks
1. `cargo b` to verify that it builds without warnings
2. `cargo t` to verify that all unit tests work
3. `run-multiple-instances.sh` to spin up three nodes that are connected through `localhost`. Instance `I0` and `I2` should be mining and all three clients should be converging on the same blocks. You can read the hashes of the blocks in the log output and verify that they all store the same blocks.
4. Run `make restart` followed by `run-multiple-instances.sh` to verify that the nodes can start from the genesis block, create a database and store subsequent blocks in this database. This test is important to verify that the client software doesn't need an existing database to function.
5. If you encounter an error in some of the stages later then (2), i.e. an error that wasn't caught by the compiler or the tests, consider if you could add a unit test that **would** have caught this error. If that's not possible consider if you can add a manual test (for example a shell script) where the tests would have been visible. Also consider if you can add anything to this list that would have caught this error (assuming you didn't write a unit test that caught it).


## Notes
The `Makefile` recipes set the flag `RUSTFLAGS=-Dwarnings` and this sometimes makes the recompilation **much** slower than without this flag, as `cargo` for some reason rebuilds the entire crate when this flag is set and a minor change is made in a test. So it is much faster to run the tests using cargo and then use the `make all` command before e.g. committing to ensure that the test build does not produce any warnings.
