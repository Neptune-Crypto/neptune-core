# User Guides

Explainers and tutorials on how to use or get started using the various software packages that constitute the client.

Building the software, or installing it using a script, yields six executables. Two of these executables are user interfaces. The executables are:

 - `neptune-core` is the daemon that runs the protocol.
 - `neptune-prover` is a binary invoked by `neptune-core` for out-of-process proving tasks.
 - `neptune-dashboard` is a terminal user interface that requires a running instance of `neptune-core`.
 - `neptune-cli` is a command-line interface that might require a running instance of `neptune-core` depending on the command.
 - `neptune-blk-info` is a utility that prints basic information about the blocks contained in `blk<n>.dat` files.
 - `neptune-block-claims` is a utility that prints the claims related to the validity of stored canonical blocks; it is used to produce a [checkpoint](./consensus/consensus_rule_sets.md#the-checkpoint).

Except for the [installation instructions](./user-guides/installation.md), the user guides in this section assume these executables are installed.
