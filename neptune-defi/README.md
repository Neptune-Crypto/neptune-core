# neptune-defi

`neptune-defi` runs `neptune-core` for decentralized-finance protocols on
[Neptune Cash](https://neptune.cash/). Each protocol is a plugin: a separate
process that connects to `neptune-defi`, receives the node's notifications of
new blocks, transactions and block proposals, and reaches the node over its
JSON-RPC.

This crate builds two programs:

- `neptune-defi`, which starts `neptune-core` and serves the plugins.
- `neptune-sofun`, the plugin for SOFuN orders, which keeps the order book in
  step with the chain and has `neptune-core` fill the best order in every
  block it composes.

## Installing

`neptune-defi` is not part of the Neptune Cash release, so there is no
installer or prebuilt binary. Build it from source.

1. Install `neptune-core` from the same checkout, following
   [its instructions](../README.md#installing). That also installs the Rust
   toolchain and the build tools that `neptune-defi` needs.
2. From the root of the repository, run
   ```
   cargo install --locked --path neptune-defi
   ```
   This puts `neptune-defi` and `neptune-sofun` in `~/.cargo/bin/`.

`neptune-defi` runs the `neptune-core` executable next to its own if there is
one, and otherwise the first one on `PATH`. Build both from the same commit:
`neptune-defi` relies on the flags and JSON-RPC of the `neptune-core` it runs.

## Running

Start `neptune-defi` in place of `neptune-core`, with the same flags:
```
neptune-defi --network main --compose --guess
```
It passes every flag on to `neptune-core`, except the ones it sets itself
(`--block-notify`, `--tx-notify`, `--proposal-notify`, `--rpc-modules` and
`--unsafe-rpc`), which it refuses. It listens for plugins on `127.0.0.1:9802`;
pass `--plugin-listen <ADDR>` to use another address.

Then start the plugin in another terminal, with the same `--network` and
`--data-dir` as `neptune-defi`:
```
neptune-sofun --network main
```
It reads the plugin cookie that `neptune-defi` writes into `neptune-core`'s
data directory. If `neptune-defi` listens elsewhere, pass the same address as
`--plugin-address <ADDR>`.

`neptune-sofun --help` lists its options. `neptune-defi` has no flags of its
own besides `--plugin-listen`, so `neptune-defi --help` shows `neptune-core`'s.
