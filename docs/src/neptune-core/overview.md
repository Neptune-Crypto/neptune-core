# Neptune Core Overview
`neptune-core` uses the [tokio](https://tokio.rs/tokio/tutorial) async framework and tokio's multi-threaded executor which assigns tasks to threads in a threadpool and requires the use of thread synchronization primitives.  We refer to spawned tokio tasks as `tasks` but you can think of them as threads if that fits your mental model better.  Note that a tokio task may (or may not) run on a separate operating system thread from that task that spawned it, at tokio's discretion.

`neptune-core` connects to other clients through TCP/IP and accepts calls to its RPC server via [tarpc](https://github.com/google/tarpc) using json serialization over the [serde_transport](https://docs.rs/tarpc/latest/tarpc/serde_transport/index.html).  The project also includes `neptune-cli` a command-line client and `neptune-dashboard`, a cli/tui wallet tool.  Both interact with `neptune-core` via the tarpc RPC protocol.

## Long-lived async tasks of neptune-core binary
There are four classes of tasks:
- `main`: handles init and `main_loop`
- `peer[]`: handles `connect_to_peers` and `peer_loop`
- `mining`: runs `miner_loop`, has a worker and a monitor task
- `server[]`: handles `server` for incoming RPC requests

With the introduction of the libp2p [network stack](network_stack.md), there is a fifth:
 - `NetworkActor`: responsible for driving the libp2p swarm of peers and, whenever a new connection is established, spawning a `peer_loop` for it.

## Channels
Long-lived tasks can communicate with each other through channels provided by the tokio framework. All communication goes through the main task. Eg, there is no way for the miner task to communicate with peer tasks.

The channels are:
- peer to main: `mpsc`, "multiple producer, single consumer".
- main to peer: `broadcast`, messages can only be sent to *all* peer tasks. If you only want one peer task to act, the message must include an IP that represents the peer for which the action is intended.
- miner to main: `mpsc`. Only one miner task (the monitor/master task) sends messages to main. Used to tell the main loop about newly found blocks.
- main to miner: `watch`. Used to tell the miner to mine on top of a new block; to shut down; or that the mempool has been updated, and that it therefore is safe to mine on the next block.
- rpc server to main: `mpsc`: Used to e.g. send a transaction object that is built from client-controlled UTXOs to the main task where it can be added to the mempool. This channel is also used to shut down the program when the `shutdown` command is called.
- NetworkActor to main: `mpsc`: used to notify the main loop of network-level events.
- main to NetworkActor: `mpsc`: used to issue commands (e.g., "dial this address") to the NetworkActor.

## Global State
All tasks that are part of Neptune Core have access to the global state and they can all read from it. Each type of task can have its own local state that is not shared across tasks, this is **not** what is discussed here.

The global state has five fields and they each follow some rules:
- `wallet_state` contains information necessary to generate new transactions and print the user's balance.
- `chain` Blockchain state. Contains information about state of the blockchain, block height, digest of latest block etc. Only `main` task may update `chain`. `chain` consists of two field:
  - `light_state`, ephemeral, contains only latest block
  - `archival_state`, persistent.
  `archival_state` consists of data stored both in a database and on disk. The blocks themselves are stored on disk, and meta-information about the blocks are stored in the `block_index` database. `archival_state` also contains the `archival_mutator_set` which can be used to recover unsynced membership proofs for the mutator set. `archival_state` also contains an optional UTXO index that can be maintained by starting the node with the `--utxo-index` flag. The UTXO index contains a digest for each historical transaction input, and two b-field elements for each historical announcement. These two b-field elements are interpreted as `AnnouncementFlag`s and can be used to quickly identify announcements that are relevant to a wallet. They are just the two first elements of each announcement in the block. The UTXO index also contains mappings from addition records (transaction outputs) to block heights, and from the digests of absolute index sets (transaction inputs) to block heights, in other words: it maintains bi-directional mappings between blocks on one side and UTXOs and announcements on the other side. Exchanges and mining pools should run the node with the UTXO index, as this makes the full rescanning of UTXOs for once's own wallet possible. Maintaining a UTXO index also allows for the activation of the RPC namespace `UtxoIndex` which are endpoints helping non-archival nodes and wallets to find relevant UTXOs. The index does not contain a block hash to transaction output mapping, since the transaction outputs are already present in another database, the `archival_mutator_set`. The UTXO index attempts to strike a balance between functionality, lookup speeds, and the minimization of required disk space.
- `network`, network state. Consists of `peer_map` for storing in memory info about all connected peers and `peer_databases` for persisting info about banned peers. Both of these can be written to by main or by peer tasks. `network` also contains a `syncing` value (only `main` may write) and `instance_id` which is read-only.
- `cli` CLI arguments. The state carries around the CLI arguments. These are read-only.
- `mempool`, in-memory data structure of a set of transactions that have not yet been mined in a block. The miner reads from the `mempool` to find the most valuable transactions to mine. Only the main task may write to `mempool`. `mempool` comes with a concept of ordering such that only the transactions that pay the highest fee per size are remembered. `mempool` enforces a max size such that its size can be constrained.

## Receiving a New Block
When a new block is received from a peer, it is first validated by the peer task. If the block is valid and more canonical than the current tip, it is sent to the main task. The main task is responsible for updating the `GlobalState` data structure to reflect the new block. This is done by write-acquiring the single `GlobalStateLock` and then calling the respective helper functions with this lock held throughout the updating process.

There are two pieces of code in the main loop that update the state with a new block: one when new blocks are received from a peer, and one for when the block is found locally by the miner task. These two functionalities are somewhat similar. In this process all databases are flushed to ensure that the changes are persisted on disk.
The individual steps of updating the global state with a new block are:

0. &nbsp;
    - If block was found locally: Send it to all peers before updating state.
    - If block was received from peer: Check if `sync` mode is activated and if we can leave `sync` mode (see below for an explanation of synchronization).
1. `write_block`: Write the block to disk and update the `block_index` database with the block's meta information.
2. `update_mutator_set`: Update the archival mutator set with the transaction (input and output UTXOs) from this block by applying all addition records and removal records contained in the block.
3. `update_wallet_state_with_new_block`: Check if this block contains UTXOs spent by or sent to us. Also update membership proofs for unspent UTXOs that are managed/relevant to/spendable by this client's wallet.
4. `mempool.update_with_block`: Remove transactions that were included in this block and update all mutator set data associated with all remaining transactions in the mempool
5. Update `light_state` with the latest block.
6. Flush all databases
7. Tell miner
    - If block was found locally: Tell miner that it can start working on next block since the `mempool` has now been updated with the latest block.
    - If blocks were received from peer: Tell miner to start building on top of a new chain tip.

## Spending UTXOs
A transaction that spends UTXOs managed by the client can be made by calling the `create_transaction` method on the `GlobalState` instance. This function needs a synced `wallet_db` and a chain tip in `light_state` to produce a valid transaction.

For a working example, see the implementation of the `send_to_many()` RPC method.

## Scheduled Tasks in Main Loop
Different tasks are scheduled in the main loop every N seconds. These currently handle: peer discovery, block (batch) synchronization, and mempoool cleanup.
- Peer discovery: This is used to find new peers to connect to. The logic attempts to find peers that have a distance bigger than 2 in the network where distance 0 is defined as yourself; distance 1 are the peers you connect to at start up, and all incoming connections; distance 2 are your peers' peers and so on.
- Synchronization: Synchronization is intended for nodes to catch up if they are more than N blocks behind the longest reported chain. When a client is in synchronization mode, it will batch-download blocks in sequential order to catch up with the longest reported chain.
- Mempool cleanup: Remove from the mempool transactions that are more than 72 hours old.

A task for recovering unsynced membership proofs would fit well in here.

## Design Philosophies
- Avoid state-through-instruction-pointer. This means that a request/response exchange should be handled without nesting of e.g. matched messages from another peer. So when a peer task requests a block from another peer the peer task must return to the instruction pointer where it can receive *any* message from the peer and not only work if it actually gets the block as the next message. The reasoning behind this is that a peer task must be able to respond to e.g. a peer discovery request message from the same peer before that peer responds with the requested block.

## Central Primitives
From `tokio`
- `spawn`
- `select!`
- `tokio::sync::RwLock`

From Std lib:
- `Arc`

From neptune-core:
- `neptune_core::locks::tokio::AtomicRw`  (wraps `Arc<tokio::sync::RwLock>`)

## Persistent Memory

We use `leveldb` for our database layer with custom wrappers that make it more async-friendly, type safe, and emulate multi-table transactions.

`neptune_core::database::NeptuneLevelDb` provides async wrappers for leveldb APIs to avoid blocking async tasks.

`leveldb` is a simple key/value store, meaning it only allows manipulating individual strings. It does however provide a batch update facility. `neptune_core::database::storage::storage_schema::DbSchema` leverages these batch updates to provide vector and singleton types that can be manipulated in rust code and then atomically written to `leveldb` as a single batch update (aka transaction).

Blocks are stored on disk and their position on disk is stored in the `block_index` database. Blocks are read from and written to disk using `mmap`.  We wrap all file-system calls with tokio's `spawn_blocking()` so they will not block other async tasks.

## Challenges

- Deadlocks. We only have a single RwLock over the GlobalState. This is encapsulated in struct `GlobalStateLock`. This makes deadlocks pretty easy to avoid, following some simple rules:

  1. avoid deadlocking yourself. If a function has read-acquired the global lock then it must be released before write-acquiring. Likewise never attempt to write-acquire the lock twice.

  2. avoid deadlocking others. Always be certain that the global lock will be released in timely fashion. In other words if you have some kind of long running task with an event loop that needs to acquire the global lock, ensure that it gets acquired+released inside the loop rather than outside.

- Atomic writing to databases: `neptune-core` presently writes to the following databases: wallet_db, block_index_db, archival_mutator_set, peer_state. If one of the databases are updated but the other is not, this can leave data in an invalid state. We could fix this by storing all state in a single transactional database but that might make the code base less modular.

note: We should also add logic to rebuild the archival state from the `block_index_db` and the blocks stored on disk since it can be derived from the blocks. This functionality could be contained in a separate binary or a check could be performed at startup.

## Tracing
A structured way of inspecting a program when designing the RPC API, is to use tracing, which is a logger, that is suitable for programs with asynchronous control flow.
1. Get a feeling for the [core concepts](https://docs.rs/tracing/latest/tracing/).
2. Read tokio's [short tutorial](https://tokio.rs/tokio/topics/tracing).
3. View the [3 different formatters](https://docs.rs/tracing-subscriber/0.2.19/tracing_subscriber/fmt/index.html#formatters).
4. See what we can have eventually: https://tokio.rs/tokio/topics/tracing-next-steps

The main value-proposition of tracing is that you can add `#[instrument]` attribute over the function you currently work on. This will print the nested `trace!("")` statements. You can also do it more advanced:

```rust
#[instrument(ret, skip_all, fields(particular_arg = inputarg1*2), level="debug")]
fn my_func(&self, inputarg1: u32, inputarg2: u32) -> u32 {
  debug!("This will be visible from `stdout`");
  info!("This prints");
  trace!("This does not print {:#?}", inputarg2);
  inputarg1 * 42 + inputarg2
}
```

Prints the return value, but none of the args (default behaviour is to prints all arguments with std::fmt::Debug formatter). It creates a new key with a value that is the double of the `inputarg1` and prints that.
It then prints everything that is `debug` level or above, where `trace < debug < info < warn < error`, so here the `trace!()` is omitted.  You configure the lowest level you want to see with environment variable `RUST_LOG=debug`.

## RPC
To develop a new RPC, it can be productive to view two terminals simultaneously and run one of the following commands in each:

```bash
XDG_DATA_HOME=~/.local/share/neptune-integration-test/0/ RUST_LOG=debug cargo run -- --compose --guess --network regtest # Window1 RPC-server
XDG_DATA_HOME=~/.local/share/neptune-integration-test/0/ RUST_LOG=trace cargo run --bin rpc_cli -- --port 9799 send '[{"public_key": "0399bb06fa556962201e1647a7c5b231af6ff6dd6d1c1a8599309caa126526422e", "amount":{"values":[11,0,0,0]}}]' # Window2 RPC-client
```

Note that the client exists quickly, so here the `.pretty()` tracing subscriber is suitable, while `.compact()` is perhaps better for the server.

# neptune-cli client

`neptune-cli` is a separate program with a separate address space. This means the `state` object (see further down) is not available, and all data from Neptune Core must be received via RPC.

`neptune-cli` does not have any long-lived tasks but rather receives individual commands via CLI, sends a query to neptune-core, presents the response, and exits.
