# Neptune Core Overview
Neptune Core is a multi-threaded and asynchronous program using the [tokio](https://tokio.rs/tokio/tutorial) framework for concurrent primitives. It connects to other clients through TCP/IP and accepts calls to its RPC server through HTTP/JSON.  Development also includes an RPC client that issues commands parsed from its command-line interface.

## Threads of the Neptune Core binary
There are four classes of threads:
- `main`: handles init and `main_loop`
- `peer[]`: handles `connect_to_peers` and `peer_loop`
- `mining`: runs `miner_loop`, has a worker and a monitor thread
- `rpc_server[]`: handles `rpc_server` for incoming RPC requests

## Threads of the RPC client binary, the CLI interface
This is a separate program all together with a separate address space. This means the `state` object (see further down) is not available, and all data from Neptune Core must be received via RPC.
It only has one class of threads:
- `rpc_cli[]`: handles `rpc_cli` for parsing user-supplied command-line arguments and transforms them into outgoing RPC requests.

## Channels
The threads can communicate with each other through channels provided by the tokio framework. All communication goes through the main thread. There is e.g. no way for the miner to communicate with peer threads.

The channels are:
- peer to main: `mpsc`, "multiple producer, single consumer".
- main to peer: `broadcast`, messages can only be sent to *all* peer threads. If you only want one peer thread to act, the message must include an IP that represents the peer for which the action is intended.
- miner to main: `mpsc`. Only one miner thread (the monitor/master thread) sends messages to main. Used to tell the main loop about newly found blocks.
- main to miner: `watch`. Used to tell the miner to mine on top of a new block; to shut down; or that the mempool has been updated, and that it therefore is safe to mine on the next block.
- rpc server to main: `mpsc`: Used to e.g. send a transaction object that is built from client-controlled UTXOs to the main thread where it can be added to the mempool. This channel is also used to shut down the program when the `shutdown` command is called.

## Global State
All threads that are part of Neptune Core have access to the global state and they can all read from it. Each type of thread can have its own local state that is not shared across threads, this is **not** what is discussed here.

The global state has five fields and they each follow some rules and a canonical ordering of these fields exists:
- `wallet_state` contains information necessary to generate new transactions and print the user's balance.
- `chain` Blockchain state. Contains information about state of the blockchain, block height, digest of latest block etc. Only `main` thread may update `chain`. `chain` consists of two field:
  - `light_state`, ephemeral, contains only latest block
  - `archival_state`, persistent.
  `archival_state` consists of data stored both in a database and on disk. The blocks themselves are stored on disk, and meta-information about the blocks are stored in the `block_index` database. `archival_state` also contains the `archival_mutator_set` which can be used to recover unsynced membership proofs for the mutator set.
- `network`, network state. Consists of `peer_map` for storing in memory info about all connected peers and `peer_databases` for persisting info about banned peers. Both of these can be written to by main or by peer threads. `network` also contains a `syncing` value (only `main` may write) and `instance_id` which is read-only.
- `cli` CLI arguments. The state carries around the CLI arguments. These are read-only.
- `mempool`, in-memory data structure of a set of transactions that have not yet been mined in a block. The miner reads from the `mempool` to find the most valuable transactions to mine. Only the main thread may write to `mempool`. `mempool` comes with a concept of ordering such that only the transactions that pay the highest fee per size are remembered. `mempool` enforces a max size such that its size can be constrained.

## Receiving a New Block
When a new block is received from a peer, it is first validated by the peer thread. If the block is valid and more canonical than the current tip, it is sent to the main thread. The main thread is responsible for updating the `GlobalState` data structure to reflect the new block. This is done by acquiring all relevant locks in the correct order and then calling the respective helper functions with this lock held throughout the updating process.

There are two pieces of code in the main loop that update the state with a new block: one when new blocks are received from a peer, and one for when the block is found locally by the miner thread. These two functionalities are somewhat similar. In this process all databases are flushed to ensure that the changes are persisted on disk.
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

## Scheduled Tasks in Main Loop
Different tasks are scheduled in the main loop every N seconds. These currently handle: peer discovery, block (batch) synchronization, and mempoool cleanup.
- Peer discovery: This is used to find new peers to connect to. The logic attempts to find peers that have a distance bigger than 2 in the network where distance 0 is defined as yourself; distance 1 are the peers you connect to at start up, and all incoming connections; distance 2 are your peers' peers and so on.
- Synchronization: Synchronization is intended for nodes to catch up if they are more than N blocks behind the longest reported chain. When a client is in synchronization mode, it will batch-download blocks in sequential order to catch up with the longest reported chain.
- Mempool cleanup: Remove from the mempool transactions that are more than 72 hours old.

A task for recovering unsynced membership proofs would fit well in here.

## Design Philosophies
- Avoid state-through-instruction-pointer. This means that a request/response exchange should be handled without nesting of e.g. matched messages from another peer. So when a peer thread requests a block from another peer the peer thread must return to the instruction pointer where it can receive *any* message from the peer and not only work if it actually gets the block as the next message. The reasoning behind this is that a peer thread must be able to respond to e.g. a peer discovery request message from the same peer before that peer responds with the requested block.

## Central Primitives
From `tokio`
- `spawn`
- `select!`
- `tokio::sync::Mutex`

From Std lib:
- `Arc`
- `std::sync::Mutex`

## Persistent Memory
We use `rusty-leveldb` for our database layer with a custom-wrapper that makes it more type safe. `rusty-leveldb` allows for atomic writes within *one* database which is equivalent to a table in SQL lingo. So if you want atomic writes across multiple datatypes (you do want this!) you need to put that `enum` into the database and then cast the output type to the correct type. I think this is a low price to pay to achieve atomicity on the DB-layer.

Blocks are stored on disk and their position on disk is stored in the `block_index` database. Blocks are read from and written to disk using `mmap`.

## Challenges
- Deadlocks. Solution: always acquire locks in the same order. Note though that locks from `std::sync` may not be held over an `await`. The linter should tell you if you do this. When a function requires more than one lock, **the only correct ordering in which to acquire these locks is the order in which the fields are defined in `GlobalState`. Any deviation from this is a bug.**
- Atomic writing to databases: The archival mutator set is spread across multiple databases due to how the underlying data structures are defined. If one of the databases are updated but the other is not, this will leave the archival mutator set in an invalid state. We could fix this by allowing an archival mutator set to be stored in only one database. We should also add logic to rebuild the archival mutator set state from the `block_index` database and the blocks stored on disk since it can be derived from the blocks. This functionality could be contained in a separate binary, just like we have a binary for the CLI interface in the form of the RPC client.

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
XDG_DATA_HOME=~/.local/share/neptune-integration-test/0/ RUST_LOG=debug cargo run -- --mine --network regtest # Window1 RPC-server
XDG_DATA_HOME=~/.local/share/neptune-integration-test/0/ RUST_LOG=trace cargo run --bin rpc_cli -- --server-addr 127.0.0.1:9799 send '[{"public_key": "0399bb06fa556962201e1647a7c5b231af6ff6dd6d1c1a8599309caa126526422e", "amount":{"values":[11,0,0,0]}}]' # Window2 RPC-client
```

Note that the client exists quickly, so here the `.pretty()` tracing subscriber is suitable, while `.compact()` is perhaps better for the server.

