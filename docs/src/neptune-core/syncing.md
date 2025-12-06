# Syncing

*Syncing* refers to the process of replicating the (public) consensus state and aligning (private) wallet state thereto.
For archival nodes, this process involves downloading all blocks, applying their induced state updates, and storing them
correctly. Being synced is a precondition to initiating transactions, producing blocks, and evaluating the fork choice
rule.

## Archival Nodes

Archival nodes store a block database, an archival mutator set accumulator, and an archival block Merkle mountain range.
With every block, all three are updated. Moreover, the list of historical blocks suffices to bring all three databases
into an up-to-date state. The state updates are downstream from `GlobalState::set_new_tip`.

### Shallow Sync

If the node's peer loop is notified of a block height in excess of its own, but below a threshold difference, then the
shallow sync (AKA fork reconciliation process) is initiated. This process involves repeatedly querying the peer for
predecessor blocks until the latest universal common ancestor (LUCA) is found. At this point, the peer loop is sitting
on a list of blocks from LUCA to the peer's tip; and it proceeds to validate them before passing them on to the main
loop for processing.

The fork reconciliation mechanism is managed by `PeerLoopHandler::try_ensure_path` with the list of blocks living in
`MutablePeerState`. The threshold difference in block heights defaults to 1000 but can be overridden via the CLI
`sync-mode-threshold`.

The reason why the shallow sync only works for small block height differences is because the list of reconciliation
blocks (*i.e.*, those connecting LUCA to the peer's tip) are stored in RAM. It is therefore a denial of service vector.
To guard against this denial of service vector, the number of blocks stored in RAM is limited to `sync-mode-threshold`
and if the block height difference exceeds this number, the node goes into *sync mode* instead.

### Sync Challenge and Response

When it is determined that the backlog of blocks is too large for the shallow sync procedure, the node sends the peer
a `SyncChallenge`. This struct is a list of 10 block heights and a target height corresponding to the peer's
claimed tip. The peer must respond with a valid `SyncChallengeResponse`, consisting of all the indicated blocks along
with their predecessors (so that they can be determined to be valid) and membership proofs into the block MMR (so that
they can be determined to all be on the same chain). The node enters into sync mode if this response is valid (and on
time).

This architecture achieves a kind of succinctness at the expense of admitting false positive and false negative rates.
The number of blocks to be transmitted in the course of one challenge-and-response subprotocol will never exceed 22,
regardless of the number of historical blocks or the size of the backlog. However, it is possible for the proof-of-work
numbers in the response to appear fishy to the validating receiver, in which case the response will be rejected even if
it was authentic. Likewise, it is technically possible to produce series of unlinked chain segments covering all block
heights. As long as the queried block heights do not coincide with a dangling link and as long as the evolution of the
proof-of-work number is credible, the malicious sync challenge response will be accepted.

The sync challenge and response mechanism will be made obsolete by succinctness.

### The Sync Loop

The sync loop (`sync_loop.rs`) is an event loop that manages the sync. It has two responsibilities:
 1. It must download all the blocks.
 2. It must feed them, in the right order, to the main loop.

When sync mode is entered, a new sync loop is spun up. The `MutableMainLoopState` loop holds an optional
`SyncLoopHandle`, which comes with useful wrappers for communication. The node is in sync mode if this option is set.
Likewise, it is in sync mode if the sync anchor (which lives on `GlobalState::net`) is set. The two options are always
set and unset in tandem, and one is accessible to peer loops whereas the other is accessible to the main loop.

The sync loop communicates with the outside world by using the main loop as a proxy. So the main loop is responsible
for forwarding messages from the sync loop to peers if necessary, and from peers to the sync loop (if one is active).

The sync loop stores blocks in a temporary directory. By default, whenever a new sync loop starts it will attempt to
resume the sync with all blocks found in its temporary directory. To override this behavior, and force new sync loops
to start from scratch, run `neptune-core` with the argument `--no-resume-sync`.

The sync loop keeps track of which blocks have been downloaded and which ones not yet through a data structure called
the `SynchronizationBitMask` (and sometimes `coverage` for short). It is a bit mask along with two bounds. All bits
below the lower bound are implicitly 1, and all bits above the upper bound are implicitly 0. In between the bits can be
0 or 1, depending on whether the corresponding block was downloaded. The lower bound coincides with the height of the
highest block processed by the state update function of the main loop. The upper bound coincides with the target block
that we are syncing relative to.

This synchronization bit mask is how the sync loop determines which blocks to request from another node who is also
syncing. Assuming the lower and upper bounds agree, the expression `own_mask & !other_mask` puts zeros in the locations
corresponding to block heights that the peer is capable of serving and which we ourselves have not downloaded yet.

Whenever the fist bit after the lower bound is one, the sync loop spawns a separate task called the tip-successors task
and encapsulated in `SyncLoop::process_successors_of_tip`. This tokio task is responsible for reading the next block
from the temporary directory, validating it, sending it to the main loop, and updating the lower bound accordingly. When
it terminates it asynchronously sends a return code back to the sync loop which processes it accordingly.

Validation of blocks happens relative to an enum `BlockValidator`. In production there is only one variant,
`Production`, which invokes `Block::is_valid`. For tests, `Test` is an alternative that allows testing the sync loop
relative to random (and thus invalid) blocks.

The `SyncProgress` is an object heuristically indicating how far the sync loop has moved from the initial state (large 
backlog of blocks) to the intended result (all downloaded and processed). It is a noisy heuristic for at least two
reasons:
 - There are two distinct tasks, downloading blocks and processing them. Progress in the one task might not coincide
   with progress in the other.
 - Progress is given relative to a total span of blocks to download and process. However, this total span can increase
   as new blocks are found while the sync is running. Moreover, if the sync loop starts over (for instance because the
   previous one timed out or because the node shut down), then the starting point of this total span may have shifted
   to whatever the new tip height is at the time the new sync loop starts.

### Reorganization While Syncing

If there is a reorganization while syncing, then at some point a block validation will fail. When this happens, the sync
loop terminates and cleans up the temporary directory. At this point the main loop sends a `RequestBlockNotification`
message to all peers. Responses to this request may (and should) trigger a new sync.

### Sync Failure

If the sync loop fails, whether because of a reorganization or another reason, the default behavior is for the temporary
directory to be deleted so that future syncs can start from a clean slate and avoid potentially corrupt data. However,
if the temporary directory could not be deleted, the node logs a `error!` message informing the user to delete them
manually.

## Succinct Nodes

***Note:*** *succinctness is not yet supported. This section describes a future feature.*

Succinctness through recursive block validation means that the block proof certifies all of:
 - the claimed proof-of-work number (enabling the light client to decide which one of two claimants is the canonical
   fork);
 - the validity of the current block relative to its predecessor, and by induction, the validity of the entire chain of
   historical blocks;
 - the correctness of the state commitments embedded in the current block (namely, the mutator set and block MMR
   accumulators).

Consequently, by downloading one block and verifying its proof the light wallet-free node can sync trustlessly.

### Light Nodes with Wallets

Light nodes that wish to initiate transactions must update their private wallet state to the state commitment from the
most recent block. This task entails finding the up-to-date mutator set membership proof for every UTXO in the wallet.
There are several options for obtaining these membership proofs.

 1. Stay online and process blocks as they are broadcast. Every block induces a relatively inexpensive wallet state
    update task.
 2. Query them from an archival node that stores an archival membership proof. Down side: some privacy is lost.
 3. Download all blocks from the time spent offline and process them streamingly, applying the induced wallet state
    updates one by one. Down side: requires a lot of unnecessary bandwidth consumption, and moreover the speed is
    limited by the network connection.
 4. Run a bisection search to find the relevant blocks, and exfiltrate the relevant mutator set data from there. Down
    side: this strategy requires interactively querying a square-of-logarithm number of blocks.
