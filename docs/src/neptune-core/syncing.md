# Syncing

Syncing is different depending on the node type.

## Synchronization for Archival Nodes

Synchronization describes the state that a blockchain client can be in.

Synchronization is motivated by the way that regular block downloading happens. If a client receives a new block
from a peer, the client checks if it knows the parent of this block. If it does not know the parent, then
the client requests the parent from the peer. If this parent block is also not known, it requests the parent
of that and so on. In this process all blocks are received in opposite order from which they are mined, and
the blocks whose parents are not known are kept in memory. To avoid overflowing the memory if thousands of
blocks were to be fetched this way, synchronization was built.

When synchronization is active, the blocks are fetched in sequential order, from oldest to newest block.
State that is used to manage synchronization is stored in the main thread which runs at
startup. This thread ends up in `main_loop.rs` and stays there until program shutdown.

The `MutableMainLoopState` currently consists of two fields: A state to handle peer discovery and a state to
handle synchronization. The `SyncState` records which blockchain heights that the connected peers have reported
and it records the latest synchronization request that was sent by the client. When a peer is connected, the
handshake for the connection contains the latest block header, and if the height and proof-of-work-family
values exceeds the client's height value by a certain (configurable) threshold, synchronization mode is
activated. The synchronization process runs once every `N` seconds (currently 15) and which kind of request
for a batch of blocks that should be sent to a peer. A client can request a batch of blocks from a peer using
the `PeerMessage::BlockRequestBatch` type constructor. This type takes a list of block digests and a requested
batch size as parameter. The list of block digests represents the block digests of the blocks that the client
has already stored to its database.

The peer then responds with a list of transfers that follows the first digest that it recognizes in the list of
block digest the syncing node has sent.
