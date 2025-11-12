# Succinctness

Succinctness is the property of a blockchain that allows participants to synchronize to the network with negligible resources as a function of the number of historical blocks and transactions on the network. On conventional blockchain networks such as Bitcoin, synchronizing trustlessly requires replaying all of history in order to verify it, and downloading it first.

Neptune Cash does not presently have succinctness. However, this feature is on the roadmap and is unlikely to be culled from it.

## Recursive Block Validation

Neptune Cash achieves succinctness through recursive block validation. Every block comes with a proof which establishes, among other things, that the predecessor block is valid.