# Succinctness

Neptune Cash is a *succinct* blockchain, meaning that participants can
synchronize to the network with negligible resources as a function of the number
of historical blocks and transactions on the network. On conventional blockchain
networks such as Bitcoin, synchronizing trustlessly requires replaying all of
history in order to verify it, and downloading it first.

## Other Forms of Succinctness

When used without further context, the terms *succinct* and *succinctness*
denote exactly this property, where the task of validating the chain can be done
with negligible resources -- *e.g.*, downloading one block and verifying its
recursive proof.

There may be other tasks that could conceivably be done with negligible
resources, such as managing UTXOs or contributing to the consensus mechanism. To
disambiguate, we use the following terms.
 - *Succinct Validation.* Validate the chain with negligible resources. This is
   the exact meaning intended by "succinctness" whenever there is no room for
   misunderstanding.
 - *Succinct Mining.* Compose blocks or Guess on block proposals with negligible
   resources.
 - *Succinct Asset Management.* Custody UTXOs and manage their mutator set
   membership proofs with negligible resources.

Neptune Cash intentionally does not feature succinct mining. This choice is a
countermeasure against an attack that applies to blockchains with both succinct
mining and succinct validation.

The attack: mine two blocks, withhold the first, broadcast the second. Nodes
accept the second block but lack the data needed to update their mutator set
membership proofs. Existing funds have been bricked.

The (weak) countermeasure: *incremental validation*. Miners that are online when
a new block is published reject it if its predecessor is being withheld -- even
if both are valid. This rule only describes the default behavior of the
reference implementation and does not bind miners who choose to break with the
rules, so ...

The countermeasure (with teeth): Composers and Guessers are required to
demonstrate knowledge of the archival mutator set. The attack is still possible
in principle, but no self-interested miner will accept a block with a missing
predecessor since that would rob them of the mutator set data and hence of the
ability to mine blocks going forward.

As for succinct asset management, Neptune Cash does have this feature, but only
to a limited degree. Nodes managing UTXOs obtain the data they need to update
UTXO membership proofs from the blocks when they are found. This works, as long
as blocks come one by one with no reorganizations and the node is online for the
entire duration. If there are reorganizations, or if the node spent a large
amount of time offline and cannot find peers willing to serve the missed blocks,
then they have to rely on an archival peer to recover membership proofs.

There is a theoretical (not implemented) algorithm that allows a node that was
offline to recover membership proofs from $O((\log N)^2)$ interactive block
queries (to a peer willing to serve arbitrary historical blocks).

## How Neptune Cash Achieves Succinct Validation

*Recursive Block Validation*. Every block comes with a proof which establishes,
among other things, that the predecessor block is valid.

In practice, predecessor validity is a *claim* in the block's appendix, and the
block program already establishes the validity of all claims.
The predecessor-is-valid claim is present in the appendix as of the latest soft
fork.

The predecessor-is-valid program performs all checks that were previously done
only on the host machine except one: authenticating the removal records' chunks
and authentication structures. This check is still performed on the host machine
but only incrementally.

The motivation for leaving this check out is a) the concretely high cost of both
including the chunks and authentication structures in the block and
authenticating them, and b) an anticipated hard fork that moves them out of the
block, at least in terms of block size; changes their data structure, saving
VM cycles; and decomposes the entire authentication task into a PCD tree,
enabling parallelism so that transaction throughput scales with the parallel
compute power available.
