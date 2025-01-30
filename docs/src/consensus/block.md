# Block

A block kernel consists of a header, body, and an appendix.

The *block header* has constant size and consists of:
 - `version` the version of the Neptune protocol
 - `height` the block height represented as a `BFieldElement`
 - `prev_block_digest` the hash of the block's predecessor
 - `timestamp` when the block was found
 - `nonce` randomness for proof-of-work
 - `cumulative_proof_of_work` approximate number of hashes computed in the block's entire lineage
 - `difficulty` approximate number of hashes required to find a block
 - `guesser_digest` the lock prevents any but the guesser from spending guesser fees.

The *block body* holds the variable-size data, consisting of:
 - `transaction_kernel` every block contains one transaction, which represents the merger of all broadcasted transactions that the miner decided to confirm.
 - `mutator_set_accumulator` the <span style="color:red">mutator set</span> is the data structure that holds the UTXOs. It is simultaneously an accumulator (giving rise to a compact representation and compact membership proofs) and an anonymity architecture (so that outputs from one transactions cannot be linked to inputs to another).
 - `lock_free_mmr_accumulator` the data structure holding lock-free UTXOs
 - `block_mmr_accumulator` the peaks of a Merkle mountain range that contains all historical blocks in the current block's line.

The *block appendix* consists of a list of claims. The block program verifies the truth of all of these claims. The appendix can be extended in future soft forks.

Besides the kernel, blocks also contain proofs. The block proof is a STARK proof of correct execution of the `BlockProgram`, which validates a subset of the validity rules below. In addition to that, it validates all claims listed in the appendix.

## Validity

**Note:** this section describes the validity rules for blocks at some future point when we have succinctness, not the current validity rules (although there is a significant overlap).

A block is *valid* if (any of):
 - ***a)*** it is the genesis block
 - ***b)*** the incremental validity conditions are satisfied
 - ***c)*** it lives in the `block_mmr_accumulator` of a block that is valid.

### A: Genesis Block

The genesis block is hardcoded in the source code, see `genesis_block` in `block/mod.rs`.

### B: Incremental Validity

A block is incrementally valid if (all of):
 - ***a)*** the transaction is valid
 - ***b)*** the transaction's coinbase conforms with the block subsidy schedule
 - ***c)*** all the inputs in the transaction either live in the lock-free UTXO MMR or have at least one index that is absent from the mutator set SWBF
 - ***d)*** the `mutator_set_accumulator` results from applying all removal records and then all addition records to the previous block's `mutator_set_accumulator`
 - ***e)*** the `block_mmr_accumulator` results from appending the previous block's hash to the previous block's `block_mmr_accumulator`
 - ***f)*** there is an ancestor block `luca` of the current block such that for each uncle block `uncle`
   - `uncle` is valid
   - `luca` is an ancestor of `uncle`
   - neither `luca` nor any of the blocks between `luca` and the current block list `uncle` as an uncle block
 - ***g)*** the `version` matches that of its predecessor or is member of a predefined list of exceptions
 - ***h)*** the `height` is one greater than that of its predecessor
 - ***i)*** the `timestamp` is greater than that of its predecssor
 - ***j)*** the network statistics trackers are updated correctly
 - ***k)*** the variable network parameters are updated correctly.

### C: Mmr Membership

A block is valid if it lives in the `block_mmr_accumulator` of a valid block. This feature ensures several things.
 1. It is possible to prove that one block is an ancestor of another.
 2. Archival nodes do not need to store old block proofs; storing the most recent block proof suffices.
 3. Non-tip blocks can be quickly verified to be valid and, if the receiver is synchronized to the tip, canonical as well.
 4. In case of reorganization, storing the now-abandoned tip proof continues to suffice to establish the *validity* of shared blocks. (That said, an archival node should prove *canonicity* of shared blocks also, and to do this he must synchronize and download all blocks on the new fork.)

## Confirmability

A block is *confirmable* if (all of):
 - ***a)*** it is valid
 - ***b)*** its timestamp is less than 5 minutes into the future
 - ***c)*** its size is less than the `MAX_BLOCK_SIZE` in `BFieldElement`s
 - ***d)*** its hash is less than the previous block's `target_difficulty`.

Confirmability is not something that can be proven. It must be checked explicitly by the node upon receiving the block.

## Canonicity

A block is *canonical* if it lives on the chain with the most cumulative proof-of-work. However, the fork chain rule is only evaluated if an incoming block has a *different* height than the current block.
