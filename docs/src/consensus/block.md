# Block

A block kernel consists of a header, body, and an appendix.

The *block header* has constant size and consists of:
 - `version` the version of the Neptune protocol
 - `height` the block height represented as a `BFieldElement`
 - `prev_block_digest` the hash of the block's predecessor
 - `timestamp` when the block was found
 - `pow` the [proof-of-work data](mining)
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

**Note:** this section describes two distinct things. First is the validity rules for blocks currently in effect on the network. Second is the validity rules as they are intended to be after some consensus rule change, for instance the one that introduces [succinctness](succinctness.md).

A block is *valid* if (any of):
 - ***a)*** it is the genesis block
 - ***b)*** the incremental validity conditions are satisfied
 - ***c)*** it lives in the `block_mmr_accumulator` of a block that is valid.

### A: Genesis Block

The genesis block is hardcoded in the source code, see `genesis_block` in `block/mod.rs`.

### B: Incremental Validity

The term "incremental validity" reflects the relativity of the predicate: a block can only be incrementally valid *relative to* a predecessor block that is assumed to be valid.

A block is incrementally valid, relative to a predecessor block, iff (all of):

 0. The block's relation to its predecessor is correct, specifically (all of):
     - a) The block height is that of its predecessor plus one.
     - b) The `prev_block_digest` of the header equals the hash of the given predecessor block.
     - c) The `prev_block_digest` is the most recently accumulated element in the `block_mmr_accumulator`.
     - d) The block timestamp must be later than that of the predecessor plus the minimum block time. The minimum block time is set to 60 seconds.
     - e) The target difficulty was updated in accordance with the <span style="color:red">difficulty control algorithm</span>.
     - f) The current block's cumulative proof-of-work number equals that of the predecessor plus the predecessor's difficulty.
     - g) The block timestamp is not set further in the future, relative to the host machine's clock, than the futuredating limit, which is 5 minutes.
 1. The block's stand-alone non-transaction data is correct, specifically (all of):
     - a) The block appendix contains the expected claims. At present, the list of expected claims contains only one item: the claim that the block's transaction is valid.
     - b) The block appendix does not contain too many claims. The limit is 500.
     - c) The block proof is of the right type, namely `SingleProof`. (This variant lives on `BlockProof` and is distinct from the like-named variant living on `TransactionProof`.) The alternatives are `Genesis` and `Invalid`.
     - d) The proof passes Triton VM verification. The input for the claim is the block mast hash; the output is the (concatenation of) hashes of claims in the appendix; and the program is the `BlockProgram`. The `BlockProgram` merely proves the integral verification of all claims in the appendix.
     - e) The block does not exceed the maximum size, which is set to 1'000'000 `BFieldElement`s, or 8 MB.
 2. The block's transaction is correct, specifically (all of):
     - a) The removal records can be *unpacked*. Phrased differently, failure to unpack the removal records results in a format error.
     - b) All removal records must be *removable* from the mutator set as it was after the predecessor block.
     - c) The absolute index sets of all removal records must be unique.
     - d) The transaction, along with the block's guesser fee addition records, gives rise to a valid mutator set update. This step can fail, for instance, if the transaction fee is negative.
     - e) This mutator set update can be applied to the mutator set as it was after the previous block.
     - f) The transaction timestamp does not exceed the block timestamp.
     - g) The coinbase amount does not exceed the [block subsidy](mining) for this height.
     - h) The coinbase amoune is not negative.
     - i) The fee must not be negative.
     - j) The number of inputs is not too large. The limit is set to 16384.
     - k) The number of outputs is not too large. The limit is set to 16384.
     - l) The number of announcements is not too large. The limit is set to 16384.

### C: Mmr Membership

**Note:** This section describes an intended future rule for block validity. It is not currently supported.

A block is valid if it lives in the `block_mmr_accumulator` of a valid block. This feature ensures several things.
 1. It is possible to prove that one block is an ancestor of another.
 2. Archival nodes do not need to store old block proofs; storing the most recent block proof suffices.
 3. Non-tip blocks can be quickly verified to be valid and, if the receiver is synchronized to the tip, canonical as well.
 4. In case of reorganization, storing the now-abandoned tip proof continues to suffice to establish the *validity* of shared blocks. (That said, an archival node should prove *canonicity* of shared blocks also, and to do this he must synchronize and download all blocks on the new fork.)

## Confirmability

A block is *confirmable* if (all of):
 - ***a)*** it is valid
 - ***b)*** its timestamp is less than the futuredating limit (5 minutes) into the future
 - ***c)*** its size is less than the `MAX_BLOCK_SIZE` (1'000'000) in `BFieldElement`s
 - ***d)*** its hash is less than the previous block's `target_difficulty`.

Confirmability is not something that can be proven. It must be checked explicitly by the node upon receiving the block.

## Canonicity

A block is *canonical* if it lives on the chain with the most cumulative proof-of-work. However, the fork chain rule is only evaluated if an incoming block has a *different* height than the current block.
