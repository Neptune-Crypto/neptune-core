# Block

A block kernel consists of a header and a body. The block header has constant size and consists of:
 - `version` the version of the Neptune protocol
 - `height` the block height represented as a `BFieldElement`
 - `prev_block_digest` the hash of the block's predecessor
 - `timestamp` when the block was found
 - `nonce` randomness for proof-of-work
 - `max_block_size` maximum block size in bytes
 - `proof_of_work_line` approximate number of hashes computed in the block's direct lineage
 - `proof_of_work_family` approximate number of hashes computed in the block's family, including uncles
 - `difficulty` approximate number of hashes required to find a block.
 - (Other fields may be added to account for automatically updating network parameters.)

The block body holds the variable-size data, consisting of:
 - `transaction` every block contains one transaction, which represents the merger of all broadcasted transactions that the miner decided to confirm.
 - `mutator_set_accumulator` the [mutator set](../mutator-set.md) is the data structure that holds the UTXOs. It is simultaneously an accumulator (giving rise to a compact representation and compact membership proofs) and an anonymity architecture (so that outputs from one transactions cannot be linked to inputs to another).
 - `lock_free_mmr_accumulator` the data structure holding lock-free UTXOs
 - `block_mmr_accumulator` the peaks of a Merkle mountain range that contains all historical blocks in the current block's line.
 - `uncle_blocks` the digests of uncle blocks not listed so far. The miner needs to prove that between the latest common ancestor between the current block and all listed uncles, none of the listed uncles were included before.

## Validity

A block is *valid* if (any of):
 - ***a)*** it is the genesis block
 - ***b)*** the incremental validity conditions are satisfied
 - ***c)*** it lives in the `block_mmr_accumulator` of a block that is valid.

### A: Genesis Block

The genesis block is hardcoded in the source code.

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
 4. In case of reorganization, storing the now-abandoned tip proof continues to suffice to establish the *validity* of shared blocks. (That said, an archival node should take care to prove *canonicity* of shared blocks also, and to do this he must synchronize and download all blocks on the new fork.)

## Confirmability

## Canonicity

