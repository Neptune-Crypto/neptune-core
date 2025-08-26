# Mining

## Three-Step Mining

Three-step mining entails separating three steps out of what can jointly be considered mining:
 1. *upgrading*, wherein the proof quality of transactions in the mempool is upgraded;
 2. *composing*, wherein one merger of transactions is used to build a block proposal;
 3. *guessing*, which is a search for a random number called a *nonce* (and other proof-of-work data) that sends the block's hash below the <span  style="color:red">target</span>.

## Composing

Composing involves making a selection of transactions, merging them, and producing a block proof. Because it involves proving, it requires beefy machinery.

## Guessing

The objective in the guessing step is to find *proof-of-work data*, (called `Pow` in the source code), which consists of:
 - one nonce, which is a `Digest`;
 - one root, which is a `Digest`;
 - two authentication paths, which are both lists of `Digest`s of length `M`.

Here, `M = 29` is the memory parameter which is chosen so as to make guessing expensive when done with significantly less memory than 40 GB or RAM.

Guessing consists of two phases, a preprocessing phase and an online phase.

### Preprocessing

During the preprocessing phase, a large buffer of around 40 GB is prepared. In the source code it is the `GuesserBuffer`. The *root* field of the proof-of-work data lives in this buffer.

### Online Guessing

Making one guess involves:
 - Sampling a nonce;
 - Hashing it to derive pseudorandom locations.
 - Reading authentication paths corresponding to those locations from the guesser buffer, thus completing the proof-of-work data.
 - Hashing the block.
 - Comparing the digest against the <span  style="color:red">target</span>.

The [Tip5](https://eprint.iacr.org/2023/107) hash function is used internally.

### Validating

In addition to verifying the inequality between the block hash and the target, validating proof-of-work also involves verifying the authentication paths embedded in the proof-of-work data. Phrased differently, the guesser *must* produce a valid root and authentication paths in order for his block to be accepted.

## Block Rewards

In the beginning of Neptune Cash's life, every block is allowed to mint a certain number of Neptune Coins. This number is known as the *block subsidy*. The initial subsidy is set to `INITIAL_BLOCK_SUBSIDY = 128`. This subsidy is halved automatically every `BLOCKS_PER_GENERATION = 160815` blocks , which corresponds to approximately three years. On the rebooted network, the first generation consists of only 139505 blocks, accounting for the 21310 blocks that were mined on the legacy network.

Half of the block subsidy is time-locked for `MINING_REWARD_TIME_LOCK_PERIOD = 3` years; and the other half is liquid immediately.

In addition to the block subsidy, blocks also redistribute the transaction fees paid by the transactions included in their block. The sum of the block subsidy and the transaction fees is the *block reward*.

## Distribution of Block Reward

The block reward is distributed between the composer and the guesser at a ratio determined solely by the composer. The composer claims (part of) the block reward by including into the block a transaction that spends it to UTXOs under his control. The guesser automatically receives the remaining portion upon finding the winning nonce.

Block composers can choose to disseminate block proposals, which are blocks without winning nonces. Guessers can pick the block proposal that is most favorable to them.
