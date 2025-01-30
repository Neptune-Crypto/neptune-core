# Two-Step Mining

Two-step mining entails separating two steps out of what can jointly be considered mining:
 1. *composing*, wherein transactions are assembled and a block proposal is composed;
 2. *guessing*, which is a search for a random number called a *nonce* that sends the block's hash below the target.

## Composing

Composing involves making a selection of transactions, merging them, and producing a block proof. Because it involves proving, it requires beefy machinery.

## Guessing

Making one guess involves sampling a random number and hashing 7 times using the [Tip5](https://eprint.iacr.org/2023/107) hash function. Very few computational resources are required to perform this step and as a result it should be possible on simple and cheap hardware.

## Block Rewards

In the beginning of Neptune's life, every block is allowed to mint a certain number of Neptune coins. This number is known as the *block subsidy*. The initial subsidy is set to `INITIAL_BLOCK_SUBSIDY = 64`. This subsidy is halved automatically every `BLOCKS_PER_GENERATION = 321630` blocks , which corresponds to approximately three years.

In addition to the block subsidy, blocks also redistribute the transaction fees paid by the transactions included in their block. The sum of the block subsidy and the transaction fees is the *block reward*.

Half of the block reward is time-locked for `MINING_REWARD_TIME_LOCK_PERIOD = 3` years; and the other half is liquid immediately.

## Distribution of Block Reward

The block reward is distributed between the composer and the guesser at a ratio determined solely by the composer. The composer claims (part of) the block reward by including into the block a transaction that spends it to UTXOs under his control. The guesser automatically receives the remaining portion upon finding the winning nonce.

Block composers can choose to disseminate block proposals, which are blocks without winning nonces. Guessers can pick the block proposal that is most favorable to them.
