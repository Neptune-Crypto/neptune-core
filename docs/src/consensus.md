## Consensus

Consensus is the feature of a network whose nodes overwhelmingly agree on the current contents of a database, typically a blockchain. This database is append-only. While reorganizations can happen they are expected to be rare and shallow. Every once in a while, a new block is added. The block contains, among other things, a transaction. [Block](./consensus/block.md)s, [Transaction](./consensus/transaction.md)s, and [UTXO](./consensus/utxo.md)s are the key data objects that consensus pertains to. The *consensus logic* determines which blocks and transactions are *valid* and *confirmable*.

Note that there is a distinction between *valid* and *confirmable*. Validity refers to the internal consistency of a data object. Confirmable refers to its current relation to the rest of the blockchain. For example, having insufficient proof-of-work or including a double-spending transaction makes a block invalid. But a block can be both valid and unconfirmable, for instance if its timestamp is too far into the future. STARK proofs are capable of establishing validity but not confirmability.

Since both blocks and transactions come with STARK proofs certifying their validity, it is worthwhile to separate the kernel from the proof. The *kernel* is the actual payload data that appears on the blockchain, and the object that the proof asserts validity of. There can be different proofs certifying the validity of a block or transaction kernel. Proofs can typically be recursed away so that the marginal cost of storing them is zero.

