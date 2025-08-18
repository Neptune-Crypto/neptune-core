# UTXO

A UTXO is a collection of coins owned by some person in between two transactions, along with a set of conditions under which it can be spent. Every UTXO is generated as an output of a transaction and is consumed as an input of a transaction.

A UTXO can be *lockable* or *lock-free*. Lockable and lock-free UTXOs are stored in different data structures, the [Mutator Set](./mutator-set.md) and an [MMR](./mmr.md) respectively. Consequently, lockable UTXOs undergo mixing whereas lock-free UTXOs are traceable by design. Another difference is that lockable UTXOs have lock scripts whereas lock-free UTXOs do not. (Note: lock-free UTXOs are not supported yet; they are including here as a wishlist feature.)

A coin consists of state and a type script hash. A UTXO can have multiple coins, but for every type script hash it can have at most one. The state of a coin can be any string of `BFieldElement`s; it relies on the type script for interpretation.

Type scripts and lock scripts are programs that prevent invalid expenditures. They are written in Triton VM assembler ("*tasm*") and their graceful execution is attested to through a Triton STARK proof.

## Lock Script

A *lock script* determines who, or more generally, under which conditions, a (lockable) UTXO can be spent. In the most basic case, the lock script verifies the presence or knowledge of secret key material that only the UTXO owner has access to, and crashes otherwise. Lock scripts can be arbitrarily complex, supporting shared ownership with quorums or even unlocking contingent upon certain cryptographic proofs unrelated to data.

The input to a lock script program is the transaction kernel MAST hash. As a result, a proof of graceful execution of a lock script is tailored to the transaction. Using nondeterminism, the program can *divine* features of the transaction and then authenticate that information against the kernel. In this way, a lock script can restrict the format of transactions that spend it.

## Type Script

A *type script* determines how the state of coins of a particular type is allowed to evolve across transaction. For instance, a type script could interpret the states of all coins of its type as amounts, and then verify for all UTXOs involved in a transaction, that the sum of inputs equals the sum of outputs and that no numbers are negative. This example captures accounting logic, and indeed, [Neptune Coins](./neptune-coins.md) embody this logic. Another example is a [time lock](./time-lock.md): this type script verifies that the timestamp on a transaction is larger than some specified value.

The input to a type script program is the transaction kernel MAST hash, the hash of the salted list of input UTXOs, and the hash of the salted list of output UTXOs. It takes two more arguments than lock scripts do, in order to facilitate reasoning about UTXOs involved in the transaction.

The `CollectTypeScripts` program, which is part of a `ProofCollection` testifying to the validity of a transaction, establishes that *all* type scripts are satisfied, including in particular both the input UTXOs' coins and the output UTXOs' coins. It is necessary to include the output UTXOs' type scripts because otherwise it is possible to generate a valid transaction whose inputs do not have any native currency coins but whose outputs do.
