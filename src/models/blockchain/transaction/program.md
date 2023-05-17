# Transaction Program

The *transaction program* is the unit of logic that establishes that a transaction is *valid* (i.e., internally consistent regardless of canonical chain context). Its input (supplied via standard input) is the hash of the transaction kernel. Its output (supplied to standard output) is the hash of the list of removal record indices of all input UTXOs. If the transaction is valid the transaction program halts gracefully; if not, it panics.

In order to facilitate outsourcing of recursion, the witness to the transaction program consists of the following data objects.

 1. A list of canonical commitments (with fresh randomness) to all input UTXOs along with their mutator set membership proofs.
 2. The hash of every type script.

With those witnesses in place, it is possible to chunk the pieces of logic into standalone programs -- which can be proved independently without recursion.

 1. For every committed input UTXO, the UTXO and membership proof generate the matching removal record indices in the kernel.
 2. For every committed input UTXO, its lock script is satisfied.
 3. The set of type scripts hashes matches with the set of all type scripts in all inputs and outputs as read from the kernel.
 4. For every type script, it is satisfied.

In order to outsource the proving step to a proof service, the witness data must be supplied along with proofs for the various chunks. The recursion step moves the witness to secret input and generates a single recursive proof that establishes that all component proofs were valid.
