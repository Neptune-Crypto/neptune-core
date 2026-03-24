# Triton Program

The canonical virtual machine that the nodes on the network use -- not to replicate state but to validate state updates in sync -- is [Triton VM](https://triton-vm.org/). As Triton-VM comes with a STARK prover and verifier, validating these updates boils down to verifying STARK proofs of particular programs called *Triton programs*. Triton programs are written in tasm (or compiled to tasm), which is the assembler language for Triton VM.

## Consensus versus Non-Consensus

Triton programs that govern the update of data related to the current state of the blockchain, and are validated (perhaps indirectly) as part of the block validity test, are called *consensus programs*. These are categorizable into two categories: those related to transactions, and those related to blocks.

For the time being, a lot of consensus rules are being enforced not through Triton programs but through code running on the host machine. In the future, notable with *succinctness*, almost all consensus rule enforcement will be moved from the host machine to consensus programs. Some features, like timestamp validation, can never be moved to the VM.

Not all Triton programs must affect the block validity test.

## In the Code

File `protocol/proof_abstractions/tasm/program.rs` defines a `TritonProgram` trait, which lets the user define the raw tasm code for the program they are writing. In the test module, there is also a `TritonProgramSpecification` trait which allows the programmer to additionally specify a rust shadow of the same program, which is useful simultaneously for specification and for testing. There are plenty of examples in `protocol/consensus/transaction/validity` to start from.
