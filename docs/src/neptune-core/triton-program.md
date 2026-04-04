# Triton Program

Neptune Cash relies on [Triton VM](https://triton-vm.org/) as the canonical virtual machine. Most other blockchains use their virtual machine to replicate state, meaning that all nodes on the network reproduce the same state. In constrast, Neptune Cash uses Triton VM to validate updates to the state commitment in sync, meaning that all nodes on the network reproduce the same *state commitment* and the integral evolution of the underlying state, which individual nodes may be oblivious of, is guaranteed through Triton VM.

Triton-VM comes with a STARK prover and verifier, validating these updates boils down to verifying STARK proofs of particular programs called *Triton programs*. Triton VM defines an instruction set architecture and hence an assembler language, which is called *tasm*. Triton programs are written in tasm (or compiled to tasm).

## Consensus versus Non-Consensus

*Consensus programs* is the name for the set of Triton programs that govern the update of data related to the current state of the blockchain, and are validated (perhaps indirectly) as part of the block validity test. Consensus programs are further divided into two categories: those related to transactions, and those related to blocks.

For the time being, a lot of consensus rules are being enforced not through Triton programs but through code running on the host machine. In the future, notably with *succinctness*, almost all consensus rule enforcement will be moved from the host machine to consensus programs. Some features, like timestamp validation, can never be moved to the VM.

Not all Triton programs must affect the block validity test.

## In the Code

All Triton programs whose execution is proven or verified (or both) implement a trait called `TritonProgram`, defined in `protocol/proof_abstractions/tasm/program.rs`. This trait lets the user define the raw tasm code for the program they are writing. In the test module, there is also a `TritonProgramSpecification` trait, which all programs should also implement. This additional trait allows the programmer to specify a rust shadow of the same program, which is useful simultaneously for specification and for testing. Furthermore, `TritonProgramSpecification` comes with a bunch of handy testing tools. There are plenty of examples in `protocol/consensus/transaction/validity` to start from.

To aid in debugging and testing, instructions `assert` and `assert_vector` can be marked with a unique error ID. Error IDs are indexed in `neptune-core/src/assertion_error_ids.md`, and there is a similar file in repository tasm-lib. So if your program crashes due to an assertion error, looking up which error code was returned will help you pinpoint the crash site. If you write a new Triton program and if you introduce new assert statements, be sure to add them to this file.
