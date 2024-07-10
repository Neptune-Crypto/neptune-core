# Neptune Documentation

The documentation for Neptune is distributed across the following categories.

{{#include consensus.md}}

{{#include neptune-core.md}}

## Triton VM

Neptune achieves succinctness by requiring STARK proofs to certify most of the consensus-critical logic. As a consequence, verifying and even running a full node is cheap. The tradeoff is that someone has to produce these STARK proofs, and this burden ultimately falls on the miner.

The particular proof system that Neptune uses is [Triton VM](https://triton-vm.org/). Triton VM is a standalone project and comes with its own [documentation](https://triton-vm.org/spec/)

{{#include contributing.md}}
