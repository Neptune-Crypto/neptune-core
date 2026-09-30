# Consensus Rule Sets

A consensus rule set is the collection of rules that determines whether a block is valid and whether a transaction can be included in a future block.

A fork is a change to the consensus rule set. A fork is a **softfork** if legacy versions of neptune-core (those that do not upgrade) still consider new blocks valid. A fork is a **hardfork** if old versions do not consider blocks following the new rules valid. Generally, a softfork adds requirements for a block to be valid, whereas a hardfork modifies or relaxes existing rules.

## Forks

Which rule set is in force is a function of two things: the network, and the height of the block in question. A node does not track the rule set as state; it derives it, and derives it afresh for every block, so a block deep in the chain is still validated under the rules that held when it was mined.

The rule sets below are the ones main net has used since the (balance-preserving) reboot of the network on August 5, 2025. Each row's activation height is the height of the *first* block to follow that rule set.

| **Name**         | **Type**                   | **Activation date (on main net)** | **Activation height (on main net)** | **Changes from previous rules**                                                                                                                                                   |
|------------------|----------------------------|-----------------------------------|-------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Reboot           | Balance-preserving restart | 2025-08-05                        | 0                                   | Fixed an inflation bug relating to transaction fees.                                                                                                                              |
| HardforkAlpha    | hard                       | 2025-11-14                        | 15,000                              | Allow the reuse of PoW preprocessing result across different block proposals in order to increase transaction throughput.                                                         |
| TvmProofVersion1 | hard                       | 2026-02-04                        | 23,401                              | Fixed a soundness bug in Triton VM (proof version 0), which was used by Triton VM v1.0.0. Note that proof version (0 vs 1) is independent of semantic version (v1.0.0 vs v2.0.0)  |
| HardforkBeta     | hard                       | ~2026-05-13                       | 38,000                              | Removes memory hardness of PoW; adds a lustration barrier to ensure the prior soundness bug did not inflate supply; checks PoW threshold against own difficulty, not parent.      |
| HardforkGamma    | hard                       | 2026-06-18                        | 40,300                              | Fixes June 2026 soundness bugs in the recursive proof verifier (upstream in `tasm-lib`) and in Triton VM's `sponge_mem_absorb` instruction, along with other under-constrained trace values; restarts the lustration counting, all earlier proofs having been found unsound; rejects transactions backdated by more than three days. |
| HardforkDelta    | hard                       | ~2026-09-24 (scheduled)           | 55,000                              | Activates transaction chaining: `SingleProof` gains the `Fix` and `Weld` branches, which recursively verify a `LinkProof` and so let a chained transaction (`LinkTx`) become a block-borne transaction. See [Transaction](./transaction.md).      |

### Other networks

Test net (`testnet-0`) follows the same sequence of rule sets, at its own heights:

| **Name**         | **Activation height (on test net)** |
|------------------|-------------------------------------|
| Reboot           | 0                                   |
| HardforkAlpha    | 120                                 |
| TvmProofVersion1 | 3,571                               |
| HardforkBeta     | 3,669                               |
| HardforkGamma    | 4,650                               |
| HardforkDelta    | 5,400                               |

Every other network -- `regtest`, `testnet-mock`, and `testnet-`*n* for *n* > 0 -- runs the newest rule set at every height, genesis included, rather than working through the sequence. Whatever a fork introduces is therefore live there from the first block: on those networks a chained transaction can become block-borne long before hardfork delta activates anywhere else. (Lustration is the one thing that cannot start at genesis, so it starts at height 1 instead.)

### What varies

A rule set is a bundle of individually small decisions. The table below gives the ones that differ; everything not listed is the same under all six.

| | **Reboot** | **Alpha** | **TvmV1** | **Beta** | **Gamma** | **Delta** |
|---|---|---|---|---|---|---|
| Triton proof version | 0 | 0 | 1 | 1 | 5 | 8 |
| Memory-hard PoW | yes | yes | yes | no | no | no |
| PoW threshold measured against parent's difficulty | yes | yes | yes | no | no | no |
| Lustration status in the block header | no | no | no | yes | yes | yes |
| Version committed to in PoW | no | no | no | yes | yes | yes |
| Lustration double-counting fixed | -- | -- | -- | no | yes | yes |
| Transaction backdating limit | none | none | none | none | 3 days | 3 days |
| `SingleProof` has the `Fix` and `Weld` branches | no | no | no | no | no | yes |

The last row is the one that makes delta a change to `SingleProof` itself rather than to the rules around it: two branches more is a different program with a different digest, so from delta there are two `SingleProof` programs, and which one a transaction's proof is about is settled by the height of the block that would contain it. See [Transaction](./transaction.md).

Held constant throughout: a block is at most 1,000,000 b-field elements, and a block transaction carries at most 2^14 inputs, 2^14 outputs and 2^14 announcements.

### The checkpoint

Some blocks have been proven under older version of Triton VM than the most recent. To prevent neptune-core from having to rely on multiple versions of Triton VM, the validity of blocks proved under older versions of Triton
VM is taken on faith by `neptune-core`. To verify their validity, older versions of `neptune-core` must be used.

To avoid having to carry around multiple versions of Triton VM, all blocks prior to the activation of hardfork delta are verified through a checkpoint that is defined for both main net and for testnet-0. All blocks mined
prior to the activation of hardfork delta are part of the checkpoint.

Consensus therefore carries a *checkpoint*: block 54,999, one below the HardforkDelta activation height, on main net; block 5,599 on test net; and genesis on every other network. At or below the checkpoint, stored blocks are canonical and their proofs are valid by fiat.

Two implications. A node that starts up and finds its own tip's block proof no longer valid rolls back to the checkpoint rather than all the way to genesis. And a node importing blocks from disk skips an invalid block at or below the checkpoint, instead of rejecting the file it came in.

To be clear: Triton VM can be upgraded to a version incompatible with the previous release either to fix a soundness error, or to increase performance. Triton VM proofs from Triton VM v7.0.0 (the hardfork gamma proof,
proof version 5) have been found to be *sound* for the consensus programs used by `neptune-core`. But they have been found to be unsound for some programs, namely those where the execution of the last part of the
program resulted in an unchanged claim and didn't crash execution in the VM. For this reason, the upgrade to Triton VM v8 (proof version 8) was made, such that more complicated programs could be run securely on the
Neptune protocol than just those defined by the consensus rules. This, along with the introduction of transaction chaining, was the reason for hardfork delta.

All blocks proofs after the activation of hardfork gamma are believed to be sound. None of the many extensive analysis have shown otherwise. Therefore, the lustration counter was not restarted by the activation of
hardfork delta. If anyone presents us with a proof that a hardfork gamma proof is unsound, that decision can be revised. Anyone wanting to verify the blocks of hardfork gamma will have to download an older client
(0.12.0-0.18.0, both inclusive) and verify those blocks with that older software. To minimize the size of this program, it does not carry verifiers for older versions of Triton VM.

## Notes
- **Historical proof versions** Reboot and HardforkAlpha use proof version 0; TvmProofVersion1 and HardforkBeta use 1; HardforkGamma uses 5; HardforkDelta uses 8. Every claim names the version it is made under, so a proof produced for one rule set does not verify under another.
- **HardforkBeta** introduces a lustration barrier to the block header. This lustration barrier acts as a counter that is decremented whenever a UTXO generated prior to the barrier is spent. The counter is decremented by the number of Neptune coins being spent. If the counter reaches zero, UTXOs generated prior to the barrier become unspendable. The guarantee is global: no more can ever be spent out of the pre-barrier supply than the counter was initialised to, so a soundness error preceding the barrier cannot be cashed out beyond that bound.
- **HardforkGamma** restarts the lustration counting, and it is worth being clear why: The barrier that HardforkBeta erected bounds what can be spent out of the UTXOs that predate *it*; the June 2026 soundness bugs then showed that proofs made between beta and gamma could not be relied upon either. Gamma therefore moves the barrier forward to its own activation height and re-initialises the counter -- to the premine, plus the claims pool, plus everything mined up to that height -- so that the bound once again covers every proof that might be unsound.
- **HardforkDelta** Upgraded the proof version to a more secure version of Triton VM, namely proof version 8. However, the problem with Triton VM proof version 7 did not affect the consensus programs that protect the total supply of Neptune coins. So the lustration counter was not restarted with hardfork delta, since all block proofs after hardfork *gamma* have been found to be valid and sound.
