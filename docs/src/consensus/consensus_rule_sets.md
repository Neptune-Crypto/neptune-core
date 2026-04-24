# Consensus Rule Sets

A consensus rule set is the collection of rules that determines whether a block is valid and whether a transaction can be included in a future block.

A fork is a change to the consensus rule set. A fork is a **softfork** if legacy versions of neptune-core (those that do not upgrade) still consider new blocks valid. A fork is a **hardfork** if old versions do not consider blocks following the new rules valid. Generally, a softfork adds requirements for a block to be valid, whereas a hardfork modifies or relaxes existing rules.

## Forks
Neptune Core's mainnet has utilized the following consensus rule sets since the (balance-preserving) reboot of the network on August 5, 2025.

| **Name**         | **Type**                   | **Activation date (on main net)** | **Activation height (on main net)** | **Changes from previous rules**                                                                                                                                                   |
|------------------|----------------------------|-----------------------------------|-------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Reboot           | Balance-preserving restart | 2025-08-05                        | 0                                   | Fixed an inflation bug relating to transaction fees.                                                                                                                              |
| HardforkAlpha    | hard                       | 2025-11-14                        | 15,000                              | Allow the reuse of PoW preprocessing result across different block proposals in order to increase transaction throughput.                                                         |
| TvmProofVersion1 | hard                       | 2026-02-04                        | 23,401                              | Fixed a soundness bug in Triton VM (proof version 0), which was used by Triton VM v1.0.0. Note that proof version (0 vs 1) is independent of semantic version (v1.0.0 vs v2.0.0)  |
| HardforkBeta     | hard                       | ~2026-05-13                       | 38,000                              | Removes memory hardness of PoW; adds a lustration barrier to ensure the prior soundness bug did not inflate supply; checks PoW threshold against own difficulty, not parent.      |

## Notes
- **TvmProofVersion1** fixed the soundness error that was present in the `triton-vm` proof version 0, which was used by `triton-vm` version `v1.0.0`. `triton-vm` `v2.0.0` uses proof version 1.
- **HardforkBeta** introduces a lustration barrier to the block header. This lustration barrier acts as a counter that is decremented whenever a UTXO generated prior to HardforkBeta is spent. The counter is decremented by the number of Neptune coins being spent. If the counter reaches zero, UTXOs generated prior to the activation of HardforkBeta become unspendable. This provides a global guarantee that the total money supply was not increased beyond its intended limit due to the soundness error prior to the **TvmProofVersion1** rule set.
