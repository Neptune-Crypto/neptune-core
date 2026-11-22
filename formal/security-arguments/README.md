# Machine-checked security arguments (Lean 4)

Lean proofs of the quantitative security arguments behind Neptune Cash's
proof system and mutator set, in the style of a security-proof bundle: each
argument is stated precisely, proved without `sorry` and with only Lean's
standard axioms, and **pinned to the exact source it is about** (see
[`../pins.toml`](../pins.toml)), so the proofs cannot silently drift from the
code. Core Lean only (no Mathlib); builds in seconds.

| ID | Argument | Key result |
|---|---|---|
| SA-1 | **Query counting** for FRI with `Stark::default()` | 80 collinearity checks give exactly 160 bits (conjectured regime) and 80 bits (provable regime) for the query phase; `Stark::new` never loses more than `k − 1` bits to rounding; `|F_{p³}| > 2^191` |
| SA-2 | **Merkle-leaf injectivity** for the authentication walk of `MmrMembershipProof::verify` | Two different leaves verifying to one root give an explicit `hash_pair` collision |
| SA-3 | **Exact sampling** in `Tip5::sample_indices` | Rejecting `p − 1` makes Bloom-filter indices exactly uniform: each of the 2²⁰ values has `2^44 − 2^12` preimages; without rejection index 0 is biased |
| SA-4 | **Privacy overlap / false-positive bound** for the mutator set | At most 4,088 outputs can touch a window, at most 45·4,088 of its bits are set, so a fresh output appears spent with probability below **2⁻¹¹²** |

Probabilities are ratios of counts, defined by explicit recursion
(`countBelow`, `sumBelow`, `tcount` in `Counting.lean` and `Overlap.lean`),
and every bound is proved about those definitions.

**What is not claimed.** Assumptions and scope limits of each argument are in
[`claims.toml`](claims.toml). In particular SA-1 covers the FRI query phase
only and takes the per-query error as a modelling assumption; the component
bounds here are not a whole-system security level.

## Running

```sh
./check.sh                         # build + axiom check
python3 ../pins.py check           # source pins (offline)
python3 ../pins.py check --upstream  # also re-hash upstream Triton VM / twenty-first items
```
