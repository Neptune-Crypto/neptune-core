# Formal model of the mutator set (Lean 4)

Machine-checked proofs about the index derivation and spending rules of the
mutator set in [`neptune-mutator-set`](../../neptune-mutator-set), as of
neptune-core v0.19.0. The project uses core Lean 4 only (no Mathlib), so it
builds in about a second.

## What is proven

| Claim | Theorem | Statement |
|---|---|---|
| MS-1 | `no_double_spend` | After a UTXO's removal record is applied, no later removal record for it is removable, whatever happens in between. |
| MS-1b | `removable_after_unrelated` | An unrelated removal cannot spend an item one of whose bits it does not touch. |
| MS-2 | `compute_deterministic` | The index set depends only on (item, sender randomness, receiver preimage, AOCL index). |
| MS-W | `compute_in_window` | Every index lies in the active window of the UTXO's batch. |
| MS-3 | `compute_aoclRange_contains` | `aocl_range` of a removal record always succeeds and contains the true AOCL index. |
| MS-4a | `compute_aoclRange_width`, `aoclRange_width` | That range spans 8 to 2048 AOCL positions, and at most `((2^20 − s)/2^12 + 1)·8` for index spread `s`. |

MS-4a is the deterministic part of the anonymity-set question: a removal
record narrows the spent output down to at most 2048 and at least 8 candidate
positions. Simulation suggests a median of about 72; proving that
distribution (MS-4b), unlinkability (MS-5), and that the accumulator implements
the bit-set model (MS-6) are listed as open in [`claims.toml`](claims.toml).

## Model and assumptions

* **Tip5 is not modelled.** The sampler is a parameter (`Sampler`) whose only
  assumed property is what `sample_indices(WINDOW_SIZE, NUM_TRIALS)`
  guarantees: 45 values, each below 2^20.
* **The SWBF is one bit set** over absolute indices. The active window, the
  archived chunks and their MMR are representations of that set; their
  correctness is MS-6 (open).
* **Unbounded naturals.** Rust's `u64` overflow errors in `aocl_range` are not
  modelled; they cannot occur for realistic AOCL sizes.
* Lean's natural-number subtraction is saturating, which matches the
  `saturating_sub` calls in the Rust code.

## How the model is tied to the Rust code

`lake exe genvectors` writes [`vectors/aocl_range.csv`](vectors/aocl_range.csv):
2110 inputs to `aocl_range` (110 edge cases around chunk and window
boundaries, including 33 that must be rejected, plus 2000 pseudo-random cases)
with the outputs the Lean model computes. The Rust unit test
`removal_record::absolute_index_set::lean_model_vectors` checks that the Rust
implementation returns exactly the same values. If either side changes, one of
the two checks fails.

## Running

```sh
cd formal/mutator-set
./check.sh   # build, check axioms, and regenerate + compare the vectors
```

`check.sh` fails if any theorem uses `sorry` or an axiom other than
`propext`, `Quot.sound` and `Classical.choice`, or if the committed vectors
differ from what the model generates. The Rust side runs with the normal test
suite: `cargo test -p neptune-mutator-set lean_model_vectors`.

## Layout

| File | Content |
|---|---|
| `MutatorSet/Params.lean` | `WINDOW_SIZE`, `CHUNK_SIZE`, `BATCH_SIZE`, `NUM_TRIALS` |
| `MutatorSet/AoclRange.lean` | Model of `aocl_range`; range correctness and width bounds |
| `MutatorSet/IndexSet.lean` | Model of `AbsoluteIndexSet::compute`; window lemma; MS-3 and MS-4a for removal records |
| `MutatorSet/Filter.lean` | Bit-set model of the SWBF; MS-1 and MS-2 |
| `GenVectors.lean` | Test-vector generator |
| `CheckAxioms.lean` | Axiom report used by `check.sh` |
| `claims.toml` | Claims registry, including open claims |
