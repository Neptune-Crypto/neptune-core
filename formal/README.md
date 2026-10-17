# Formal verification

Machine-checked (Lean 4) models and proofs for consensus- and privacy-critical
parts of Neptune Cash.

| Directory | Content |
|---|---|
| [`mutator-set/`](mutator-set) | Model of `AbsoluteIndexSet::compute`, `aocl_range` and the spending rule: no double spend, determinism, window lemma, range correctness and width bounds (MS-1 … MS-4a) |
| [`security-arguments/`](security-arguments) | Quantitative security arguments: FRI query counting, Merkle-leaf injectivity, exact index sampling, privacy-overlap / false-positive bound (SA-1 … SA-4) |
| [`pins.toml`](pins.toml), [`pins.py`](pins.py) | Source pins: every claim is tied to the SHA-256 of the Rust items, upstream crate items and Lean files it is about |

## Source pinning

A proof about a model protects users only while the model matches the code.
`pins.toml` records, for every claim, the hash of:

* each **Rust item** it models (function or constant, extracted by marker, so
  unrelated edits in the same file do not matter);
* each **upstream crate** it depends on, via the `Cargo.lock` checksum
  (Triton VM 9.0.0, twenty-first 3.0.0), plus the specific upstream items;
* the **Lean files** containing the proofs.

`python3 formal/pins.py check` fails when any pinned source changes. The fix
is never to just update the hash: re-examine the claim, adjust the model and
proofs if needed, re-run `check.sh`, and then `pins.py update`.

## CI

`.github/workflows/formal.yml` runs both Lean projects' `check.sh` and the pin
check on every change to `formal/`, `neptune-mutator-set/`, `neptune-consensus/`
or `Cargo.lock`.
