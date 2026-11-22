/-!
# Mutator set parameters

Mirrors `neptune-mutator-set/src/shared.rs` (neptune-core v0.19.0):

```rust
pub const WINDOW_SIZE: u32 = 1 << 20;
pub const CHUNK_SIZE: u32 = 1 << 12;
pub const BATCH_SIZE: u32 = 1 << 3;
pub const NUM_TRIALS: u32 = 45;
```

They are written as literals (not `2 ^ k`) so that `omega` can use them directly.
-/

namespace MutatorSet

/-- `WINDOW_SIZE`: width of the active window of the sliding-window Bloom filter. -/
abbrev W : Nat := 1048576
/-- `CHUNK_SIZE`: the window slides by one chunk per batch. -/
abbrev C : Nat := 4096
/-- `BATCH_SIZE`: number of AOCL additions per window slide. -/
abbrev B : Nat := 8
/-- `NUM_TRIALS`: number of Bloom-filter indices per removal record. -/
abbrev NumTrials : Nat := 45

theorem W_eq : W = 2 ^ 20 := by decide
theorem C_eq : C = 2 ^ 12 := by decide
theorem B_eq : B = 2 ^ 3 := by decide
/-- The active window spans exactly 256 chunks. -/
theorem window_chunks : W / C = 256 := by decide

/-- Rust's `u128::next_multiple_of(c)` for `c > 0`: the least multiple of `c`
that is `≥ x`. Natural-number subtraction in Lean is saturating, which matches
Rust's `saturating_sub` used by the code below. -/
def nextMultipleOf (x c : Nat) : Nat := (x + c - 1) / c * c

end MutatorSet
