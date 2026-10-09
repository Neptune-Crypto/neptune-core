import MutatorSet.Params

/-!
# The AOCL range revealed by a removal record

Model of `AbsoluteIndexSet::aocl_range`
(`neptune-mutator-set/src/removal_record/absolute_index_set.rs`, v0.19.0).

An absolute index set is stored as a `minimum` plus 45 `distances`. The range
depends only on `minimum` and on the largest distance, `maxOffset`.

The Rust code converts intermediate values to `u64` and returns an error if a
conversion overflows. Lean's `Nat` is unbounded, so the model omits those
overflow errors; for inputs where Rust does not overflow, the results agree.
This is checked by shared test vectors (see `GenVectors.lean`).
-/

namespace MutatorSet

/-- Lower end of the range: the first AOCL index of the earliest batch whose
active window could contain every index of the set. -/
def rangeLo (minimum maxOffset : Nat) : Nat :=
  nextMultipleOf (maxOffset + minimum - (W - 1)) C / C * B

/-- Upper end of the range: the last AOCL index of the latest batch whose
active window could contain every index of the set. -/
def rangeHi (minimum : Nat) : Nat :=
  (nextMultipleOf (minimum + W + 1) C - C - W) / C * B + (B - 1)

/-- Model of `AbsoluteIndexSet::aocl_range`. Returns `none` exactly when Rust
returns `AbsoluteIndexExceedsTheoreticalBound` because `maxOffset ≥ W`. -/
def aoclRange (minimum maxOffset : Nat) : Option (Nat × Nat) :=
  if W ≤ maxOffset then none else some (rangeLo minimum maxOffset, rangeHi minimum)

/-- The `minimum` that `AbsoluteIndexSet::compute` produces for AOCL index `i`
when the smallest sampled relative index is `m`. -/
def computedMinimum (m i : Nat) : Nat := m + i / B * C

/-- **MS-3 (range correctness).** If the sampled relative indices have minimum
`m` and maximum `M` with `m ≤ M < W` (which `sample_indices(WINDOW_SIZE, _)`
guarantees), then the range computed from the resulting removal record exists
and contains the true AOCL index `i`. -/
theorem aoclRange_contains (m M i : Nat) (hmM : m ≤ M) (hM : M < W) :
    aoclRange (computedMinimum m i) (M - m) =
        some (rangeLo (computedMinimum m i) (M - m), rangeHi (computedMinimum m i)) ∧
      rangeLo (computedMinimum m i) (M - m) ≤ i ∧ i ≤ rangeHi (computedMinimum m i) := by
  refine ⟨?_, ?_, ?_⟩
  · have h : ¬ (W ≤ M - m) := by simp only [W] at *; omega
    simp [aoclRange, h]
  · simp only [rangeLo, nextMultipleOf, computedMinimum, W, C, B] at *; omega
  · simp only [rangeHi, nextMultipleOf, computedMinimum, W, C, B] at *; omega

/-- **MS-4a (width bound, refined).** The number of candidate AOCL positions
is at most `((W - s) / C + 1) · B`, where `s = M - m` is the spread of the
sampled indices. More spread-out index sets reveal a narrower range. -/
theorem aoclRange_width (m M i : Nat) (hmM : m ≤ M) (hM : M < W) :
    rangeHi (computedMinimum m i) + 1 - rangeLo (computedMinimum m i) (M - m)
      ≤ ((W - (M - m)) / C + 1) * B := by
  simp only [rangeLo, rangeHi, nextMultipleOf, computedMinimum, W, C, B] at *; omega

/-- **MS-4b (width bound, absolute).** A removal record always leaves at least
one full batch of candidates and at most `W / C · B = 2048`. -/
theorem aoclRange_width_bounds (m M i : Nat) (hmM : m ≤ M) (hM : M < W) :
    B ≤ rangeHi (computedMinimum m i) + 1 - rangeLo (computedMinimum m i) (M - m) ∧
    rangeHi (computedMinimum m i) + 1 - rangeLo (computedMinimum m i) (M - m) ≤ 2048 := by
  simp only [rangeLo, rangeHi, nextMultipleOf, computedMinimum, W, C, B] at *; omega

/-- `aoclRange` rejects exactly the index sets whose spread is not below `W`. -/
theorem aoclRange_none_iff (minimum maxOffset : Nat) :
    aoclRange minimum maxOffset = none ↔ W ≤ maxOffset := by
  unfold aoclRange
  by_cases h : W ≤ maxOffset <;> simp [h]

end MutatorSet
