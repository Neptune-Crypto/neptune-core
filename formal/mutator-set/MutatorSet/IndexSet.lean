import MutatorSet.AoclRange

/-!
# Absolute index sets

Model of `AbsoluteIndexSet::compute`
(`neptune-mutator-set/src/removal_record/absolute_index_set.rs`, v0.19.0):

```rust
let batch_index = aocl_leaf_index / BATCH_SIZE;
let batch_offset = batch_index * CHUNK_SIZE;
let relative_indices = sponge.sample_indices(WINDOW_SIZE, NUM_TRIALS);  // Tip5
let minimum = relative_indices.min();
let distances = relative_indices.map(|x| x - minimum);
Self { minimum: minimum + batch_offset, distances }
```

Tip5 is not modelled. Instead the sampler is a parameter whose only assumed
properties are the ones `sample_indices(WINDOW_SIZE, NUM_TRIALS)` guarantees:
it returns `NUM_TRIALS` values, each below `WINDOW_SIZE`.
-/

namespace MutatorSet

/-- Opaque stand-in for a Tip5 digest. Nothing is assumed about its structure. -/
opaque Digest : Type

/-- The index sampler: Tip5 absorbs (item, sender randomness, receiver
preimage, AOCL leaf index) and squeezes `NUM_TRIALS` indices below `W`. -/
structure Sampler where
  sample : Digest → Digest → Digest → Nat → List Nat
  length_eq : ∀ item r ρ i, (sample item r ρ i).length = NumTrials
  lt_W : ∀ item r ρ i, ∀ x ∈ sample item r ρ i, x < W

/-- Minimum of a list (`0` for the empty list, which never occurs here). -/
def lmin : List Nat → Nat
  | [] => 0
  | [x] => x
  | x :: y :: ys => min x (lmin (y :: ys))

/-- Maximum of a list (`0` for the empty list). -/
def lmax : List Nat → Nat
  | [] => 0
  | [x] => x
  | x :: y :: ys => max x (lmax (y :: ys))

theorem lmin_le : ∀ (l : List Nat), ∀ x ∈ l, lmin l ≤ x
  | [], _, h => by simp at h
  | [a], x, h => by simp at h; simp [lmin, h]
  | a :: b :: bs, x, h => by
      simp only [List.mem_cons] at h
      have ih := lmin_le (b :: bs)
      rcases h with rfl | h
      · simp [lmin]; omega
      · have := ih x (by simpa using h); simp only [lmin]; omega

theorem le_lmax : ∀ (l : List Nat), ∀ x ∈ l, x ≤ lmax l
  | [], _, h => by simp at h
  | [a], x, h => by simp at h; simp [lmax, h]
  | a :: b :: bs, x, h => by
      simp only [List.mem_cons] at h
      have ih := le_lmax (b :: bs)
      rcases h with rfl | h
      · simp [lmax]; omega
      · have := ih x (by simpa using h); simp only [lmax]; omega

theorem lmax_lt : ∀ (l : List Nat) (n : Nat), (∀ x ∈ l, x < n) → l ≠ [] → lmax l < n
  | [], _, _, h => absurd rfl h
  | [a], n, h, _ => by simp [lmax]; exact h a (by simp)
  | a :: b :: bs, n, h, _ => by
      have ih := lmax_lt (b :: bs) n (fun x hx => h x (List.mem_cons_of_mem _ hx)) (by simp)
      have ha := h a (by simp)
      simp only [lmax]; omega

theorem lmin_le_lmax (l : List Nat) (h : l ≠ []) : lmin l ≤ lmax l := by
  match l, h with
  | a :: as, _ => exact Nat.le_trans (lmin_le _ a (by simp)) (le_lmax _ a (by simp))

/-- Subtracting a common lower bound commutes with taking the maximum. -/
theorem lmax_map_sub : ∀ (l : List Nat) (m : Nat), lmax (l.map (· - m)) = lmax l - m
  | [], m => by simp [lmax]
  | [a], m => by simp [lmax]
  | a :: b :: bs, m => by
      have ih := lmax_map_sub (b :: bs) m
      simp only [List.map_cons, lmax] at *
      rw [ih]; omega

/-- Model of `AbsoluteIndexSet`: a `minimum` and the `distances` from it. -/
structure AbsoluteIndexSet where
  minimum : Nat
  distances : List Nat

/-- `AbsoluteIndexSet::to_array`: the absolute Bloom-filter indices. -/
def AbsoluteIndexSet.toList (s : AbsoluteIndexSet) : List Nat :=
  s.distances.map (s.minimum + ·)

/-- The largest distance, which `aocl_range` calls `max_offset`. -/
def AbsoluteIndexSet.maxOffset (s : AbsoluteIndexSet) : Nat := lmax s.distances

/-- Model of `AbsoluteIndexSet::compute`. -/
def compute (S : Sampler) (item r ρ : Digest) (i : Nat) : AbsoluteIndexSet :=
  let rel := S.sample item r ρ i
  let m := lmin rel
  { minimum := m + i / B * C, distances := rel.map (· - m) }

/-- `aocl_range` of an absolute index set. -/
def AbsoluteIndexSet.aoclRange (s : AbsoluteIndexSet) : Option (Nat × Nat) :=
  MutatorSet.aoclRange s.minimum s.maxOffset

theorem sample_ne_nil (S : Sampler) (item r ρ : Digest) (i : Nat) :
    S.sample item r ρ i ≠ [] := by
  intro h; have := S.length_eq item r ρ i; rw [h] at this; simp at this

/-- **Window lemma.** Every index of the removal record for AOCL index `i`
lies in the active window of `i`'s batch: `[⌊i/B⌋·C, ⌊i/B⌋·C + W)`. -/
theorem compute_in_window (S : Sampler) (item r ρ : Digest) (i : Nat) :
    ∀ a ∈ (compute S item r ρ i).toList, i / B * C ≤ a ∧ a < i / B * C + W := by
  intro a ha
  simp only [compute, AbsoluteIndexSet.toList, List.map_map, List.mem_map, Function.comp] at ha
  obtain ⟨x, hx, rfl⟩ := ha
  have h1 := lmin_le _ x hx
  have h2 := S.lt_W item r ρ i x hx
  simp only [W, C, B] at *
  omega

/-- **MS-3 (range correctness), stated for real removal records.** For every
item, randomness, receiver preimage and AOCL index `i`, the AOCL range
computed from the removal record exists and contains `i`. -/
theorem compute_aoclRange_contains (S : Sampler) (item r ρ : Digest) (i : Nat) :
    ∃ lo hi, (compute S item r ρ i).aoclRange = some (lo, hi) ∧ lo ≤ i ∧ i ≤ hi := by
  let rel := S.sample item r ρ i
  have hne : rel ≠ [] := sample_ne_nil S item r ρ i
  have hmM : lmin rel ≤ lmax rel := lmin_le_lmax rel hne
  have hM : lmax rel < W := lmax_lt rel W (S.lt_W item r ρ i) hne
  have key := aoclRange_contains (lmin rel) (lmax rel) i hmM hM
  refine ⟨_, _, ?_, key.2.1, key.2.2⟩
  have hoff : (compute S item r ρ i).maxOffset = lmax rel - lmin rel := by
    simp only [compute, AbsoluteIndexSet.maxOffset]; exact lmax_map_sub _ _
  simp only [AbsoluteIndexSet.aoclRange, hoff]
  exact key.1

/-- **MS-4 (width), stated for real removal records.** At most 2048 and at
least 8 candidate AOCL positions. -/
theorem compute_aoclRange_width (S : Sampler) (item r ρ : Digest) (i : Nat) :
    ∀ lo hi, (compute S item r ρ i).aoclRange = some (lo, hi) →
      B ≤ hi + 1 - lo ∧ hi + 1 - lo ≤ 2048 := by
  intro lo hi h
  let rel := S.sample item r ρ i
  have hne : rel ≠ [] := sample_ne_nil S item r ρ i
  have hmM : lmin rel ≤ lmax rel := lmin_le_lmax rel hne
  have hM : lmax rel < W := lmax_lt rel W (S.lt_W item r ρ i) hne
  have hoff : (compute S item r ρ i).maxOffset = lmax rel - lmin rel := by
    simp only [compute, AbsoluteIndexSet.maxOffset]; exact lmax_map_sub _ _
  have key := aoclRange_contains (lmin rel) (lmax rel) i hmM hM
  simp only [AbsoluteIndexSet.aoclRange, hoff] at h
  have hc : (compute S item r ρ i).minimum = computedMinimum (lmin rel) i := rfl
  rw [hc, key.1] at h
  simp only [Option.some.injEq, Prod.mk.injEq] at h
  obtain ⟨rfl, rfl⟩ := h
  exact aoclRange_width_bounds (lmin rel) (lmax rel) i hmM hM

end MutatorSet
