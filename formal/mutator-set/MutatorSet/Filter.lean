import MutatorSet.IndexSet

/-!
# Spending and double spends

The sliding-window Bloom filter is modelled as a set of bit positions,
`Nat → Bool`, over *absolute* indices. The active window, the archived chunks
and their Merkle mountain range are representations of this one bit set; this
file reasons about the bit set itself, not its commitment.

* A removal record **spends** an item by setting all of its indices.
* An index set is **spent** when all of its indices are set.
* A block may only apply a removal record that is **removable**: at least one
  of its indices is still unset (block validity rule 2(b) in
  `docs/src/consensus/block.md`).
-/

namespace MutatorSet

/-- The Bloom filter: which absolute indices are set. -/
abbrev Filter := Nat → Bool

/-- Apply a removal record: set all of its indices. -/
def setAll (f : Filter) (idx : List Nat) : Filter :=
  fun j => f j || decide (j ∈ idx)

/-- All indices are set. -/
def Spent (f : Filter) (idx : List Nat) : Prop := ∀ j ∈ idx, f j = true

/-- At least one index is still unset, so the removal record may be applied. -/
def Removable (f : Filter) (idx : List Nat) : Prop := ∃ j ∈ idx, f j = false

theorem removable_iff_not_spent (f : Filter) (idx : List Nat) :
    Removable f idx ↔ ¬ Spent f idx := by
  constructor
  · rintro ⟨j, hj, hf⟩ hs; have := hs j hj; simp_all
  · intro h
    apply Classical.byContradiction; intro hn
    apply h; intro j hj
    cases hfj : f j
    · exact absurd ⟨j, hj, hfj⟩ hn
    · rfl

/-- Setting bits never clears bits. -/
theorem setAll_mono (f : Filter) (idx : List Nat) (j : Nat) (h : f j = true) :
    setAll f idx j = true := by simp [setAll, h]

/-- Applying a removal record spends its index set. -/
theorem setAll_spends (f : Filter) (idx : List Nat) : Spent (setAll f idx) idx := by
  intro j hj; simp [setAll, hj]

/-- Once spent, always spent: later removals cannot unspend an item. -/
theorem spent_preserved (f : Filter) (idx idx' : List Nat) (h : Spent f idx) :
    Spent (setAll f idx') idx := fun j hj => setAll_mono f idx' j (h j hj)

/-- Applying a sequence of removal records. -/
def applyAll (f : Filter) : List (List Nat) → Filter
  | [] => f
  | r :: rs => applyAll (setAll f r) rs

theorem spent_preserved_all (f : Filter) (idx : List Nat) :
    ∀ (rs : List (List Nat)), Spent f idx → Spent (applyAll f rs) idx
  | [], h => h
  | r :: rs, h => spent_preserved_all _ idx rs (spent_preserved f idx r h)

/-- **MS-2 (determinism).** The index set depends only on (item, sender
randomness, receiver preimage, AOCL index). Two removal records for the same
UTXO at the same AOCL position are identical. -/
theorem compute_deterministic (S : Sampler) {item item' r r' ρ ρ' : Digest} {i i' : Nat}
    (h1 : item = item') (h2 : r = r') (h3 : ρ = ρ') (h4 : i = i') :
    compute S item r ρ i = compute S item' r' ρ' i' := by
  subst h1 h2 h3 h4; rfl

/-- **MS-1 (no double spend).** Once the removal record of a UTXO has been
applied, no later removal record for the same UTXO is removable, whatever
other removal records were applied in between. -/
theorem no_double_spend (S : Sampler) (item r ρ : Digest) (i : Nat)
    (f : Filter) (between : List (List Nat)) :
    let idx := (compute S item r ρ i).toList
    ¬ Removable (applyAll (setAll f idx) between) idx := by
  intro idx
  rw [removable_iff_not_spent]
  exact fun h => h (spent_preserved_all _ idx between (setAll_spends f idx))

/-- Applying an unrelated removal record does not spend an item whose index
set contains a bit that neither the filter nor the new record sets. This is
the formal content of "a removal only affects its own bits". -/
theorem removable_after_unrelated (f : Filter) (idx other : List Nat) (j : Nat)
    (hj : j ∈ idx) (hf : f j = false) (ho : j ∉ other) :
    Removable (setAll f other) idx := ⟨j, hj, by simp [setAll, hf, ho]⟩

end MutatorSet
