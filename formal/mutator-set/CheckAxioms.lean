import MutatorSet

/-!
Prints the axioms each registered theorem depends on. CI fails if any output
mentions `sorryAx` or an axiom other than Lean's standard three
(`propext`, `Quot.sound`, `Classical.choice`). Run: `lake env lean CheckAxioms.lean`.
-/

open MutatorSet
#print axioms aoclRange_contains
#print axioms aoclRange_width
#print axioms aoclRange_width_bounds
#print axioms aoclRange_none_iff
#print axioms compute_in_window
#print axioms compute_aoclRange_contains
#print axioms compute_aoclRange_width
#print axioms compute_deterministic
#print axioms no_double_spend
#print axioms removable_after_unrelated
