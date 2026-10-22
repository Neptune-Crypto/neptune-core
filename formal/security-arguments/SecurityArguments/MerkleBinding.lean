/-!
# SA-2: Merkle-leaf injectivity

Model of the authentication-path walk in twenty-first 3.0.0
(`util_types/mmr/mmr_membership_proof.rs`, `MmrMembershipProof::verify`):

```rust
let mut current_node = leaf_hash;
for &sibling in &self.authentication_path {
    let current_node_is_left_sibling = mt_index % 2 == 0;
    current_node = if current_node_is_left_sibling {
        Tip5::hash_pair(current_node, sibling)
    } else {
        Tip5::hash_pair(sibling, current_node)
    };
    mt_index /= 2;
}
peaks[peak_index] == current_node
```

The same walk authenticates FRI and trace commitments in Triton VM, the AOCL
and the inactive-SWBF chunks of the mutator set, and the block MMR.

**Theorem.** If two *different* leaves at the same node index both verify
against the same root, with authentication paths of the same length, then the
two walks contain an explicit collision of `hash_pair`. Contrapositive: as
long as no collision of Tip5's `hash_pair` is known, a verified path binds
its root to exactly one leaf at that position.
-/

namespace SecurityArguments

variable {D : Type} [DecidableEq D]

/-- The root reached from `cur` at heap index `idx` by following `path`. -/
def climb (H : D → D → D) : Nat → D → List D → D
  | _, cur, [] => cur
  | idx, cur, s :: ss => climb H (idx / 2) (if idx % 2 = 0 then H cur s else H s cur) ss

/-- A collision of the two-to-one hash function. -/
def Collision (H : D → D → D) : Prop :=
  ∃ a b a' b', (a, b) ≠ (a', b') ∧ H a b = H a' b'

/-- **SA-2 (Merkle-leaf injectivity / collision extraction).** -/
theorem leaf_injective_or_collision (H : D → D → D) :
    ∀ (idx : Nat) (x y : D) (px py : List D), px.length = py.length → x ≠ y →
      climb H idx x px = climb H idx y py → Collision H := by
  intro idx x y px
  induction px generalizing idx x y with
  | nil =>
      intro py hlen hxy heq
      match py, hlen with
      | [], _ => exact absurd heq hxy
  | cons s ss ih =>
      intro py hlen hxy heq
      match py, hlen with
      | t :: ts, hlen =>
        simp only [climb] at heq
        have hlen' : ss.length = ts.length := by simpa using hlen
        by_cases hpar : idx % 2 = 0
        · simp only [hpar, ite_true] at heq
          by_cases hnode : H x s = H y t
          · exact ⟨x, s, y, t, fun h => hxy (Prod.mk.inj h).1, hnode⟩
          · exact ih (idx / 2) _ _ ts hlen' hnode heq
        · simp only [hpar, ite_false] at heq
          by_cases hnode : H s x = H t y
          · exact ⟨s, x, t, y, fun h => hxy (Prod.mk.inj h).2, hnode⟩
          · exact ih (idx / 2) _ _ ts hlen' hnode heq

/-- Corollary in the usual form: with a collision-free hash, the leaf is unique. -/
theorem leaf_unique (H : D → D → D) (hcr : ¬ Collision H)
    (idx : Nat) (x y : D) (px py : List D) (hlen : px.length = py.length)
    (heq : climb H idx x px = climb H idx y py) : x = y := by
  by_cases hxy : x = y
  · exact hxy
  · exact absurd (leaf_injective_or_collision H idx x y px py hlen hxy heq) hcr

end SecurityArguments
